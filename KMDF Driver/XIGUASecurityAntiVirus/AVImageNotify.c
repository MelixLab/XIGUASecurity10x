//=============================================================================
// AVImageNotify.c - 镜像加载监控模块
//
// 使用 PsSetLoadImageNotifyRoutine 监控 DLL/驱动加载:
//   1. 系统进程注入: explorer/svchost 等加载非系统目录的 DLL
//   2. 可疑路径: 从 Temp/Downloads/Desktop 加载 DLL
//   3. 反射式注入: 无文件背书的内存镜像 (ImageInfo->ImageFileName == NULL)
//
// 注: 原"白加黑"(DLL与exe同目录)检测已移除 — 正常程序普遍将 DLL
//     放在 exe 同目录, 该规则产生大量误报。真正的白加黑攻击已被
//     上述检查覆盖 (系统进程从非系统目录加载 DLL / 可疑路径 DLL)。
//
// 检测逻辑:
//   - 只监控 DLL 加载 (ImageInfo->ImageFileType == ImageDdsType 0x3)
//   - 跳过 \Windows\System32\ 等系统目录的正常 DLL 加载
//   - 对可疑加载记录告警并通知用户态, 用户"拒绝"时终止加载进程
//
// IRQL: 回调运行在 PASSIVE_LEVEL
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVImageNotify.h"
#include "AVProcessNotify.h"
#include <ntstrsafe.h>

//=============================================================================
// 手动声明的内核 API
//=============================================================================
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwTerminateProcess(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    );

NTKERNELAPI
PEPROCESS
NTAPI
PsGetCurrentProcess(
    VOID
    );

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process
    );

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

#define AV_PROCESS_IMAGE_FILE_NAME_CLASS 27

//
// ImageFileType 值 (来自 PIMAGE_INFO_EX)
//   ImageDdsType  = 0  (DDS 纹理)
//   ImageVxdType  = 1  (VxD)
//   ImageExeType  = 2  (EXE)
//   ImageDllType  = 3  (DLL)
//
// 旧版 PIMAGE_INFO 无 ImageFileType 字段, 通过信息大小判断
//

//=============================================================================
// 全局数据
//=============================================================================

#pragma section("NonPaged", long, read, write)
#define AV_NON_PAGED __declspec(allocate("NonPaged"))

//
// 待处理通知 (单条目, 自旋锁保护)
//
AV_NON_PAGED static KSPIN_LOCK        g_ImageLock;
AV_NON_PAGED static AV_IMAGE_NOTIFICATION g_ImagePendingNotify;
AV_NON_PAGED static BOOLEAN           g_ImageNotifyAvailable = FALSE;
AV_NON_PAGED static BOOLEAN           g_ImageDecisionPending = FALSE;
AV_NON_PAGED static BOOLEAN           g_ImageAllow = FALSE;
AV_NON_PAGED static UINT64            g_ImageNotifyIdCounter = 0;
AV_NON_PAGED static KEVENT            g_ImageWaitEvent;

//
// 决策等待超时 (毫秒)
// 回调不阻塞加载 (通知回调无法阻止), 超时后默认允许
//
#define AV_IMAGE_DECISION_TIMEOUT_MS 30000

AV_NON_PAGED static BOOLEAN           g_ImageNotifyRegistered = FALSE;
AV_NON_PAGED static UINT64            g_ImageAnomalyCount = 0;

//
// 需要保护的关键系统进程 (加载非系统DLL时告警)
// 使用子串匹配 (绕过 PsGetProcessImageFileName 14字符截断)
//
AV_NON_PAGED static const PCSTR g_ProtectedSystemProcesses[] =
{
    "explorer",       // 资源管理器 (银狐常注入目标)
    "svchost",        // 服务宿主 (银狐常注入目标)
    "winlogon",       // 登录管理器
    "lsass",          // 本地安全授权
    "csrss",          // 客户端服务器运行时
    "services",       // 服务管理器
    "spoolsv",        // 打印后台处理
    "rundll32",       // DLL 宿主 (白加黑常用)
    "regsvr32",       // 注册/反注册 (LotL 滥用)
    "dllhost",        // COM Surrogate
    "taskhostw",      // 任务宿主
    "sihost",         // Shell 基础结构宿主
};
AV_NON_PAGED static const UINT32 g_ProtectedSystemProcCount =
    sizeof(g_ProtectedSystemProcesses) / sizeof(g_ProtectedSystemProcesses[0]);

//=============================================================================
// 字符串辅助
//=============================================================================

static
SIZE_T
AvImageStrLenA(
    _In_ PCSTR s
    )
{
    SIZE_T n = 0;
    while (s[n] != '\0') n++;
    return n;
}

static
CHAR
AvImageToLowerA(
    _In_ CHAR c
    )
{
    if (c >= 'A' && c <= 'Z') return (CHAR)(c + 32);
    return c;
}

//
// 大小写不敏感的子串查找 (ASCII)
//
static
BOOLEAN
AvImageContainsSubstrA(
    _In_ PCSTR haystack,
    _In_ PCSTR needle
    )
{
    SIZE_T hayLen, needleLen, i, j;

    if (haystack == NULL || needle == NULL) return FALSE;

    hayLen = AvImageStrLenA(haystack);
    needleLen = AvImageStrLenA(needle);

    if (needleLen == 0 || hayLen < needleLen) return FALSE;

    for (i = 0; i + needleLen <= hayLen; i++)
    {
        BOOLEAN match = TRUE;
        for (j = 0; j < needleLen; j++)
        {
            if (AvImageToLowerA(haystack[i + j]) != AvImageToLowerA(needle[j]))
            {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

//
// 大小写不敏感的子串查找 (UNICODE, 基于 UNICODE_STRING)
//
static
BOOLEAN
AvImageContainsSubstrW(
    _In_ const UNICODE_STRING* Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T hayChars, needleChars, i, j;

    if (Haystack == NULL || Haystack->Buffer == NULL || Needle == NULL)
        return FALSE;

    hayChars = Haystack->Length / sizeof(WCHAR);
    needleChars = wcslen(Needle);

    if (needleChars == 0 || hayChars < needleChars) return FALSE;

    for (i = 0; i + needleChars <= hayChars; i++)
    {
        BOOLEAN match = TRUE;
        for (j = 0; j < needleChars; j++)
        {
            if (RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]) !=
                RtlUpcaseUnicodeChar(Needle[j]))
            {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

//
// 获取进程镜像路径
//
static
NTSTATUS
AvImageGetProcessImagePath(
    _In_ UINT32 ProcessId,
    _Out_writes_bytes_(BufferBytes) PWCHAR Path,
    _In_ SIZE_T BufferBytes
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES oa;
    BYTE buffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
    PUNICODE_STRING imagePath = (PUNICODE_STRING)buffer;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (Path == NULL || BufferBytes < sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    Path[0] = L'\0';

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &clientId);
    if (!NT_SUCCESS(status)) return status;

    status = ZwQueryInformationProcess(hProcess, AV_PROCESS_IMAGE_FILE_NAME_CLASS,
                                       buffer, sizeof(buffer), &returnLength);
    if (NT_SUCCESS(status) && imagePath->Buffer != NULL && imagePath->Length > 0 &&
        ((ULONG_PTR)imagePath->Buffer - (ULONG_PTR)buffer + imagePath->Length) <= sizeof(buffer))
    {
        SIZE_T copyBytes = min(imagePath->Length, BufferBytes - sizeof(WCHAR));
        RtlCopyMemory(Path, imagePath->Buffer, copyBytes);
        Path[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    ZwClose(hProcess);
    return status;
}

//=============================================================================
// 异常检测逻辑
//=============================================================================

//
// AvImageCheckAnomaly - 检查镜像加载是否异常
// 返回异常类型和描述; 无异常返回 AvImageAnomalyNone
//
static
AV_IMAGE_ANOMALY_TYPE
AvImageCheckAnomaly(
    _In_ const UNICODE_STRING* ImageFileName,
    _In_ UINT32 ProcessId,
    _Out_ PCWSTR* Description
    )
{
    PEPROCESS process = NULL;
    PCHAR procName = NULL;
    NTSTATUS status;
    UINT32 i;

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0)
    {
        //
        // 无文件背书的镜像加载 -> 反射式注入
        // (PsSetLoadImageNotifyRoutine 正常情况下 ImageFileName 不为 NULL,
        //  反射式注入/手动映射可能触发无文件名回调)
        //
        if (Description) *Description = L"Reflective DLL injection (no file backing)";
        return AvImageAnomalySystemInject;
    }

    //
    // 检查 1: 从可疑路径加载 DLL (Temp/Downloads/Desktop)
    //
    if (AvImageContainsSubstrW(ImageFileName, L"\\Temp\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Downloads\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Desktop\\"))
    {
        if (Description) *Description = L"DLL loaded from suspicious user directory";
        return AvImageAnomalySuspiciousPath;
    }

    //
    // 系统目录的 DLL 加载通常是正常的, 跳过后续检查
    //
    if (AvImageContainsSubstrW(ImageFileName, L"\\Windows\\System32\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Windows\\SysWOW64\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Windows\\WinSxS\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Windows\\assembly\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Program Files\\") ||
        AvImageContainsSubstrW(ImageFileName, L"\\Program Files (x86)\\"))
    {
        return AvImageAnomalyNone;
    }

    //
    // 检查 2: 系统关键进程加载非系统目录 DLL
    //
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (NT_SUCCESS(status) && process != NULL)
    {
        procName = PsGetProcessImageFileName(process);

        if (procName != NULL)
        {
            for (i = 0; i < g_ProtectedSystemProcCount; i++)
            {
                if (AvImageContainsSubstrA(procName, g_ProtectedSystemProcesses[i]))
                {
                    //
                    // 系统进程加载了非系统目录的 DLL -> 疑似注入
                    //
                    if (Description)
                        *Description = L"System process loading non-system DLL (potential injection)";
                    ObDereferenceObject(process);
                    return AvImageAnomalySystemInject;
                }
            }
        }
        ObDereferenceObject(process);
    }

    //
    // 注: 原"白加黑"检测 (DLL 与 exe 同目录) 已移除。
    // 正常应用程序普遍将 DLL 放在 exe 同目录, 该规则产生大量误报。
    // 真正的白加黑攻击已被上面的检查覆盖:
    //   - 检查 1: 可疑路径 (Temp/Downloads/Desktop) 的 DLL
    //   - 检查 2: 系统进程加载非系统目录 DLL
    //   - 反射式注入: 无文件背书的镜像
    //

    return AvImageAnomalyNone;
}

//=============================================================================
// 镜像加载回调
//=============================================================================

static
VOID
AvImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    UINT32 pid;
    AV_IMAGE_ANOMALY_TYPE anomaly;
    PCWSTR description = NULL;
    UNICODE_STRING imageFileName;
    KIRQL irql;
    BOOLEAN clientActive;

    //
    // 只监控用户态进程 (ProcessId != 0) 且有用户态客户端在线
    //
    pid = (UINT32)(ULONG_PTR)ProcessId;
    if (pid == 0 || pid == 4)
        return;

    //
    // 无用户态客户端时跳过 (无人处理通知)
    //
    clientActive = AvProcessIsClientActive();
    if (!clientActive)
        return;

    //
    // 只处理 DLL 加载 (ImageInfo 没有直接的 FileType 字段,
    // 通过 FullImageName 扩展名判断)
    //
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0)
    {
        //
        // 无文件名 -> 可能是反射式注入, 进一步检查
        //
        RtlInitUnicodeString(&imageFileName, L"");
    }
    else
    {
        imageFileName = *FullImageName;

        //
        // 跳过非 DLL 的镜像 (exe, sys 等已在进程创建回调拦截)
        //
        if (!AvImageContainsSubstrW(&imageFileName, L".dll") &&
            !AvImageContainsSubstrW(&imageFileName, L".DLL") &&
            !AvImageContainsSubstrW(&imageFileName, L".ocx") &&
            !AvImageContainsSubstrW(&imageFileName, L".cpl"))
        {
            return;
        }
    }

    //
    // 检查异常
    //
    anomaly = AvImageCheckAnomaly(&imageFileName, pid, &description);
    if (anomaly == AvImageAnomalyNone)
        return;

    //
    // 已有待处理通知时丢弃新的 (单条目设计, 避免系统卡顿)
    //
    KeAcquireSpinLock(&g_ImageLock, &irql);

    if (g_ImageDecisionPending)
    {
        KeReleaseSpinLock(&g_ImageLock, irql);
        return;
    }

    //
    // 填充通知
    //
    RtlZeroMemory(&g_ImagePendingNotify, sizeof(g_ImagePendingNotify));
    g_ImagePendingNotify.HasPending = TRUE;
    g_ImagePendingNotify.NotificationId =
        InterlockedIncrement64((PLONG64)&g_ImageNotifyIdCounter);
    g_ImagePendingNotify.ProcessId = pid;
    g_ImagePendingNotify.AnomalyType = (UINT32)anomaly;

    //
    // 复制镜像路径
    //
    if (imageFileName.Length > 0 && imageFileName.Buffer != NULL)
    {
        SIZE_T copyBytes = min(imageFileName.Length,
                               sizeof(g_ImagePendingNotify.ImagePath) - sizeof(WCHAR));
        RtlCopyMemory(g_ImagePendingNotify.ImagePath, imageFileName.Buffer, copyBytes);
        g_ImagePendingNotify.ImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    //
    // 复制加载者进程路径
    //
    {
        WCHAR procPath[AV_MAX_PROCESS_PATH_LEN];
        RtlZeroMemory(procPath, sizeof(procPath));
        AvImageGetProcessImagePath(pid, procPath, sizeof(procPath));
        RtlStringCbCopyW(g_ImagePendingNotify.ProcessImagePath,
                         sizeof(g_ImagePendingNotify.ProcessImagePath), procPath);
    }

    //
    // 复制描述
    //
    if (description != NULL)
    {
        RtlStringCbCopyW(g_ImagePendingNotify.RuleDescription,
                         sizeof(g_ImagePendingNotify.RuleDescription), description);
    }

    g_ImageNotifyAvailable = TRUE;
    g_ImageDecisionPending = TRUE;
    g_ImageAllow = FALSE;

    InterlockedIncrement64((PLONG64)&g_ImageAnomalyCount);

    KeReleaseSpinLock(&g_ImageLock, irql);

    KdPrint(("AVImage: Anomaly detected PID %u type %u: %ws -> %ws\n",
             pid, (UINT32)anomaly,
             g_ImagePendingNotify.RuleDescription,
             g_ImagePendingNotify.ImagePath));
}

//=============================================================================
// 初始化 / 卸载
//=============================================================================

NTSTATUS
AvImageNotifyInitialize(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    KdPrint(("AVImage: Initializing image load notification\n"));

    KeInitializeSpinLock(&g_ImageLock);
    KeInitializeEvent(&g_ImageWaitEvent, NotificationEvent, FALSE);
    RtlZeroMemory(&g_ImagePendingNotify, sizeof(g_ImagePendingNotify));
    g_ImageNotifyAvailable = FALSE;
    g_ImageDecisionPending = FALSE;
    g_ImageNotifyIdCounter = 0;
    g_ImageAnomalyCount = 0;

    status = PsSetLoadImageNotifyRoutine(AvImageLoadCallback);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVImage: PsSetLoadImageNotifyRoutine failed 0x%08X\n", status));
        return status;
    }

    g_ImageNotifyRegistered = TRUE;

    KdPrint(("AVImage: Initialized successfully\n"));
    return STATUS_SUCCESS;
}

VOID
AvImageNotifyUninitialize(
    VOID
    )
{
    PAGED_CODE();

    KdPrint(("AVImage: Uninitializing\n"));

    if (g_ImageNotifyRegistered)
    {
        PsRemoveLoadImageNotifyRoutine(AvImageLoadCallback);
        g_ImageNotifyRegistered = FALSE;
    }

    //
    // 如果有等待中的决策, 唤醒并默认允许
    //
    if (g_ImageDecisionPending)
    {
        g_ImageAllow = TRUE;
        KeSetEvent(&g_ImageWaitEvent, IO_NO_INCREMENT, FALSE);
    }

    KdPrint(("AVImage: Uninitialized (anomalies detected: %llu)\n", g_ImageAnomalyCount));
}

//=============================================================================
// 通知获取 / 决策处理
//=============================================================================

NTSTATUS
AvImageGetPendingNotification(
    _Out_ AV_IMAGE_NOTIFICATION* Notification
    )
{
    KIRQL irql;

    PAGED_CODE();

    if (Notification == NULL)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Notification, sizeof(*Notification));

    KeAcquireSpinLock(&g_ImageLock, &irql);

    if (g_ImageNotifyAvailable)
    {
        RtlCopyMemory(Notification, &g_ImagePendingNotify, sizeof(*Notification));
        g_ImageNotifyAvailable = FALSE;
    }
    else
    {
        Notification->HasPending = FALSE;
    }

    KeReleaseSpinLock(&g_ImageLock, irql);

    return STATUS_SUCCESS;
}

NTSTATUS
AvImageHandleDecision(
    _In_ const AV_IMAGE_DECISION* Decision
    )
{
    KIRQL irql;
    UINT32 pid = 0;
    BOOLEAN shouldTerminate = FALSE;

    PAGED_CODE();

    if (Decision == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_ImageLock, &irql);

    if (!g_ImageDecisionPending)
    {
        KeReleaseSpinLock(&g_ImageLock, irql);
        return STATUS_NOT_FOUND;
    }

    //
    // 验证通知 ID 匹配
    //
    if (Decision->NotificationId != g_ImagePendingNotify.NotificationId)
    {
        KeReleaseSpinLock(&g_ImageLock, irql);
        return STATUS_INVALID_PARAMETER;
    }

    pid = g_ImagePendingNotify.ProcessId;

    //
    // 决策: 允许 / 拒绝
    //
    if (Decision->Decision == AvDecisionAllowOnce ||
        Decision->Decision == AvDecisionAllowAlways)
    {
        g_ImageAllow = TRUE;
        shouldTerminate = FALSE;
    }
    else
    {
        g_ImageAllow = FALSE;
        shouldTerminate = TRUE;
    }

    g_ImageDecisionPending = FALSE;
    KeSetEvent(&g_ImageWaitEvent, IO_NO_INCREMENT, FALSE);

    KeReleaseSpinLock(&g_ImageLock, irql);

    //
    // 用户选择拒绝: 终止加载可疑 DLL 的进程
    // (无法卸载已加载的 DLL, 但可以终止整个进程)
    //
    if (shouldTerminate && pid != 0)
    {
        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        cid.UniqueThread = NULL;

        if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &oa, &cid)))
        {
            ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
            ZwClose(hProcess);
            KdPrint(("AVImage: Terminated PID %u (image load anomaly)\n", pid));
        }
    }

    KdPrint(("AVImage: Decision processed (PID %u, allow=%d)\n", pid, !shouldTerminate));

    return STATUS_SUCCESS;
}
