//=============================================================================
// AVInjectNotify.c - 远程线程注入防护模块
//
// 检测原理 (基于微软文档 PsSetCreateThreadNotifyRoutine, ntddk.h):
//   线程创建回调在"创建线程的进程"上下文中执行。回调参数 ProcessId
//   是线程所属进程 (目标), PsGetCurrentProcessId() 是发起进程 (来源)。
//   两者不同 = 跨进程线程创建 (CreateRemoteThread / NtCreateThreadEx)。
//
// 防误报设计 (正常应用也大量使用注入, 不能一刀切):
//   1. 排除可信来源: 镜像位于 \Windows\ 下的系统进程 / System (PID 4)
//   2. 排除新进程初始线程: 父进程为新创建的子进程创建首个线程属正常
//   3. 其余跨进程注入: 工作线程挂起被注入线程 -> 查询线程起始地址
//      -> 通知用户态弹窗 -> 允许=恢复线程, 拒绝=终止被注入线程。
//      用户态对起始地址做模块归属分析 (是否在目标进程已加载模块内),
//      原始代码注入 (未映射模块) 会显著提示。
//
// IRQL: 线程创建回调 PASSIVE/APC, 其余 PASSIVE_LEVEL
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVInjectNotify.h"
#include "AVProcessNotify.h"
#include <ntstrsafe.h>

//
// 手动声明的内核 API (ntoskrnl.exe 导出, Win10/Win11 均可用)
//
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
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// 动态解析的内核 API
// ZwOpenThread / ZwSuspendThread / ZwResumeThread / ZwQueryInformationThread
// 在 Win10 ntoskrnl.exe 中未导出 (Win11 才导出)。静态链接会导致驱动
// 在 Win10 加载时报 ERROR_PROC_NOT_FOUND (127)。
// 改为 MmGetSystemRoutineAddress 动态解析: Win11 可用时正常工作,
// Win10 不可用时注入防护降级为仅终止源进程 (不挂起线程)。
//
// 注: ntoskrnl 不导出 ZwTerminateThread / NtTerminateThread,
//     线程终止无法通过导出系统调用完成。拒绝注入时:
//       1. 被注入线程保持挂起 (无法执行注入代码, 即被中和)
//       2. 通过 ZwTerminateProcess 终止注入源进程 (恶意软件本体)
//
typedef NTSTATUS (NTAPI *PFN_ZwOpenThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );
typedef NTSTATUS (NTAPI *PFN_ZwSuspendThread)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS (NTAPI *PFN_ZwResumeThread)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// ThreadQuerySetWin32StartAddress = 9 (线程起始地址)
// ProcessImageFileName = 27 (进程镜像路径)
//
#define AV_THREAD_QUERY_SET_WIN32_START_ADDRESS 9
#define AV_PROCESS_IMAGE_FILE_NAME_CLASS        27

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0004
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

//=============================================================================
// 全局数据 (回调访问的全局数据置于非分页内存)
//=============================================================================

#pragma section("NonPaged", long, read, write)
#define AV_NON_PAGED __declspec(allocate("NonPaged"))

//
// 注入决策等待超时 (毫秒)
// 被注入线程被挂起等待决策, 超时后自动终止 (安全默认)
//
#define AV_INJECT_DECISION_TIMEOUT_MS 30000

//
// 新进程初始线程判别窗口 (tick 数, 每 tick ~15.6ms, 100 tick ≈ 1.5 秒)
// 父进程在子进程创建后短暂时间内创建的首个线程视为初始线程
//
#define AV_INJECT_INITIAL_THREAD_WINDOW_TICKS 100

//
// 最近创建进程环形记录 (用于初始线程判别)
//
#define AV_INJECT_RECENT_MAX 64

typedef struct _AV_INJECT_RECENT_PROC
{
    BOOLEAN    Active;
    BOOLEAN    InitialThreadSeen;   // 父进程创建的首个线程 (初始线程) 是否已观测并豁免
    UINT32     ProcessId;
    UINT32     ParentProcessId;
    ULONGLONG  CreateTicks;
} AV_INJECT_RECENT_PROC;

//
// 待检测的注入事件 (线程回调写入, 工作线程认领)
//
typedef struct _AV_INJECT_DETECT
{
    BOOLEAN  Valid;
    UINT32   SourcePid;
    UINT32   TargetPid;
    HANDLE   ThreadId;
} AV_INJECT_DETECT;

//
// 注入规则 (按发起进程镜像路径子串匹配)
//
#define AV_INJECT_RULE_MAX 64

AV_NON_PAGED static KSPIN_LOCK   g_InjectLock;
AV_NON_PAGED static AV_INJECT_RECENT_PROC g_RecentProcs[AV_INJECT_RECENT_MAX];
AV_NON_PAGED static UINT32       g_RecentProcNext = 0;

AV_NON_PAGED static AV_INJECT_DETECT g_InjectDetect;

AV_NON_PAGED static AV_INJECTION_NOTIFICATION g_InjectPendingNotify;
AV_NON_PAGED static BOOLEAN      g_InjectNotifyAvailable = FALSE;
AV_NON_PAGED static BOOLEAN      g_InjectDecisionPending = FALSE;
AV_NON_PAGED static BOOLEAN      g_InjectAllow = FALSE;
AV_NON_PAGED static UINT64       g_InjectNotifyIdCounter = 0;
AV_NON_PAGED static KEVENT       g_InjectWaitEvent;
AV_NON_PAGED static HANDLE       g_InjectSuspendedThread = NULL;

AV_NON_PAGED static WCHAR   g_InjectAllowRules[AV_INJECT_RULE_MAX][AV_MAX_PROCESS_PATH_LEN];
AV_NON_PAGED static UINT32  g_InjectAllowRuleCount = 0;
AV_NON_PAGED static WCHAR   g_InjectDenyRules[AV_INJECT_RULE_MAX][AV_MAX_PROCESS_PATH_LEN];
AV_NON_PAGED static UINT32  g_InjectDenyRuleCount = 0;

AV_NON_PAGED static BOOLEAN g_InjectThreadNotifyRegistered = FALSE;
AV_NON_PAGED static BOOLEAN g_InjectProcessNotifyRegistered = FALSE;
AV_NON_PAGED static BOOLEAN g_InjectWorkerStop = FALSE;
AV_NON_PAGED static HANDLE  g_InjectWorkerHandle = NULL;

AV_NON_PAGED static UINT64  g_InjectionTriggers = 0;

//
// 动态解析的线程 API 函数指针 (Win10 不导出, 运行时解析)
//
AV_NON_PAGED static PFN_ZwOpenThread              g_pZwOpenThread              = NULL;
AV_NON_PAGED static PFN_ZwSuspendThread           g_pZwSuspendThread           = NULL;
AV_NON_PAGED static PFN_ZwResumeThread            g_pZwResumeThread            = NULL;
AV_NON_PAGED static PFN_ZwQueryInformationThread  g_pZwQueryInformationThread  = NULL;

//=============================================================================
// 字符串辅助 (大小写不敏感子串匹配)
//=============================================================================

static
BOOLEAN
AvInjectContainsSubstring(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T hayLen;
    SIZE_T needleLen;
    SIZE_T i, j;

    if (Haystack == NULL || Needle == NULL)
    {
        return FALSE;
    }

    hayLen = wcslen(Haystack);
    needleLen = wcslen(Needle);

    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }

    for (i = 0; i + needleLen <= hayLen; i++)
    {
        for (j = 0; j < needleLen; j++)
        {
            if (RtlUpcaseUnicodeChar(Haystack[i + j]) !=
                RtlUpcaseUnicodeChar(Needle[j]))
            {
                break;
            }
        }

        if (j == needleLen)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//=============================================================================
// AvInjectGetProcessImagePath - 获取指定进程的完整镜像路径
// IRQL: PASSIVE_LEVEL
//=============================================================================

static
NTSTATUS
AvInjectGetProcessImagePath(
    _In_ UINT32 ProcessId,
    _Out_writes_bytes_(BufferBytes) PWCHAR Path,
    _In_ SIZE_T BufferBytes
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objectAttributes;
    BYTE buffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
    PUNICODE_STRING imagePath = (PUNICODE_STRING)buffer;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (Path == NULL || BufferBytes < sizeof(WCHAR))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Path[0] = L'\0';

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                           &objectAttributes, &clientId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ZwQueryInformationProcess(hProcess,
                                       AV_PROCESS_IMAGE_FILE_NAME_CLASS,
                                       buffer,
                                       sizeof(buffer),
                                       &returnLength);
    if (NT_SUCCESS(status) &&
        imagePath->Buffer != NULL &&
        imagePath->Length > 0 &&
        ((ULONG_PTR)imagePath->Buffer - (ULONG_PTR)buffer + imagePath->Length)
            <= sizeof(buffer))
    {
        SIZE_T copyBytes = min(imagePath->Length, BufferBytes - sizeof(WCHAR));
        RtlCopyMemory(Path, imagePath->Buffer, copyBytes);
        Path[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    ZwClose(hProcess);
    return status;
}

//=============================================================================
// AvInjectIsTrustedSource - 注入来源是否为可信系统进程
// IRQL: PASSIVE_LEVEL (工作线程)
//
// System (PID 4) / 镜像位于 \Windows\ 下的进程 (svchost, explorer,
// csrss, services 等 Windows 组件) 的注入属系统正常行为, 直接放行。
//=============================================================================

static
BOOLEAN
AvInjectIsTrustedSource(
    _In_ UINT32 SourcePid,
    _In_ PCWSTR SourcePath
    )
{
    if (SourcePid == 4)   // System
    {
        return TRUE;
    }

    if (SourcePath != NULL &&
        AvInjectContainsSubstring(SourcePath, L"\\Windows\\"))
    {
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// AvInjectTerminateProcessById - 通过 Zw 终止注入源进程
// IRQL: PASSIVE_LEVEL
//
// 拒绝注入时的落地动作: 恶意软件本体 (注入源进程) 被终止,
// 被注入线程保持挂起, 无法执行注入代码。
//=============================================================================

static
NTSTATUS
AvInjectTerminateProcessById(
    _In_ UINT32 ProcessId
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVInject: ZwOpenProcess(PID %u) failed 0x%08X\n", ProcessId, status));
        return status;
    }

    status = ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
    ZwClose(hProcess);

    KdPrint(("AVInject: ZwTerminateProcess(PID %u) status 0x%08X\n", ProcessId, status));
    return status;
}

//=============================================================================
// 规则列表辅助 (按来源镜像路径)
//=============================================================================

static
BOOLEAN
AvInjectIsInRuleList(
    _In_ PCWSTR SourcePath,
    _In_ BOOLEAN IsDeny
    )
{
    KIRQL irql;
    UINT32 i;
    UINT32 count;
    BOOLEAN found = FALSE;

    if (SourcePath == NULL || SourcePath[0] == L'\0')
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_InjectLock, &irql);

    if (IsDeny)
    {
        count = g_InjectDenyRuleCount;
        for (i = 0; i < count; i++)
        {
            if (g_InjectDenyRules[i][0] != L'\0' &&
                AvInjectContainsSubstring(SourcePath, g_InjectDenyRules[i]))
            {
                found = TRUE;
                break;
            }
        }
    }
    else
    {
        count = g_InjectAllowRuleCount;
        for (i = 0; i < count; i++)
        {
            if (g_InjectAllowRules[i][0] != L'\0' &&
                AvInjectContainsSubstring(SourcePath, g_InjectAllowRules[i]))
            {
                found = TRUE;
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_InjectLock, irql);
    return found;
}

static
NTSTATUS
AvInjectAddRule(
    _In_ PCWSTR SourcePath,
    _In_ BOOLEAN IsDeny
    )
{
    KIRQL irql;
    UINT32 i;
    UINT32* count;
    WCHAR (*rules)[AV_MAX_PROCESS_PATH_LEN];

    if (SourcePath == NULL || SourcePath[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_InjectLock, &irql);

    if (IsDeny)
    {
        count = &g_InjectDenyRuleCount;
        rules = g_InjectDenyRules;
    }
    else
    {
        count = &g_InjectAllowRuleCount;
        rules = g_InjectAllowRules;
    }

    for (i = 0; i < *count; i++)
    {
        if (_wcsicmp(rules[i], SourcePath) == 0)
        {
            KeReleaseSpinLock(&g_InjectLock, irql);
            return STATUS_SUCCESS;
        }
    }

    if (*count >= AV_INJECT_RULE_MAX)
    {
        KeReleaseSpinLock(&g_InjectLock, irql);
        return STATUS_TOO_MANY_SESSIONS;
    }

    RtlStringCbCopyW(rules[*count], sizeof(rules[*count]), SourcePath);
    (*count)++;

    KdPrint(("AVInject: Added %s rule [%u]: %ws\n",
             IsDeny ? "DENY" : "ALLOW", *count - 1, SourcePath));

    KeReleaseSpinLock(&g_InjectLock, irql);
    return STATUS_SUCCESS;
}

//=============================================================================
// AvInjectResolveDecision - 唤醒等待决策的工作线程
// IRQL: PASSIVE_LEVEL
//=============================================================================

static
VOID
AvInjectResolveDecision(
    _In_ BOOLEAN Allow
    )
{
    KIRQL irql;
    BOOLEAN wake = FALSE;

    KeAcquireSpinLock(&g_InjectLock, &irql);

    if (g_InjectDecisionPending)
    {
        g_InjectAllow = Allow;
        g_InjectDecisionPending = FALSE;
        wake = TRUE;
    }

    KeReleaseSpinLock(&g_InjectLock, irql);

    if (wake)
    {
        KeSetEvent(&g_InjectWaitEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// AvInjectThreadNotifyCallback - 线程创建/退出回调
// IRQL: PASSIVE_LEVEL 或 APC_LEVEL
//
// 仅做轻量检测 (纯内存操作), 不在回调中调用 Zw*:
//   来源进程 != 目标进程 且 非新进程初始线程 且 非可信来源
//   -> 记录待处理注入事件, 由 PASSIVE_LEVEL 工作线程挂起并处理
//=============================================================================

static
VOID
AvInjectThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    UINT32 sourcePid;
    UINT32 targetPid;
    ULONGLONG nowTicks;
    LARGE_INTEGER tickCount;
    KIRQL irql;
    UINT32 i;

    if (!Create)
    {
        return;
    }

    sourcePid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    targetPid = (UINT32)(ULONG_PTR)ProcessId;

    //
    // 同进程线程创建 (绝大多数) 直接短路
    //
    if (sourcePid == targetPid || sourcePid == 0)
    {
        return;
    }

    //
    // 无活跃客户端时静默放行
    //
    if (!AvProcessIsClientActive())
    {
        return;
    }

    KeQueryTickCount(&tickCount);
    nowTicks = (ULONGLONG)tickCount.QuadPart;

    KeAcquireSpinLock(&g_InjectLock, &irql);

    //
    // 新进程初始线程判别: 目标进程刚由来源进程创建 (窗口期内) 时,
    // 只豁免"首个"线程 (真正的初始线程)。
    // 初始线程已观测过之后, 父进程再次向子进程注入线程 = 远程注入,
    // 必须拦截 (典型恶意行为: 启动子进程后立刻注入, 若只按时间窗口
    // 判定会漏掉)。
    //
    for (i = 0; i < AV_INJECT_RECENT_MAX; i++)
    {
        if (g_RecentProcs[i].Active &&
            g_RecentProcs[i].ProcessId == targetPid &&
            g_RecentProcs[i].ParentProcessId == sourcePid &&
            (nowTicks - g_RecentProcs[i].CreateTicks) <
                AV_INJECT_INITIAL_THREAD_WINDOW_TICKS)
        {
            if (g_RecentProcs[i].InitialThreadSeen)
            {
                break;   // 初始线程已观测, 本次按注入处理
            }

            g_RecentProcs[i].InitialThreadSeen = TRUE;
            KeReleaseSpinLock(&g_InjectLock, irql);
            return;   // 新进程初始线程, 放行
        }
    }

    //
    // 单槽忙 (已有检测待处理或已在等待决策) 时丢弃本次检测
    //
    if (g_InjectDetect.Valid || g_InjectDecisionPending)
    {
        KeReleaseSpinLock(&g_InjectLock, irql);
        return;
    }

    g_InjectDetect.Valid = TRUE;
    g_InjectDetect.SourcePid = sourcePid;
    g_InjectDetect.TargetPid = targetPid;
    g_InjectDetect.ThreadId = ThreadId;

    KeReleaseSpinLock(&g_InjectLock, irql);

    InterlockedIncrement64((PLONG64)&g_InjectionTriggers);

    KdPrint(("AVInject: Cross-process thread create detected, src=%u tgt=%u tid=%lu\n",
             sourcePid, targetPid, (ULONG)(ULONG_PTR)ThreadId));
}

//=============================================================================
// AvInjectProcessNotifyCallback - 进程创建/退出回调
// IRQL: APC_LEVEL
//
// 记录最近创建的进程 (PID + 父 PID + 时间), 供线程回调做初始线程判别
//=============================================================================

static
VOID
AvInjectProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KIRQL irql;
    LARGE_INTEGER tickCount;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL)
    {
        return;   // 只记录进程创建
    }

    KeQueryTickCount(&tickCount);

    KeAcquireSpinLock(&g_InjectLock, &irql);

    g_RecentProcs[g_RecentProcNext].Active = TRUE;
    g_RecentProcs[g_RecentProcNext].InitialThreadSeen = FALSE;
    g_RecentProcs[g_RecentProcNext].ProcessId = (UINT32)(ULONG_PTR)ProcessId;
    g_RecentProcs[g_RecentProcNext].ParentProcessId =
        (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;
    g_RecentProcs[g_RecentProcNext].CreateTicks = (ULONGLONG)tickCount.QuadPart;

    g_RecentProcNext = (g_RecentProcNext + 1) % AV_INJECT_RECENT_MAX;

    KeReleaseSpinLock(&g_InjectLock, irql);
}

//=============================================================================
// AvInjectWorkerRoutine - 注入处理工作线程
// IRQL: PASSIVE_LEVEL (系统线程)
//
// 认领检测到的注入事件:
//   1. 解析来源镜像路径, 信任来源/规则命中直接处理
//   2. 挂起被注入线程, 查询起始地址
//   3. 发布通知, 等待用户决策 (30 秒超时, 超时默认终止)
//   4. 允许=恢复线程, 拒绝=NtTerminateThread 终止被注入线程
//=============================================================================

static
VOID
AvInjectWorkerRoutine(
    _In_ PVOID Context
    )
{
    LARGE_INTEGER delay;

    UNREFERENCED_PARAMETER(Context);

    delay.QuadPart = -20000;   // 2ms, 100ns 单位

    while (!g_InjectWorkerStop)
    {
        BOOLEAN claimed = FALSE;
        KIRQL irql;
        WCHAR sourcePath[AV_MAX_PROCESS_PATH_LEN];
        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;
        ULONG_PTR startAddress = 0;
        ULONG returnLength = 0;
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;
        AV_INJECT_DETECT detect = { 0 };

        //
        // 认领检测事件
        //
        KeAcquireSpinLock(&g_InjectLock, &irql);
        if (g_InjectDetect.Valid)
        {
            RtlCopyMemory(&detect, &g_InjectDetect, sizeof(detect));
            g_InjectDetect.Valid = FALSE;
            claimed = TRUE;
        }
        KeReleaseSpinLock(&g_InjectLock, irql);

        if (!claimed)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            continue;
        }

        RtlZeroMemory(sourcePath, sizeof(sourcePath));
        AvInjectGetProcessImagePath(detect.SourcePid, sourcePath, sizeof(sourcePath));

        //
        // 信任来源 (System / \Windows\ 下进程) 放行
        //
        if (AvInjectIsTrustedSource(detect.SourcePid, sourcePath))
        {
            KdPrint(("AVInject: Trusted source PID %u, allowing\n", detect.SourcePid));
            continue;
        }

        //
        // 规则: 拒绝 -> 挂起被注入线程并终止注入源进程; 允许 -> 放行
        //
        if (AvInjectIsInRuleList(sourcePath, TRUE))
        {
            InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
            cid.UniqueProcess = NULL;
            cid.UniqueThread = detect.ThreadId;

            if (g_pZwOpenThread != NULL &&
                NT_SUCCESS(g_pZwOpenThread(&hThread, THREAD_SUSPEND_RESUME, &oa, &cid)))
            {
                if (g_pZwSuspendThread != NULL)
                    g_pZwSuspendThread(hThread, NULL);
                ZwClose(hThread);
            }

            AvInjectTerminateProcessById(detect.SourcePid);
            KdPrint(("AVInject: Denied by rule, source %u neutralized\n",
                     detect.SourcePid));
            continue;
        }

        if (AvInjectIsInRuleList(sourcePath, FALSE))
        {
            KdPrint(("AVInject: Allowed by rule, source %u\n", detect.SourcePid));
            continue;   // 线程已创建运行, 直接放行
        }

        //
        // 打开被注入线程并挂起, 等待用户决策
        //
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = NULL;
        cid.UniqueThread = detect.ThreadId;

        if (g_pZwOpenThread == NULL)
        {
            KdPrint(("AVInject: ZwOpenThread not available on this OS, skipping\n"));
            continue;
        }

        if (!NT_SUCCESS(g_pZwOpenThread(&hThread,
                                     THREAD_SUSPEND_RESUME | THREAD_TERMINATE |
                                     THREAD_QUERY_INFORMATION,
                                     &oa, &cid)))
        {
            KdPrint(("AVInject: OpenThread(tid %lu) failed, thread likely exited\n",
                     (ULONG)(ULONG_PTR)detect.ThreadId));
            continue;
        }

        if (g_pZwSuspendThread != NULL)
            g_pZwSuspendThread(hThread, NULL);

        //
        // 查询线程起始地址 (供用户态做模块归属分析)
        //
        if (g_pZwQueryInformationThread == NULL ||
            !NT_SUCCESS(g_pZwQueryInformationThread(hThread,
                                                 AV_THREAD_QUERY_SET_WIN32_START_ADDRESS,
                                                 &startAddress,
                                                 sizeof(startAddress),
                                                 &returnLength)))
        {
            startAddress = 0;
        }

        //
        // 发布通知
        //
        AV_INJECTION_NOTIFICATION notify;
        RtlZeroMemory(&notify, sizeof(notify));
        notify.HasPending = TRUE;
        notify.SourceProcessId = detect.SourcePid;
        notify.TargetProcessId = detect.TargetPid;
        notify.ThreadId = (UINT32)(ULONG_PTR)detect.ThreadId;
        notify.StartAddress = (UINT64)startAddress;
        if (sourcePath[0] != L'\0')
        {
            RtlStringCbCopyW(notify.SourceImagePath, sizeof(notify.SourceImagePath),
                             sourcePath);
        }
        notify.NotificationId =
            InterlockedIncrement64((PLONG64)&g_InjectNotifyIdCounter);

        KeAcquireSpinLock(&g_InjectLock, &irql);
        RtlCopyMemory(&g_InjectPendingNotify, &notify, sizeof(g_InjectPendingNotify));
        g_InjectNotifyAvailable = TRUE;
        g_InjectDecisionPending = TRUE;
        g_InjectAllow = FALSE;
        g_InjectSuspendedThread = hThread;
        KeReleaseSpinLock(&g_InjectLock, irql);

        KdPrint(("AVInject: Suspended injected thread tid %lu of PID %u (start 0x%p)\n",
                 (ULONG)(ULONG_PTR)detect.ThreadId, detect.TargetPid,
                 (PVOID)startAddress));

        //
        // 等待用户决策 (30 秒超时, 超时默认拒绝)
        //
        KeResetEvent(&g_InjectWaitEvent);

        timeout.QuadPart = -((LONGLONG)AV_INJECT_DECISION_TIMEOUT_MS * 10000);
        waitStatus = KeWaitForSingleObject(&g_InjectWaitEvent, Executive,
                                           KernelMode, FALSE, &timeout);

        //
        // 读取决策并落地:
        //   允许 -> 恢复被注入线程
        //   拒绝 -> 被注入线程保持挂起 (无法执行注入代码) +
        //           终止注入源进程 (恶意软件本体)
        //
        BOOLEAN allow = FALSE;
        KeAcquireSpinLock(&g_InjectLock, &irql);
        allow = g_InjectAllow;
        g_InjectDecisionPending = FALSE;
        g_InjectNotifyAvailable = FALSE;
        g_InjectSuspendedThread = NULL;
        KeReleaseSpinLock(&g_InjectLock, irql);

        if (allow)
        {
            if (g_pZwResumeThread != NULL)
                g_pZwResumeThread(hThread, NULL);
            KdPrint(("AVInject: ALLOWED, resumed thread tid %lu\n",
                     (ULONG)(ULONG_PTR)detect.ThreadId));
        }
        else
        {
            AvInjectTerminateProcessById(detect.SourcePid);
            KdPrint(("AVInject: %s, source %u neutralized (wait 0x%08X)\n",
                     (waitStatus == STATUS_TIMEOUT) ? "TIMEOUT DENIED" : "DENIED",
                     detect.SourcePid, waitStatus));
        }

        ZwClose(hThread);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//=============================================================================
// AvInjectNotifyInitialize - 初始化注入防护模块
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvInjectNotifyInitialize(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    KdPrint(("AVInject: Initializing remote thread injection protection\n"));

    //
    // 动态解析 Win10 不导出的线程 API
    // Win11 ntoskrnl 导出这些函数; Win10 不导出, 指针为 NULL 时降级处理
    //
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwOpenThread");
        g_pZwOpenThread = (PFN_ZwOpenThread)MmGetSystemRoutineAddress(&name);
        RtlInitUnicodeString(&name, L"ZwSuspendThread");
        g_pZwSuspendThread = (PFN_ZwSuspendThread)MmGetSystemRoutineAddress(&name);
        RtlInitUnicodeString(&name, L"ZwResumeThread");
        g_pZwResumeThread = (PFN_ZwResumeThread)MmGetSystemRoutineAddress(&name);
        RtlInitUnicodeString(&name, L"ZwQueryInformationThread");
        g_pZwQueryInformationThread = (PFN_ZwQueryInformationThread)MmGetSystemRoutineAddress(&name);
        KdPrint(("AVInject: DynAPI OpenThread=%p Suspend=%p Resume=%p QueryThread=%p\n",
                 g_pZwOpenThread, g_pZwSuspendThread, g_pZwResumeThread,
                 g_pZwQueryInformationThread));
    }

    KeInitializeSpinLock(&g_InjectLock);
    KeInitializeEvent(&g_InjectWaitEvent, NotificationEvent, FALSE);
    RtlZeroMemory(g_RecentProcs, sizeof(g_RecentProcs));
    g_RecentProcNext = 0;
    RtlZeroMemory(&g_InjectDetect, sizeof(g_InjectDetect));
    RtlZeroMemory(&g_InjectPendingNotify, sizeof(g_InjectPendingNotify));
    g_InjectNotifyAvailable = FALSE;
    g_InjectDecisionPending = FALSE;
    g_InjectAllow = FALSE;
    g_InjectNotifyIdCounter = 0;
    g_InjectSuspendedThread = NULL;
    g_InjectAllowRuleCount = 0;
    g_InjectDenyRuleCount = 0;
    RtlZeroMemory(g_InjectAllowRules, sizeof(g_InjectAllowRules));
    RtlZeroMemory(g_InjectDenyRules, sizeof(g_InjectDenyRules));
    g_InjectionTriggers = 0;

    //
    // 注册进程创建回调 (记录最近创建的进程, 供初始线程判别)
    //
    status = PsSetCreateProcessNotifyRoutineEx(AvInjectProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVInject: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status));
        return status;
    }
    g_InjectProcessNotifyRegistered = TRUE;

    //
    // 注册线程创建回调 (跨进程线程创建检测)
    //
    status = PsSetCreateThreadNotifyRoutine(AvInjectThreadNotifyCallback);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVInject: PsSetCreateThreadNotifyRoutine failed 0x%08X\n", status));
        PsSetCreateProcessNotifyRoutineEx(AvInjectProcessNotifyCallback, TRUE);
        g_InjectProcessNotifyRegistered = FALSE;
        return status;
    }
    g_InjectThreadNotifyRegistered = TRUE;

    //
    // 启动注入处理工作线程 (PASSIVE_LEVEL, 挂起/查询/终止被注入线程)
    //
    g_InjectWorkerStop = FALSE;
    status = PsCreateSystemThread(
        &g_InjectWorkerHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        AvInjectWorkerRoutine,
        NULL
        );
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVInject: PsCreateSystemThread failed 0x%08X\n", status));
        PsRemoveCreateThreadNotifyRoutine(AvInjectThreadNotifyCallback);
        g_InjectThreadNotifyRegistered = FALSE;
        PsSetCreateProcessNotifyRoutineEx(AvInjectProcessNotifyCallback, TRUE);
        g_InjectProcessNotifyRegistered = FALSE;
        return status;
    }

    KdPrint(("AVInject: Initialized successfully\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// AvInjectNotifyUninitialize - 卸载注入防护模块
// IRQL: PASSIVE_LEVEL
//
// 1. 唤醒并停止工作线程 (若有线程等待决策, 先恢复避免遗留冻结线程)
// 2. 注销回调
//=============================================================================

VOID
AvInjectNotifyUninitialize(
    VOID
    )
{
    KIRQL irql;

    PAGED_CODE();

    KdPrint(("AVInject: Uninitializing\n"));

    //
    // 若有被挂起等待决策的线程, 恢复它 (安全清理, 不遗留冻结线程)
    //
    KeAcquireSpinLock(&g_InjectLock, &irql);
    if (g_InjectDecisionPending)
    {
        g_InjectAllow = TRUE;
        g_InjectDecisionPending = FALSE;
        KeReleaseSpinLock(&g_InjectLock, irql);
        KeSetEvent(&g_InjectWaitEvent, IO_NO_INCREMENT, FALSE);
    }
    else
    {
        KeReleaseSpinLock(&g_InjectLock, irql);
    }

    //
    // 停止工作线程。
    //
    // 【关键 - 修复重连/卸载蓝屏 (IRQL_NOT_LESS_OR_EQUAL, 报 NTOSKRNL)】
    // 原实现在此调用 KeWaitForSingleObject 无限期等待工作线程退出。
    // 但 DriverUnload 由 IopLoadUnloadDriver 在工作线程(ExpWorkerThread)
    // 上下文中调用, 实际运行在 DISPATCH_LEVEL。在 DISPATCH_LEVEL 调用
    // KeWaitForSingleObject(无超时) 会触发 IRQL_NOT_LESS_OR_EQUAL 蓝屏
    // (页错误发生在 nt!KeWaitForSingleObject 内部, 故报 NTOSKRNL.EXE,
    // 而非本驱动)。
    // 因此这里不能等待工作线程, 只能: 置停止标志 + 唤醒事件, 让工作线程
    // 自行退出; 关闭句柄(关闭句柄不等待线程结束, DISPATCH_LEVEL 安全)。
    // 工作线程在收到停止标志后会立即退出循环并返回, 无需也不应在
    // DriverUnload 中阻塞等待。
    //
    g_InjectWorkerStop = TRUE;
    KeSetEvent(&g_InjectWaitEvent, IO_NO_INCREMENT, FALSE);
    if (g_InjectWorkerHandle != NULL)
    {
        ZwClose(g_InjectWorkerHandle);
        g_InjectWorkerHandle = NULL;
    }

    //
    // 注销回调
    //
    if (g_InjectThreadNotifyRegistered)
    {
        PsRemoveCreateThreadNotifyRoutine(AvInjectThreadNotifyCallback);
        g_InjectThreadNotifyRegistered = FALSE;
    }

    if (g_InjectProcessNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(AvInjectProcessNotifyCallback, TRUE);
        g_InjectProcessNotifyRegistered = FALSE;
    }

    RtlZeroMemory(&g_InjectPendingNotify, sizeof(g_InjectPendingNotify));
    g_InjectNotifyAvailable = FALSE;
    g_InjectDecisionPending = FALSE;
    g_InjectAllowRuleCount = 0;
    g_InjectDenyRuleCount = 0;

    KdPrint(("AVInject: Uninitialized\n"));
}

//=============================================================================
// AvInjectGetPendingNotification - 获取待处理注入通知
// IRQL: PASSIVE_LEVEL
//
// 取出通知副本供用户态弹窗; 被注入线程保持挂起,
// 由 IOCTL_AV_SEND_INJECTION_DECISION 完成恢复/终止
//=============================================================================

NTSTATUS
AvInjectGetPendingNotification(
    _Out_ AV_INJECTION_NOTIFICATION* Notification
    )
{
    KIRQL irql;

    PAGED_CODE();

    if (Notification == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Notification, sizeof(AV_INJECTION_NOTIFICATION));

    KeAcquireSpinLock(&g_InjectLock, &irql);

    if (g_InjectNotifyAvailable)
    {
        RtlCopyMemory(Notification, &g_InjectPendingNotify,
                      sizeof(AV_INJECTION_NOTIFICATION));
        Notification->HasPending = TRUE;
        g_InjectNotifyAvailable = FALSE;
    }
    else
    {
        Notification->HasPending = FALSE;
    }

    KeReleaseSpinLock(&g_InjectLock, irql);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvInjectHandleDecision - 处理用户态注入决策
// IRQL: PASSIVE_LEVEL
//
// 允许 -> 唤醒工作线程恢复被注入线程
// 拒绝 -> 唤醒工作线程终止被注入线程
// Always 决策同时按来源镜像路径维护规则
//=============================================================================

NTSTATUS
AvInjectHandleDecision(
    _In_ const AV_INJECTION_DECISION* Decision
    )
{
    if (Decision == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Decision->Decision)
    {
    case AvDecisionAllowOnce:
        AvInjectResolveDecision(TRUE);
        break;

    case AvDecisionAllowAlways:
        AvInjectResolveDecision(TRUE);
        AvInjectAddRule(Decision->SourceImagePath, FALSE);
        break;

    case AvDecisionDenyOnce:
        AvInjectResolveDecision(FALSE);
        break;

    case AvDecisionDenyAlways:
        AvInjectResolveDecision(FALSE);
        AvInjectAddRule(Decision->SourceImagePath, TRUE);
        break;

    default:
        //
        // 无效决策: 默认拒绝 (安全优先)
        //
        AvInjectResolveDecision(FALSE);
        break;
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// AvInjectGetDebugInfo - 获取注入防护诊断信息
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvInjectGetDebugInfo(
    _Inout_ AV_DEBUG_INFO* Info
    )
{
    PAGED_CODE();

    if (Info == NULL)
    {
        return;
    }

    Info->InjectionTriggers = g_InjectionTriggers;
}
