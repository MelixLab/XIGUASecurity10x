//=============================================================================
// XGSEndPoint.c - XIGUASecurity EndPoint 端点防护驱动
//
// 架构: 传统型 Minifilter + 系统回调 (非 KMDF)
//   - minifilter 预操作: IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION (文件采集)
//   - PsSetCreateProcessNotifyRoutineEx: 进程创建/退出 (父进程链)
//   - PsSetCreateThreadNotifyRoutine: 线程创建 (远程线程注入信号)
//   - ObRegisterCallbacks: 可写可执行映射 (RWX) / 跨进程终止挂起控制
//   - CmRegisterCallbackEx: 注册表写入 (自启动项检测)
//
// IOA 检测: 行为事件按进程聚合评分 (60 秒窗口), 评分 >= 阈值
//   -> 工作线程挂起威胁进程 -> 通知用户态决策:
//      放行=恢复进程, 终止=ZwTerminateProcess
//   -> 60 秒无决策自动放行 (防用户态故障锁死系统)
//
// 所有回调仅做轻量记录与评分 (纯内存操作, 自旋锁保护);
// 挂起/终止等重操作统一由 PASSIVE_LEVEL 工作线程完成。
//=============================================================================

#include "XIGUAEndPoint.h"

//=============================================================================
// 手动声明的内核 API (WDK 头文件未声明或仅在 ntifs.h 中)
//=============================================================================

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
// ZwOpenThread / ZwSuspendThread / ZwResumeThread
// Win10 ntoskrnl.exe 不导出 (Win11 才导出), 静态链接会导致驱动在 Win10
// 加载时报 ERROR_PROC_NOT_FOUND (127), 必须动态解析。
//
typedef NTSTATUS (NTAPI *EP_PF_ZW_OPEN_THREAD)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );
typedef NTSTATUS (NTAPI *EP_PF_ZW_SUSPEND_THREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );
typedef NTSTATUS (NTAPI *EP_PF_ZW_RESUME_THREAD)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

//
// NtGetNextThread 在 ntoskrnl 导出但未包含在 WDK 导入库中,
// 通过 MmGetSystemRoutineAddress 在 DriverEntry 运行时解析
//
typedef NTSTATUS (NTAPI *EP_NT_GET_NEXT_THREAD)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewThreadHandle
    );

//
// NtSuspendProcess / NtResumeProcess 未文档化但 ntoskrnl 导出,
// 进程级挂起/恢复, 比逐线程挂起更可靠 (不依赖 NtGetNextThread 枚举)
//
typedef NTSTATUS (NTAPI *EP_NT_SUSPEND_PROCESS)(_In_ HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *EP_NT_RESUME_PROCESS)(_In_ HANDLE ProcessHandle);

static EP_NT_GET_NEXT_THREAD  g_pNtGetNextThread  = NULL;
static EP_NT_SUSPEND_PROCESS  g_pNtSuspendProcess = NULL;
static EP_NT_RESUME_PROCESS   g_pNtResumeProcess  = NULL;
static EP_PF_ZW_OPEN_THREAD   g_pZwOpenThread     = NULL;
static EP_PF_ZW_SUSPEND_THREAD g_pZwSuspendThread  = NULL;
static EP_PF_ZW_RESUME_THREAD  g_pZwResumeThread   = NULL;

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
    );

#define EP_PROCESS_IMAGE_FILE_NAME_CLASS  27

//
// FILE_RENAME_INFORMATION_EX 在本 WDK 的 ntifs.h 中未声明, 手动定义
// (与 Windows 10 1809+ 布局一致: Flags + RootDirectory + FileNameLength)
//
typedef struct _EP_FILE_RENAME_INFORMATION_EX
{
    ULONG  Flags;
    HANDLE RootDirectory;
    ULONG  FileNameLength;
    WCHAR  FileName[1];
} EP_FILE_RENAME_INFORMATION_EX, *PEP_FILE_RENAME_INFORMATION_EX;

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE 0x0002
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif

//=============================================================================
// 全局状态
//=============================================================================
static PDRIVER_OBJECT g_DriverObject = NULL;
static PFLT_FILTER    g_EpFilter = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;
static LARGE_INTEGER  g_Cookie = { 0 };

//
// 嫌疑进程记录 (进程生命周期累计评分)
//
typedef struct _EP_SUSPECT
{
    BOOLEAN  Active;
    UINT32   Pid;
    UINT32   Ppid;
    UINT32   TotalScore;          // 累计评分 (整个进程生命周期, 不衰减)
    BOOLEAN  Suspended;           // 是否已挂起等待决策
    UINT64   SuspendTicks;        // 挂起时间戳
    HANDLE   ThreadHandles[EP_SUSPEND_THREADS_MAX];  // 挂起的线程句柄
    UINT32   ThreadCount;
    UINT32   RuleCount;
    XGS_EP_RULE_HIT Rules[EP_SUSPECT_RULES_MAX];     // 命中的规则
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN];
} EP_SUSPECT, *PEP_SUSPECT;

//
// 全部可变状态集中在一个非分页结构中, 由 g_Ep.Lock 保护
//
typedef struct _EP_GLOBAL_STATE
{
    KSPIN_LOCK Lock;

    // 鉴权
    BOOLEAN  Authed;
    BOOLEAN  ChallengeValid;
    UINT64   ChallengeSeq;
    UCHAR    Challenge[AV_CHALLENGE_SIZE];

    // 行为记录环 (全部行为审计)
    XGS_EP_BEHAVIOR Behaviors[XGS_EP_BEHAVIORS_MAX];
    UINT32 BehaviorHead;
    UINT32 BehaviorCount;

    // 嫌疑进程表
    EP_SUSPECT Suspects[XGS_EP_SUSPECT_MAX];

    // 通知
    BOOLEAN  NotificationPending;
    UINT64   NotificationId;
    XGS_EP_NOTIFICATION Notification;

    // 挂起工作队列 + 决策
    UINT32   PendingSuspendPid;   // 0 = 无待处理挂起
    UINT64   PendingSuspendPpid;
    BOOLEAN  DecisionPending;
    BOOLEAN  DecisionAllow;
    KEVENT   DecisionEvent;
    BOOLEAN  WorkerStop;

    // 引导防护: 标记当前挂起是由引导区写入触发 (非评分路径)
    BOOLEAN  BootWritePending;

    // 统计
    UINT64   BehaviorsRecorded;
    UINT64   ThreatsDetected;
    UINT64   ProcessesSuspended;
} EP_GLOBAL_STATE;

static EP_GLOBAL_STATE g_Ep = { 0 };

//
// 回调注册状态 (卸载用)
//
static BOOLEAN g_ProcNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_LoadImageNotifyRegistered = FALSE;
static BOOLEAN g_RegNotifyRegistered = FALSE;
static BOOLEAN g_ObCallbackRegistered = FALSE;
static PVOID  g_RegNotifyContext = NULL;
static PVOID  g_ObRegHandle = NULL;
static PETHREAD g_WorkerThreadObj = NULL;   // 工作线程对象引用 (卸载时等待退出)

//=============================================================================
// 时间
//=============================================================================
static
ULONGLONG
EpNow(
    VOID
    )
{
    return KeQueryUnbiasedInterruptTime();
}

//=============================================================================
// 字符串工具
//=============================================================================
static
SIZE_T
EpStrLenW(
    _In_ PCWSTR s
    )
{
    SIZE_T n = 0;
    while (s[n] != L'\0')
    {
        n++;
    }
    return n;
}

static
VOID
EpStrNCpyW(
    _Out_writes_(maxChars) PWCHAR dst,
    _In_ PCWSTR src,
    _In_ SIZE_T maxChars
    )
{
    SIZE_T i;

    if (maxChars == 0)
    {
        return;
    }
    for (i = 0; i + 1 < maxChars && src[i] != L'\0'; i++)
    {
        dst[i] = src[i];
    }
    dst[i] = L'\0';
}

static
BOOLEAN
EpWcsCaseCmp(
    _In_ PCWSTR a,
    _In_ PCWSTR b
    )
{
    SIZE_T i = 0;

    for (;;)
    {
        WCHAR ca = a[i];
        WCHAR cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb)
        {
            return FALSE;
        }
        if (ca == L'\0')
        {
            return TRUE;
        }
        i++;
    }
}

//
// 是否包含子串 (大小写不敏感)
//
static
BOOLEAN
EpContainsSubstrW(
    _In_ PCWSTR haystack,
    _In_ PCWSTR needle
    )
{
    SIZE_T hayLen = EpStrLenW(haystack);
    SIZE_T needleLen = EpStrLenW(needle);
    SIZE_T i, j;

    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }
    for (i = 0; i + needleLen <= hayLen; i++)
    {
        for (j = 0; j < needleLen; j++)
        {
            WCHAR ch = haystack[i + j];
            WCHAR cn = needle[j];
            if (ch >= L'A' && ch <= L'Z') ch += 32;
            if (cn >= L'A' && cn <= L'Z') cn += 32;
            if (ch != cn)
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
// 行为记录 + 评分引擎
//=============================================================================

//
// 写入行为记录环 (带锁)
//
static
VOID
EpRecordBehavior(
    _In_ UINT32 type,
    _In_ UINT32 pid,
    _In_ UINT32 ppid,
    _In_ PCWSTR detail
    )
{
    KIRQL irql;
    ULONG idx;

    KeAcquireSpinLock(&g_Ep.Lock, &irql);

    if (g_Ep.BehaviorCount < XGS_EP_BEHAVIORS_MAX)
    {
        g_Ep.BehaviorCount++;
    }
    idx = g_Ep.BehaviorHead;
    g_Ep.Behaviors[idx].Type = type;
    g_Ep.Behaviors[idx].ProcessId = pid;
    g_Ep.Behaviors[idx].ParentProcessId = ppid;
    g_Ep.Behaviors[idx].Timestamp100ns = EpNow();
    if (detail != NULL)
    {
        EpStrNCpyW(g_Ep.Behaviors[idx].Detail, detail, XGS_EP_DETAIL_LEN);
    }
    else
    {
        g_Ep.Behaviors[idx].Detail[0] = L'\0';
    }
    g_Ep.BehaviorHead = (g_Ep.BehaviorHead + 1) % XGS_EP_BEHAVIORS_MAX;
    g_Ep.BehaviorsRecorded++;

    KeReleaseSpinLock(&g_Ep.Lock, irql);
}

//
// 查找嫌疑进程记录 (调用者已持有锁)
//
static
PEP_SUSPECT
EpFindSuspectLocked(
    _In_ UINT32 pid
    )
{
    ULONG i;

    for (i = 0; i < XGS_EP_SUSPECT_MAX; i++)
    {
        if (g_Ep.Suspects[i].Active && g_Ep.Suspects[i].Pid == pid)
        {
            return &g_Ep.Suspects[i];
        }
    }
    return NULL;
}

//
// 获取或创建嫌疑进程记录 (调用者已持有锁)
//
static
PEP_SUSPECT
EpGetOrCreateSuspectLocked(
    _In_ UINT32 pid,
    _In_ UINT32 ppid
    )
{
    PEP_SUSPECT s = EpFindSuspectLocked(pid);

    if (s != NULL)
    {
        return s;
    }

    {
        ULONG i;
        ULONG free = 0;
        BOOLEAN foundFree = FALSE;

        for (i = 0; i < XGS_EP_SUSPECT_MAX; i++)
        {
            if (!g_Ep.Suspects[i].Active)
            {
                free = i;
                foundFree = TRUE;
                break;
            }
        }
        if (!foundFree)
        {
            free = (ULONG)(g_Ep.BehaviorsRecorded % XGS_EP_SUSPECT_MAX);  // 简单覆盖
        }

        s = &g_Ep.Suspects[free];
        RtlZeroMemory(s, sizeof(*s));
        s->Active = TRUE;
        s->Pid = pid;
        s->Ppid = ppid;
    }
    return s;
}

//
// 检查规则是否已命中 (调用者已持有锁)
// 返回 TRUE 表示已存在 (去重判断)
//
static
BOOLEAN
EpSuspectHasRuleLocked(
    _In_ PEP_SUSPECT s,
    _In_ UINT32 ruleId
    )
{
    ULONG i;
    for (i = 0; i < s->RuleCount; i++)
    {
        if (s->Rules[i].RuleId == ruleId)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 记录命中规则 (调用者已持有锁, 已确认去重)
//
static
VOID
EpSuspectAddRuleLocked(
    _In_ PEP_SUSPECT s,
    _In_ UINT32 ruleId,
    _In_ UINT32 score,
    _In_ PCWSTR description
    )
{
    if (s->RuleCount < EP_SUSPECT_RULES_MAX)
    {
        s->Rules[s->RuleCount].RuleId = ruleId;
        s->Rules[s->RuleCount].Score = score;
        EpStrNCpyW(s->Rules[s->RuleCount].Description, description,
                   XGS_EP_RULE_DESC_LEN);
        s->RuleCount++;
    }
}

//
// 行为评分入口: 进程生命周期累计评分 + 触发判定
// IRQL: 任意 (仅纯内存操作)
//
static
VOID
EpScore(
    _In_ UINT32 type,
    _In_ UINT32 pid,
    _In_ UINT32 ppid,
    _In_ UINT32 score,
    _In_opt_ PCWSTR ruleDesc
    )
{
    KIRQL irql;
    BOOLEAN trigger = FALSE;

    if (pid == 0 || pid == 4)
    {
        return;   // System / 空 PID 不评分
    }

    KeAcquireSpinLock(&g_Ep.Lock, &irql);

    if (g_Ep.NotificationPending)
    {
        // 已有待处理通知, 不再触发新挂起 (避免堆积)
        KeReleaseSpinLock(&g_Ep.Lock, irql);
        return;
    }

    PEP_SUSPECT s = EpGetOrCreateSuspectLocked(pid, ppid);
    if (s->Suspended)
    {
        KeReleaseSpinLock(&g_Ep.Lock, irql);
        return;
    }

    //
    // IOA 去重: 同一规则只计一次分, 避免重复行为累积误触发
    // (如多次注册表写入 / 多个非系统模块加载不会重复加分)
    //
    if (EpSuspectHasRuleLocked(s, type))
    {
        KeReleaseSpinLock(&g_Ep.Lock, irql);
        return;
    }

    s->TotalScore += score;
    if (ruleDesc != NULL)
    {
        EpSuspectAddRuleLocked(s, type, score, ruleDesc);
    }

    if (s->TotalScore >= EP_TRIGGER_SCORE &&
        g_Ep.PendingSuspendPid == 0)
    {
        g_Ep.PendingSuspendPid = pid;
        g_Ep.PendingSuspendPpid = s->Ppid;
        trigger = TRUE;
    }

    KeReleaseSpinLock(&g_Ep.Lock, irql);

    if (trigger)
    {
        KdPrint(("XGSEndPoint: Threat score %u reached for PID %u (ppid %u)\n",
                 s->TotalScore, pid, ppid));
    }
}

//=============================================================================
// 进程创建/退出回调
//=============================================================================
static
VOID
EpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    WCHAR imageName[64];
    UINT32 pid;
    UINT32 ppid;

    UNREFERENCED_PARAMETER(Process);

    pid = (UINT32)(ULONG_PTR)ProcessId;
    ppid = 0;

    if (CreateInfo != NULL)
    {
        ppid = (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;

        imageName[0] = L'\0';
        if (CreateInfo->ImageFileName != NULL &&
            CreateInfo->ImageFileName->Buffer != NULL &&
            CreateInfo->ImageFileName->Length > 0)
        {
            ULONG chars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (chars >= 63)
            {
                chars = 62;
            }
            RtlCopyMemory(imageName, CreateInfo->ImageFileName->Buffer,
                          chars * sizeof(WCHAR));
            imageName[chars] = L'\0';
        }

        EpRecordBehavior(XgsEpProcessCreate, pid, ppid, imageName);
    }
    else
    {
        WCHAR detail[32];
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail), L"PID %u exited", pid);
        EpRecordBehavior(XgsEpProcessExit, pid, 0, detail);
    }
}

//=============================================================================
// 线程创建回调 (远程线程注入信号)
//=============================================================================
static
VOID
EpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    UINT32 sourcePid;
    UINT32 targetPid;
    WCHAR detail[96];

    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create)
    {
        return;
    }

    sourcePid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    targetPid = (UINT32)(ULONG_PTR)ProcessId;

    if (sourcePid == 0 || sourcePid == targetPid || sourcePid == 4)
    {
        return;   // System / 同进程线程创建 (绝大多数)
    }

    RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                        L"Remote thread %lu -> PID %u", (ULONG)(ULONG_PTR)ThreadId,
                        targetPid);
    EpRecordBehavior(XgsEpRemoteThread, sourcePid, 0, detail);

    EpScore(XgsEpRemoteThread, sourcePid, 0, EP_SCORE_REMOTE_THREAD,
            L"远程线程注入 (跨进程线程创建)");
}

//=============================================================================
// 模块加载回调 (DLL 侧载 / 非系统模块加载信号)
//=============================================================================
static
VOID
EpLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    UINT32 pid;
    WCHAR imagePath[520];
    BOOLEAN isSystem;

    UNREFERENCED_PARAMETER(ImageInfo);

    pid = (UINT32)(ULONG_PTR)ProcessId;
    if (pid == 0 || pid == 4)
    {
        return;
    }

    imagePath[0] = L'\0';
    if (FullImageName != NULL && FullImageName->Buffer != NULL &&
        FullImageName->Length > 0)
    {
        ULONG chars = FullImageName->Length / sizeof(WCHAR);
        if (chars >= ARRAYSIZE(imagePath))
        {
            chars = ARRAYSIZE(imagePath) - 1;
        }
        RtlCopyMemory(imagePath, FullImageName->Buffer, chars * sizeof(WCHAR));
        imagePath[chars] = L'\0';
    }

    if (imagePath[0] == L'\0')
    {
        return;
    }

    //
    // 记录模块加载行为
    //
    EpRecordBehavior(XgsEpModuleLoad, pid, 0, imagePath);

    //
    // 非系统目录模块加载: 评分 (DLL 侧载/注入信号)
    // 仅基于模块路径判断, 不做进程名/目录白名单 (病毒可能伪装系统名/驻留系统目录)
    //
    isSystem = EpContainsSubstrW(imagePath, L"\\Windows\\") ||
               EpContainsSubstrW(imagePath, L"\\SystemRoot\\");

    if (!isSystem)
    {
        EpScore(XgsEpModuleLoad, pid, 0, EP_SCORE_MODULE_LOAD,
                L"加载非系统目录模块 (DLL 侧载/注入)");
    }
}

//=============================================================================
// ObRegisterCallbacks (进程句柄: 注入/控制; Section 句柄: RWX)
//=============================================================================

static
OB_PREOP_CALLBACK_STATUS
EpProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    UINT32 sourcePid;
    UINT32 targetPid;
    ACCESS_MASK desired;
    WCHAR detail[128];

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE)
    {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    targetPid = (UINT32)(ULONG_PTR)PsGetProcessId(
        (PEPROCESS)OperationInformation->Object);
    desired = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

    if (sourcePid == 0 || sourcePid == targetPid || sourcePid == 4)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 远程线程注入信号: 请求对目标进程创建线程
    //
    if (desired & PROCESS_CREATE_THREAD)
    {
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                            L"OpenProcess(0x%08X) -> PID %u", desired, targetPid);
        EpRecordBehavior(XgsEpRemoteThread, sourcePid, 0, detail);
        EpScore(XgsEpRemoteThread, sourcePid, 0, EP_SCORE_REMOTE_THREAD,
                L"远程线程注入 (跨进程句柄权限)");
    }

    //
    // 跨进程内存读写信号: 请求读写/操纵目标进程内存 (内存操纵/注入前置)
    //
    if (desired & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))
    {
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                            L"OpenProcess(mem 0x%08X) -> PID %u", desired,
                            targetPid);
        EpRecordBehavior(XgsEpCrossMem, sourcePid, 0, detail);
        EpScore(XgsEpCrossMem, sourcePid, 0, EP_SCORE_CROSS_MEM,
                L"跨进程内存读写 (内存操纵)");
    }

    //
    // 跨进程控制信号: 请求终止/挂起其他进程
    //
    if (desired & (PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME))
    {
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                            L"OpenProcess(control 0x%08X) -> PID %u", desired,
                            targetPid);
        EpRecordBehavior(XgsEpProcessControl, sourcePid, 0, detail);
        EpScore(XgsEpProcessControl, sourcePid, 0, EP_SCORE_PROC_CONTROL,
                L"跨进程终止/挂起控制尝试");
    }

    return OB_PREOP_SUCCESS;
}

static
OB_PREOP_CALLBACK_STATUS
EpSectionPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    UINT32 sourcePid;
    ACCESS_MASK desired;
    WCHAR detail[128];

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE)
    {
        return OB_PREOP_SUCCESS;
    }

    sourcePid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    desired = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

    if (sourcePid == 0 || sourcePid == 4)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 仅关注可写 + 可执行映射 (RWX)
    //
    if (!(desired & SECTION_MAP_EXECUTE) || !(desired & SECTION_MAP_WRITE))
    {
        return OB_PREOP_SUCCESS;
    }

    RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                        L"RWX section map (0x%08X)", desired);
    EpRecordBehavior(XgsEpRwxMapping, sourcePid, 0, detail);
    EpScore(XgsEpRwxMapping, sourcePid, 0, EP_SCORE_RWX_MAPPING,
            L"可写可执行内存映射 (RWX)");

    return OB_PREOP_SUCCESS;
}

//=============================================================================
// 注册表回调 (自启动项检测)
//=============================================================================
static
NTSTATUS
EpRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    UINT32 sourcePid;
    WCHAR keyPath[AV_MAX_REG_PATH_LEN];
    BOOLEAN isRunKey = FALSE;
    BOOLEAN isDelete = FALSE;
    WCHAR detail[AV_MAX_REG_PATH_LEN + 64];

    UNREFERENCED_PARAMETER(CallbackContext);

    switch (notifyClass)
    {
    case RegNtSetValueKey:
    case RegNtPreCreateKey:
    case RegNtDeleteKey:
    case RegNtDeleteValueKey:
        break;

    default:
        return STATUS_SUCCESS;
    }

    sourcePid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    if (sourcePid == 0 || sourcePid == 4)
    {
        return STATUS_SUCCESS;
    }

    keyPath[0] = L'\0';

    //
    // 提取被操作键的完整路径
    //
    if (notifyClass == RegNtSetValueKey || notifyClass == RegNtDeleteValueKey)
    {
        PREG_SET_VALUE_KEY_INFORMATION info =
            (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info != NULL && info->Object != NULL)
        {
            PUNICODE_STRING keyName = NULL;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(
                    g_RegNotifyContext, info->Object, NULL, &keyName, 0)) &&
                keyName != NULL && keyName->Buffer != NULL)
            {
                ULONG chars = keyName->Length / sizeof(WCHAR);
                if (chars >= AV_MAX_REG_PATH_LEN)
                {
                    chars = AV_MAX_REG_PATH_LEN - 1;
                }
                RtlCopyMemory(keyPath, keyName->Buffer, chars * sizeof(WCHAR));
                keyPath[chars] = L'\0';
            }
        }
    }
    else
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (info != NULL && info->RootObject != NULL)
        {
            PUNICODE_STRING keyName = NULL;
            if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(
                    g_RegNotifyContext, info->RootObject, NULL, &keyName, 0)) &&
                keyName != NULL && keyName->Buffer != NULL)
            {
                ULONG chars = keyName->Length / sizeof(WCHAR);
                if (chars >= AV_MAX_REG_PATH_LEN)
                {
                    chars = AV_MAX_REG_PATH_LEN - 1;
                }
                RtlCopyMemory(keyPath, keyName->Buffer, chars * sizeof(WCHAR));
                keyPath[chars] = L'\0';
            }
        }
    }

    if (keyPath[0] == L'\0')
    {
        return STATUS_SUCCESS;
    }

    //
    // 自启动相关路径检测
    //
    if (EpContainsSubstrW(keyPath, L"CurrentVersion\\Run") ||
        EpContainsSubstrW(keyPath, L"CurrentVersion\\RunOnce") ||
        EpContainsSubstrW(keyPath, L"\\Services\\") ||
        EpContainsSubstrW(keyPath, L"Winlogon"))
    {
        isRunKey = TRUE;
    }

    if (notifyClass == RegNtDeleteKey || notifyClass == RegNtDeleteValueKey)
    {
        isDelete = TRUE;
    }

    //
    // 记录行为 (写入自启动项才评分)
    //
    if (isRunKey)
    {
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail),
                            isDelete ? L"Reg delete %ls" : L"Reg write %ls",
                            keyPath);
        EpRecordBehavior(isDelete ? XgsEpRegDelete : XgsEpRegWrite,
                         sourcePid, 0, detail);
        if (!isDelete)
        {
            EpScore(XgsEpRegWrite, sourcePid, 0, EP_SCORE_REG_RUNKEY,
                    L"注册表自启动项写入");
        }
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// minifilter 预操作回调 (文件写入/删除)
//=============================================================================

//
// 检测是否为引导区写入路径
//   物理磁盘:  \Device\HarddiskX\DRX  或  \??\PhysicalDriveN
//   BCD 文件:  \Boot\BCD  或  \EFI\Microsoft\Boot\BCD
//   卷根写入:  路径极短 (如 "\") 且写入偏移在前 64KB (覆盖 MBR + GPT 表)
//
static
BOOLEAN
EpIsBootWrite(
    _In_ PCWSTR path,
    _In_ LARGE_INTEGER writeOffset
    )
{
    if (path == NULL)
    {
        return FALSE;
    }

    //
    // 1. 物理磁盘设备 (\\Device\\HarddiskX\\DRX, \\??\\PhysicalDriveN)
    //
    // 注意: 必须精确匹配物理磁盘设备, 不能用子串匹配!
    //   - 物理磁盘:  \Device\Harddisk0\DR0      <- 这是物理磁盘设备
    //   - 卷设备:    \Device\HarddiskVolume1     <- 这是普通文件系统卷
    //   如果用 EpContainsSubstrW(path, "\\Device\\Harddisk") 会误匹配卷路径!
    //
    // 物理磁盘路径特征: \Device\Harddisk<数字>\DR<数字>
    //                   \??\PhysicalDrive<数字>
    {
        SIZE_T len = EpStrLenW(path);

        //
        // 检查 \Device\HarddiskX\DRX 格式
        // 路径前缀: \Device\Harddisk, 后面紧跟数字, 再后面是 \DR<数字>
        //
        if (len >= 18 &&
            path[0] == L'\\' && path[1] == L'D' && path[2] == L'e' &&
            path[3] == L'v' && path[4] == L'i' && path[5] == L'c' &&
            path[6] == L'e' && path[7] == L'\\' && path[8] == L'H' &&
            path[9] == L'a' && path[10] == L'r' && path[11] == L'd' &&
            path[12] == L'd' && path[13] == L'i' && path[14] == L's' &&
            path[15] == L'k')
        {
            //
            // path[16] 应为数字, path[17] 应为 '\'
            // 排除卷设备 \Device\HarddiskVolumeX (V 不是 \)
            //
            if (path[16] >= L'0' && path[16] <= L'9' && path[17] == L'\\')
            {
                if (writeOffset.QuadPart < (34 * 512))
                {
                    return TRUE;
                }
                return FALSE;
            }
        }

        //
        // 检查 \??\PhysicalDriveN 格式 (用户态 \\.\PhysicalDriveN)
        //
        if (len >= 18 &&
            path[0] == L'\\' && path[1] == L'?' && path[2] == L'?' &&
            path[3] == L'\\' && path[4] == L'P' && path[5] == L'h' &&
            path[6] == L'y' && path[7] == L's' && path[8] == L'i' &&
            path[9] == L'c' && path[10] == L'a' && path[11] == L'l' &&
            path[12] == L'D' && path[13] == L'r' && path[14] == L'i' &&
            path[15] == L'v' && path[16] == L'e')
        {
            if (writeOffset.QuadPart < (34 * 512))
            {
                return TRUE;
            }
            return FALSE;
        }

        //
        // 检查 \Device\CdromX (光驱设备, 也可能包含引导扇区)
        //
        if (len >= 14 &&
            path[0] == L'\\' && path[1] == L'D' && path[2] == L'e' &&
            path[3] == L'v' && path[4] == L'i' && path[5] == L'c' &&
            path[6] == L'e' && path[7] == L'\\' && path[8] == L'C' &&
            path[9] == L'd' && path[10] == L'r' && path[11] == L'o' &&
            path[12] == L'm')
        {
            if (writeOffset.QuadPart < (34 * 512))
            {
                return TRUE;
            }
            return FALSE;
        }
    }

    //
    // 2. BCD 文件 (大小写不敏感)
    //
    if (EpContainsSubstrW(path, L"\\Boot\\BCD") ||
        EpContainsSubstrW(path, L"\\EFI\\Microsoft\\Boot\\BCD"))
    {
        return TRUE;
    }

    //
    // 3. 卷根写入 (MBR/GPT 扇区)
    //    路径为 "\" 或极短时, 且写入偏移在前 64KB
    //
    {
        SIZE_T len = EpStrLenW(path);
        if (len <= 2 && writeOffset.QuadPart < (64 * 1024))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
EpGetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(buflen) PWCHAR out,
    _In_ ULONG buflen
    )
{
    NTSTATUS st;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG charCount;

    //
    // 优先用 NORMALIZED (可拿到 \\Device\\HarddiskX\\DRX 这种设备路径)
    // 旧驱动用 NORMALIZED 才能拦截 PhysicalDrive0
    //
    st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL)
    {
        //
        // Fallback: OPENED (失败时回退, 至少能拿到部分路径)
        //
        st = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(st) || nameInfo == NULL)
        {
            return FALSE;
        }
    }

    charCount = nameInfo->Name.Length / sizeof(WCHAR);
    if (charCount >= buflen)
    {
        charCount = buflen - 1;
    }
    RtlCopyMemory(out, nameInfo->Name.Buffer, charCount * sizeof(WCHAR));
    out[charCount] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return TRUE;
}

static
FLT_PREOP_CALLBACK_STATUS
EpPreWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    WCHAR path[560];
    UINT32 pid;
    KIRQL irql;
    BOOLEAN isBoot = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (iopb->Parameters.Write.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == 0 || pid == 4)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 尝试获取文件/设备路径 (优先 NORMALIZED, 可拿到 \Device\HarddiskX\DRX)
    //
    if (!EpGetFilePath(Data, path, ARRAYSIZE(path)))
    {
        //
        // 路径获取失败: 如果是分页 IO 或非 PASSIVE, 直接放行
        // (旧驱动只检查 paging IO, 不检查 IRQL)
        //
        if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
            (iopb->IrpFlags & IRP_PAGING_IO))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 引导区写入检测
    //
    isBoot = EpIsBootWrite(path, iopb->Parameters.Write.ByteOffset);
    if (isBoot)
    {
        EpRecordBehavior(XgsEpBootWrite, pid, 0, path);

        //
        // 引导区写入: 不 pend IRP (避免 FltCompletePendedPreOperation 的复杂生命周期问题)
        // 直接阻止写入 + 触发挂起流程
        // 评分仅在用户拒绝时才计入 (满分 200)
        //
        KeAcquireSpinLock(&g_Ep.Lock, &irql);

        if (g_Ep.NotificationPending)
        {
            //
            // 已有待处理决策 -> 直接拒绝
            //
            KeReleaseSpinLock(&g_Ep.Lock, irql);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        //
        // 首次引导区写入: 阻止写入 + 触发挂起 (不 pend IRP, 直接 COMPLETE)
        //
        g_Ep.PendingSuspendPid = pid;
        g_Ep.PendingSuspendPpid = 0;
        g_Ep.BootWritePending = TRUE;

        KeReleaseSpinLock(&g_Ep.Lock, irql);

        KdPrint(("XGSEndPoint: Boot write detected from PID %u, blocking + suspending\n", pid));

        //
        // 直接拒绝写入 (不走 pending 流程)
        //
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    EpRecordBehavior(XgsEpFileWrite, pid, 0, path);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
EpPreSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FILE_INFORMATION_CLASS fic;
    WCHAR path[560];
    UINT32 pid;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == 0 || pid == 4)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    fic = iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    // 文件删除: 仅记录行为, 不参与评分 (正常软件也批量删除文件)
    //
    if (fic == FileDispositionInformation)
    {
        PFILE_DISPOSITION_INFORMATION dispInfo =
            (PFILE_DISPOSITION_INFORMATION)
                iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispInfo == NULL || !dispInfo->DeleteFile)
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (!EpGetFilePath(Data, path, ARRAYSIZE(path)))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        EpRecordBehavior(XgsEpFileDelete, pid, 0, path);
    }

    //
    // 文件重命名: 记录行为 (勒索软件常批量重命名加密)
    //
    else if (fic == FileRenameInformation || fic == FileRenameInformationEx)
    {
        PVOID infoBuffer = iopb->Parameters.SetFileInformation.InfoBuffer;
        ULONG infoLen = iopb->Parameters.SetFileInformation.Length;
        ULONG nameOffset = 0;
        ULONG nameLength = 0;
        PWCHAR namePtr = NULL;

        if (infoBuffer == NULL)
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (fic == FileRenameInformation)
        {
            PFILE_RENAME_INFORMATION renameInfo =
                (PFILE_RENAME_INFORMATION)infoBuffer;
            nameOffset = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
            nameLength = renameInfo->FileNameLength;
            namePtr = renameInfo->FileName;
        }
        else
        {
            PEP_FILE_RENAME_INFORMATION_EX renameInfoEx =
                (PEP_FILE_RENAME_INFORMATION_EX)infoBuffer;
            nameOffset = FIELD_OFFSET(EP_FILE_RENAME_INFORMATION_EX, FileName);
            nameLength = renameInfoEx->FileNameLength;
            namePtr = renameInfoEx->FileName;
        }

        if (nameLength > infoLen - nameOffset)
        {
            nameLength = infoLen - nameOffset;
        }

        if (nameLength < sizeof(WCHAR))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (!EpGetFilePath(Data, path, ARRAYSIZE(path)))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        ULONG nameChars = nameLength / sizeof(WCHAR);
        if (nameChars > 200)
        {
            nameChars = 200;
        }

        WCHAR detail[560];
        RtlStringCchPrintfW(detail, ARRAYSIZE(detail), L"%ls -> %.*ls",
                            path, (int)nameChars, namePtr);
        EpRecordBehavior(XgsEpFileRename, pid, 0, detail);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
const
FLT_OPERATION_REGISTRATION
EpCallbacks[] =
{
    { IRP_MJ_WRITE, 0, EpPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, EpPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static
const
FLT_REGISTRATION
EpReg =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                        // Flags
    NULL,                     // ContextRegistration
    EpCallbacks,              // OperationRegistration
    NULL,                     // FilterUnloadCallback
    NULL,                     // InstanceSetupCallback
    NULL,                     // InstanceQueryTeardownCallback
    NULL,                     // InstanceTeardownStartCallback
    NULL,                     // InstanceTeardownCompleteCallback
    NULL,                     // GenerateFileNameCallback
    NULL,                     // NormalizeNameComponentCallback
    NULL,                     // NormalizeContextCleanupCallback
    NULL,                     // TransactionNotificationCallback
    NULL,                     // NormalizeNameComponentExCallback
    NULL                      // SectionNotificationCallback
};

//=============================================================================
// 进程挂起 / 恢复 / 终止 (PASSIVE_LEVEL 工作线程)
//=============================================================================

//
// 挂起指定进程的全部线程 (保存线程句柄)
//
static
NTSTATUS
EpSuspendProcess(
    _In_ PEP_SUSPECT suspect
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS st;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)suspect->Pid;
    cid.UniqueThread = NULL;

    //
    // 优先使用进程级挂起 (NtSuspendProcess), 比 NtGetNextThread 枚举更可靠
    // 所需权限: PROCESS_SUSPEND_RESUME
    //
    if (g_pNtSuspendProcess != NULL)
    {
        st = ZwOpenProcess(&hProcess, PROCESS_SUSPEND_RESUME, &oa, &cid);
        if (!NT_SUCCESS(st))
        {
            KdPrint(("XGSEndPoint: ZwOpenProcess(suspend) PID %u failed 0x%08X\n",
                     suspect->Pid, st));
            return st;
        }

        st = g_pNtSuspendProcess(hProcess);
        ZwClose(hProcess);

        suspect->ThreadCount = 0;   // 进程级挂起, 无需保存线程句柄
        KdPrint(("XGSEndPoint: NtSuspendProcess PID %u -> 0x%08X\n",
                 suspect->Pid, st));
        return st;
    }

    //
    // 回退方案: 逐线程挂起 (NtGetNextThread 枚举)
    // 需要保存线程句柄以便恢复
    //
    if (g_pNtGetNextThread == NULL)
    {
        KdPrint(("XGSEndPoint: No suspend API available (NtSuspendProcess and NtGetNextThread both NULL)\n"));
        return STATUS_NOT_IMPLEMENTED;
    }

    {
        HANDLE hThread = NULL;

        st = ZwOpenProcess(&hProcess,
                           PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
                           &oa, &cid);
        if (!NT_SUCCESS(st))
        {
            return st;
        }

        suspect->ThreadCount = 0;
        hThread = NULL;

        for (;;)
        {
            HANDLE hNext = NULL;

            st = g_pNtGetNextThread(hProcess, hThread, THREAD_SUSPEND_RESUME, 0, 0,
                                    &hNext);
            if (hThread != NULL)
            {
                ZwClose(hThread);
                hThread = NULL;
            }
            if (!NT_SUCCESS(st))
            {
                break;   // STATUS_NO_MORE_ENTRIES
            }

            hThread = hNext;

            if (suspect->ThreadCount < EP_SUSPEND_THREADS_MAX)
            {
                CLIENT_ID tid;
                OBJECT_ATTRIBUTES toa;
                HANDLE hOpen = NULL;

                InitializeObjectAttributes(&toa, NULL, 0, NULL, NULL);
                tid.UniqueProcess = NULL;
                tid.UniqueThread = (HANDLE)PsGetThreadId(hThread);

                if (g_pZwOpenThread != NULL &&
                    NT_SUCCESS(g_pZwOpenThread(&hOpen, THREAD_SUSPEND_RESUME,
                                            &toa, &tid)))
                {
                    if (g_pZwSuspendThread != NULL &&
                        g_pZwSuspendThread(hOpen, NULL) == STATUS_SUCCESS)
                    {
                        suspect->ThreadHandles[suspect->ThreadCount++] = hOpen;
                    }
                    else
                    {
                        ZwClose(hOpen);
                    }
                }
            }
            else
            {
                break;
            }
        }

        ZwClose(hProcess);
        return STATUS_SUCCESS;
    }
}

//
// 恢复已挂起的进程
// 优先使用进程级恢复 (NtResumeProcess), 回退到逐线程恢复
//
static
VOID
EpResumeProcess(
    _In_ PEP_SUSPECT suspect
    )
{
    //
    // 进程级恢复 (NtResumeProcess): 无需线程句柄
    //
    if (g_pNtResumeProcess != NULL && suspect->ThreadCount == 0)
    {
        HANDLE hProcess = NULL;
        CLIENT_ID cid;
        OBJECT_ATTRIBUTES oa;

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = (HANDLE)(ULONG_PTR)suspect->Pid;
        cid.UniqueThread = NULL;

        if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_SUSPEND_RESUME, &oa, &cid)))
        {
            NTSTATUS st = g_pNtResumeProcess(hProcess);
            KdPrint(("XGSEndPoint: NtResumeProcess PID %u -> 0x%08X\n",
                     suspect->Pid, st));
            ZwClose(hProcess);
        }
    }
    else
    {
        //
        // 回退: 逐线程恢复 (线程句柄在挂起时保存)
        //
        ULONG i;
        for (i = 0; i < suspect->ThreadCount; i++)
        {
            if (g_pZwResumeThread != NULL)
                g_pZwResumeThread(suspect->ThreadHandles[i], NULL);
            ZwClose(suspect->ThreadHandles[i]);
            suspect->ThreadHandles[i] = NULL;
        }
    }

    suspect->ThreadCount = 0;
    suspect->Suspended = FALSE;
}

//
// 终止进程
//
static
NTSTATUS
EpTerminateProcess(
    _In_ UINT32 pid
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS st;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    st = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &oa, &cid);
    if (!NT_SUCCESS(st))
    {
        return st;
    }
    st = ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
    ZwClose(hProcess);
    return st;
}

//
// 获取进程镜像路径 (PASSIVE_LEVEL)
//
static
VOID
EpGetProcessImagePath(
    _In_ UINT32 pid,
    _Out_writes_bytes_(BufferBytes) PWCHAR Path,
    _In_ SIZE_T BufferBytes
    )
{
    HANDLE hProcess = NULL;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    UCHAR buffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
    PUNICODE_STRING imagePath = (PUNICODE_STRING)buffer;
    ULONG returnLength = 0;
    NTSTATUS status;

    Path[0] = L'\0';

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                           &oa, &cid);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    status = ZwQueryInformationProcess(hProcess,
                                       EP_PROCESS_IMAGE_FILE_NAME_CLASS,
                                       buffer, sizeof(buffer), &returnLength);
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
}

//=============================================================================
// 工作线程: 认领挂起请求 -> 挂起进程 -> 通知 -> 等决策 -> 恢复/终止
//=============================================================================
static
VOID
EpWorkerRoutine(
    _In_ PVOID Context
    )
{
    LARGE_INTEGER delay;
    KIRQL irql;

    UNREFERENCED_PARAMETER(Context);

    delay.QuadPart = -20000;   // 2ms

    for (;;)
    {
        UINT32 pid = 0;
        UINT32 ppid = 0;
        PEP_SUSPECT suspect = NULL;
        WCHAR imagePath[AV_MAX_PROCESS_PATH_LEN];
        NTSTATUS st;
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;
        BOOLEAN allow = FALSE;
        BOOLEAN bootWrite = FALSE;

        KeAcquireSpinLock(&g_Ep.Lock, &irql);
        if (g_Ep.WorkerStop)
        {
            KeReleaseSpinLock(&g_Ep.Lock, irql);
            break;
        }
        if (g_Ep.PendingSuspendPid != 0)
        {
            pid = g_Ep.PendingSuspendPid;
            ppid = g_Ep.PendingSuspendPpid;
            g_Ep.PendingSuspendPid = 0;
            bootWrite = g_Ep.BootWritePending;
        }
        KeReleaseSpinLock(&g_Ep.Lock, irql);

        if (pid == 0)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            continue;
        }

        //
        // 找到或创建嫌疑记录并挂起进程
        //
        KeAcquireSpinLock(&g_Ep.Lock, &irql);
        suspect = EpFindSuspectLocked(pid);
        if (suspect == NULL && bootWrite)
        {
            //
            // 引导写入不经过评分, 无嫌疑记录 -> 创建一个
            //
            suspect = EpGetOrCreateSuspectLocked(pid, 0);
        }
        if (suspect != NULL && !suspect->Suspended)
        {
            suspect->Suspended = TRUE;
            suspect->SuspendTicks = EpNow();
        }
        else
        {
            suspect = NULL;
        }
        KeReleaseSpinLock(&g_Ep.Lock, irql);

        if (suspect == NULL)
        {
            KeAcquireSpinLock(&g_Ep.Lock, &irql);
            g_Ep.BootWritePending = FALSE;
            KeReleaseSpinLock(&g_Ep.Lock, irql);
            continue;
        }

        EpGetProcessImagePath(pid, imagePath, sizeof(imagePath));
        EpStrNCpyW(suspect->ImagePath, imagePath, AV_MAX_PROCESS_PATH_LEN);

        st = EpSuspendProcess(suspect);
        if (!NT_SUCCESS(st))
        {
            KdPrint(("XGSEndPoint: Suspend PID %u failed 0x%08X\n", pid, st));
            KeAcquireSpinLock(&g_Ep.Lock, &irql);
            suspect->Suspended = FALSE;
            g_Ep.BootWritePending = FALSE;
            KeReleaseSpinLock(&g_Ep.Lock, irql);
            continue;
        }

        InterlockedIncrement64((PLONG64)&g_Ep.ProcessesSuspended);

        //
        // 构建通知
        //
        KeAcquireSpinLock(&g_Ep.Lock, &irql);
        g_Ep.NotificationId++;
        RtlZeroMemory(&g_Ep.Notification, sizeof(g_Ep.Notification));
        g_Ep.Notification.HasPending = TRUE;
        g_Ep.Notification.NotificationId = g_Ep.NotificationId;
        g_Ep.Notification.ProcessId = pid;
        g_Ep.Notification.ParentProcessId = ppid;

        if (bootWrite)
        {
            //
            // 引导区写入: 通知显示满分规则 (实际评分仅在拒绝时计入)
            //
            g_Ep.Notification.TotalScore = EP_SCORE_BOOT_MODIFY;
            g_Ep.Notification.RuleCount = 1;
            g_Ep.Notification.Rules[0].RuleId = EP_RULE_BOOT_MODIFY;
            g_Ep.Notification.Rules[0].Score = EP_SCORE_BOOT_MODIFY;
            EpStrNCpyW(g_Ep.Notification.Rules[0].Description,
                       L"试图修改引导区 (BCD/MBR/GPT)",
                       XGS_EP_RULE_DESC_LEN);
        }
        else
        {
            g_Ep.Notification.TotalScore = suspect->TotalScore;
            g_Ep.Notification.RuleCount = suspect->RuleCount;
            if (g_Ep.Notification.RuleCount > XGS_EP_RULE_MAX)
            {
                g_Ep.Notification.RuleCount = XGS_EP_RULE_MAX;
            }
            RtlCopyMemory(g_Ep.Notification.Rules, suspect->Rules,
                          g_Ep.Notification.RuleCount * sizeof(XGS_EP_RULE_HIT));
        }

        EpStrNCpyW(g_Ep.Notification.ImagePath, suspect->ImagePath,
                   AV_MAX_PROCESS_PATH_LEN);

        g_Ep.NotificationPending = TRUE;
        g_Ep.DecisionPending = TRUE;
        g_Ep.DecisionAllow = FALSE;
        InterlockedIncrement64((PLONG64)&g_Ep.ThreatsDetected);
        KeReleaseSpinLock(&g_Ep.Lock, irql);

        KdPrint(("XGSEndPoint: Suspended %s PID %u (score %u), notifying\n",
                 bootWrite ? "boot-write" : "threat",
                 pid, g_Ep.Notification.TotalScore));

        //
        // 等待决策 (60 秒超时自动放行)
        //
        KeResetEvent(&g_Ep.DecisionEvent);
        timeout.QuadPart = -(LONGLONG)XGS_EP_TIMEOUT_100NS;
        waitStatus = KeWaitForSingleObject(&g_Ep.DecisionEvent, Executive,
                                           KernelMode, FALSE, &timeout);

        KeAcquireSpinLock(&g_Ep.Lock, &irql);
        allow = g_Ep.DecisionAllow;
        g_Ep.DecisionPending = FALSE;
        g_Ep.NotificationPending = FALSE;
        g_Ep.BootWritePending = FALSE;
        KeReleaseSpinLock(&g_Ep.Lock, irql);

        if (bootWrite)
        {
            //
            // 引导区写入: 写入已在 EpPreWrite 中被阻止 (FLT_PREOP_COMPLETE)
            // 这里只处理进程决策
            //
            if (allow || waitStatus == STATUS_TIMEOUT)
            {
                //
                // 允许: 恢复进程 (不加分)
                //
                EpResumeProcess(suspect);
                KdPrint(("XGSEndPoint: Boot write ALLOWED (timeout=%d), PID %u\n",
                         (waitStatus == STATUS_TIMEOUT), pid));
            }
            else
            {
                //
                // 拒绝: 加满分 (行为链报告) + 终止进程
                //
                KeAcquireSpinLock(&g_Ep.Lock, &irql);
                if (!EpSuspectHasRuleLocked(suspect, EP_RULE_BOOT_MODIFY))
                {
                    EpSuspectAddRuleLocked(suspect, EP_RULE_BOOT_MODIFY,
                        EP_SCORE_BOOT_MODIFY,
                        L"试图修改引导区 (BCD/MBR/GPT)");
                    suspect->TotalScore += EP_SCORE_BOOT_MODIFY;
                }
                KeReleaseSpinLock(&g_Ep.Lock, irql);

                st = EpTerminateProcess(pid);
                EpResumeProcess(suspect);
                KdPrint(("XGSEndPoint: Boot write DENIED, KILLED PID %u (0x%08X)\n",
                         pid, st));
            }
        }
        else
        {
            //
            // 常规 EDR 决策
            //
            if (allow || waitStatus == STATUS_TIMEOUT)
            {
                EpResumeProcess(suspect);
                KdPrint(("XGSEndPoint: ALLOWED (timeout=%d), resumed PID %u\n",
                         (waitStatus == STATUS_TIMEOUT), pid));
            }
            else
            {
                st = EpTerminateProcess(pid);
                EpResumeProcess(suspect);
                KdPrint(("XGSEndPoint: KILLED PID %u (status 0x%08X)\n", pid, st));
            }
        }

        KeAcquireSpinLock(&g_Ep.Lock, &irql);
        suspect->Active = FALSE;   // 清理嫌疑记录
        KeReleaseSpinLock(&g_Ep.Lock, irql);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//=============================================================================
// 内联 SHA-256 + HMAC-SHA256 (无 BCrypt/cng.sys 依赖, FIPS 180-4)
//=============================================================================

#define SHA256_ROTR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_SHR(x,n)   ((x) >> (n))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_BSIG0(x)   (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_BSIG1(x)   (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SSIG0(x)   (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ SHA256_SHR(x,3))
#define SHA256_SSIG1(x)   (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ SHA256_SHR(x,10))

typedef struct _SHA256_CTX {
    ULONG       state[8];
    ULONGLONG   bitlen;
    ULONG       datalen;
    UCHAR       data[64];
} SHA256_CTX;

static const ULONG sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const UCHAR *data)
{
    ULONG w[64];
    ULONG a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((ULONG)data[i*4] << 24) | ((ULONG)data[i*4+1] << 16) |
               ((ULONG)data[i*4+2] << 8) | (ULONG)data[i*4+3];

    for (i = 16; i < 64; i++)
        w[i] = SHA256_SSIG1(w[i-2]) + w[i-7] + SHA256_SSIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA256_BSIG1(e) + SHA256_CH(e,f,g) + sha256_k[i] + w[i];
        t2 = SHA256_BSIG0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const UCHAR *data, ULONG len)
{
    ULONG i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, UCHAR *hash)
{
    ULONG i = ctx->datalen;

    ctx->data[i++] = 0x80;

    if (ctx->datalen < 56) {
        while (i < 56) ctx->data[i++] = 0;
    } else {
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        RtlZeroMemory(ctx->data, 56);
    }

    ctx->bitlen += (ULONGLONG)ctx->datalen * 8;
    ctx->data[63] = (UCHAR)(ctx->bitlen);
    ctx->data[62] = (UCHAR)(ctx->bitlen >> 8);
    ctx->data[61] = (UCHAR)(ctx->bitlen >> 16);
    ctx->data[60] = (UCHAR)(ctx->bitlen >> 24);
    ctx->data[59] = (UCHAR)(ctx->bitlen >> 32);
    ctx->data[58] = (UCHAR)(ctx->bitlen >> 40);
    ctx->data[57] = (UCHAR)(ctx->bitlen >> 48);
    ctx->data[56] = (UCHAR)(ctx->bitlen >> 56);

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; i++) {
        hash[i*4]   = (UCHAR)(ctx->state[i] >> 24);
        hash[i*4+1] = (UCHAR)(ctx->state[i] >> 16);
        hash[i*4+2] = (UCHAR)(ctx->state[i] >> 8);
        hash[i*4+3] = (UCHAR)(ctx->state[i]);
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
}

static void hmac_sha256(
    const UCHAR *Key, ULONG KeyLen,
    const UCHAR *Data, ULONG DataLen,
    UCHAR *Hmac)
{
    UCHAR k_ipad[64];
    UCHAR k_opad[64];
    UCHAR tk[32];
    UCHAR inner_hash[32];
    SHA256_CTX ctx;
    ULONG i;

    if (KeyLen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, Key, KeyLen);
        sha256_final(&ctx, tk);
        Key = tk;
        KeyLen = 32;
    }

    RtlZeroMemory(k_ipad, 64);
    RtlZeroMemory(k_opad, 64);
    RtlCopyMemory(k_ipad, Key, KeyLen);
    RtlCopyMemory(k_opad, Key, KeyLen);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, Data, DataLen);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, Hmac);

    RtlZeroMemory(k_ipad, 64);
    RtlZeroMemory(k_opad, 64);
    RtlZeroMemory(inner_hash, 32);
}

//=============================================================================
// EpHmac - HMAC-SHA256 (内联实现, 无 cng.sys 依赖)
//=============================================================================
static
NTSTATUS
EpHmac(
    _In_reads_bytes_(dataLen) const UCHAR* data,
    _In_ ULONG dataLen,
    _Out_writes_bytes_(AV_HASH_SIZE) UCHAR* out
    )
{
    hmac_sha256(AV_SHARED_KEY, AV_SHARED_KEY_SIZE, data, dataLen, out);
    return STATUS_SUCCESS;
}

//=============================================================================
// IOCTL 处理 (传统 IRP, METHOD_BUFFERED)
//=============================================================================
static
BOOLEAN
EpIsAuthed(
    VOID
    )
{
    KIRQL irql;
    BOOLEAN authed;

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    authed = g_Ep.Authed;
    KeReleaseSpinLock(&g_Ep.Lock, irql);
    return authed;
}

static
NTSTATUS
EpIoctlAuthInit(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    AV_AUTH_CHALLENGE* out = (AV_AUTH_CHALLENGE*)systemBuffer;
    NTSTATUS st;
    KIRQL irql;
    LARGE_INTEGER sysTime;
    ULONG seed;
    ULONG i;

    *info = 0;

    if (outLen < sizeof(AV_AUTH_CHALLENGE))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 内联随机数生成 (无 BCryptGenRandom/cng.sys 依赖)
    //
    KeQuerySystemTime(&sysTime);
    seed = sysTime.LowPart ^
           (ULONG)(ULONG_PTR)PsGetCurrentProcessId() ^
           (ULONG)(ULONG_PTR)&g_Ep.Challenge;

    for (i = 0; i < AV_CHALLENGE_SIZE; i += sizeof(ULONG)) {
        seed = seed * 1103515245 + 12345;
        ULONG rand = (seed >> 16) & 0x7FFF;
        rand |= (seed & 0xFFFF) << 15;
        ULONG copyLen = (AV_CHALLENGE_SIZE - i < sizeof(ULONG)) ? (AV_CHALLENGE_SIZE - i) : sizeof(ULONG);
        RtlCopyMemory(g_Ep.Challenge + i, &rand, copyLen);
    }

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    g_Ep.ChallengeSeq++;
    g_Ep.ChallengeValid = TRUE;
    KeReleaseSpinLock(&g_Ep.Lock, irql);

    out->SequenceId = g_Ep.ChallengeSeq;
    RtlCopyMemory(out->Challenge, g_Ep.Challenge, AV_CHALLENGE_SIZE);
    *info = sizeof(AV_AUTH_CHALLENGE);
    return STATUS_SUCCESS;
}

static
NTSTATUS
EpIoctlAuthVerify(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    AV_AUTH_RESPONSE resp;
    AV_AUTH_RESULT* out;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    UCHAR hmac[AV_HASH_SIZE];
    NTSTATUS st = STATUS_SUCCESS;
    BOOLEAN valid = FALSE;
    KIRQL irql;

    *info = 0;

    if (inLen < sizeof(AV_AUTH_RESPONSE) ||
        outLen < sizeof(AV_AUTH_RESULT))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&resp, systemBuffer, sizeof(AV_AUTH_RESPONSE));

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    if (g_Ep.ChallengeValid && resp.SequenceId == g_Ep.ChallengeSeq)
    {
        valid = TRUE;
    }
    KeReleaseSpinLock(&g_Ep.Lock, irql);

    if (valid)
    {
        RtlCopyMemory(hmacInput, g_Ep.Challenge, AV_CHALLENGE_SIZE);
        RtlCopyMemory(hmacInput + AV_CHALLENGE_SIZE, &resp.SequenceId,
                      sizeof(UINT64));
        st = EpHmac(hmacInput, sizeof(hmacInput), hmac);
        if (NT_SUCCESS(st) &&
            RtlEqualMemory(hmac, resp.Hmac, AV_HASH_SIZE))
        {
            KeAcquireSpinLock(&g_Ep.Lock, &irql);
            g_Ep.Authed = TRUE;
            KeReleaseSpinLock(&g_Ep.Lock, irql);
        }
        else
        {
            st = STATUS_SUCCESS;
            valid = FALSE;
        }
    }

    out = (AV_AUTH_RESULT*)systemBuffer;
    if (valid)
    {
        out->Status = STATUS_SUCCESS;
        RtlCopyMemory(out->SessionId, hmac, AV_SESSION_ID_SIZE);
    }
    else
    {
        out->Status = STATUS_ACCESS_DENIED;
        RtlZeroMemory(out->SessionId, AV_SESSION_ID_SIZE);
    }
    *info = sizeof(AV_AUTH_RESULT);
    return st;
}

static
NTSTATUS
EpIoctlGetNotification(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    XGS_EP_NOTIFICATION* out = (XGS_EP_NOTIFICATION*)systemBuffer;
    KIRQL irql;

    *info = 0;

    if (outLen < sizeof(XGS_EP_NOTIFICATION))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    RtlCopyMemory(out, &g_Ep.Notification, sizeof(XGS_EP_NOTIFICATION));
    KeReleaseSpinLock(&g_Ep.Lock, irql);
    *info = sizeof(XGS_EP_NOTIFICATION);
    return STATUS_SUCCESS;
}

static
NTSTATUS
EpIoctlSendDecision(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _Out_ PULONG info
    )
{
    XGS_EP_DECISION decision;
    KIRQL irql;
    BOOLEAN wake = FALSE;
    NTSTATUS st = STATUS_SUCCESS;

    *info = 0;

    if (inLen < sizeof(XGS_EP_DECISION))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&decision, systemBuffer, sizeof(XGS_EP_DECISION));

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    if (g_Ep.DecisionPending &&
        decision.NotificationId == g_Ep.Notification.NotificationId)
    {
        switch (decision.Decision)
        {
        case XGS_EP_DECISION_ALLOW:
            g_Ep.DecisionAllow = TRUE;
            wake = TRUE;
            break;

        case XGS_EP_DECISION_KILL:
            g_Ep.DecisionAllow = FALSE;
            wake = TRUE;
            break;

        default:
            st = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    else
    {
        st = STATUS_NOT_FOUND;
    }
    KeReleaseSpinLock(&g_Ep.Lock, irql);

    if (wake)
    {
        KeSetEvent(&g_Ep.DecisionEvent, IO_NO_INCREMENT, FALSE);
    }

    return st;
}

static
NTSTATUS
EpIoctlGetStatus(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    XGS_EP_STATUS* out = (XGS_EP_STATUS*)systemBuffer;
    KIRQL irql;

    *info = 0;

    if (outLen < sizeof(XGS_EP_STATUS))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    out->Version = 1;
    out->PendingNotification = g_Ep.NotificationPending ? 1 : 0;
    out->BehaviorsRecorded = g_Ep.BehaviorsRecorded;
    out->ThreatsDetected = g_Ep.ThreatsDetected;
    out->ProcessesSuspended = g_Ep.ProcessesSuspended;
    out->SuspendedCount = 0;
    KeReleaseSpinLock(&g_Ep.Lock, irql);
    *info = sizeof(XGS_EP_STATUS);
    return STATUS_SUCCESS;
}

static
NTSTATUS
EpIoctlGetBehavior(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    UINT32 index;
    XGS_EP_BEHAVIOR* out;
    KIRQL irql;

    *info = 0;

    if (inLen < sizeof(UINT32) || outLen < sizeof(XGS_EP_BEHAVIOR))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&index, systemBuffer, sizeof(index));

    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    if (index >= g_Ep.BehaviorCount)
    {
        KeReleaseSpinLock(&g_Ep.Lock, irql);
        return STATUS_NOT_FOUND;
    }
    out = (XGS_EP_BEHAVIOR*)systemBuffer;
    RtlCopyMemory(out, &g_Ep.Behaviors[index], sizeof(XGS_EP_BEHAVIOR));
    KeReleaseSpinLock(&g_Ep.Lock, irql);

    *info = sizeof(XGS_EP_BEHAVIOR);
    return STATUS_SUCCESS;
}

//
// IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN 处理:
// 输入 XGS_EP_BEHAVIOR_CHAIN_REQUEST (PID), 输出该 PID 的全部行为链
// 遍历行为记录环, 按 PID 过滤, 保持时间顺序
//
static
NTSTATUS
EpIoctlGetBehaviorChain(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    XGS_EP_BEHAVIOR_CHAIN_REQUEST* req;
    XGS_EP_BEHAVIOR_CHAIN* out;
    UINT32 targetPid;
    UINT32 count;
    ULONG i;
    KIRQL irql;

    *info = 0;

    if (inLen < sizeof(XGS_EP_BEHAVIOR_CHAIN_REQUEST) ||
        outLen < sizeof(XGS_EP_BEHAVIOR_CHAIN))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (XGS_EP_BEHAVIOR_CHAIN_REQUEST*)systemBuffer;
    targetPid = req->ProcessId;

    if (targetPid == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    out = (XGS_EP_BEHAVIOR_CHAIN*)systemBuffer;
    count = 0;

    KeAcquireSpinLock(&g_Ep.Lock, &irql);

    //
    // 遍历行为记录环, 按 PID 过滤
    // BehaviorHead 指向下一个写入位置, 从最早的记录开始遍历
    //
    {
        UINT32 total = g_Ep.BehaviorCount;
        UINT32 startIdx;

        if (total > XGS_EP_BEHAVIORS_MAX)
        {
            total = XGS_EP_BEHAVIORS_MAX;
        }

        // 环形缓冲区: 若已写满, BehaviorHead 指向最旧记录
        if (g_Ep.BehaviorCount >= XGS_EP_BEHAVIORS_MAX)
        {
            startIdx = g_Ep.BehaviorHead;
        }
        else
        {
            startIdx = 0;
        }

        for (i = 0; i < total && count < XGS_EP_REPORT_BEHAVIORS_MAX; i++)
        {
            UINT32 idx = (startIdx + i) % XGS_EP_BEHAVIORS_MAX;

            if (g_Ep.Behaviors[idx].ProcessId == targetPid)
            {
                RtlCopyMemory(&out->Behaviors[count],
                              &g_Ep.Behaviors[idx],
                              sizeof(XGS_EP_BEHAVIOR));
                count++;
            }
        }
    }

    KeReleaseSpinLock(&g_Ep.Lock, irql);

    out->ProcessId = targetPid;
    out->BehaviorCount = count;

    *info = sizeof(XGS_EP_BEHAVIOR_CHAIN);
    return STATUS_SUCCESS;
}

//=============================================================================
// 控制设备
//=============================================================================
static
NTSTATUS
EpDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
EpDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (systemBuffer == NULL)
    {
        st = STATUS_INVALID_PARAMETER;
    }
    else
    {
        switch (ctl)
        {
        case IOCTL_XGS_EP_AUTH_INIT:
            st = EpIoctlAuthInit(systemBuffer, outLen, &info);
            break;

        case IOCTL_XGS_EP_AUTH_VERIFY:
            st = EpIoctlAuthVerify(systemBuffer, inLen, outLen, &info);
            break;

        case IOCTL_XGS_EP_GET_NOTIFICATION:
            if (!EpIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = EpIoctlGetNotification(systemBuffer, outLen, &info);
            }
            break;

        case IOCTL_XGS_EP_SEND_DECISION:
            if (!EpIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = EpIoctlSendDecision(systemBuffer, inLen, &info);
            }
            break;

        case IOCTL_XGS_EP_GET_STATUS:
            if (!EpIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = EpIoctlGetStatus(systemBuffer, outLen, &info);
            }
            break;

        case IOCTL_XGS_EP_GET_BEHAVIOR:
            if (!EpIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = EpIoctlGetBehavior(systemBuffer, inLen, outLen, &info);
            }
            break;

        case IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN:
            if (!EpIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = EpIoctlGetBehaviorChain(systemBuffer, inLen, outLen, &info);
            }
            break;

        default:
            st = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static
VOID
EpDeleteControlDevice(
    VOID
    )
{
    UNICODE_STRING symlinkName;

    if (g_ControlDevice == NULL)
    {
        return;
    }

    RtlInitUnicodeString(&symlinkName, XGS_EP_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(g_ControlDevice);
    g_ControlDevice = NULL;
}

static
NTSTATUS
EpCreateControlDevice(
    VOID
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT device = NULL;
    NTSTATUS st;

    RtlInitUnicodeString(&deviceName, XGS_EP_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, XGS_EP_SYMLINK_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    st = IoCreateDeviceSecure(g_DriverObject,
                              0,
                              &deviceName,
                              FILE_DEVICE_UNKNOWN,
                              0,
                              FALSE,
                              &sddl,
                              NULL,
                              &device);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: IoCreateDeviceSecure failed 0x%08X\n", st));
        return st;
    }

    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    st = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(st))
    {
        IoDeleteDevice(device);
        KdPrint(("XGSEndPoint: IoCreateSymbolicLink failed 0x%08X\n", st));
        return st;
    }

    g_ControlDevice = device;
    return STATUS_SUCCESS;
}

//=============================================================================
// 驱动卸载
//=============================================================================
VOID
EpUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    KIRQL irql;

    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("XGSEndPoint: Unload\n"));

    //
    // 停止工作线程 (先唤醒处理中的决策)
    //
    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    if (g_Ep.DecisionPending)
    {
        g_Ep.DecisionAllow = TRUE;
        g_Ep.DecisionPending = FALSE;
        KeReleaseSpinLock(&g_Ep.Lock, irql);
        KeSetEvent(&g_Ep.DecisionEvent, IO_NO_INCREMENT, FALSE);
    }
    else
    {
        KeReleaseSpinLock(&g_Ep.Lock, irql);
    }
    g_Ep.WorkerStop = TRUE;
    KeSetEvent(&g_Ep.DecisionEvent, IO_NO_INCREMENT, FALSE);

    //
    // 等待工作线程退出 (确保 pending 的引导写入 IRP 被完成)
    //
    if (g_WorkerThreadObj != NULL)
    {
        KeWaitForSingleObject(g_WorkerThreadObj, Executive,
                              KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThreadObj);
        g_WorkerThreadObj = NULL;
    }

    //
    // 兜底: 清理 pending 状态
    // (不再有 pending IRP, 因为 EpPreWrite 直接 COMPLETE, 不 pend)
    //
    KeAcquireSpinLock(&g_Ep.Lock, &irql);
    g_Ep.BootWritePending = FALSE;
    g_Ep.PendingSuspendPid = 0;
    KeReleaseSpinLock(&g_Ep.Lock, irql);

    if (g_EpFilter != NULL)
    {
        FltUnregisterFilter(g_EpFilter);
        g_EpFilter = NULL;
    }

    if (g_ObRegHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }

    if (g_RegNotifyRegistered)
    {
        CmUnRegisterCallback(g_Cookie);
        g_RegNotifyRegistered = FALSE;
    }

    if (g_ThreadNotifyRegistered)
    {
        PsRemoveCreateThreadNotifyRoutine(EpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
    }

    if (g_LoadImageNotifyRegistered)
    {
        PsRemoveLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
        g_LoadImageNotifyRegistered = FALSE;
    }

    if (g_ProcNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
    }

    EpDeleteControlDevice();
}

//=============================================================================
// DriverEntry
//=============================================================================
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS st;
    POBJECT_TYPE sectionType = NULL;
    OB_CALLBACK_REGISTRATION procCallback;
    OB_CALLBACK_REGISTRATION sectionCallback;
    OB_OPERATION_REGISTRATION procOps[2];
    OB_OPERATION_REGISTRATION sectionOps[1];
    UNICODE_STRING altitude;
    UNICODE_STRING altProc;
    UNICODE_STRING altSection;
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING sectionName;
    LARGE_INTEGER sectionSize;
    HANDLE hWorker = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("XGSEndPoint: DriverEntry\n"));

    g_DriverObject = DriverObject;
    KeInitializeSpinLock(&g_Ep.Lock);
    KeInitializeEvent(&g_Ep.DecisionEvent, NotificationEvent, FALSE);

    //
    // 运行时解析 NtGetNextThread / NtSuspendProcess / NtResumeProcess
    // (ntoskrnl 导出但不在 WDK 导入库中)
    // NtSuspendProcess/NtResumeProcess 为进程级挂起, 优先使用
    //
    {
        UNICODE_STRING apiName;

        RtlInitUnicodeString(&apiName, L"NtGetNextThread");
        g_pNtGetNextThread = (EP_NT_GET_NEXT_THREAD)
            MmGetSystemRoutineAddress(&apiName);

        RtlInitUnicodeString(&apiName, L"NtSuspendProcess");
        g_pNtSuspendProcess = (EP_NT_SUSPEND_PROCESS)
            MmGetSystemRoutineAddress(&apiName);

        RtlInitUnicodeString(&apiName, L"NtResumeProcess");
        g_pNtResumeProcess = (EP_NT_RESUME_PROCESS)
            MmGetSystemRoutineAddress(&apiName);

        RtlInitUnicodeString(&apiName, L"ZwOpenThread");
        g_pZwOpenThread = (EP_PF_ZW_OPEN_THREAD)
            MmGetSystemRoutineAddress(&apiName);

        RtlInitUnicodeString(&apiName, L"ZwSuspendThread");
        g_pZwSuspendThread = (EP_PF_ZW_SUSPEND_THREAD)
            MmGetSystemRoutineAddress(&apiName);

        RtlInitUnicodeString(&apiName, L"ZwResumeThread");
        g_pZwResumeThread = (EP_PF_ZW_RESUME_THREAD)
            MmGetSystemRoutineAddress(&apiName);

        KdPrint(("XGSEndPoint: DynAPI - NtSuspendProcess=%p NtResumeProcess=%p NtGetNextThread=%p ZwOpenThread=%p ZwSuspendThread=%p ZwResumeThread=%p\n",
                 g_pNtSuspendProcess, g_pNtResumeProcess, g_pNtGetNextThread,
                 g_pZwOpenThread, g_pZwSuspendThread, g_pZwResumeThread));
    }

    DriverObject->DriverUnload = EpUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = EpDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = EpDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = EpDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EpDispatchDeviceControl;

    st = EpCreateControlDevice();
    if (!NT_SUCCESS(st))
    {
        return st;
    }

    //
    // 注册进程创建/退出回调
    //
    st = PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", st));
        EpDeleteControlDevice();
        return st;
    }
    g_ProcNotifyRegistered = TRUE;

    //
    // 注册线程创建回调 (远程线程注入)
    //
    st = PsSetCreateThreadNotifyRoutine(EpThreadNotifyCallback);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: PsSetCreateThreadNotifyRoutine failed 0x%08X\n", st));
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
        EpDeleteControlDevice();
        return st;
    }
    g_ThreadNotifyRegistered = TRUE;

    //
    // 注册模块加载回调 (DLL 侧载/非系统模块加载信号)
    // 注册失败不致命, 其余防护继续工作
    //
    st = PsSetLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: PsSetLoadImageNotifyRoutine failed 0x%08X\n", st));
    }
    else
    {
        g_LoadImageNotifyRegistered = TRUE;
    }

    //
    // 注册注册表回调 (自启动项检测)
    //
    RtlInitUnicodeString(&altitude, L"327010");
    st = CmRegisterCallbackEx(EpRegistryCallback, &altitude, g_DriverObject,
                              NULL, &g_Cookie, NULL);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: CmRegisterCallbackEx failed 0x%08X\n", st));
        if (g_LoadImageNotifyRegistered)
        {
            PsRemoveLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
            g_LoadImageNotifyRegistered = FALSE;
        }
        PsRemoveCreateThreadNotifyRoutine(EpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
        EpDeleteControlDevice();
        return st;
    }
    g_RegNotifyRegistered = TRUE;

    //
    // 获取 Section 对象类型 (通过创建临时 Section 对象)
    //
    RtlInitUnicodeString(&sectionName, NULL);
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    sectionSize.QuadPart = 4096;
    st = ZwCreateSection(&hSection, SECTION_MAP_READ, &oa, &sectionSize,
                         PAGE_READONLY, SEC_COMMIT, NULL);
    if (NT_SUCCESS(st))
    {
        PVOID obj = NULL;
        st = ObReferenceObjectByHandle(hSection, SECTION_MAP_READ,
                                       NULL, KernelMode, &obj, NULL);
        if (NT_SUCCESS(st))
        {
            sectionType = ObGetObjectType(obj);
            ObDereferenceObject(obj);
        }
        ZwClose(hSection);
    }

    if (sectionType == NULL)
    {
        KdPrint(("XGSEndPoint: Unable to resolve Section object type\n"));
    }
    else
    {
        //
        // 注册 ObRegisterCallbacks: 进程句柄 (注入/控制) + Section 句柄 (RWX)
        //
        RtlZeroMemory(&procCallback, sizeof(procCallback));
        RtlZeroMemory(&sectionCallback, sizeof(sectionCallback));
        RtlZeroMemory(procOps, sizeof(procOps));
        RtlZeroMemory(sectionOps, sizeof(sectionOps));

        RtlInitUnicodeString(&altProc, L"327020");
        RtlInitUnicodeString(&altSection, L"327030");

        procCallback.Version = OB_FLT_REGISTRATION_VERSION;
        procCallback.OperationRegistrationCount = 1;
        procCallback.Altitude = altProc;
        procCallback.RegistrationContext = NULL;
        procOps[0].ObjectType = PsProcessType;
        procOps[0].Operations = OB_OPERATION_HANDLE_CREATE |
                                OB_OPERATION_HANDLE_DUPLICATE;
        procOps[0].PreOperation = EpProcessPreCallback;
        procOps[0].PostOperation = NULL;
        procCallback.OperationRegistration = procOps;

        st = ObRegisterCallbacks(&procCallback, &g_ObRegHandle);
        if (NT_SUCCESS(st))
        {
            RtlZeroMemory(&sectionCallback, sizeof(sectionCallback));
            RtlZeroMemory(sectionOps, sizeof(sectionOps));

            sectionCallback.Version = OB_FLT_REGISTRATION_VERSION;
            sectionCallback.OperationRegistrationCount = 1;
            sectionCallback.Altitude = altSection;
            sectionCallback.RegistrationContext = NULL;
            sectionOps[0].ObjectType = sectionType;
            sectionOps[0].Operations = OB_OPERATION_HANDLE_CREATE;
            sectionOps[0].PreOperation = EpSectionPreCallback;
            sectionOps[0].PostOperation = NULL;
            sectionCallback.OperationRegistration = sectionOps;

            PVOID sectionRegHandle = NULL;
            st = ObRegisterCallbacks(&sectionCallback, &sectionRegHandle);
            if (NT_SUCCESS(st))
            {
                g_ObRegHandle = sectionRegHandle;   // 记录 (统一注销入口)
                g_ObCallbackRegistered = TRUE;
            }
            else
            {
                KdPrint(("XGSEndPoint: Section ObRegisterCallbacks failed 0x%08X\n", st));
                ObUnRegisterCallbacks(g_ObRegHandle);
                g_ObRegHandle = NULL;
            }
        }
        else
        {
            KdPrint(("XGSEndPoint: Process ObRegisterCallbacks failed 0x%08X\n", st));
        }
    }

    //
    // 启动工作线程 (挂起/恢复/终止)
    //
    g_Ep.WorkerStop = FALSE;
    st = PsCreateSystemThread(&hWorker, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                              EpWorkerRoutine, NULL);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: PsCreateSystemThread failed 0x%08X\n", st));
        if (g_ObRegHandle != NULL)
        {
            ObUnRegisterCallbacks(g_ObRegHandle);
            g_ObRegHandle = NULL;
        }
        CmUnRegisterCallback(g_Cookie);
        g_RegNotifyRegistered = FALSE;
        if (g_LoadImageNotifyRegistered)
        {
            PsRemoveLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
            g_LoadImageNotifyRegistered = FALSE;
        }
        PsRemoveCreateThreadNotifyRoutine(EpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
        EpDeleteControlDevice();
        return st;
    }
    //
    // 保存工作线程对象引用 (卸载时等待退出, 确保 pending IRP 被完成)
    // 必须在 ZwClose 之前引用, 句柄关闭后无法再引用
    //
    st = ObReferenceObjectByHandle(hWorker, THREAD_ALL_ACCESS, NULL,
                                    KernelMode, &g_WorkerThreadObj, NULL);
    if (!NT_SUCCESS(st))
    {
        g_WorkerThreadObj = NULL;
        KdPrint(("XGSEndPoint: ObReferenceObjectByHandle failed 0x%08X\n", st));
    }
    ZwClose(hWorker);

    //
    // 注册 minifilter (文件写入/删除采集)
    //
    st = FltRegisterFilter(DriverObject, &EpReg, &g_EpFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: FltRegisterFilter failed 0x%08X\n", st));
        g_Ep.WorkerStop = TRUE;
        if (g_ObRegHandle != NULL)
        {
            ObUnRegisterCallbacks(g_ObRegHandle);
            g_ObRegHandle = NULL;
        }
        CmUnRegisterCallback(g_Cookie);
        g_RegNotifyRegistered = FALSE;
        if (g_LoadImageNotifyRegistered)
        {
            PsRemoveLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
            g_LoadImageNotifyRegistered = FALSE;
        }
        PsRemoveCreateThreadNotifyRoutine(EpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
        EpDeleteControlDevice();
        return st;
    }

    st = FltStartFiltering(g_EpFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSEndPoint: FltStartFiltering failed 0x%08X\n", st));
        FltUnregisterFilter(g_EpFilter);
        g_EpFilter = NULL;
        g_Ep.WorkerStop = TRUE;
        if (g_ObRegHandle != NULL)
        {
            ObUnRegisterCallbacks(g_ObRegHandle);
            g_ObRegHandle = NULL;
        }
        CmUnRegisterCallback(g_Cookie);
        g_RegNotifyRegistered = FALSE;
        if (g_LoadImageNotifyRegistered)
        {
            PsRemoveLoadImageNotifyRoutine(EpLoadImageNotifyCallback);
            g_LoadImageNotifyRegistered = FALSE;
        }
        PsRemoveCreateThreadNotifyRoutine(EpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
        PsSetCreateProcessNotifyRoutineEx(EpProcessNotifyCallback, TRUE);
        g_ProcNotifyRegistered = FALSE;
        EpDeleteControlDevice();
        return st;
    }

    KdPrint(("XGSEndPoint: DriverEntry completed\n"));
    return STATUS_SUCCESS;
}
