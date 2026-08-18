//=============================================================================
// AVProcessNotify.c - 进程通知回调模块
//
// 使用 PsSetCreateProcessNotifyRoutineEx 拦截系统目录中的进程启动。
// 当检测到受保护目录中的新进程时:
//   1. 检查白名单, 若在白名单中则放行
//   2. 否则拦截进程并通知用户态程序弹窗决策
//
// IRQL: 回调函数运行在 APC_LEVEL, 其余在 PASSIVE_LEVEL
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVProcessNotify.h"
#include <ntstrsafe.h>

//=============================================================================
// 手动声明的内核 API
//
// ZwOpenThread/ZwSuspendThread/ZwResumeThread 为 Zw* 导出, 当前 WDK 头文件
// 未声明 (仅能用于 PASSIVE_LEVEL, 不能在回调中调用);
// PROCESS_TERMINATE/THREAD_SUSPEND_RESUME/THREAD_ALL_ACCESS 内核头文件
// 未定义 (值来自 winnt.h)
//=============================================================================
NTKERNELAPI
NTSTATUS
NTAPI
ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

NTKERNELAPI
NTSTATUS
NTAPI
ZwResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE  0x0001
#endif

#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS     0x001FFFFF
#endif

//=============================================================================
// 全局数据
//=============================================================================

//
// 进程通知回调运行在 APC_LEVEL, 访问的全局数据必须位于非分页内存!
// 普通静态变量在分页段, APC_LEVEL 下页错误会导致系统崩溃。
// 使用 NonPaged 段 (链接器合并到非分页区域)。
//
#pragma section("NonPaged", long, read, write)
#define AV_NON_PAGED __declspec(allocate("NonPaged"))

//
// 受保护系统目录列表 (非分页内存, 初始化后只读)
//
AV_NON_PAGED AV_PROTECTED_DIR g_ProtectedDirs[AV_MAX_PROTECTED_DIRS];
AV_NON_PAGED UINT32           g_ProtectedDirCount = 0;

//
// 白名单路径数组 (受 WDFWAITLOCK 保护, 仅 PASSIVE_LEVEL 写; 回调 APC_LEVEL 读)
//
AV_NON_PAGED static WCHAR      g_AllowList[AV_ALLOW_LIST_MAX][AV_MAX_PROCESS_PATH_LEN];
AV_NON_PAGED static UINT32     g_AllowListCount = 0;
static WDFWAITLOCK g_AllowListLock = NULL;

//
// 黑名单路径数组 (受 WDFWAITLOCK 保护, 仅 PASSIVE_LEVEL 写; 回调 APC_LEVEL 读)
// 黑名单中的进程直接拒绝, 不再弹窗
//
AV_NON_PAGED static WCHAR      g_DenyList[AV_ALLOW_LIST_MAX][AV_MAX_PROCESS_PATH_LEN];
AV_NON_PAGED static UINT32     g_DenyListCount = 0;
static WDFWAITLOCK g_DenyListLock = NULL;

//
// 待处理通知 (单条目, 受 KSPIN_LOCK 保护, 回调在 APC_LEVEL 访问)
//
AV_NON_PAGED static KSPIN_LOCK          g_NotifyLock;
AV_NON_PAGED static AV_PROCESS_NOTIFICATION g_PendingNotify;
AV_NON_PAGED static BOOLEAN             g_HasPendingNotify = FALSE;
AV_NON_PAGED static UINT64              g_NotifyIdCounter = 0;

//
// 进程通知回调句柄
//
AV_NON_PAGED static BOOLEAN g_ProcessNotifyRegistered = FALSE;

//
// 统计计数器 (回调在 APC_LEVEL 递增, 用户态通过 IOCTL_AV_GET_STATUS 读取)
//
AV_NON_PAGED static UINT64   g_CallbackTriggers = 0;
AV_NON_PAGED static UINT64   g_BlockAttempts = 0;
AV_NON_PAGED static UINT64   g_ProtectedHits = 0;
AV_NON_PAGED static UINT64   g_BehaviorTriggers = 0;   // 行为防护规则命中次数

//
// 行为防护规则表 (可疑命令行工具调用)
//
// 在进程创建回调中匹配 CreateInfo->CommandLine (大小写不敏感子串匹配)。
// 命中即按病毒流程处理: 冻结进程 -> 通知用户态弹窗 -> 决策后恢复/终止。
// 测试阶段内置示例规则, 后续可扩展为可配置规则。
//
typedef struct _AV_BEHAVIOR_RULE
{
    PCWSTR Pattern;        // 命令行动作子串 (必须匹配)
    PCWSTR Context;        // 可选上下文子串 (非 NULL 时必须同时匹配, 用于降低误报)
    PCWSTR Description;    // 规则描述 (弹窗展示)
} AV_BEHAVIOR_RULE;

AV_NON_PAGED static const AV_BEHAVIOR_RULE g_BehaviorRules[] =
{
    //
    // 计划任务 / 服务 / 用户管理
    //
    { L"schtasks /create", NULL, L"Create scheduled task" },
    { L"schtasks /change", NULL, L"Modify scheduled task" },
    { L"sc create",        NULL, L"Create service or driver" },
    { L"sc start",         NULL, L"Start service or driver" },
    { L"net user /add",    NULL, L"Add user account" },
    { L"net localgroup administrators /add", NULL, L"Add user to administrators group" },

    //
    // 恶意删除 / 格式化
    //
    { L"del c:\\",         NULL, L"Delete files on C:\\ (malicious delete)" },
    { L"format c:",        NULL, L"Format C: drive" },

    //
    // 启动配置
    //
    { L"bcdedit /set",     NULL, L"Modify boot configuration" },

    //
    // 关闭用户账户控制 (UAC)
    // 恶意软件重启后无管理员权限无法配置自启动,
    // 常通过注册表关闭 UAC (EnableLUA=0) 实现无提示自启动。
    // Context 限定为写入动作 (reg add / Set-ItemProperty),
    // 避免 reg query 等读取操作误报。
    //
    { L"EnableLUA",                  L"reg add",         L"Disable UAC (EnableLUA=0)" },
    { L"EnableLUA",                  L"Set-ItemProperty", L"Disable UAC via PowerShell (EnableLUA=0)" },
    { L"ConsentPromptBehaviorAdmin", L"reg add",         L"Disable UAC consent prompt" },
    { L"PromptOnSecureDesktop",      L"reg add",         L"Disable UAC secure desktop" },
    { L"EnableInstallerDetection",   L"reg add",         L"Disable UAC installer detection" },
};
AV_NON_PAGED static const UINT32 g_BehaviorRuleCount =
    sizeof(g_BehaviorRules) / sizeof(g_BehaviorRules[0]);

//
// 客户端活跃时间戳 (KeQueryTickCount)
// 用户态每次发起 IOCTL 时刷新; 回调检查超时, 超时(约 5 秒)后静默放行
// 避免用户态退出后所有进程创建卡住, 同时不依赖文件对象回调
//
AV_NON_PAGED static volatile ULONGLONG g_LastClientActivityTicks = 0;

//
// 最近处理的进程信息 (调试, 受 g_NotifyLock 保护)
//
AV_NON_PAGED static BOOLEAN  g_LastWasProtected = FALSE;
AV_NON_PAGED static WCHAR    g_LastImagePath[256];

//=============================================================================
// 进程挂起列表 (非分页, 自旋锁保护)
//
// 驱动层"挂起进程"的正确实现:
//   进程创建回调触发时, 新进程的主线程尚未创建, 没有任何线程可挂;
//   内核也没有"挂起整个进程"的导出 API (NtSuspendProcess 是 ntdll 系统
//   调用, 不向驱动导出)。因此采用线程创建回调:
//   进程创建回调把 PID 加入挂起列表 -> 线程创建回调记录该进程的每个
//   新线程 TID -> PASSIVE_LEVEL 工作线程用 ZwSuspendThread 立即挂起。
//   效果: 进程从出生起完全冻结, 窗口不可能出现。
//   用户决策后: 允许 = 恢复所有挂起线程; 拒绝 = ZwTerminateProcess 终止。
//=============================================================================
#define AV_SUSPEND_LIST_MAX     32
#define AV_MAX_TRACKED_THREADS  64

//
// 线程挂起状态机:
//   Pending    - 已记录, 等待工作线程挂起
//   Suspending - 工作线程正在挂起中 (claim, 防止重复处理)
//   Suspended  - 已挂起 (允许时恢复)
//
typedef enum _AV_TID_STATE
{
    AvTidPending = 0,
    AvTidSuspending = 1,
    AvTidSuspended = 2
} AV_TID_STATE;

typedef struct _AV_SUSPEND_ENTRY
{
    BOOLEAN Active;
    UINT32  ProcessId;
    UINT32  ThreadCount;
    AV_TID_STATE ThreadState[AV_MAX_TRACKED_THREADS];
    HANDLE  ThreadIds[AV_MAX_TRACKED_THREADS];
} AV_SUSPEND_ENTRY;

AV_NON_PAGED static AV_SUSPEND_ENTRY g_SuspendList[AV_SUSPEND_LIST_MAX];
AV_NON_PAGED static KSPIN_LOCK       g_SuspendListLock;
AV_NON_PAGED static BOOLEAN          g_ThreadNotifyRegistered = FALSE;

//
// 挂起列表活跃条目数 (线程创建回调对系统每个线程创建都会触发,
// 计数为 0 时直接短路返回, 避免无谓的全局自旋锁竞争)
//
AV_NON_PAGED static volatile LONG    g_SuspendListActiveCount = 0;

//
// 挂起工作线程 (PASSIVE_LEVEL)
// 线程创建回调在 APC_LEVEL 不能调用 Zw*, 因此由本工作线程轮询挂起列表,
// 用 ZwOpenThread/ZwSuspendThread 挂起新记录的线程
//
AV_NON_PAGED static BOOLEAN  g_SuspendWorkerStop = FALSE;
AV_NON_PAGED static HANDLE   g_SuspendWorkerHandle = NULL;

//=============================================================================
// 受保护目录初始化
//=============================================================================
// IRQL: PASSIVE_LEVEL

static
VOID
AvpInitProtectedDirs(
    VOID
    )
{
    UINT32 i = 0;

    PAGED_CODE();

    //
    // 初始化受保护目录列表
    // 测试阶段: 排除系统目录 (\Windows\*), 拦截应用/用户目录
    //   - Program Files / Program Files (x86): 应用目录
    //   - \Desktop\ / \Downloads\: 用户桌面与下载目录
    //
    RtlZeroMemory(g_ProtectedDirs, sizeof(g_ProtectedDirs));

    //
    // 受保护目录使用子串匹配 (不依赖 \??\C: 前缀格式),
    // 覆盖 \??\C:\... 与 \Device\HarddiskVolumeN\... 等
    // 全部镜像路径格式
    //

    // "\Program Files\"
    g_ProtectedDirs[i].Active = TRUE;
    RtlStringCbCopyW(g_ProtectedDirs[i].DirectoryPath,
                     sizeof(g_ProtectedDirs[i].DirectoryPath),
                     L"\\Program Files\\");
    RtlStringCbLengthW(g_ProtectedDirs[i].DirectoryPath,
                       sizeof(g_ProtectedDirs[i].DirectoryPath),
                       &g_ProtectedDirs[i].PathLength);
    g_ProtectedDirs[i].PathLength /= sizeof(WCHAR);
    i++;

    // "\Program Files (x86)\"
    g_ProtectedDirs[i].Active = TRUE;
    RtlStringCbCopyW(g_ProtectedDirs[i].DirectoryPath,
                     sizeof(g_ProtectedDirs[i].DirectoryPath),
                     L"\\Program Files (x86)\\");
    RtlStringCbLengthW(g_ProtectedDirs[i].DirectoryPath,
                       sizeof(g_ProtectedDirs[i].DirectoryPath),
                       &g_ProtectedDirs[i].PathLength);
    g_ProtectedDirs[i].PathLength /= sizeof(WCHAR);
    i++;

    // "\Desktop\" (任意用户的桌面)
    g_ProtectedDirs[i].Active = TRUE;
    RtlStringCbCopyW(g_ProtectedDirs[i].DirectoryPath,
                     sizeof(g_ProtectedDirs[i].DirectoryPath),
                     L"\\Desktop\\");
    RtlStringCbLengthW(g_ProtectedDirs[i].DirectoryPath,
                       sizeof(g_ProtectedDirs[i].DirectoryPath),
                       &g_ProtectedDirs[i].PathLength);
    g_ProtectedDirs[i].PathLength /= sizeof(WCHAR);
    i++;

    // "\Downloads\" (任意用户的下载目录)
    g_ProtectedDirs[i].Active = TRUE;
    RtlStringCbCopyW(g_ProtectedDirs[i].DirectoryPath,
                     sizeof(g_ProtectedDirs[i].DirectoryPath),
                     L"\\Downloads\\");
    RtlStringCbLengthW(g_ProtectedDirs[i].DirectoryPath,
                       sizeof(g_ProtectedDirs[i].DirectoryPath),
                       &g_ProtectedDirs[i].PathLength);
    g_ProtectedDirs[i].PathLength /= sizeof(WCHAR);
    i++;

    g_ProtectedDirCount = i;
}

//=============================================================================
// 挂起列表辅助函数
// IRQL: APC_LEVEL (回调中) 或 PASSIVE_LEVEL
//=============================================================================

//
// AvpIsInSuspendList - 检查 PID 是否在挂起列表中
//
static
BOOLEAN
AvpIsInSuspendList(
    _In_ UINT32 ProcessId
    )
{
    UINT32 i;

    for (i = 0; i < AV_SUSPEND_LIST_MAX; i++)
    {
        if (g_SuspendList[i].Active && g_SuspendList[i].ProcessId == ProcessId)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//
// AvpAddToSuspendList - 把 PID 加入挂起列表
// 进程创建回调 (APC_LEVEL) 中调用, 自旋锁保护
//
static
VOID
AvpAddToSuspendList(
    _In_ UINT32 ProcessId
    )
{
    KIRQL irql;
    UINT32 i;

    KeAcquireSpinLock(&g_SuspendListLock, &irql);

    if (AvpIsInSuspendList(ProcessId))
    {
        KeReleaseSpinLock(&g_SuspendListLock, irql);
        return;
    }

    for (i = 0; i < AV_SUSPEND_LIST_MAX; i++)
    {
        if (!g_SuspendList[i].Active)
        {
            g_SuspendList[i].Active = TRUE;
            g_SuspendList[i].ProcessId = ProcessId;
            g_SuspendList[i].ThreadCount = 0;
            InterlockedIncrement(&g_SuspendListActiveCount);
            KeReleaseSpinLock(&g_SuspendListLock, irql);
            return;
        }
    }

    KeReleaseSpinLock(&g_SuspendListLock, irql);
    KdPrint(("AVProcess: Suspend list full, PID %u not tracked!\n", ProcessId));
}

//
// AvpThreadNotifyCallback - 线程创建/退出回调
// IRQL: PASSIVE_LEVEL 或 APC_LEVEL
//
// 若线程所属进程在挂起列表中, 记录该线程 TID,
// 由 PASSIVE_LEVEL 挂起工作线程 (AvpSuspendWorkerRoutine) 立即挂起。
// 新线程在创建回调返回后才会被调度, 因此挂起发生在它运行任何指令之前,
// 整个进程从出生起完全冻结。
//
static
VOID
AvpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    UINT32 pid;
    UINT32 i;
    KIRQL irql;

    //
    // 只处理线程创建, 忽略线程退出
    //
    if (!Create)
    {
        return;
    }

    //
    // 无被拦截进程时直接短路 (系统每个线程创建都会触发本回调)
    //
    if (g_SuspendListActiveCount == 0)
    {
        return;
    }

    pid = (UINT32)(ULONG_PTR)ProcessId;

    KeAcquireSpinLock(&g_SuspendListLock, &irql);

    for (i = 0; i < AV_SUSPEND_LIST_MAX; i++)
    {
        if (g_SuspendList[i].Active && g_SuspendList[i].ProcessId == pid)
        {
            //
            // 记录 TID, 交给工作线程挂起 (回调在 APC_LEVEL 不能调 Zw*)
            //
            if (g_SuspendList[i].ThreadCount < AV_MAX_TRACKED_THREADS)
            {
                UINT32 idx = g_SuspendList[i].ThreadCount;
                g_SuspendList[i].ThreadIds[idx] = ThreadId;
                g_SuspendList[i].ThreadState[idx] = AvTidPending;
                g_SuspendList[i].ThreadCount++;
            }
            else
            {
                KdPrint(("AVProcess: Too many threads for PID %u, TID %lu untracked\n",
                         pid, (ULONG)(ULONG_PTR)ThreadId));
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_SuspendListLock, irql);
}

//=============================================================================
// 挂起工作线程
// IRQL: PASSIVE_LEVEL (系统线程)
//
// 轮询挂起列表, 用 ZwOpenThread/ZwSuspendThread 挂起所有
// AvTidPending 状态的线程。线程回调在 APC_LEVEL 不能调用 Zw*,
// 必须由本工作线程在 PASSIVE_LEVEL 完成挂起。
//=============================================================================
static
VOID
AvpSuspendWorkerRoutine(
    _In_ PVOID Context
    )
{
    LARGE_INTEGER delay;
    UNREFERENCED_PARAMETER(Context);

    //
    // 轮询间隔 2ms
    //
    delay.QuadPart = -20000;   // 100ns 单位

    while (!g_SuspendWorkerStop)
    {
        HANDLE  pendingTids[AV_MAX_TRACKED_THREADS];
        UINT32  pendingCount = 0;
        KIRQL   irql;
        UINT32  i, j;

        KeAcquireSpinLock(&g_SuspendListLock, &irql);

        //
        // Phase 1: 认领所有 AvTidPending 的线程 (置 AvTidSuspending)
        //
        if (g_SuspendListActiveCount > 0)
        {
            for (i = 0; i < AV_SUSPEND_LIST_MAX && pendingCount < AV_MAX_TRACKED_THREADS; i++)
            {
                if (!g_SuspendList[i].Active)
                {
                    continue;
                }

                for (j = 0; j < g_SuspendList[i].ThreadCount && pendingCount < AV_MAX_TRACKED_THREADS; j++)
                {
                    if (g_SuspendList[i].ThreadState[j] == AvTidPending)
                    {
                        g_SuspendList[i].ThreadState[j] = AvTidSuspending;
                        pendingTids[pendingCount++] = g_SuspendList[i].ThreadIds[j];
                    }
                }
            }
        }

        KeReleaseSpinLock(&g_SuspendListLock, irql);

        //
        // Phase 2: 逐个挂起 (PASSIVE_LEVEL, Zw* 安全)
        //
        for (i = 0; i < pendingCount; i++)
        {
            HANDLE hThread = NULL;
            OBJECT_ATTRIBUTES oa;
            CLIENT_ID cid;
            BOOLEAN suspended = FALSE;

            InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
            cid.UniqueProcess = NULL;
            cid.UniqueThread = pendingTids[i];

            if (NT_SUCCESS(ZwOpenThread(&hThread, THREAD_SUSPEND_RESUME, &oa, &cid)))
            {
                if (NT_SUCCESS(ZwSuspendThread(hThread, NULL)))
                {
                    suspended = TRUE;
                }
                ZwClose(hThread);
            }

            //
            // Phase 3: 回写状态
            // 若条目已被移除 (用户已选"允许"并恢复了进程), 撤销本次挂起
            //
            KeAcquireSpinLock(&g_SuspendListLock, &irql);

            BOOLEAN entryFound = FALSE;
            for (j = 0; j < AV_SUSPEND_LIST_MAX; j++)
            {
                UINT32 k;
                if (!g_SuspendList[j].Active)
                {
                    continue;
                }
                for (k = 0; k < g_SuspendList[j].ThreadCount; k++)
                {
                    if (g_SuspendList[j].ThreadIds[k] == pendingTids[i] &&
                        g_SuspendList[j].ThreadState[k] == AvTidSuspending)
                    {
                        entryFound = TRUE;
                        g_SuspendList[j].ThreadState[k] = AvTidSuspended;
                        break;
                    }
                }
                if (entryFound)
                {
                    break;
                }
            }

            KeReleaseSpinLock(&g_SuspendListLock, irql);

            if (!entryFound && suspended)
            {
                //
                // 条目已被移除 (允许先到): 撤销挂起, 避免线程永久冻结
                //
                ZwResumeThread(pendingTids[i], NULL);
                KdPrint(("AVProcess: Undid late suspend of TID %lu\n",
                         (ULONG)(ULONG_PTR)pendingTids[i]));
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// AvpResumeSuspendedThreads - 恢复进程的所有挂起线程
// 用户选择"允许"时由决策处理调用, IRQL: PASSIVE_LEVEL
//
static
VOID
AvpResumeSuspendedThreads(
    _In_ UINT32 ProcessId
    )
{
    KIRQL irql;
    UINT32 i;
    HANDLE tids[AV_MAX_TRACKED_THREADS];
    UINT32 tidCount = 0;

    KeAcquireSpinLock(&g_SuspendListLock, &irql);

    for (i = 0; i < AV_SUSPEND_LIST_MAX; i++)
    {
        if (g_SuspendList[i].Active && g_SuspendList[i].ProcessId == ProcessId)
        {
            UINT32 j;

            //
            // 只收集真正已挂起 (AvTidSuspended) 的线程
            //
            for (j = 0; j < g_SuspendList[i].ThreadCount && tidCount < AV_MAX_TRACKED_THREADS; j++)
            {
                if (g_SuspendList[i].ThreadState[j] == AvTidSuspended)
                {
                    tids[tidCount++] = g_SuspendList[i].ThreadIds[j];
                }
            }

            g_SuspendList[i].Active = FALSE;
            g_SuspendList[i].ProcessId = 0;
            g_SuspendList[i].ThreadCount = 0;
            InterlockedDecrement(&g_SuspendListActiveCount);
            break;
        }
    }

    KeReleaseSpinLock(&g_SuspendListLock, irql);

    //
    // 恢复所有已挂起的线程 (线程可能已退出, 忽略失败)
    //
    for (i = 0; i < tidCount; i++)
    {
        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = NULL;
        cid.UniqueThread = tids[i];

        if (NT_SUCCESS(ZwOpenThread(&hThread, THREAD_SUSPEND_RESUME, &oa, &cid)))
        {
            ZwResumeThread(hThread, NULL);
            ZwClose(hThread);
        }
    }

    if (tidCount > 0)
    {
        KdPrint(("AVProcess: Resumed %u threads of PID %u\n", tidCount, ProcessId));
    }
}

//
// AvpTerminateProcessById - 通过 Zw 终止进程
// 用户选择"拒绝"时由决策处理调用, IRQL: PASSIVE_LEVEL
//
static
NTSTATUS
AvpTerminateProcessById(
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
        KdPrint(("AVProcess: ZwOpenProcess(PID %u) failed 0x%08X\n", ProcessId, status));
        return status;
    }

    status = ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
    ZwClose(hProcess);

    KdPrint(("AVProcess: ZwTerminateProcess(PID %u) status 0x%08X\n", ProcessId, status));
    return status;
}

//=============================================================================
// AvpMatchBehaviorRule - 匹配行为防护命令行规则
// IRQL: APC_LEVEL
//
// 对进程创建回调中的命令行做大小写不敏感的子串匹配。
// 命中返回规则描述 (弹窗展示), 未命中返回 NULL。
//=============================================================================

//
// AvpContainsSubstring 定义在文件后部, 此处前向声明
//
static
BOOLEAN
AvpContainsSubstring(
    _In_ const UNICODE_STRING* Haystack,
    _In_ PCWSTR Needle,
    _In_ SIZE_T NeedleChars
    );

//
// AvpMatchRuleText - 命令行规则文本匹配 (容忍可执行文件名扩展名)
// IRQL: APC_LEVEL
//
// 直接匹配 (如 "schtasks /create") 或第一段后带 ".exe" 的变体
// (如 "schtasks.exe /create" / "C:\...\schtasks.exe /create")。
// PowerShell/cmd 启动工具时常带 .exe 扩展名或完整路径,
// 仅匹配 "schtasks /create" 会漏掉这些情况。
//
static
BOOLEAN
AvpMatchRuleText(
    _In_ const UNICODE_STRING* CommandLine,
    _In_ PCWSTR Text
    )
{
    WCHAR variant[128];
    SIZE_T textChars;
    SIZE_T firstSpace;

    if (Text == NULL || Text[0] == L'\0')
    {
        return FALSE;
    }

    textChars = wcslen(Text);

    //
    // 直接匹配
    //
    if (AvpContainsSubstring(CommandLine, Text, textChars))
    {
        return TRUE;
    }

    //
    // 生成变体: "schtasks /create" -> "schtasks.exe /create"
    //
    firstSpace = 0;
    while (firstSpace < textChars &&
           Text[firstSpace] != L' ' && Text[firstSpace] != L'\t')
    {
        firstSpace++;
    }

    if (firstSpace > 0 && firstSpace < textChars && firstSpace + 4 < 128)
    {
        RtlCopyMemory(variant, Text, firstSpace * sizeof(WCHAR));
        RtlCopyMemory(variant + firstSpace, L".exe", 4 * sizeof(WCHAR));
        RtlCopyMemory(variant + firstSpace + 4, Text + firstSpace,
                      (textChars - firstSpace) * sizeof(WCHAR));
        variant[firstSpace + 4 + (textChars - firstSpace)] = L'\0';

        if (AvpContainsSubstring(CommandLine, variant, textChars + 4))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static
PCWSTR
AvpMatchBehaviorRule(
    _In_opt_ const UNICODE_STRING* CommandLine
    )
{
    UINT32 i;

    if (CommandLine == NULL || CommandLine->Buffer == NULL ||
        CommandLine->Length == 0)
    {
        return NULL;
    }

    for (i = 0; i < g_BehaviorRuleCount; i++)
    {
        //
        // 匹配动作 (容忍 ".exe" 扩展名变体)
        //
        if (AvpMatchRuleText(CommandLine, g_BehaviorRules[i].Pattern))
        {
            //
            // 规则带上下文时, 上下文必须同时匹配
            // (例如 EnableLUA 需配合 reg add, 避免 reg query 误报)
            //
            if (g_BehaviorRules[i].Context != NULL &&
                !AvpMatchRuleText(CommandLine, g_BehaviorRules[i].Context))
            {
                continue;   // 上下文不匹配, 检查下一条规则
            }

            return g_BehaviorRules[i].Description;
        }
    }

    return NULL;
}

//=============================================================================
// 进程通知回调函数
// IRQL: APC_LEVEL
//
// 当有新进程创建或进程退出时被调用。
// CreateInfo != NULL = 进程创建, CreateInfo == NULL = 进程退出
//=============================================================================

static
VOID
AvpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    //
    // 忽略进程退出事件
    //
    if (CreateInfo == NULL)
    {
        return;
    }

    //
    // 忽略受信任的系统进程 (如 smss.exe 的子进程)
    // CreatingThreadId.UniqueProcess == NULL 表示是系统创建的进程
    //
    if (CreateInfo->CreatingThreadId.UniqueProcess == NULL ||
        CreateInfo->ImageFileName == NULL)
    {
        return;
    }

    //
    // 无活跃用户态客户端时静默放行
    // (用户态已退出/未连接, 无人处理决策, 拦截会导致进程创建卡 30 秒)
    //
    if (!AvProcessIsClientActive())
    {
        return;
    }

    //
    // 统计回调触发次数
    //
    InterlockedIncrement64((PLONG64)&g_CallbackTriggers);

    //
    // 记录最近处理的进程路径 (调试用)
    //
    KIRQL debugIrql;
    KeAcquireSpinLock(&g_NotifyLock, &debugIrql);
    {
        SIZE_T copyBytes = min(CreateInfo->ImageFileName->Length,
                               sizeof(g_LastImagePath) - sizeof(WCHAR));
        RtlCopyMemory(g_LastImagePath, CreateInfo->ImageFileName->Buffer, copyBytes);
        g_LastImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
        g_LastWasProtected = FALSE;
    }
    KeReleaseSpinLock(&g_NotifyLock, debugIrql);

    //
    // 判断拦截原因: 目录保护 / 行为防护 (可疑命令行)
    //
    UINT32 blockReason = AvBlockReasonNone;
    WCHAR ruleDescription[128];
    RtlZeroMemory(ruleDescription, sizeof(ruleDescription));

    if (AvProcessIsPathProtected(CreateInfo->ImageFileName))
    {
        //
        // 命中受保护目录
        //
        InterlockedIncrement64((PLONG64)&g_ProtectedHits);
        KeAcquireSpinLock(&g_NotifyLock, &debugIrql);
        g_LastWasProtected = TRUE;
        KeReleaseSpinLock(&g_NotifyLock, debugIrql);
        blockReason = AvBlockReasonPathProtect;
    }
    else
    {
        //
        // 行为防护: 匹配可疑命令行工具调用 (schtasks / sc / 恶意 del 等)
        //
        PCWSTR matchedDesc = AvpMatchBehaviorRule(CreateInfo->CommandLine);
        if (matchedDesc != NULL)
        {
            InterlockedIncrement64((PLONG64)&g_BehaviorTriggers);
            RtlStringCbCopyW(ruleDescription, sizeof(ruleDescription), matchedDesc);
            blockReason = AvBlockReasonBehaviorCmdline;
            KdPrint(("AVProcess: Behavior rule matched (%ws), PID %lu\n",
                     matchedDesc, (ULONG)(ULONG_PTR)ProcessId));
        }
    }

    //
    // 全拦截模式: 所有进程启动都通知用户态裁决
    // (主程序引擎自行决策, 驱动仅负责挂起并询问)
    //
    if (blockReason == AvBlockReasonNone)
    {
        blockReason = AvBlockReasonPathProtect;
    }

    //
    // 检查黑名单: 黑名单中的进程直接拒绝, 不再弹窗
    //
    if (AvProcessIsInDenyList(CreateInfo->ImageFileName))
    {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        KdPrint(("AVProcess: Denied by blacklist: %wZ\n", CreateInfo->ImageFileName));
        return;
    }

    //
    // 检查白名单
    //
    if (AvProcessIsInAllowList(CreateInfo->ImageFileName))
    {
        return; // 在白名单中, 放行
    }

    //
    // 拦截进程! 填充通知信息
    //
    AV_PROCESS_NOTIFICATION notify;
    RtlZeroMemory(&notify, sizeof(notify));
    notify.HasPending = TRUE;
    notify.ProcessId = (UINT32)(ULONG_PTR)ProcessId;
    notify.ParentProcessId = (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;
    notify.BlockReason = blockReason;
    if (ruleDescription[0] != L'\0')
    {
        RtlStringCbCopyW(notify.RuleDescription, sizeof(notify.RuleDescription),
                         ruleDescription);
    }

    //
    // 复制镜像路径 (并强制 null 终止, 内核 UNICODE_STRING 不保证 null 终止)
    //
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL)
    {
        SIZE_T copyBytes = min(CreateInfo->ImageFileName->Length,
                               sizeof(notify.ImagePath) - sizeof(WCHAR));
        RtlCopyMemory(notify.ImagePath, CreateInfo->ImageFileName->Buffer, copyBytes);
        notify.ImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    //
    // 复制命令行 (并强制 null 终止)
    //
    if (CreateInfo->CommandLine != NULL &&
        CreateInfo->CommandLine->Buffer != NULL)
    {
        SIZE_T copyBytes = min(CreateInfo->CommandLine->Length,
                               sizeof(notify.CommandLine) - sizeof(WCHAR));
        RtlCopyMemory(notify.CommandLine, CreateInfo->CommandLine->Buffer, copyBytes);
        notify.CommandLine[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    //
    // 原子递增通知 ID
    //
    notify.NotificationId = InterlockedIncrement64((PLONG64)&g_NotifyIdCounter);

    //
    // 将通知存入待处理队列 (自旋锁保护, APC_LEVEL 安全)
    //
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_NotifyLock, &oldIrql);

    RtlCopyMemory(&g_PendingNotify, &notify, sizeof(g_PendingNotify));
    g_HasPendingNotify = TRUE;

    KeReleaseSpinLock(&g_NotifyLock, oldIrql);

    //
    // 加入挂起列表: 线程创建回调会立刻挂起该进程的每一个线程
    // (在它们运行第一条指令之前), 进程从出生起完全冻结,
    // 窗口不可能出现, 等待用户决策
    //
    AvpAddToSuspendList((UINT32)(ULONG_PTR)ProcessId);

    //
    // 统计拦截尝试次数
    //
    InterlockedIncrement64((PLONG64)&g_BlockAttempts);

    KdPrint(("AVProcess: Blocked attempt PID %lu: %wZ\n",
             (ULONG)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName));

    //
    // 注意: 回调不阻塞进程创建, 立即返回。
    // 该进程已被加入挂起列表, 其所有线程由挂起工作线程在出生后立即冻结,
    // 等待用户态通过 IOCTL 送来决策 (允许=恢复, 拒绝=ZwTerminateProcess)
    //
    return;
}

//=============================================================================
// AvProcessNotifyInitialize - 初始化进程通知模块
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvProcessNotifyInitialize(
    VOID
    )
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES wdfAttributes;

    PAGED_CODE();

    KdPrint(("AVProcess: Initializing process notification\n"));

    //
    // 初始化受保护目录
    //
    AvpInitProtectedDirs();

    //
    // 初始化通知自旋锁
    //
    KeInitializeSpinLock(&g_NotifyLock);
    RtlZeroMemory(&g_PendingNotify, sizeof(g_PendingNotify));
    g_HasPendingNotify = FALSE;
    g_NotifyIdCounter = 0;
    g_BehaviorTriggers = 0;

    //
    // 初始化挂起列表 (驱动层冻结被拦截进程)
    //
    KeInitializeSpinLock(&g_SuspendListLock);
    RtlZeroMemory(g_SuspendList, sizeof(g_SuspendList));

    //
    // 创建白名单锁
    //
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &g_AllowListLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVProcess: WdfWaitLockCreate failed 0x%08X\n", status));
        return status;
    }

    g_AllowListCount = 0;
    RtlZeroMemory(g_AllowList, sizeof(g_AllowList));

    //
    // 创建黑名单锁
    //
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &g_DenyListLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVProcess: WdfWaitLockCreate(DenyList) failed 0x%08X\n", status));
        return status;
    }

    g_DenyListCount = 0;
    RtlZeroMemory(g_DenyList, sizeof(g_DenyList));

    //
    // 注册进程通知回调
    //
    status = PsSetCreateProcessNotifyRoutineEx(AvpProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVProcess: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status));
        return status;
    }

    g_ProcessNotifyRegistered = TRUE;

    //
    // 注册线程创建回调: 用于在进程出生时挂起其所有线程
    //
    status = PsSetCreateThreadNotifyRoutine(AvpThreadNotifyCallback);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVProcess: PsSetCreateThreadNotifyRoutine failed 0x%08X\n", status));
        return status;
    }

    g_ThreadNotifyRegistered = TRUE;

    //
    // 启动挂起工作线程 (PASSIVE_LEVEL)
    // 在回调中只能记录 TID (APC_LEVEL 不能调 Zw*), 由本工作线程挂起
    //
    g_SuspendWorkerStop = FALSE;
    status = PsCreateSystemThread(
        &g_SuspendWorkerHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        AvpSuspendWorkerRoutine,
        NULL
        );
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVProcess: PsCreateSystemThread failed 0x%08X\n", status));
        return status;
    }

    KdPrint(("AVProcess: Initialized successfully (%u protected dirs)\n", g_ProtectedDirCount));

    return STATUS_SUCCESS;
}

//=============================================================================
// AvProcessNotifyUninitialize - 卸载进程通知模块
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvProcessNotifyUninitialize(
    VOID
    )
{
    PAGED_CODE();

    KdPrint(("AVProcess: Uninitializing process notification\n"));

    //
    // 注销进程通知回调
    //
    if (g_ProcessNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(AvpProcessNotifyCallback, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    //
    // 注销线程创建回调 (等待正在执行的回调退出)
    //
    if (g_ThreadNotifyRegistered)
    {
        PsRemoveCreateThreadNotifyRoutine(AvpThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
    }

    //
    // 停止挂起工作线程并等待其退出
    // (工作线程可能正在 PASSIVE_LEVEL 执行 Zw* 挂起, 必须等它结束)
    //
    g_SuspendWorkerStop = TRUE;
    if (g_SuspendWorkerHandle != NULL)
    {
        KeWaitForSingleObject(g_SuspendWorkerHandle, Executive, KernelMode, FALSE, NULL);
        ZwClose(g_SuspendWorkerHandle);
        g_SuspendWorkerHandle = NULL;
    }

    //
    // 卸载前恢复所有被挂起的进程, 避免进程永久冻结
    //
    {
        UINT32 pids[AV_SUSPEND_LIST_MAX];
        UINT32 pidCount = 0;
        KIRQL irql;
        UINT32 i;

        KeAcquireSpinLock(&g_SuspendListLock, &irql);
        for (i = 0; i < AV_SUSPEND_LIST_MAX; i++)
        {
            if (g_SuspendList[i].Active)
            {
                pids[pidCount++] = g_SuspendList[i].ProcessId;
            }
        }
        KeReleaseSpinLock(&g_SuspendListLock, irql);

        for (i = 0; i < pidCount; i++)
        {
            AvpResumeSuspendedThreads(pids[i]);
        }
    }

    //
    // 清理状态
    //
    RtlZeroMemory(&g_PendingNotify, sizeof(g_PendingNotify));
    g_HasPendingNotify = FALSE;
    g_AllowListCount = 0;

    KdPrint(("AVProcess: Uninitialized\n"));
}

//=============================================================================
// AvpContainsSubstring - 大小写不敏感的子串搜索
// IRQL: APC_LEVEL 或 PASSIVE_LEVEL
//
// 基于 UNICODE_STRING.Length 搜索, 不依赖 null 终止符, 纯内存操作
//=============================================================================

static
BOOLEAN
AvpContainsSubstring(
    _In_ const UNICODE_STRING* Haystack,
    _In_ PCWSTR Needle,
    _In_ SIZE_T NeedleChars
    )
{
    SIZE_T hayChars;
    SIZE_T i;
    SIZE_T j;

    if (Haystack == NULL || Haystack->Buffer == NULL || Needle == NULL)
    {
        return FALSE;
    }

    hayChars = Haystack->Length / sizeof(WCHAR);

    if (NeedleChars == 0 || hayChars < NeedleChars)
    {
        return FALSE;
    }

    for (i = 0; i + NeedleChars <= hayChars; i++)
    {
        for (j = 0; j < NeedleChars; j++)
        {
            if (RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]) !=
                RtlUpcaseUnicodeChar(Needle[j]))
            {
                break;
            }
        }

        if (j == NeedleChars)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//=============================================================================
// AvProcessIsPathProtected - 检查路径是否在受保护目录中
// IRQL: APC_LEVEL (回调中) 或 PASSIVE_LEVEL
//
// 使用子串匹配, 覆盖 \??\C:\Windows\... 与 \Device\HarddiskVolumeN\Windows\...
// 等各种镜像路径格式
//=============================================================================

BOOLEAN
AvProcessIsPathProtected(
    _In_ const UNICODE_STRING* ImageFileName
    )
{
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL ||
        ImageFileName->Length == 0)
    {
        return FALSE;
    }

    //
    // 硬编码受保护目录子串匹配 (大小写不敏感)
    // 使用编译期常量, 不依赖任何全局数组/段初始化
    // 测试阶段排除系统目录 (\Windows\*), 拦截应用/用户目录:
    //   Program Files / Program Files (x86) / 桌面 / 下载
    //
    if (AvpContainsSubstring(ImageFileName,
                             L"\\Program Files\\",
                             (sizeof(L"\\Program Files\\") / sizeof(WCHAR)) - 1) ||
        AvpContainsSubstring(ImageFileName,
                             L"\\Program Files (x86)\\",
                             (sizeof(L"\\Program Files (x86)\\") / sizeof(WCHAR)) - 1) ||
        AvpContainsSubstring(ImageFileName,
                             L"\\Desktop\\",
                             (sizeof(L"\\Desktop\\") / sizeof(WCHAR)) - 1) ||
        AvpContainsSubstring(ImageFileName,
                             L"\\Downloads\\",
                             (sizeof(L"\\Downloads\\") / sizeof(WCHAR)) - 1))
    {
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// AvProcessAddToAllowList - 添加路径到白名单
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvProcessAddToAllowList(
    _In_ const WCHAR* ImagePath
    )
{
    PAGED_CODE();

    if (ImagePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WdfWaitLockAcquire(g_AllowListLock, NULL);

    //
    // 检查是否已存在
    //
    UINT32 i;
    for (i = 0; i < g_AllowListCount; i++)
    {
        if (_wcsicmp(g_AllowList[i], ImagePath) == 0)
        {
            WdfWaitLockRelease(g_AllowListLock);
            return STATUS_SUCCESS; // 已存在
        }
    }

    //
    // 检查数组是否已满
    //
    if (g_AllowListCount >= AV_ALLOW_LIST_MAX)
    {
        WdfWaitLockRelease(g_AllowListLock);
        return STATUS_TOO_MANY_SESSIONS;
    }

    //
    // 添加到白名单
    //
    RtlStringCbCopyW(g_AllowList[g_AllowListCount],
                     sizeof(g_AllowList[g_AllowListCount]),
                     ImagePath);
    g_AllowListCount++;

    KdPrint(("AVProcess: Added to allow list [%u]: %ws\n",
             g_AllowListCount - 1, ImagePath));

    WdfWaitLockRelease(g_AllowListLock);
    return STATUS_SUCCESS;
}

//=============================================================================
// AvProcessAddToDenyList - 添加路径到黑名单
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvProcessAddToDenyList(
    _In_ const WCHAR* ImagePath
    )
{
    PAGED_CODE();

    if (ImagePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WdfWaitLockAcquire(g_DenyListLock, NULL);

    //
    // 检查是否已存在
    //
    UINT32 i;
    for (i = 0; i < g_DenyListCount; i++)
    {
        if (_wcsicmp(g_DenyList[i], ImagePath) == 0)
        {
            WdfWaitLockRelease(g_DenyListLock);
            return STATUS_SUCCESS; // 已存在
        }
    }

    //
    // 检查数组是否已满
    //
    if (g_DenyListCount >= AV_ALLOW_LIST_MAX)
    {
        WdfWaitLockRelease(g_DenyListLock);
        return STATUS_TOO_MANY_SESSIONS;
    }

    //
    // 添加到黑名单
    //
    RtlStringCbCopyW(g_DenyList[g_DenyListCount],
                     sizeof(g_DenyList[g_DenyListCount]),
                     ImagePath);
    g_DenyListCount++;

    KdPrint(("AVProcess: Added to deny list [%u]: %ws\n",
             g_DenyListCount - 1, ImagePath));

    WdfWaitLockRelease(g_DenyListLock);
    return STATUS_SUCCESS;
}

//=============================================================================
// AvProcessIsInAllowList - 检查路径是否在白名单中
// IRQL: APC_LEVEL 或 PASSIVE_LEVEL
//=============================================================================

BOOLEAN
AvProcessIsInAllowList(
    _In_ const UNICODE_STRING* ImageFileName
    )
{
    UINT32 i;
    SIZE_T imageChars;
    SIZE_T allowChars;

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL)
    {
        return FALSE;
    }

    imageChars = ImageFileName->Length / sizeof(WCHAR);

    //
    // 遍历白名单, 精确匹配 (忽略大小写)
    // 注意: 在 APC_LEVEL (回调中) 调用, 不能使用 WdfWaitLock,
    //       这里直接遍历只读数组 (允许临时不一致)
    //
    UINT32 count = g_AllowListCount;
    for (i = 0; i < count; i++)
    {
        //
        // g_AllowList 条目以 null 终止, 用 wcslen 获取长度后精确比较
        //
        allowChars = wcslen(g_AllowList[i]);

        if (imageChars == allowChars &&
            _wcsnicmp(g_AllowList[i], ImageFileName->Buffer, allowChars) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//=============================================================================
// AvProcessIsInDenyList - 检查路径是否在黑名单中
// IRQL: APC_LEVEL 或 PASSIVE_LEVEL
//=============================================================================

BOOLEAN
AvProcessIsInDenyList(
    _In_ const UNICODE_STRING* ImageFileName
    )
{
    UINT32 i;
    SIZE_T imageChars;
    SIZE_T denyChars;

    if (ImageFileName == NULL || ImageFileName->Buffer == NULL)
    {
        return FALSE;
    }

    imageChars = ImageFileName->Length / sizeof(WCHAR);

    //
    // 遍历黑名单, 精确匹配 (忽略大小写)
    // 注意: 在 APC_LEVEL (回调中) 调用, 不能使用 WdfWaitLock,
    //       这里直接遍历只读数组 (允许临时不一致)
    //
    UINT32 count = g_DenyListCount;
    for (i = 0; i < count; i++)
    {
        denyChars = wcslen(g_DenyList[i]);

        if (imageChars == denyChars &&
            _wcsnicmp(g_DenyList[i], ImageFileName->Buffer, denyChars) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

//=============================================================================
// AvProcessGetPendingNotification - 获取待处理通知
// IRQL: PASSIVE_LEVEL
//
// 读取并清除待处理的进程拦截通知
//=============================================================================

NTSTATUS
AvProcessGetPendingNotification(
    _Out_ AV_PROCESS_NOTIFICATION* Notification
    )
{
    KIRQL oldIrql;

    PAGED_CODE();

    if (Notification == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Notification, sizeof(AV_PROCESS_NOTIFICATION));

    KeAcquireSpinLock(&g_NotifyLock, &oldIrql);

    if (g_HasPendingNotify)
    {
        RtlCopyMemory(Notification, &g_PendingNotify, sizeof(AV_PROCESS_NOTIFICATION));
        Notification->HasPending = TRUE;
        RtlZeroMemory(&g_PendingNotify, sizeof(g_PendingNotify));
        g_HasPendingNotify = FALSE;
    }
    else
    {
        Notification->HasPending = FALSE;
    }

    KeReleaseSpinLock(&g_NotifyLock, oldIrql);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvProcessGetStats - 获取进程通知统计 (回调触发/拦截次数)
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvProcessGetStats(
    _Out_opt_ UINT64* CallbackTriggers,
    _Out_opt_ UINT64* BlockAttempts
    )
{
    PAGED_CODE();

    if (CallbackTriggers != NULL)
    {
        *CallbackTriggers = g_CallbackTriggers;
    }

    if (BlockAttempts != NULL)
    {
        *BlockAttempts = g_BlockAttempts;
    }
}

//=============================================================================
// AvProcessGetDebugInfo - 获取进程通知诊断信息
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvProcessGetDebugInfo(
    _Out_ AV_DEBUG_INFO* Info
    )
{
    KIRQL irql;

    PAGED_CODE();

    if (Info == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(*Info));

    Info->CallbackTriggers = g_CallbackTriggers;
    Info->BlockAttempts = g_BlockAttempts;
    Info->ProtectedHits = g_ProtectedHits;
    Info->BehaviorTriggers = g_BehaviorTriggers;

    KeAcquireSpinLock(&g_NotifyLock, &irql);
    Info->LastWasProtected = g_LastWasProtected;
    RtlCopyMemory(Info->LastImagePath, g_LastImagePath, sizeof(g_LastImagePath));
    KeReleaseSpinLock(&g_NotifyLock, irql);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvProcessMarkClientActive - 标记客户端活跃
// IRQL: PASSIVE_LEVEL (IOCTL 分发调用)
//
// 用户态每次发起任意 IOCTL 时调用, 刷新活跃时间戳
//=============================================================================

VOID
AvProcessMarkClientActive(VOID)
{
    LARGE_INTEGER tickCount;
    KeQueryTickCount(&tickCount);
    g_LastClientActivityTicks = (ULONGLONG)tickCount.QuadPart;
}

//=============================================================================
// AvProcessIsClientActive - 客户端是否活跃 (基于心跳超时)
// IRQL: APC_LEVEL (回调中) 或 PASSIVE_LEVEL
//
// 返回 TRUE 表示用户态最近有 IOCTL 活动, 可以执行拦截
// 返回 FALSE 表示用户态已退出/停止活动, 回调应静默放行
// 超时约 5 秒 (100ns tick 数)
//=============================================================================

#define AV_CLIENT_ACTIVITY_TIMEOUT_TICKS 320   // ~5 秒 (每 tick ~15.6ms)

BOOLEAN
AvProcessIsClientActive(VOID)
{
    LARGE_INTEGER tickCount;
    ULONGLONG now;

    KeQueryTickCount(&tickCount);
    now = (ULONGLONG)tickCount.QuadPart;

    return (now - g_LastClientActivityTicks < AV_CLIENT_ACTIVITY_TIMEOUT_TICKS);
}

//=============================================================================
// AvProcessHandleDecision - 处理用户态决策
// IRQL: PASSIVE_LEVEL
//
// 决策的落地执行完全在驱动层完成:
//   允许 -> 恢复该进程所有被挂起的线程 (进程继续运行)
//   拒绝 -> ZwTerminateProcess 终止该进程
// 同时维护白/黑名单
//=============================================================================

NTSTATUS
AvProcessHandleDecision(
    _In_ const AV_PROCESS_DECISION* Decision
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (Decision == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Decision->Decision)
    {
    case AvDecisionAllowAlways:
    case AvDecisionAllowOnce:
        //
        // 允许: 恢复被冻结的进程
        //
        AvpResumeSuspendedThreads(Decision->ProcessId);

        if (Decision->Decision == AvDecisionAllowAlways &&
            Decision->ImagePath[0] != L'\0')
        {
            status = AvProcessAddToAllowList(Decision->ImagePath);
        }
        KdPrint(("AVProcess: Decision %s for PID %u: %ws\n",
                 (Decision->Decision == AvDecisionAllowAlways) ? "ALLOW_ALWAYS" : "ALLOW_ONCE",
                 Decision->ProcessId, Decision->ImagePath));
        break;

    case AvDecisionDenyAlways:
    case AvDecisionDenyOnce:
        //
        // 拒绝: 驱动通过 Zw 终止进程
        //
        status = AvpTerminateProcessById(Decision->ProcessId);

        if (Decision->Decision == AvDecisionDenyAlways &&
            Decision->ImagePath[0] != L'\0')
        {
            AvProcessAddToDenyList(Decision->ImagePath);
        }
        KdPrint(("AVProcess: Decision %s for PID %u: %ws\n",
                 (Decision->Decision == AvDecisionDenyAlways) ? "DENY_ALWAYS" : "DENY_ONCE",
                 Decision->ProcessId, Decision->ImagePath));
        break;

    default:
        //
        // 无效决策: 恢复进程, 避免系统阻塞
        //
        AvpResumeSuspendedThreads(Decision->ProcessId);
        KdPrint(("AVProcess: Decision INVALID, resumed PID %u\n", Decision->ProcessId));
        break;
    }

    return status;
}
