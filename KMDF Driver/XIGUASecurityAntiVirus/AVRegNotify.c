//=============================================================================
// AVRegNotify.c - 注册表通知回调模块
//
// 使用 CmRegisterCallbackEx 拦截敏感注册表操作 (Run 键 / Services 等):
//   回调中检测到敏感路径后同步等待用户决策 (30 秒超时, 超时默认拒绝),
//   决策通过 IOCTL_AV_SEND_REGISTRY_DECISION 到达后唤醒回调。
//
// 重要说明 (CM 回调的阻塞特性):
//   CM 回调在发起注册表操作的线程上下文同步调用。回调阻塞期间,
//   其他进程的注册表操作也会排队等待, 因此本模块使用 30 秒超时,
//   保证任何情况下回调都会在 30 秒内返回, 系统不会永久卡死。
//
// IRQL: 回调运行在 PASSIVE_LEVEL (CM 回调), 其余在 PASSIVE_LEVEL
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVRegNotify.h"
#include "AVProcessNotify.h"
#include <ntstrsafe.h>

//
// PsGetProcessImageFileName 在 ntifs.h 中声明, 此处手动声明
//
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

//
// 手动声明 ZwQueryInformationProcess (仅用于查询当前进程完整镜像路径)
// ProcessImageFileName = 27
//
#define AV_PROCESS_IMAGE_FILE_NAME_CLASS 27

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

//=============================================================================
// 全局数据
//
// CM 回调虽然运行在 PASSIVE_LEVEL, 但为稳妥起见,
// 回调访问的全局数据全部置于非分页内存
//=============================================================================

#pragma section("NonPaged", long, read, write)
#define AV_NON_PAGED __declspec(allocate("NonPaged"))

//
// 注册表决策等待超时 (毫秒)
// 回调阻塞期间其他进程的注册表操作被拖住, 超时必须尽可能小
//
#define AV_REG_DECISION_TIMEOUT_MS 30000

//
// 注册表规则 (Always Allow/Deny) 最大数量
//
#define AV_REG_RULE_MAX 64

//
// 待处理注册表通知 (单条目, 自旋锁保护)
// CM 回调全局串行执行, 单条目足够
//
AV_NON_PAGED static KSPIN_LOCK   g_RegLock;
AV_NON_PAGED static AV_REGISTRY_NOTIFICATION g_RegPendingNotify;
AV_NON_PAGED static BOOLEAN      g_RegNotifyAvailable = FALSE;  // 有通知可被用户态取走
AV_NON_PAGED static BOOLEAN      g_RegDecisionPending = FALSE;  // 回调正在等待决策
AV_NON_PAGED static BOOLEAN      g_RegAllow = FALSE;            // 决策结果 (允许/拒绝)
AV_NON_PAGED static UINT64       g_RegNotifyIdCounter = 0;
AV_NON_PAGED static KEVENT       g_RegWaitEvent;                // 决策到达事件

//
// 注册表 Always 规则 (子串匹配, 大小写不敏感)
//
AV_NON_PAGED static WCHAR   g_RegAllowRules[AV_REG_RULE_MAX][AV_MAX_REG_PATH_LEN];
AV_NON_PAGED static UINT32  g_RegAllowRuleCount = 0;
AV_NON_PAGED static WCHAR   g_RegDenyRules[AV_REG_RULE_MAX][AV_MAX_REG_PATH_LEN];
AV_NON_PAGED static UINT32  g_RegDenyRuleCount = 0;

//
// 注册表回调句柄与信任客户端 PID
//
AV_NON_PAGED static LARGE_INTEGER g_RegCookie;
AV_NON_PAGED static BOOLEAN       g_RegCallbackRegistered = FALSE;
AV_NON_PAGED static UINT32        g_TrustedClientPid = 0;

//
// 诊断计数 (回调串行执行, 简单递增即可; 用户态通过 IOCTL_AV_GET_DEBUG_INFO 读取)
//
AV_NON_PAGED static UINT64 g_RegCallbackTriggers = 0;   // 写操作回调处理总数
AV_NON_PAGED static UINT64 g_RegSensitiveHits = 0;      // 命中敏感路径次数
AV_NON_PAGED static UINT64 g_RegBlockAttempts = 0;      // 拦截等待决策次数
AV_NON_PAGED static UINT64 g_RegPathFailures = 0;       // 键路径提取失败次数
AV_NON_PAGED static UINT32 g_LastRegAction = AV_REG_ACTION_NONE;
AV_NON_PAGED static WCHAR  g_LastRegPath[AV_MAX_REG_PATH_LEN];

//
// AvRegRecordAction - 记录最近处理动作与路径 (诊断用)
//
static
VOID
AvRegRecordAction(
    _In_ UINT32 Action,
    _In_ PCWSTR Path
    )
{
    KIRQL irql;

    KeAcquireSpinLock(&g_RegLock, &irql);
    g_LastRegAction = Action;
    if (Path != NULL && Path[0] != L'\0')
    {
        RtlStringCbCopyW(g_LastRegPath, sizeof(g_LastRegPath), Path);
    }
    KeReleaseSpinLock(&g_RegLock, irql);
}

//=============================================================================
// 字符串辅助 (PASSIVE_LEVEL, 大小写不敏感子串匹配)
//=============================================================================

static
BOOLEAN
AvRegContainsSubstring(
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
// AvRegIsSensitivePath - 检查注册表路径是否为敏感路径
// IRQL: PASSIVE_LEVEL
//
// 子串匹配 (编译期字面量, 大小写不敏感)。
// 只保留真正的"自启动/持久化"点, 避免误报:
//   Run / RunOnce / Policies\Explorer\Run / Winlogon
// 注意: 宽泛的 CurrentVersion\Policies 会拦截 Windows 自身的策略写入
//       (如 DataCollection), 已移除; Services / Session Manager 写入频繁
//       (驱动加载/服务配置), 已移除。
//=============================================================================

static
BOOLEAN
AvRegIsSensitivePath(
    _In_ PCWSTR KeyPath
    )
{
    if (KeyPath == NULL || KeyPath[0] == L'\0')
    {
        return FALSE;
    }

    return
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Run") ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\RunOnce") ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Policies\\Explorer\\Run") ||
        AvRegContainsSubstring(KeyPath, L"\\Winlogon");
}

//=============================================================================
// 规则列表辅助
// IRQL: PASSIVE_LEVEL (回调与决策处理均可用)
//=============================================================================

//
// AvRegIsInRuleList - 检查路径是否命中规则 (Allow/Deny)
//
static
BOOLEAN
AvRegIsInRuleList(
    _In_ PCWSTR KeyPath,
    _In_ BOOLEAN IsDeny
    )
{
    KIRQL irql;
    UINT32 i;
    UINT32 count;
    BOOLEAN found = FALSE;

    if (KeyPath == NULL)
    {
        return FALSE;
    }

    KeAcquireSpinLock(&g_RegLock, &irql);

    if (IsDeny)
    {
        count = g_RegDenyRuleCount;
        for (i = 0; i < count; i++)
        {
            if (g_RegDenyRules[i][0] != L'\0' &&
                AvRegContainsSubstring(KeyPath, g_RegDenyRules[i]))
            {
                found = TRUE;
                break;
            }
        }
    }
    else
    {
        count = g_RegAllowRuleCount;
        for (i = 0; i < count; i++)
        {
            if (g_RegAllowRules[i][0] != L'\0' &&
                AvRegContainsSubstring(KeyPath, g_RegAllowRules[i]))
            {
                found = TRUE;
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_RegLock, irql);
    return found;
}

//
// AvRegAddRule - 添加 Always 规则
//
static
NTSTATUS
AvRegAddRule(
    _In_ PCWSTR KeyPath,
    _In_ BOOLEAN IsDeny
    )
{
    KIRQL irql;
    UINT32 i;
    UINT32* count;
    WCHAR (*rules)[AV_MAX_REG_PATH_LEN];

    if (KeyPath == NULL || KeyPath[0] == L'\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_RegLock, &irql);

    if (IsDeny)
    {
        count = &g_RegDenyRuleCount;
        rules = g_RegDenyRules;
    }
    else
    {
        count = &g_RegAllowRuleCount;
        rules = g_RegAllowRules;
    }

    for (i = 0; i < *count; i++)
    {
        if (_wcsicmp(rules[i], KeyPath) == 0)
        {
            KeReleaseSpinLock(&g_RegLock, irql);
            return STATUS_SUCCESS;   // 已存在
        }
    }

    if (*count >= AV_REG_RULE_MAX)
    {
        KeReleaseSpinLock(&g_RegLock, irql);
        return STATUS_TOO_MANY_SESSIONS;
    }

    RtlStringCbCopyW(rules[*count], sizeof(rules[*count]), KeyPath);
    (*count)++;

    KdPrint(("AVReg: Added %s rule [%u]: %ws\n",
             IsDeny ? "DENY" : "ALLOW", *count - 1, KeyPath));

    KeReleaseSpinLock(&g_RegLock, irql);
    return STATUS_SUCCESS;
}

//=============================================================================
// AvRegIsTrustedProcess - 当前进程是否为可信进程
// IRQL: PASSIVE_LEVEL
//
// 可信进程的注册表操作直接放行:
//   - 信任客户端 (AVSystem): 避免其自身注册表操作自锁死
//   - System (PID 4) / services.exe: 系统服务管理器写 Services 键是
//     正常系统行为, 拦截会破坏服务启动/驱动安装
//   - 镜像位于 \Windows\ 下的进程 (svchost/explorer 等 Windows 组件):
//     系统自身写 Run/Policies 等键属正常行为, 拦截会产生大量误报
//
// 注: 该函数同时被注入防护 (AVInjectNotify) 复用,
//     判断"当前进程是否为可信系统进程"。
//=============================================================================

BOOLEAN
AvRegIsTrustedProcess(
    VOID
    )
{
    UINT32 pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    PCHAR imageName;

    //
    // 信任客户端 (AVSystem) 自身的注册表操作
    //
    if (pid == g_TrustedClientPid)
    {
        return TRUE;
    }

    //
    // System 进程 (PID 4)
    //
    if (pid == 4)
    {
        return TRUE;
    }

    //
    // services.exe (SCM, 服务注册/启动)
    //
    imageName = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (imageName != NULL && _stricmp(imageName, "services.exe") == 0)
    {
        return TRUE;
    }

    //
    // 镜像位于 \Windows\ 目录下的进程 (Windows 组件) 放行
    // 通过 ZwQueryInformationProcess 查询当前进程完整镜像路径
    //
    {
        BYTE buffer[sizeof(UNICODE_STRING) + 260 * sizeof(WCHAR)];
        PUNICODE_STRING imagePath = (PUNICODE_STRING)buffer;
        ULONG returnLength = 0;

        if (NT_SUCCESS(ZwQueryInformationProcess(
                NtCurrentProcess(),
                AV_PROCESS_IMAGE_FILE_NAME_CLASS,
                buffer,
                sizeof(buffer),
                &returnLength)) &&
            imagePath->Buffer != NULL &&
            imagePath->Length > 0 &&
            ((ULONG_PTR)imagePath->Buffer - (ULONG_PTR)buffer + imagePath->Length)
                <= sizeof(buffer))
        {
            imagePath->Buffer[imagePath->Length / sizeof(WCHAR)] = L'\0';

            if (AvRegContainsSubstring(imagePath->Buffer, L"\\Windows\\"))
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

//=============================================================================
// AvRegResolveDecision - 回调等待的决策到达, 唤醒回调
// IRQL: PASSIVE_LEVEL
//=============================================================================

static
VOID
AvRegResolveDecision(
    _In_ BOOLEAN Allow
    )
{
    KIRQL irql;
    BOOLEAN wake = FALSE;

    KeAcquireSpinLock(&g_RegLock, &irql);

    if (g_RegDecisionPending)
    {
        g_RegAllow = Allow;
        g_RegDecisionPending = FALSE;
        wake = TRUE;
    }

    KeReleaseSpinLock(&g_RegLock, irql);

    if (wake)
    {
        KeSetEvent(&g_RegWaitEvent, IO_NO_INCREMENT, FALSE);
    }
}

//=============================================================================
// 键路径/值名提取辅助
//=============================================================================

//
// AvRegGetKeyPath - 通过键对象句柄获取完整路径
// (使用 CmCallbackGetKeyObjectIDEx 获取, 立即复制, 用后立即释放)
//
static
VOID
AvRegGetKeyPath(
    _In_ PVOID Object,
    _Out_writes_bytes_(AV_MAX_REG_PATH_LEN * sizeof(WCHAR)) PWCHAR KeyPath
    )
{
    PCUNICODE_STRING fullName = NULL;
    SIZE_T copyBytes;

    if (Object == NULL || KeyPath == NULL)
    {
        return;
    }

    if (NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_RegCookie, Object, NULL,
                                              &fullName, 0)) &&
        fullName != NULL && fullName->Buffer != NULL)
    {
        copyBytes = min(fullName->Length,
                        AV_MAX_REG_PATH_LEN * sizeof(WCHAR) - sizeof(WCHAR));
        RtlCopyMemory(KeyPath, fullName->Buffer, copyBytes);
        KeyPath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    if (fullName != NULL)
    {
        CmCallbackReleaseKeyObjectIDEx(fullName);
    }
}

//
// AvRegCopyValueName - 复制值名 (并强制 null 终止)
//
static
VOID
AvRegCopyValueName(
    _In_ PUNICODE_STRING ValueName,
    _Out_writes_bytes_(AV_MAX_REG_VALUE_LEN * sizeof(WCHAR)) PWCHAR OutValue
    )
{
    SIZE_T copyBytes;

    if (ValueName == NULL || ValueName->Buffer == NULL || OutValue == NULL)
    {
        return;
    }

    copyBytes = min(ValueName->Length,
                    AV_MAX_REG_VALUE_LEN * sizeof(WCHAR) - sizeof(WCHAR));
    RtlCopyMemory(OutValue, ValueName->Buffer, copyBytes);
    OutValue[copyBytes / sizeof(WCHAR)] = L'\0';
}

//=============================================================================
// 注册表回调函数
// IRQL: PASSIVE_LEVEL
//
// 只处理 Pre 写操作 (SetValueKey/DeleteValueKey/DeleteKey/CreateKey)。
// 命中敏感路径且不是可信进程/规则命中时:
//   发布通知 -> 等待用户决策 (30 秒超时, 超时默认拒绝)
//   允许 -> 返回 STATUS_SUCCESS (操作继续)
//   拒绝 -> 返回 STATUS_ACCESS_DENIED (操作被拦截)
//=============================================================================

static
NTSTATUS
AvRegCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS opCode = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    WCHAR keyPath[AV_MAX_REG_PATH_LEN];
    WCHAR valueName[AV_MAX_REG_VALUE_LEN];
    UINT32 opType = AvRegOpInvalid;
    KIRQL irql;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    UNREFERENCED_PARAMETER(CallbackContext);

    RtlZeroMemory(keyPath, sizeof(keyPath));
    RtlZeroMemory(valueName, sizeof(valueName));

    //
    // 提取键路径与值名
    //
    switch (opCode)
    {
    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        SIZE_T copyBytes;

        if (info == NULL || info->CompleteName == NULL ||
            info->CompleteName->Buffer == NULL)
        {
            return STATUS_SUCCESS;
        }

        //
        // Create 的 CompleteName 即新键的完整路径
        //
        copyBytes = min(info->CompleteName->Length,
                        sizeof(keyPath) - sizeof(WCHAR));
        RtlCopyMemory(keyPath, info->CompleteName->Buffer, copyBytes);
        keyPath[copyBytes / sizeof(WCHAR)] = L'\0';
        opType = AvRegOpCreateKey;
        break;
    }

    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

        if (info == NULL || info->Object == NULL)
        {
            return STATUS_SUCCESS;
        }

        AvRegGetKeyPath(info->Object, keyPath);
        AvRegCopyValueName(info->ValueName, valueName);
        opType = AvRegOpSetValueKey;
        break;
    }

    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;

        if (info == NULL || info->Object == NULL)
        {
            return STATUS_SUCCESS;
        }

        AvRegGetKeyPath(info->Object, keyPath);
        AvRegCopyValueName(info->ValueName, valueName);
        opType = AvRegOpDeleteValueKey;
        break;
    }

    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;

        if (info == NULL || info->Object == NULL)
        {
            return STATUS_SUCCESS;
        }

        AvRegGetKeyPath(info->Object, keyPath);
        opType = AvRegOpDeleteKey;
        break;
    }

    default:
        //
        // 只处理 Pre 写操作, 其余 (含所有 Post 操作) 直接放行
        //
        return STATUS_SUCCESS;
    }

    //
    // 无法解析路径: 放行 (记录失败次数, 便于诊断)
    //
    if (opType == AvRegOpInvalid || keyPath[0] == L'\0')
    {
        InterlockedIncrement64((PLONG64)&g_RegPathFailures);
        AvRegRecordAction(AV_REG_ACTION_ALLOW_PATHFAIL, keyPath);
        KdPrint(("AVReg: Key path extraction failed (op %u), allowing\n", (UINT32)opCode));
        return STATUS_SUCCESS;
    }

    //
    // 统计写操作回调处理总数
    //
    InterlockedIncrement64((PLONG64)&g_RegCallbackTriggers);

    //
    // 命中 Deny 规则: 直接拒绝, 不弹窗
    //
    if (AvRegIsInRuleList(keyPath, TRUE))
    {
        AvRegRecordAction(AV_REG_ACTION_DENY_RULE, keyPath);
        KdPrint(("AVReg: Denied by rule: %ws\n", keyPath));
        return STATUS_ACCESS_DENIED;
    }

    //
    // 命中 Allow 规则: 直接放行, 不弹窗
    //
    if (AvRegIsInRuleList(keyPath, FALSE))
    {
        AvRegRecordAction(AV_REG_ACTION_ALLOW_RULE, keyPath);
        return STATUS_SUCCESS;
    }

    //
    // 非敏感路径: 放行
    //
    if (!AvRegIsSensitivePath(keyPath))
    {
        AvRegRecordAction(AV_REG_ACTION_ALLOW_NOMATCH, keyPath);
        return STATUS_SUCCESS;
    }

    //
    // 命中敏感路径
    //
    InterlockedIncrement64((PLONG64)&g_RegSensitiveHits);

    //
    // 可信进程 (AVSystem / System / services.exe): 放行
    //
    if (AvRegIsTrustedProcess())
    {
        AvRegRecordAction(AV_REG_ACTION_ALLOW_TRUSTED, keyPath);
        KdPrint(("AVReg: Trusted process (PID %u), allowing %ws\n",
                 (UINT32)(ULONG_PTR)PsGetCurrentProcessId(), keyPath));
        return STATUS_SUCCESS;
    }

    //
    // 无活跃客户端: 静默放行 (无人处理决策, 拦截会导致注册表卡 30 秒)
    //
    if (!AvProcessIsClientActive())
    {
        AvRegRecordAction(AV_REG_ACTION_ALLOW_INACTIVE, keyPath);
        KdPrint(("AVReg: Client inactive, allowing %ws\n", keyPath));
        return STATUS_SUCCESS;
    }

    //
    // 拦截! 组装通知并发布
    //
    AV_REGISTRY_NOTIFICATION notify;
    RtlZeroMemory(&notify, sizeof(notify));
    notify.HasPending = TRUE;
    notify.ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    notify.OperationType = opType;
    RtlStringCbCopyW(notify.KeyPath, sizeof(notify.KeyPath), keyPath);
    RtlStringCbCopyW(notify.ValueName, sizeof(notify.ValueName), valueName);
    notify.NotificationId = InterlockedIncrement64((PLONG64)&g_RegNotifyIdCounter);

    KeAcquireSpinLock(&g_RegLock, &irql);
    RtlCopyMemory(&g_RegPendingNotify, &notify, sizeof(g_RegPendingNotify));
    g_RegNotifyAvailable = TRUE;
    g_RegDecisionPending = TRUE;
    g_RegAllow = FALSE;
    KeReleaseSpinLock(&g_RegLock, irql);

    InterlockedIncrement64((PLONG64)&g_RegBlockAttempts);
    AvRegRecordAction(AV_REG_ACTION_BLOCKED, keyPath);

    KdPrint(("AVReg: Blocked %ws on %ws (PID %u)\n", valueName, keyPath, notify.ProcessId));

    //
    // 等待用户决策 (30 秒超时, 超时默认拒绝)
    // CM 回调阻塞期间其他进程的注册表操作被拖住, 超时保证不会永久卡死
    //
    KeResetEvent(&g_RegWaitEvent);

    timeout.QuadPart = -((LONGLONG)AV_REG_DECISION_TIMEOUT_MS * 10000);   // 100ns 单位
    waitStatus = KeWaitForSingleObject(&g_RegWaitEvent, Executive, KernelMode, FALSE, &timeout);

    //
    // 读取决策结果
    //
    BOOLEAN allow = FALSE;
    KeAcquireSpinLock(&g_RegLock, &irql);
    allow = g_RegAllow;
    g_RegDecisionPending = FALSE;
    //
    // 回调已返回, 清除通知 (决策一定在取走通知之后才到达,
    // 若超时未被取走则丢弃, 避免用户态对已处理事件重复弹窗)
    //
    g_RegNotifyAvailable = FALSE;
    KeReleaseSpinLock(&g_RegLock, irql);

    if (allow)
    {
        if (waitStatus == STATUS_TIMEOUT)
        {
            KdPrint(("AVReg: Decision timeout, but decision resolved, allowing %ws\n", keyPath));
        }
        return STATUS_SUCCESS;
    }

    KdPrint(("AVReg: %s: %ws (PID %u, wait 0x%08X)\n",
             (waitStatus == STATUS_TIMEOUT) ? "TIMEOUT DENIED" : "DENIED",
             keyPath, notify.ProcessId, waitStatus));

    return STATUS_ACCESS_DENIED;
}

//=============================================================================
// AvRegNotifyInitialize - 初始化注册表通知模块
// IRQL: PASSIVE_LEVEL
//=============================================================================

NTSTATUS
AvRegNotifyInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    PAGED_CODE();

    KdPrint(("AVReg: Initializing registry notification\n"));

    KeInitializeSpinLock(&g_RegLock);
    KeInitializeEvent(&g_RegWaitEvent, NotificationEvent, FALSE);
    RtlZeroMemory(&g_RegPendingNotify, sizeof(g_RegPendingNotify));
    g_RegNotifyAvailable = FALSE;
    g_RegDecisionPending = FALSE;
    g_RegAllow = FALSE;
    g_RegNotifyIdCounter = 0;
    g_RegAllowRuleCount = 0;
    g_RegDenyRuleCount = 0;
    RtlZeroMemory(g_RegAllowRules, sizeof(g_RegAllowRules));
    RtlZeroMemory(g_RegDenyRules, sizeof(g_RegDenyRules));
    g_TrustedClientPid = 0;
    g_RegCallbackTriggers = 0;
    g_RegSensitiveHits = 0;
    g_RegBlockAttempts = 0;
    g_RegPathFailures = 0;
    g_LastRegAction = AV_REG_ACTION_NONE;
    RtlZeroMemory(g_LastRegPath, sizeof(g_LastRegPath));

    //
    // 注册配置管理器回调 (带高度值, 支持卸载)
    // Driver 参数传真实驱动对象 (此 WDK 声明为必填), 保证卸载安全;
    // 第 6 参数 Reserved 必须为 NULL
    //
    RtlInitUnicodeString(&altitude, L"400000.1");

    status = CmRegisterCallbackEx(AvRegCallback, &altitude, DriverObject, NULL,
                                  &g_RegCookie, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVReg: CmRegisterCallbackEx failed 0x%08X\n", status));
        return status;
    }

    g_RegCallbackRegistered = TRUE;

    KdPrint(("AVReg: Registry callback registered\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// AvRegNotifyUninitialize - 卸载注册表通知模块
// IRQL: PASSIVE_LEVEL
//
// CmUnregisterCallback 会等待正在执行的回调返回
// (回调内最多阻塞 30 秒, 因此卸载最多延迟 30 秒)
//=============================================================================

VOID
AvRegNotifyUninitialize(
    VOID
    )
{
    PAGED_CODE();

    KdPrint(("AVReg: Uninitializing registry notification\n"));

    if (g_RegCallbackRegistered)
    {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCallbackRegistered = FALSE;
    }

    RtlZeroMemory(&g_RegPendingNotify, sizeof(g_RegPendingNotify));
    g_RegNotifyAvailable = FALSE;
    g_RegDecisionPending = FALSE;

    KdPrint(("AVReg: Uninitialized\n"));
}

//=============================================================================
// AvRegGetPendingNotification - 获取待处理注册表通知
// IRQL: PASSIVE_LEVEL
//
// 取出通知副本供用户态弹窗; 回调仍在等待决策,
// 由 IOCTL_AV_SEND_REGISTRY_DECISION 完成唤醒
//=============================================================================

NTSTATUS
AvRegGetPendingNotification(
    _Out_ AV_REGISTRY_NOTIFICATION* Notification
    )
{
    KIRQL irql;

    PAGED_CODE();

    if (Notification == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Notification, sizeof(AV_REGISTRY_NOTIFICATION));

    KeAcquireSpinLock(&g_RegLock, &irql);

    if (g_RegNotifyAvailable)
    {
        RtlCopyMemory(Notification, &g_RegPendingNotify, sizeof(AV_REGISTRY_NOTIFICATION));
        Notification->HasPending = TRUE;
        g_RegNotifyAvailable = FALSE;
    }
    else
    {
        Notification->HasPending = FALSE;
    }

    KeReleaseSpinLock(&g_RegLock, irql);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvRegHandleDecision - 处理用户态注册表决策
// IRQL: PASSIVE_LEVEL
//
// 决策通过事件唤醒回调:
//   允许 -> 回调返回 STATUS_SUCCESS (注册表操作继续)
//   拒绝 -> 回调返回 STATUS_ACCESS_DENIED (注册表操作被拦截)
// Always 决策同时维护规则列表
//=============================================================================

NTSTATUS
AvRegHandleDecision(
    _In_ const AV_REGISTRY_DECISION* Decision
    )
{
    if (Decision == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    switch (Decision->Decision)
    {
    case AvDecisionAllowOnce:
        AvRegResolveDecision(TRUE);
        break;

    case AvDecisionAllowAlways:
        AvRegResolveDecision(TRUE);
        AvRegAddRule(Decision->KeyPath, FALSE);
        break;

    case AvDecisionDenyOnce:
        AvRegResolveDecision(FALSE);
        break;

    case AvDecisionDenyAlways:
        AvRegResolveDecision(FALSE);
        AvRegAddRule(Decision->KeyPath, TRUE);
        break;

    default:
        //
        // 无效决策: 默认拒绝 (安全优先)
        //
        AvRegResolveDecision(FALSE);
        break;
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// AvRegSetTrustedClientPid - 记录信任客户端 (AVSystem) 进程 ID
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvRegSetTrustedClientPid(
    _In_ UINT32 ProcessId
    )
{
    g_TrustedClientPid = ProcessId;
    KdPrint(("AVReg: Trusted client PID set to %u\n", ProcessId));
}

//=============================================================================
// AvRegGetDebugInfo - 获取注册表保护诊断信息
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvRegGetDebugInfo(
    _Inout_ AV_DEBUG_INFO* Info
    )
{
    KIRQL irql;

    PAGED_CODE();

    if (Info == NULL)
    {
        return;
    }

    Info->RegCallbackTriggers = g_RegCallbackTriggers;
    Info->RegSensitiveHits = g_RegSensitiveHits;
    Info->RegBlockAttempts = g_RegBlockAttempts;
    Info->RegPathFailures = g_RegPathFailures;

    KeAcquireSpinLock(&g_RegLock, &irql);
    Info->LastRegAction = g_LastRegAction;
    RtlCopyMemory(Info->LastRegPath, g_LastRegPath, sizeof(g_LastRegPath));
    KeReleaseSpinLock(&g_RegLock, irql);
}
