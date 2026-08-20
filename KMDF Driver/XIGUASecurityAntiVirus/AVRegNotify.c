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
#include "../AVCommon/AVPoolCompat.h"

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
// 回调阻塞期间其他进程的注册表操作被拖住, 超时必须尽可能小。
// 用户态断开时由 AvProcessIsClientActive 兜底静默放行。
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
// 驱动服务注册表键路径 (规则持久化用)
// 初始化时从 DriverEntry 的 RegistryPath 复制, 卸载时释放
//
AV_NON_PAGED static UNICODE_STRING g_RegServicePath = { 0, 0, NULL };
AV_NON_PAGED static BOOLEAN        g_RegServicePathValid = FALSE;

//
// UAC 策略敏感值 (CurrentVersion\Policies\System 下, 值名精确匹配)
// 攻击者禁用 UAC 的标准手法: EnableLUA=0 等 (银狐/勒索均使用)
//
AV_NON_PAGED static const PCWSTR g_UacPolicyValues[] =
{
    L"EnableLUA",
    L"ConsentPromptBehaviorAdmin",
    L"PromptOnSecureDesktop",
    L"EnableInstallerDetection",
    L"FilterAdministratorToken",
    L"ValidateAdminCodeSignatures",
    L"EnableVirtualization",
};
AV_NON_PAGED static const UINT32 g_UacPolicyValueCount =
    sizeof(g_UacPolicyValues) / sizeof(g_UacPolicyValues[0]);

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
// 规则持久化
//
// "始终允许/始终拒绝"规则保存在驱动服务注册表键下:
//   HKLM\SYSTEM\CurrentControlSet\Services\XIGUASecurityAntiVirus\RegRules
//     AllowRules (REG_MULTI_SZ): 始终允许的注册表路径
//     DenyRules  (REG_MULTI_SZ): 始终拒绝的注册表路径
// 驱动每次加载时恢复规则, 保证用户的选择在重启后仍然生效。
//=============================================================================

#define AV_REG_RULES_SUBKEY    L"RegRules"
#define AV_REG_ALLOW_VAL       L"AllowRules"
#define AV_REG_DENY_VAL        L"DenyRules"

//
// 规则持久化缓冲区大小 (64 条规则 * (520 字符 + 终止) * 2 字节)
//
#define AV_REG_RULES_BUF_BYTES (AV_REG_RULE_MAX * (AV_MAX_REG_PATH_LEN + 1) * sizeof(WCHAR))

//
// AvRegOpenRulesKey - 打开/创建规则存储键
// IRQL: PASSIVE_LEVEL
//
static
NTSTATUS
AvRegOpenRulesKey(
    _Out_ PHANDLE pKey
    )
{
    WCHAR fullPath[AV_MAX_REG_PATH_LEN + 64];
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;
    ULONG disposition = 0;

    if (pKey == NULL || !g_RegServicePathValid || g_RegServicePath.Buffer == NULL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = RtlStringCbPrintfW(fullPath, sizeof(fullPath),
                                L"%ws\\%ws", g_RegServicePath.Buffer, AV_REG_RULES_SUBKEY);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlInitUnicodeString(&path, fullPath);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwCreateKey(pKey, KEY_READ | KEY_WRITE, &oa, 0, NULL,
                       REG_OPTION_NON_VOLATILE, &disposition);
}

//
// AvRegSaveRulesToRegistry - 把内存中的规则持久化到注册表
// IRQL: PASSIVE_LEVEL (在 AvRegAddRule 释放自旋锁后调用)
//
static
VOID
AvRegSaveRulesToRegistry(
    VOID
    )
{
    HANDLE hKey = NULL;
    NTSTATUS status;
    KIRQL irql;
    PWCHAR allowBuf = NULL;
    PWCHAR denyBuf = NULL;
    PWCHAR cursor;
    ULONG allowLen = 0;
    ULONG denyLen = 0;
    UINT32 i;
    UNICODE_STRING valueName;

    status = AvRegOpenRulesKey(&hKey);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVReg: Open rules key failed 0x%08X, rules not persisted\n", status));
        return;
    }

    allowBuf = (PWCHAR)AV_ALLOC_PAGED(AV_REG_RULES_BUF_BYTES, 'lgRA');
    denyBuf = (PWCHAR)AV_ALLOC_PAGED(AV_REG_RULES_BUF_BYTES, 'lgRD');
    if (allowBuf == NULL || denyBuf == NULL)
    {
        KdPrint(("AVReg: Rule persistence buffer allocation failed\n"));
        if (allowBuf != NULL) ExFreePool(allowBuf);
        if (denyBuf != NULL) ExFreePool(denyBuf);
        ZwClose(hKey);
        return;
    }

    //
    // 在自旋锁保护下构建 MULTI_SZ (纯内存操作, 无分配)
    //
    KeAcquireSpinLock(&g_RegLock, &irql);

    cursor = allowBuf;
    for (i = 0; i < g_RegAllowRuleCount; i++)
    {
        RtlStringCbCopyW(cursor,
                         AV_REG_RULES_BUF_BYTES -
                             (SIZE_T)((PCHAR)cursor - (PCHAR)allowBuf),
                         g_RegAllowRules[i]);
        cursor += wcslen(g_RegAllowRules[i]) + 1;
    }
    *cursor = L'\0';
    allowLen = (ULONG)((SIZE_T)((PCHAR)cursor - (PCHAR)allowBuf) + sizeof(WCHAR));

    cursor = denyBuf;
    for (i = 0; i < g_RegDenyRuleCount; i++)
    {
        RtlStringCbCopyW(cursor,
                         AV_REG_RULES_BUF_BYTES -
                             (SIZE_T)((PCHAR)cursor - (PCHAR)denyBuf),
                         g_RegDenyRules[i]);
        cursor += wcslen(g_RegDenyRules[i]) + 1;
    }
    *cursor = L'\0';
    denyLen = (ULONG)((SIZE_T)((PCHAR)cursor - (PCHAR)denyBuf) + sizeof(WCHAR));

    KeReleaseSpinLock(&g_RegLock, irql);

    //
    // 写回注册表 (PASSIVE_LEVEL, 注册表操作会被拷贝, 缓冲区内存在调用期间安全)
    //
    RtlInitUnicodeString(&valueName, AV_REG_ALLOW_VAL);
    status = ZwSetValueKey(hKey, &valueName, 0, REG_MULTI_SZ, allowBuf, allowLen);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVReg: Write AllowRules failed 0x%08X\n", status));
    }

    RtlInitUnicodeString(&valueName, AV_REG_DENY_VAL);
    status = ZwSetValueKey(hKey, &valueName, 0, REG_MULTI_SZ, denyBuf, denyLen);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVReg: Write DenyRules failed 0x%08X\n", status));
    }

    ZwClose(hKey);
    ExFreePool(allowBuf);
    ExFreePool(denyBuf);
}

//
// AvRegLoadRulesFromRegistry - 从注册表恢复规则
// IRQL: PASSIVE_LEVEL (驱动初始化时调用)
//
static
NTSTATUS
AvRegLoadRulesFromRegistry(
    VOID
    )
{
    HANDLE hKey = NULL;
    NTSTATUS status;
    KIRQL irql;
    PVOID buf = NULL;
    ULONG bufSize = (ULONG)(AV_REG_RULES_BUF_BYTES + sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 64);
    PKEY_VALUE_PARTIAL_INFORMATION info;
    UNICODE_STRING valueName;
    PWCHAR parsed[AV_REG_RULE_MAX];
    UINT32 parsedCount = 0;
    UINT32 i;

    if (!g_RegServicePathValid)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = AvRegOpenRulesKey(&hKey);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVReg: Rules key unavailable 0x%08X, no persisted rules loaded\n", status));
        return status;
    }

    buf = AV_ALLOC_PAGED(bufSize, 'lgRL');
    if (buf == NULL)
    {
        ZwClose(hKey);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 解析 AllowRules (MULTI_SZ) -> 指向缓冲区内的字符串
    //
    parsedCount = 0;
    RtlInitUnicodeString(&valueName, AV_REG_ALLOW_VAL);
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                             buf, bufSize, NULL);
    if (NT_SUCCESS(status))
    {
        info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_MULTI_SZ && info->DataLength >= sizeof(WCHAR))
        {
            PWCHAR p = (PWCHAR)info->Data;
            while (p[0] != L'\0' && parsedCount < AV_REG_RULE_MAX)
            {
                parsed[parsedCount++] = p;
                p += wcslen(p) + 1;
            }
        }
    }

    if (parsedCount > 0)
    {
        KeAcquireSpinLock(&g_RegLock, &irql);
        for (i = 0; i < parsedCount && g_RegAllowRuleCount < AV_REG_RULE_MAX; i++)
        {
            RtlStringCbCopyW(g_RegAllowRules[g_RegAllowRuleCount],
                             sizeof(g_RegAllowRules[g_RegAllowRuleCount]),
                             parsed[i]);
            g_RegAllowRuleCount++;
        }
        KeReleaseSpinLock(&g_RegLock, irql);
    }

    //
    // 解析 DenyRules (MULTI_SZ) -> 指向缓冲区内的字符串
    //
    parsedCount = 0;
    RtlInitUnicodeString(&valueName, AV_REG_DENY_VAL);
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                             buf, bufSize, NULL);
    if (NT_SUCCESS(status))
    {
        info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_MULTI_SZ && info->DataLength >= sizeof(WCHAR))
        {
            PWCHAR p = (PWCHAR)info->Data;
            while (p[0] != L'\0' && parsedCount < AV_REG_RULE_MAX)
            {
                parsed[parsedCount++] = p;
                p += wcslen(p) + 1;
            }
        }
    }

    if (parsedCount > 0)
    {
        KeAcquireSpinLock(&g_RegLock, &irql);
        for (i = 0; i < parsedCount && g_RegDenyRuleCount < AV_REG_RULE_MAX; i++)
        {
            RtlStringCbCopyW(g_RegDenyRules[g_RegDenyRuleCount],
                             sizeof(g_RegDenyRules[g_RegDenyRuleCount]),
                             parsed[i]);
            g_RegDenyRuleCount++;
        }
        KeReleaseSpinLock(&g_RegLock, irql);
    }

    ExFreePool(buf);
    ZwClose(hKey);

    KdPrint(("AVReg: Loaded %u allow / %u deny persisted rules\n",
             g_RegAllowRuleCount, g_RegDenyRuleCount));

    return STATUS_SUCCESS;
}

//=============================================================================
// AvRegIsSensitivePath - 检查注册表路径是否为敏感路径
// IRQL: PASSIVE_LEVEL
//
// 子串匹配 (编译期字面量, 大小写不敏感)。
// 只保留真正的"自启动/持久化"点, 避免误报:
//   Run / RunOnce / Policies\Explorer\Run / Winlogon
//
// 注意: 普通软件写 Run 键是常见行为 (自启动配置), 全部拦截会产生大量误报。
// 为降低误报, 仅拦截以下高价值目标:
//   - 机器级 Run (HKLM\...\CurrentVersion\Run, 需要管理员权限, 更危险)
//   - 所有 RunOnce (重启后执行, 一次性持久化, 正常软件极少用)
//   - Policies\Explorer\Run (组策略强制自启动)
//   - Winlogon 键 (登录触发, 正常软件极少写)
// 用户级 Run (HKCU\...\CurrentVersion\Run) 是普通软件最常见的自启动位置,
// 放行以减少误报; 该路径仍可通过用户手动添加白名单规则加强。
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

    //
    // 区分机器级 (HKLM) 与用户级 (HKCU) Run 键:
    // 机器级 Run 需要管理员权限且影响所有用户, 是恶意软件首选;
    // 用户级 Run 是正常软件常见自启动位置, 放行避免误报。
    //
    BOOLEAN isMachineRun = FALSE;
    BOOLEAN isUserRun = FALSE;

    if (AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Run"))
    {
        if (AvRegContainsSubstring(KeyPath, L"\\Microsoft\\Windows\\CurrentVersion\\Run") ||
            AvRegContainsSubstring(KeyPath, L"\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            //
            // 完整路径前缀命中: 再区分 HKLM / HKCU
            //
            if (AvRegContainsSubstring(KeyPath, L"HKLM\\") ||
                AvRegContainsSubstring(KeyPath, L"\\REGISTRY\\MACHINE\\") ||
                AvRegContainsSubstring(KeyPath, L"\\Registry\\Machine\\"))
            {
                isMachineRun = TRUE;
            }
            else
            {
                isUserRun = TRUE;
            }
        }
        else
        {
            //
            // 路径不含完整前缀, 保守处理: 机器级
            //
            isMachineRun = TRUE;
        }
    }

    //
    // 敏感路径判定:
    //   机器级 Run (HKLM) / 所有 RunOnce / Policies\Explorer\Run / Winlogon
    //   用户级 Run (HKCU) 不拦截 (正常软件常见行为)
    //
    return
        isMachineRun ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\RunOnce") ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Policies\\Explorer\\Run") ||
        AvRegContainsSubstring(KeyPath, L"\\Winlogon") ||

        //
        // ===== 恶意软件持久化/自启动点 (新增) =====
        //

        //
        // 启动文件夹对应注册表键 (当前用户/所有用户)
        //
        AvRegContainsSubstring(KeyPath, L"Start Menu\\Programs\\Startup") ||
        AvRegContainsSubstring(KeyPath, L"Startup\\Programs") ||

        //
        // 认证包/安全包/通知包 (恶意软件注入登录进程, 写入极少)
        //
        AvRegContainsSubstring(KeyPath, L"\\Control\\Lsa\\Authentication Packages") ||
        AvRegContainsSubstring(KeyPath, L"\\Control\\Lsa\\Security Packages") ||
        AvRegContainsSubstring(KeyPath, L"\\Control\\Lsa\\Notification Packages") ||
        AvRegContainsSubstring(KeyPath, L"\\Control\\Lsa\\LsaExtensions") ||

        //
        // 打印监视器 DLL 持久化 (写入极少, 正常添加打印机不触碰)
        //
        AvRegContainsSubstring(KeyPath, L"Control\\Print\\Monitors") ||

        //
        // 屏幕保护程序持久化 (写入少)
        //
        AvRegContainsSubstring(KeyPath, L"Control Panel\\Desktop\\SCRNSAVE") ||

        //
        // 图标覆盖处理器 (写入少)
        //
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers") ||

        //
        // 旧式自启动 (RunServices, 写入少)
        //
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\RunServicesOnce") ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\RunServices") ||

        //
        // Windows Defender 策略禁用 (写入少, 仅策略分支)
        //
        AvRegContainsSubstring(KeyPath, L"\\Policies\\Microsoft\\Windows Defender") ||
        AvRegContainsSubstring(KeyPath, L"\\Policies\\Microsoft\\WindowsFirewall") ||

        //
        // 防火墙策略 (写防火墙规则时更新, 中等频率)
        //
        AvRegContainsSubstring(KeyPath, L"Services\\SharedAccess\\Parameters\\FirewallPolicy") ||

        //
        // 浏览器主页劫持 (写入少)
        //
        AvRegContainsSubstring(KeyPath, L"Software\\Policies\\Microsoft\\Internet Explorer\\Main") ||
        AvRegContainsSubstring(KeyPath, L"\\Internet Explorer\\Main\\Start Page") ||

        //
        // 无文件持久化: AppInit_DLLs 注入所有进程 (写入极少)
        //
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Windows\\AppInit_DLLs") ||
        AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Windows\\LoadAppInit_DLLs") ||

        //
        // 会话管理器 BootExecute (恶意软件开机执行)
        //
        AvRegContainsSubstring(KeyPath, L"CurrentControlSet\\Control\\Session Manager\\") ||

        //
        // 环境变量替换 (恶意软件劫持系统命令)
        // \??\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
        //
        AvRegContainsSubstring(KeyPath, L"\\Session Manager\\Environment") ||

        //
        // 已知 DLL 列表 (恶意软件注入系统调用链)
        //
        AvRegContainsSubstring(KeyPath, L"\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs");
}

//=============================================================================
// AvRegIsSensitiveValue - 检查值级敏感操作
// IRQL: PASSIVE_LEVEL
//
// 值级检测覆盖以下恶意软件常用攻击点:
//   - UAC 策略值 (EnableLUA 等 7 个): 禁用 UAC 的标准手法
//   - IFEO Debugger / GlobalFlag / VerifierDlls: 进程劫持/AppCompat 攻击
//   - 服务 ImagePath / Start: 创建/篡改服务实现持久化
//   - Session Manager BootExecute: 开机执行恶意载荷
//   - Winlogon Shell / Userinit: 登录自启动注入
// 只对值名精确匹配, 不影响同键下的其他正常写入。
//=============================================================================

static
BOOLEAN
AvRegIsSensitiveValue(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName
    )
{
    UINT32 i;

    if (KeyPath == NULL || KeyPath[0] == L'\0' ||
        ValueName == NULL || ValueName[0] == L'\0')
    {
        return FALSE;
    }

    //
    // UAC 策略值 (CurrentVersion\Policies\System 下, 值名精确匹配)
    //
    if (AvRegContainsSubstring(KeyPath, L"CurrentVersion\\Policies\\System"))
    {
        for (i = 0; i < g_UacPolicyValueCount; i++)
        {
            if (_wcsicmp(ValueName, g_UacPolicyValues[i]) == 0)
            {
                return TRUE;
            }
        }
    }

    //
    // IFEO: Image File Execution Options\<exe>\
    //   Debugger       - 把目标程序重定向到恶意程序 (进程劫持)
    //   GlobalFlag     - 开启调试器附加, 配合 Debugger 使用
    //   VerifierDlls   - 注入 AppCompat 兼容性 DLL (持久化)
    //
    if (AvRegContainsSubstring(KeyPath, L"Image File Execution Options"))
    {
        if (_wcsicmp(ValueName, L"Debugger") == 0 ||
            _wcsicmp(ValueName, L"GlobalFlag") == 0 ||
            _wcsicmp(ValueName, L"VerifierDlls") == 0)
        {
            return TRUE;
        }
    }

    //
    // 服务持久化: Services\<service>\
    //   ImagePath  - 服务二进制路径 (恶意软件指向其载荷)
    //   Start      - 服务启动类型 (改为 2/0 实现开机自启)
    //   Type       - 服务类型 (改为 kernel/system 提升权限)
    //   ObjectName - 服务运行账户 (改为 SYSTEM)
    // 仅值级匹配, 避免 Services 整键的频繁写入误报
    //
    if (AvRegContainsSubstring(KeyPath, L"CurrentControlSet\\Services\\"))
    {
        if (_wcsicmp(ValueName, L"ImagePath") == 0 ||
            _wcsicmp(ValueName, L"Start") == 0 ||
            _wcsicmp(ValueName, L"Type") == 0 ||
            _wcsicmp(ValueName, L"ObjectName") == 0)
        {
            return TRUE;
        }
    }

    //
    // Session Manager BootExecute: 开机时执行 (恶意软件持久化,
    // 正常系统该值为 autocheck autochk *, 写入极少)
    //
    if (AvRegContainsSubstring(KeyPath, L"Control\\Session Manager") &&
        _wcsicmp(ValueName, L"BootExecute") == 0)
    {
        return TRUE;
    }

    //
    // Winlogon Shell / Userinit: 登录时启动 (恶意软件替换 Shell 实现持久化)
    // (Winlogon 键路径级已拦截, 此处按值精确匹配增强)
    //
    if (AvRegContainsSubstring(KeyPath, L"\\Winlogon") &&
        (_wcsicmp(ValueName, L"Shell") == 0 ||
         _wcsicmp(ValueName, L"Userinit") == 0))
    {
        return TRUE;
    }

    return FALSE;
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
// IRQL: PASSIVE_LEVEL
//
// 添加成功后把规则持久化到注册表,
// 使"始终允许/始终拒绝"在驱动重启后仍然生效。
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
    BOOLEAN added = FALSE;

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
    added = TRUE;

    KdPrint(("AVReg: Added %s rule [%u]: %ws\n",
             IsDeny ? "DENY" : "ALLOW", *count - 1, KeyPath));

    KeReleaseSpinLock(&g_RegLock, irql);

    //
    // 持久化到注册表 (PASSIVE_LEVEL, 不受自旋锁限制)
    //
    if (added)
    {
        AvRegSaveRulesToRegistry();
    }

    return STATUS_SUCCESS;
}

//
// 注册表操作可信系统进程名单 (按镜像名精确匹配, 大小写不敏感)
// 这些进程作为 Windows 正常运行的一部分写入敏感注册表路径,
// 拦截它们会导致系统功能异常 (登录/服务启动/安全子系统等)。
//
// 注意: reg.exe / regedit.exe / cmd.exe / powershell.exe / explorer.exe
//       均不在信任名单中 — 它们是用户主动操作的工具,
//       其注册表写操作必须弹窗让用户确认。
//       (原实现通过 \Windows\ 路径子串匹配信任所有 Windows 目录下进程,
//        导致 reg.exe/regedit.exe 等用户工具的注册表操作被静默放行)
//
AV_NON_PAGED static const PCSTR g_TrustedRegProcNames[] =
{
    "winlogon.exe",    // 登录管理器 (写 \Winlogon 键)
    "svchost.exe",     // 服务宿主 (组件更新可能写 Run 键)
    "csrss.exe",       // 客户端服务器运行时
    "services.exe",    // 服务管理器 (SCM)
    "lsass.exe",       // 本地安全授权
    "smss.exe",        // 会话管理器
    "wininit.exe",     // Windows 启动应用
    "dwm.exe",         // 桌面窗口管理器
};
AV_NON_PAGED static const UINT32 g_TrustedRegProcNameCount =
    sizeof(g_TrustedRegProcNames) / sizeof(g_TrustedRegProcNames[0]);

//=============================================================================
// AvRegIsTrustedProcess - 当前进程是否为可信系统进程
// IRQL: PASSIVE_LEVEL
//
// 可信进程的注册表操作直接放行:
//   - 信任客户端 (AVSystem): 避免其自身注册表操作自锁死
//   - System (PID 4): 内核系统进程
//   - 关键系统进程 (winlogon/svchost/csrss/services/lsass/smss/wininit/dwm):
//     这些进程作为 Windows 正常运行的一部分写入敏感注册表路径,
//     拦截会导致系统功能异常。
//
// 不在信任名单中的进程 (包括 reg.exe / regedit.exe / cmd.exe /
// powershell.exe / explorer.exe 等位于 \Windows\System32\ 下的用户工具):
//   命中敏感路径时正常弹窗, 由用户决策。
//=============================================================================

BOOLEAN
AvRegIsTrustedProcess(
    VOID
    )
{
    UINT32 pid = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    PCHAR imageName;
    UINT32 i;

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
    // 关键系统进程 (按镜像名精确匹配, 大小写不敏感)
    // 这些进程名均 ≤14 字符, 不受 PsGetProcessImageFileName 截断影响
    //
    imageName = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (imageName != NULL)
    {
        for (i = 0; i < g_TrustedRegProcNameCount; i++)
        {
            if (_stricmp(imageName, g_TrustedRegProcNames[i]) == 0)
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
    // 非敏感路径/值: 放行
    // (值级敏感检测覆盖 UAC 策略值如 EnableLUA, 及 IFEO Debugger)
    //
    if (!AvRegIsSensitivePath(keyPath) &&
        !AvRegIsSensitiveValue(keyPath, valueName))
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
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
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
    // 保存驱动服务注册表键路径 (规则持久化存储位置)
    // RegistryPath 只在 DriverEntry 期间有效, 必须复制
    //
    g_RegServicePathValid = FALSE;
    if (g_RegServicePath.Buffer != NULL)
    {
        ExFreePool(g_RegServicePath.Buffer);
        g_RegServicePath.Buffer = NULL;
    }

    if (RegistryPath != NULL && RegistryPath->Buffer != NULL && RegistryPath->Length > 0)
    {
        PWCHAR pathBuf = (PWCHAR)AV_ALLOC_PAGED(
            RegistryPath->Length + sizeof(WCHAR), 'lgSP');

        if (pathBuf != NULL)
        {
            RtlCopyMemory(pathBuf, RegistryPath->Buffer, RegistryPath->Length);
            pathBuf[RegistryPath->Length / sizeof(WCHAR)] = L'\0';
            g_RegServicePath.Length = RegistryPath->Length;
            g_RegServicePath.MaximumLength =
                (USHORT)(RegistryPath->Length + sizeof(WCHAR));
            g_RegServicePath.Buffer = pathBuf;
            g_RegServicePathValid = TRUE;
            KdPrint(("AVReg: Service registry path: %wZ\n", RegistryPath));
        }
    }

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

    //
    // 恢复持久化的规则 ("始终允许/始终拒绝" 重启后仍生效)
    //
    AvRegLoadRulesFromRegistry();

    KdPrint(("AVReg: Registry callback registered, rules: %u allow / %u deny\n",
             g_RegAllowRuleCount, g_RegDenyRuleCount));
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

    //
    // 释放驱动服务注册表路径缓冲区
    //
    if (g_RegServicePath.Buffer != NULL)
    {
        ExFreePool(g_RegServicePath.Buffer);
        g_RegServicePath.Buffer = NULL;
        g_RegServicePathValid = FALSE;
    }

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
