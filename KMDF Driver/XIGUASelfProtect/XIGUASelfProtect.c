//=============================================================================
// XGSSelfProtect.c - XIGUASecurity 自我保护驱动
//
// 架构: ObRegisterCallbacks 拦截进程/线程句柄操作
//   - 进程句柄: 剥离 TERMINATE/SUSPEND/VM 等危险权限
//   - 线程句柄: 剥离 THREAD_TERMINATE/THREAD_SUSPEND_RESUME/THREAD_SET_CONTEXT
//   - 子串匹配进程名 (strstr), 绕过 PsGetProcessImageFileName 14 字符截断
//   - 受保护进程之间互相放行
//
// 保护范围 (子串匹配):
//   - "xiguasecurity"  -> 匹配 XIGUASecurity.exe, XIGUASecurityAgent.exe
//   - "avmain"          -> 当前模拟主程序
//   - "msedgewebview2"  -> WebView2 渲染进程
//
// 效果: 外部进程拿到的句柄无法终止/挂起/注入受保护进程
//=============================================================================

#include "XIGUASelfProtect.h"
#include <ntstrsafe.h>
#include <wdmsec.h>

//=============================================================================
// 手动声明的权限位 (避免头文件差异)
//=============================================================================
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE              0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD          0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION           0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE               0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE             0x0040
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION        0x0200
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION      0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME         0x0800
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA              0x0100
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS         0x0080
#endif
#ifndef SYNCHRONIZE
#define SYNCHRONIZE                    0x00100000L
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE               0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME          0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT             0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION         0x0020
#endif

//
// 进程句柄剥离掩码 (阻止所有可能用于终止/操纵的权限)
//
#define XGS_SP_PROCESS_DENY_MASK  \
    (PROCESS_TERMINATE     | \
     PROCESS_CREATE_THREAD | \
     PROCESS_SUSPEND_RESUME| \
     PROCESS_VM_OPERATION  | \
     PROCESS_VM_WRITE      | \
     PROCESS_VM_READ       | \
     PROCESS_DUP_HANDLE    | \
     PROCESS_SET_INFORMATION| \
     PROCESS_SET_QUOTA     | \
     PROCESS_CREATE_PROCESS)

//
// 线程句柄剥离掩码
//
#define XGS_SP_THREAD_DENY_MASK  \
    (THREAD_TERMINATE      | \
     THREAD_SUSPEND_RESUME | \
     THREAD_SET_CONTEXT    | \
     THREAD_SET_INFORMATION)

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
PEPROCESS
NTAPI
IoThreadToProcess(
    _In_ PETHREAD Thread
    );

//=============================================================================
// 全局状态
//=============================================================================
static PDRIVER_OBJECT  g_DriverObject = NULL;
static PVOID           g_ObRegHandle  = NULL;

//
// 通道保活机制:
//   Agent 打开 \\.\XGSSelfProtect 设备句柄时, g_SessionCount++ -> 自保激活
//   Agent 退出/崩溃/句柄关闭时, g_SessionCount-- -> 自保失效
//   下次 Agent 启动时, 自保暂时关闭, 系统进程可正常初始化 Agent
//   Agent 初始化完成后重新打开句柄 -> 自保恢复
//
static volatile LONG   g_SessionCount    = 0;   // 打开的设备句柄数
static volatile BOOLEAN g_ProtectionActive = FALSE;  // 自保是否激活

//=============================================================================
// 字符串工具 (不依赖 CRT)
//=============================================================================

static
SIZE_T
SpStrLenA(
    _In_ PCSTR s
    )
{
    SIZE_T n = 0;
    while (s[n] != '\0')
    {
        n++;
    }
    return n;
}

//
// ASCII 转小写
//
static
CHAR
SpToLowerA(
    _In_ CHAR c
    )
{
    if (c >= 'A' && c <= 'Z')
    {
        return (CHAR)(c + 32);
    }
    return c;
}

//
// 大小写不敏感的子串查找 (类似 strstr)
// 返回 TRUE 如果 haystack 包含 needle
//
static
BOOLEAN
SpContainsSubstrA(
    _In_ PCSTR haystack,
    _In_ PCSTR needle
    )
{
    SIZE_T hayLen;
    SIZE_T needleLen;
    SIZE_T i;
    SIZE_T j;

    if (haystack == NULL || needle == NULL)
    {
        return FALSE;
    }

    hayLen = SpStrLenA(haystack);
    needleLen = SpStrLenA(needle);

    if (needleLen == 0 || hayLen < needleLen)
    {
        return FALSE;
    }

    for (i = 0; i + needleLen <= hayLen; i++)
    {
        BOOLEAN match = TRUE;
        for (j = 0; j < needleLen; j++)
        {
            if (SpToLowerA(haystack[i + j]) != SpToLowerA(needle[j]))
            {
                match = FALSE;
                break;
            }
        }
        if (match)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 检查进程名是否为受保护进程 (子串匹配, 绕过 14 字符截断)
// 例如 "XIGUASECURITYAGENT" (截断为 "XIGUASECURITYAG") 仍能匹配 "xiguasecurity"
//
static
BOOLEAN
SpIsProtectedProcessName(
    _In_opt_ PCHAR processName
    )
{
    if (processName == NULL || processName[0] == '\0')
    {
        return FALSE;
    }

    //
    // 子串匹配: 只要进程名包含以下关键字之一即为受保护进程
    // - "xiguasecurity" -> 匹配 XIGUASecurity.exe / XIGUASecurityAgent.exe
    // - "avmain"         -> 当前模拟主程序
    // - "msedgewebview2" -> WebView2 渲染进程
    //
    if (SpContainsSubstrA(processName, "xiguasecurity") ||
        SpContainsSubstrA(processName, "avmain") ||
        SpContainsSubstrA(processName, "msedgewebview2"))
    {
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// ObRegisterCallbacks - 进程/线程句柄拦截
//=============================================================================

//
// 预操作回调 (同时处理进程和线程句柄)
//
static
OB_PREOP_CALLBACK_STATUS
SpPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS targetProcess = NULL;
    PEPROCESS currentProcess;
    PCHAR targetName;
    PCHAR currentName;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // 通道保活检查: 通道断开时自保完全失效
    // (Agent 退出后, 系统进程需要能正常打开受保护进程做初始化)
    //
    if (!g_ProtectionActive)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 仅处理句柄创建和复制
    //
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 获取目标进程:
    //   - 进程句柄: 直接是 Process 对象
    //   - 线程句柄: 通过 IoThreadToProcess 获取所属进程
    //
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        targetProcess = (PEPROCESS)OperationInformation->Object;
    }
    else if (OperationInformation->ObjectType == *PsThreadType)
    {
        targetProcess = IoThreadToProcess((PETHREAD)OperationInformation->Object);
    }
    else
    {
        return OB_PREOP_SUCCESS;
    }

    if (targetProcess == NULL)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 目标是否受保护
    //
    targetName = PsGetProcessImageFileName(targetProcess);
    if (targetName == NULL || !SpIsProtectedProcessName(targetName))
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 自己访问自己 -> 放行
    //
    currentProcess = PsGetCurrentProcess();
    if (currentProcess == targetProcess)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // 受保护进程之间互相访问 -> 放行
    // (XIGUASecurity <-> XIGUASecurityAgent <-> msedgewebview2 之间 IPC/DUP/VM 读写)
    //
    currentName = PsGetProcessImageFileName(currentProcess);
    if (currentName != NULL && SpIsProtectedProcessName(currentName))
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // System (PID 4) 放行
    //
    {
        HANDLE srcPid = PsGetCurrentProcessId();
        if (srcPid == (HANDLE)4 || srcPid == (HANDLE)0)
        {
            return OB_PREOP_SUCCESS;
        }
    }

    //
    // 外部进程访问受保护进程 -> 剥离危险权限
    //
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~XGS_SP_PROCESS_DENY_MASK;
        }
        else
        {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~XGS_SP_PROCESS_DENY_MASK;
        }
    }
    else  // PsThreadType
    {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
        {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~XGS_SP_THREAD_DENY_MASK;
        }
        else
        {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~XGS_SP_THREAD_DENY_MASK;
        }
    }

    KdPrint(("XGSSelfProtect: Stripped %hs handle access from %hs -> %hs\n",
             OperationInformation->ObjectType == *PsProcessType ? "process" : "thread",
             currentName ? currentName : "?",
             targetName));

    return OB_PREOP_SUCCESS;
}

//=============================================================================
// 设备句柄 (通道保活)
//=============================================================================
// Agent 打开 \\.\XGSSelfProtect 时, g_SessionCount++ -> 自保激活
// Agent 退出/句柄关闭时, g_SessionCount-- -> 自保失效
//
static
NTSTATUS
SpCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PIO_STACK_LOCATION ioStack;

    UNREFERENCED_PARAMETER(DeviceObject);

    ioStack = IoGetCurrentIrpStackLocation(Irp);

    if (ioStack->MajorFunction == IRP_MJ_CREATE)
    {
        //
        // 通道建立: 自保激活
        //
        LONG count = InterlockedIncrement(&g_SessionCount);
        g_ProtectionActive = TRUE;
        KdPrint(("XGSSelfProtect: Session opened (count=%d), protection ACTIVE\n", count));
    }
    else if (ioStack->MajorFunction == IRP_MJ_CLOSE)
    {
        //
        // 通道断开: 自保失效
        // (Agent 退出/崩溃 -> 系统进程可正常打开受保护进程做初始化)
        //
        LONG count = InterlockedDecrement(&g_SessionCount);
        if (count <= 0)
        {
            g_ProtectionActive = FALSE;
            KdPrint(("XGSSelfProtect: Session closed (count=%d), protection INACTIVE\n", count));
        }
        else
        {
            KdPrint(("XGSSelfProtect: Session closed (count=%d), protection still active\n", count));
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// IOCTL 处理 (兼容旧版 Agent 的 IOCTL_XGS_SP_REGISTER_PIDS 调用)
// 当前基于镜像名匹配, 不需要注册 PID, 但接受 IOCTL 避免调用失败
//
static
NTSTATUS
SpDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//=============================================================================
// 驱动入口 / 卸载
//=============================================================================

DRIVER_UNLOAD SpUnload;
#pragma alloc_text(PAGE, SpUnload)

VOID
SpUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    PDEVICE_OBJECT device;

    PAGED_CODE();

    KdPrint(("XGSSelfProtect: Unloading\n"));

    //
    // 清理通道保活状态
    //
    g_ProtectionActive = FALSE;
    g_SessionCount = 0;

    if (g_ObRegHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }

    device = g_DriverObject->DeviceObject;
    while (device != NULL)
    {
        PDEVICE_OBJECT next = device->NextDevice;
        IoDeleteDevice(device);
        device = next;
    }

    KdPrint(("XGSSelfProtect: Unloaded\n"));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS st;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT deviceObj = NULL;
    OB_OPERATION_REGISTRATION obReg[2];
    OB_CALLBACK_REGISTRATION obCallbackReg;
    UNICODE_STRING altitude;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("XGSSelfProtect: DriverEntry\n"));

    g_DriverObject = DriverObject;

    //
    // 创建控制设备 (满足 ObRegisterCallbacks 要求)
    // SDDL: System + Admins 完全控制, Everyone 只读
    //
    RtlInitUnicodeString(&devName, L"\\Device\\XGSSelfProtect");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\XGSSelfProtect");
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)");

    st = IoCreateDeviceSecure(DriverObject, 0, &devName,
                              FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN,
                              FALSE, &sddl, NULL, &deviceObj);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSSelfProtect: IoCreateDeviceSecure failed 0x%08X\n", st));
        return st;
    }

    IoCreateSymbolicLink(&symLink, &devName);

    //
    // 注册设备句柄处理 (通道保活机制)
    // Agent 通过打开/关闭 \\.\XGSSelfProtect 控制 自保的激活/失效
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = SpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SpDeviceControl;

    DriverObject->DriverUnload = SpUnload;

    //
    // 注册 Ob 回调 (进程 + 线程)
    // 进程句柄: 阻止终止/挂起/注入/VM 操纵
    // 线程句柄: 阻止通过线程操作终止/挂起/修改上下文
    //
    RtlZeroMemory(obReg, sizeof(obReg));

    obReg[0].ObjectType = PsProcessType;
    obReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obReg[0].PreOperation = SpPreCallback;
    obReg[0].PostOperation = NULL;

    obReg[1].ObjectType = PsThreadType;
    obReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    obReg[1].PreOperation = SpPreCallback;
    obReg[1].PostOperation = NULL;

    RtlZeroMemory(&obCallbackReg, sizeof(obCallbackReg));
    obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    obCallbackReg.OperationRegistrationCount = 2;
    obCallbackReg.OperationRegistration = obReg;

    RtlInitUnicodeString(&altitude, L"329000");
    obCallbackReg.Altitude = altitude;

    st = ObRegisterCallbacks(&obCallbackReg, &g_ObRegHandle);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSSelfProtect: ObRegisterCallbacks failed 0x%08X\n", st));
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(deviceObj);
        return st;
    }

    KdPrint(("XGSSelfProtect: Loaded (process + thread protection active)\n"));

    return STATUS_SUCCESS;
}
