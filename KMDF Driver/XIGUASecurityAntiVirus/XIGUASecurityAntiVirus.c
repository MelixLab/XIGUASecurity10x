//=============================================================================
// AVDriver.c - 杀毒驱动 KMDF 主文件
//
// 包含:
//   - DriverEntry: 驱动入口
//   - EvtDriverDeviceAdd: 设备创建
//   - EvtIoDeviceControl: IOCTL 请求处理
//
// IOCTL 处理均在 PASSIVE_LEVEL 完成
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVSession.h"
#include "AVProcessNotify.h"
#include "AVRegNotify.h"
#include "AVInjectNotify.h"

//
// 前向声明 - 确保内核模式下类型可见
//
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT;
typedef DEVICE_CONTEXT* PDEVICE_CONTEXT;

//=============================================================================
// 前向声明 - IOCTL 处理函数 (不使用 SAL 注解以兼容内核模式)
//=============================================================================

static
NTSTATUS
AvIoctlAuthInit(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlAuthVerify(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlValidateSession(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlScanFile(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlGetStatus(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlHeartbeat(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlGetPendingNotification(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlSendProcessDecision(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlAddAllowedPath(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlGetPendingRegNotification(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlSendRegDecision(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlGetPendingInjectionNotification(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlSendInjectionDecision(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

static
NTSTATUS
AvIoctlGetDebugInfo(
    PDEVICE_CONTEXT DevContext,
    WDFREQUEST Request,
    size_t InputBufferSize,
    size_t OutputBufferSize
    );

//=============================================================================
// 前向声明 - 控制设备创建
//=============================================================================

static
NTSTATUS
AvCreateControlDevice(
    _In_ WDFDRIVER Driver
    );

//=============================================================================
// DriverEntry - 驱动入口
// IRQL: PASSIVE_LEVEL
//
// 控制设备模式: 不注册 PnP 设备回调, 驱动加载后立即创建控制设备
//=============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDFDRIVER driver = NULL;
    NTSTATUS status;

    KdPrint(("AVDriver: DriverEntry\n"));

    //
    // 配置 WDF 驱动 (控制设备模式, 无 PnP 设备回调)
    //
    WDF_DRIVER_CONFIG_INIT(&config, NULL);

    //
    // 注册驱动清理回调
    //
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);
    driverAttributes.EvtCleanupCallback = EvtDriverContextCleanup;

    //
    // 创建 WDF 驱动对象
    //
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &driverAttributes,
        &config,
        &driver
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: WdfDriverCreate failed 0x%08X\n", status));
        return status;
    }

    //
    // 创建控制设备 (sc start 加载后立即可用, 无需 INF)
    //
    status = AvCreateControlDevice(driver);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvCreateControlDevice failed 0x%08X\n", status));
        return status;
    }

    KdPrint(("AVDriver: DriverEntry completed successfully\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// AvCreateControlDevice - 创建控制设备
// IRQL: PASSIVE_LEVEL
//
// 控制设备模式: 驱动加载 (sc start) 后立即创建设备和符号链接,
// 无需 INF 安装或 PnP 枚举。AVSystem 通过 \\.\AVDriver 连接。
//=============================================================================

static
NTSTATUS
AvCreateControlDevice(
    _In_ WDFDRIVER Driver
    )
{
    PWDFDEVICE_INIT controlInit = NULL;
    WDFDEVICE device = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue = NULL;
    PDEVICE_CONTEXT devContext = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    UNICODE_STRING sddl;
    NTSTATUS status;

    PAGED_CODE();

    //
    // 构建安全描述符 SDDL: 仅 SYSTEM 和管理员可访问
    //
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    //
    // 分配控制设备初始化结构
    //
    controlInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (controlInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 设置设备属性 (METHOD_BUFFERED, 无 PnP)
    //
    WdfDeviceInitSetDeviceType(controlInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(controlInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetCharacteristics(controlInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    //
    // 分配设备名称
    //
    RtlInitUnicodeString(&deviceName, AV_DEVICE_NAME);
    status = WdfDeviceInitAssignName(controlInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    //
    // 创建设备对象 (带设备上下文)
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DEVICE_CONTEXT);
    status = WdfDeviceCreate(&controlInit, &attributes, &device);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: WdfDeviceCreate failed 0x%08X\n", status));
        return status;
    }

    //
    // 获取设备上下文
    //
    devContext = GetDeviceContext(device);
    if (devContext == NULL)
    {
        KdPrint(("AVDriver: GetDeviceContext returned NULL\n"));
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 初始化设备上下文
    //
    devContext->DefaultQueue = NULL;
    devContext->SessionCount = 0;
    devContext->TotalScans = 0;
    devContext->SequenceCounter = 0;
    RtlZeroMemory(devContext->Sessions, sizeof(devContext->Sessions));
    KeQuerySystemTime(&devContext->StartTime);

    //
    // 创建会话锁 (WDFWAITLOCK, 仅在 PASSIVE_LEVEL 使用)
    //
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &devContext->SessionLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: WdfWaitLockCreate failed 0x%08X\n", status));
        return status;
    }

    //
    // 创建符号链接
    //
    RtlInitUnicodeString(&symlinkName, AV_SYMLINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: WdfDeviceCreateSymbolicLink failed 0x%08X\n", status));
        return status;
    }

    //
    // 创建默认 IO 队列 (Sequential 模式)
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: WdfIoQueueCreate failed 0x%08X\n", status));
        return status;
    }

    devContext->DefaultQueue = queue;

    //
    // 完成控制设备初始化 (此后设备可被打开)
    //
    WdfControlFinishInitializing(device);

    //
    // 初始化进程通知模块 (拦截系统目录进程启动)
    // 失败则致命: 拦截是核心功能, 无法注册回调时驱动不应继续运行
    //
    status = AvProcessNotifyInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvProcessNotifyInitialize failed 0x%08X (fatal)\n", status));
        return status;
    }

    //
    // 初始化注册表通知模块 (拦截敏感注册表操作)
    // 失败不致命: 注册表防护是附加功能, 失败时仅记录日志继续运行
    // Driver 参数传真实驱动对象, 供 CmRegisterCallbackEx 使用
    //
    status = AvRegNotifyInitialize(WdfDriverWdmGetDriverObject(Driver));
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvRegNotifyInitialize failed 0x%08X (non-fatal)\n", status));
    }

    //
    // 初始化远程线程注入防护模块 (跨进程线程创建检测)
    // 失败不致命: 注入防护是附加功能, 失败时仅记录日志继续运行
    //
    status = AvInjectNotifyInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvInjectNotifyInitialize failed 0x%08X (non-fatal)\n", status));
    }

    KdPrint(("AVDriver: Control device created successfully\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// EvtDriverContextCleanup - 驱动卸载清理回调
// IRQL: PASSIVE_LEVEL
//
// 驱动卸载时清理进程通知资源
//=============================================================================

VOID
EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("AVDriver: EvtDriverContextCleanup\n"));

    //
    // 卸载远程线程注入防护模块
    //
    AvInjectNotifyUninitialize();

    //
    // 卸载注册表通知模块
    // (CmUnregisterCallback 等待正在执行的回调返回, 回调内最多阻塞 30 秒)
    //
    AvRegNotifyUninitialize();

    //
    // 卸载进程通知模块
    //
    AvProcessNotifyUninitialize();
}

//=============================================================================
// EvtIoDeviceControl - IOCTL 请求处理回调
// IRQL: PASSIVE_LEVEL
//
// 分发所有 IOCTL 请求到对应的处理函数
//=============================================================================

VOID
EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    PDEVICE_CONTEXT devContext = NULL;
    WDFDEVICE device = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    //
    // 标记客户端活跃 (用户态 IOCTL 心跳)
    // 回调拦截依赖此时间戳: 用户态退出后约 5 秒自动静默放行
    //
    AvProcessMarkClientActive();

    //
    // 获取设备对象和上下文
    //
    device = WdfIoQueueGetDevice(Queue);
    if (device == NULL)
    {
        KdPrint(("AVDriver: WdfIoQueueGetDevice returned NULL\n"));
        WdfRequestComplete(Request, STATUS_UNSUCCESSFUL);
        return;
    }

    devContext = GetDeviceContext(device);
    if (devContext == NULL)
    {
        KdPrint(("AVDriver: GetDeviceContext returned NULL\n"));
        WdfRequestComplete(Request, STATUS_UNSUCCESSFUL);
        return;
    }

    //
    // 获取实际缓冲区长度 (METHOD_BUFFERED 模式下输入输出使用同一缓冲区)
    // 注意: WdfRequestRetrieve*Buffer 的 Buffer 参数必须非 NULL,
    //       否则触发 WDF_VIOLATION (0x10D, Arg1=0x4)
    //
    size_t inputBufferSize = 0;
    size_t outputBufferSize = 0;
    PVOID probeBuffer = NULL;

    status = WdfRequestRetrieveInputBuffer(Request, 0, &probeBuffer, &inputBufferSize);
    if (!NT_SUCCESS(status))
    {
        //
        // 输入缓冲区可能为空, 对于不需要输入的 IOCTL 是正常的
        //
        inputBufferSize = 0;
    }

    probeBuffer = NULL;
    status = WdfRequestRetrieveOutputBuffer(Request, 0, &probeBuffer, &outputBufferSize);
    if (!NT_SUCCESS(status))
    {
        outputBufferSize = 0;
    }

    //
    // 根据 IOCTL 码分发
    //
    switch (IoControlCode)
    {
    case IOCTL_AV_AUTH_INIT:
        status = AvIoctlAuthInit(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_AUTH_VERIFY:
        status = AvIoctlAuthVerify(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_AUTH_VALIDATE_SESSION:
        status = AvIoctlValidateSession(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_SCAN_FILE:
        status = AvIoctlScanFile(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_GET_STATUS:
        status = AvIoctlGetStatus(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_HEARTBEAT:
        status = AvIoctlHeartbeat(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_GET_PENDING_NOTIFICATION:
        status = AvIoctlGetPendingNotification(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_SEND_PROCESS_DECISION:
        status = AvIoctlSendProcessDecision(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_ADD_ALLOWED_PATH:
        status = AvIoctlAddAllowedPath(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION:
        status = AvIoctlGetPendingRegNotification(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_SEND_REGISTRY_DECISION:
        status = AvIoctlSendRegDecision(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION:
        status = AvIoctlGetPendingInjectionNotification(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_SEND_INJECTION_DECISION:
        status = AvIoctlSendInjectionDecision(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    case IOCTL_AV_GET_DEBUG_INFO:
        status = AvIoctlGetDebugInfo(devContext, Request, inputBufferSize, outputBufferSize);
        break;

    default:
        KdPrint(("AVDriver: Unknown IOCTL 0x%08X\n", IoControlCode));
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }

    //
    // 如果 IOCTL 处理函数已经调用了 WdfRequestComplete, 这里不再操作
    // status 仅用于记录日志
    //
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: IOCTL 0x%08X completed with status 0x%08X\n",
                 IoControlCode, status));
    }
}

//=============================================================================
// AvIoctlAuthInit - 处理鉴权初始化请求
// IRQL: PASSIVE_LEVEL
//
// 输入: 无 (或可忽略)
// 输出: AV_AUTH_CHALLENGE
//=============================================================================

static
NTSTATUS
AvIoctlAuthInit(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_AUTH_CHALLENGE* challenge = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(InputBufferSize);

    //
    // 校验输出缓冲区大小
    //
    if (OutputBufferSize < sizeof(AV_AUTH_CHALLENGE))
    {
        KdPrint(("AVDriver: IOCTL_AV_AUTH_INIT buffer too small (%llu < %llu)\n",
                 (ULONGLONG)OutputBufferSize, (ULONGLONG)sizeof(AV_AUTH_CHALLENGE)));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_AUTH_CHALLENGE),
        (PVOID*)&challenge,
        NULL
        );

    if (!NT_SUCCESS(status) || challenge == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 生成随机 Challenge
    //
    status = AvAuthGenerateChallenge(challenge);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvAuthGenerateChallenge failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 设置序列号 (原子递增防止重放)
    //
    challenge->SequenceId = InterlockedIncrement64((PLONG64)&DevContext->SequenceCounter);

    //
    // 设置输出长度并完成请求
    //
    WdfRequestSetInformation(Request, sizeof(AV_AUTH_CHALLENGE));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlAuthVerify - 处理鉴权验证请求
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_AUTH_RESPONSE
// 输出: AV_AUTH_RESULT
//=============================================================================

static
NTSTATUS
AvIoctlAuthVerify(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_AUTH_RESPONSE* response = NULL;
    AV_AUTH_RESPONSE localResponse;
    AV_AUTH_RESULT* result = NULL;
    BOOLEAN isValid = FALSE;
    UCHAR expectedHmac[AV_HASH_SIZE];
    NTSTATUS status;

    PAGED_CODE();

    //
    // 校验缓冲区大小
    //
    if (InputBufferSize < sizeof(AV_AUTH_RESPONSE))
    {
        KdPrint(("AVDriver: IOCTL_AV_AUTH_VERIFY input too small (%llu < %llu)\n",
                 (ULONGLONG)InputBufferSize, (ULONGLONG)sizeof(AV_AUTH_RESPONSE)));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferSize < sizeof(AV_AUTH_RESULT))
    {
        KdPrint(("AVDriver: IOCTL_AV_AUTH_VERIFY output too small (%llu < %llu)\n",
                 (ULONGLONG)OutputBufferSize, (ULONGLONG)sizeof(AV_AUTH_RESULT)));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输入缓冲区
    //
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_AUTH_RESPONSE),
        (PVOID*)&response,
        NULL
        );

    if (!NT_SUCCESS(status) || response == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // METHOD_BUFFERED 下输入输出共用同一系统缓冲!
    // 必须先复制输入到本地, 否则后续对输出缓冲的写操作会破坏输入数据
    //
    RtlCopyMemory(&localResponse, response, sizeof(AV_AUTH_RESPONSE));

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_AUTH_RESULT),
        (PVOID*)&result,
        NULL
        );

    if (!NT_SUCCESS(status) || result == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 初始化输出
    //
    RtlZeroMemory(result, sizeof(AV_AUTH_RESULT));
    RtlZeroMemory(expectedHmac, sizeof(expectedHmac));

    //
    // 验证 HMAC 响应 (使用本地副本, 避免输出缓冲覆盖输入)
    //
    status = AvAuthVerifyResponse(&localResponse, &isValid, expectedHmac);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvAuthVerifyResponse failed 0x%08X\n", status));
        result->Status = status;
        WdfRequestSetInformation(Request, sizeof(AV_AUTH_RESULT));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    if (!isValid)
    {
        KdPrint(("AVDriver: Authentication failed - invalid HMAC\n"));
        result->Status = STATUS_ACCESS_DENIED;

        //
        // 调试回显: expectedHmac[0..7] -> SessionId[0..7], 收到的 Hmac[0..7] -> SessionId[8..15]
        // 用户态可通过 authResult.SessionId 查看驱动端计算值与接收值的对比
        //
        RtlCopyMemory(result->SessionId, expectedHmac, 8);
        RtlCopyMemory(result->SessionId + 8, localResponse.Hmac, 8);

        WdfRequestSetInformation(Request, sizeof(AV_AUTH_RESULT));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    //
    // 鉴权通过, 创建会话
    //
    status = AvSessionCreate(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        &DevContext->SessionCount,
        PsGetCurrentProcessId(),
        result->SessionId
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvSessionCreate failed 0x%08X\n", status));
        result->Status = status;
    }
    else
    {
        result->Status = STATUS_SUCCESS;

        //
        // 记录信任客户端 (AVSystem) PID
        // 注册表回调对信任进程自身的注册表操作直接放行, 避免自锁死
        //
        AvRegSetTrustedClientPid((UINT32)(ULONG_PTR)PsGetCurrentProcessId());
    }

    WdfRequestSetInformation(Request, sizeof(AV_AUTH_RESULT));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlValidateSession - 处理会话验证请求
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_SESSION_VALIDATE
// 输出: AV_SESSION_RESULT
//=============================================================================

static
NTSTATUS
AvIoctlValidateSession(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_SESSION_VALIDATE* validate = NULL;
    AV_SESSION_RESULT* result = NULL;
    NTSTATUS status;

    PAGED_CODE();

    //
    // 校验缓冲区大小
    //
    if (InputBufferSize < sizeof(AV_SESSION_VALIDATE))
    {
        KdPrint(("AVDriver: IOCTL_AV_AUTH_VALIDATE_SESSION input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferSize < sizeof(AV_SESSION_RESULT))
    {
        KdPrint(("AVDriver: IOCTL_AV_AUTH_VALIDATE_SESSION output too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输入缓冲区
    //
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_SESSION_VALIDATE),
        (PVOID*)&validate,
        NULL
        );

    if (!NT_SUCCESS(status) || validate == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_SESSION_RESULT),
        (PVOID*)&result,
        NULL
        );

    if (!NT_SUCCESS(status) || result == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 验证会话
    //
    status = AvSessionValidate(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        validate->SessionId
        );

    if (NT_SUCCESS(status))
    {
        result->Status = STATUS_SUCCESS;
    }
    else
    {
        result->Status = STATUS_NOT_FOUND;
    }

    WdfRequestSetInformation(Request, sizeof(AV_SESSION_RESULT));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlScanFile - 处理文件扫描请求
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_SCAN_REQUEST (变长)
// 输出: AV_SCAN_RESPONSE
//=============================================================================

static
NTSTATUS
AvIoctlScanFile(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_SCAN_REQUEST* scanReq = NULL;
    AV_SCAN_RESPONSE* scanResp = NULL;
    NTSTATUS status;

    PAGED_CODE();

    //
    // 校验缓冲区大小: 输入至少包含 SessionId + RequestId + FilePathLength
    //
    if (InputBufferSize < sizeof(AV_SCAN_REQUEST))
    {
        KdPrint(("AVDriver: IOCTL_AV_SCAN_FILE input too small (%llu < %llu)\n",
                 (ULONGLONG)InputBufferSize, (ULONGLONG)sizeof(AV_SCAN_REQUEST)));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferSize < sizeof(AV_SCAN_RESPONSE))
    {
        KdPrint(("AVDriver: IOCTL_AV_SCAN_FILE output too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输入缓冲区
    //
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_SCAN_REQUEST),
        (PVOID*)&scanReq,
        NULL
        );

    if (!NT_SUCCESS(status) || scanReq == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 验证 FilePathLength 不越界
    //
    if (scanReq->FilePathLength > AV_MAX_IOCTL_SIZE ||
        (sizeof(AV_SCAN_REQUEST) + scanReq->FilePathLength - sizeof(WCHAR)) > InputBufferSize)
    {
        KdPrint(("AVDriver: Scan request invalid FilePathLength %u\n",
                 scanReq->FilePathLength));
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_SCAN_RESPONSE),
        (PVOID*)&scanResp,
        NULL
        );

    if (!NT_SUCCESS(status) || scanResp == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 验证会话
    //
    status = AvSessionValidate(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        scanReq->SessionId
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: Scan request - invalid session\n"));
        scanResp->RequestId = scanReq->RequestId;
        scanResp->Status = STATUS_ACCESS_DENIED;
        scanResp->ThreatLevel = 0;
        RtlZeroMemory(scanResp->ThreatName, sizeof(scanResp->ThreatName));

        WdfRequestSetInformation(Request, sizeof(AV_SCAN_RESPONSE));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    //
    // 更新会话活动时间
    //
    AvSessionUpdateActivity(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        scanReq->SessionId
        );

    //
    // Mock 扫描: 返回安全结果
    //
    DevContext->TotalScans++;
    scanResp->RequestId = scanReq->RequestId;
    scanResp->Status = STATUS_SUCCESS;
    scanResp->ThreatLevel = 0;   // 0 = 安全
    RtlZeroMemory(scanResp->ThreatName, sizeof(scanResp->ThreatName));

    KdPrint(("AVDriver: Mock scan completed for RequestId %llu\n", scanReq->RequestId));

    WdfRequestSetInformation(Request, sizeof(AV_SCAN_RESPONSE));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlGetStatus - 获取驱动状态
// IRQL: PASSIVE_LEVEL
//
// 输入: 无
// 输出: AV_DRIVER_STATUS
//=============================================================================

static
NTSTATUS
AvIoctlGetStatus(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_DRIVER_STATUS* statusOut = NULL;
    NTSTATUS status;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER uptimeDelta;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(InputBufferSize);

    //
    // 校验输出缓冲区大小
    //
    if (OutputBufferSize < sizeof(AV_DRIVER_STATUS))
    {
        KdPrint(("AVDriver: IOCTL_AV_GET_STATUS buffer too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_DRIVER_STATUS),
        (PVOID*)&statusOut,
        NULL
        );

    if (!NT_SUCCESS(status) || statusOut == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 计算运行时间
    //
    KeQuerySystemTime(&currentTime);
    uptimeDelta.QuadPart = currentTime.QuadPart - DevContext->StartTime.QuadPart;
    //
    // 系统时间以 100ns 为单位, 转换为毫秒
    //
    ULONGLONG uptimeMs = (ULONGLONG)(uptimeDelta.QuadPart / 10000);

    //
    // 填充状态结构
    //
    statusOut->Version = AV_DRIVER_VERSION;
    statusOut->ActiveSessions = DevContext->SessionCount;
    statusOut->TotalScans = DevContext->TotalScans;
    statusOut->UptimeMs = uptimeMs;

    //
    // 进程通知统计 (回调触发/拦截次数)
    //
    AvProcessGetStats(&statusOut->ProcessCallbackTriggers,
                      &statusOut->ProcessBlockAttempts);

    KdPrint(("AVDriver: Status - Version=%u Sessions=%u Scans=%llu Uptime=%llums "
             "CbTrig=%llu Block=%llu\n",
             statusOut->Version, statusOut->ActiveSessions,
             statusOut->TotalScans, statusOut->UptimeMs,
             statusOut->ProcessCallbackTriggers,
             statusOut->ProcessBlockAttempts));

    WdfRequestSetInformation(Request, sizeof(AV_DRIVER_STATUS));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlHeartbeat - 处理心跳请求
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_HEARTBEAT_REQUEST
// 输出: AV_HEARTBEAT_RESPONSE
//=============================================================================

static
NTSTATUS
AvIoctlHeartbeat(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_HEARTBEAT_REQUEST* hbReq = NULL;
    AV_HEARTBEAT_REQUEST localHbReq;
    AV_HEARTBEAT_RESPONSE* hbResp = NULL;
    BOOLEAN hmacValid = FALSE;
    NTSTATUS status;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    //
    // 校验缓冲区大小
    //
    if (InputBufferSize < sizeof(AV_HEARTBEAT_REQUEST))
    {
        KdPrint(("AVDriver: IOCTL_AV_HEARTBEAT input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (OutputBufferSize < sizeof(AV_HEARTBEAT_RESPONSE))
    {
        KdPrint(("AVDriver: IOCTL_AV_HEARTBEAT output too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 获取输入缓冲区
    //
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_HEARTBEAT_REQUEST),
        (PVOID*)&hbReq,
        NULL
        );

    if (!NT_SUCCESS(status) || hbReq == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // METHOD_BUFFERED 下输入输出共用同一系统缓冲!
    // 必须先复制输入到本地, 否则后续对输出缓冲的写操作会破坏输入数据
    //
    RtlCopyMemory(&localHbReq, hbReq, sizeof(AV_HEARTBEAT_REQUEST));

    //
    // 获取输出缓冲区
    //
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_HEARTBEAT_RESPONSE),
        (PVOID*)&hbResp,
        NULL
        );

    if (!NT_SUCCESS(status) || hbResp == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    //
    // 初始化输出
    //
    RtlZeroMemory(hbResp, sizeof(AV_HEARTBEAT_RESPONSE));
    KeQuerySystemTime(&currentTime);
    hbResp->ServerTimestamp = (UINT64)currentTime.QuadPart;

    //
    // Step 1: 验证会话是否存在
    //
    status = AvSessionValidate(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        localHbReq.SessionId
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: Heartbeat - invalid session\n"));
        hbResp->Status = STATUS_ACCESS_DENIED;
        WdfRequestSetInformation(Request, sizeof(AV_HEARTBEAT_RESPONSE));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    //
    // Step 2: 验证心跳 HMAC
    //
    status = AvAuthVerifyHeartbeatHmac(&localHbReq, &hmacValid);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: Heartbeat - HMAC verification failed 0x%08X\n", status));
        hbResp->Status = STATUS_ACCESS_DENIED;
        WdfRequestSetInformation(Request, sizeof(AV_HEARTBEAT_RESPONSE));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    if (!hmacValid)
    {
        KdPrint(("AVDriver: Heartbeat - invalid HMAC\n"));
        hbResp->Status = STATUS_ACCESS_DENIED;
        WdfRequestSetInformation(Request, sizeof(AV_HEARTBEAT_RESPONSE));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    //
    // Step 3: 更新会话活动时间
    //
    AvSessionUpdateActivity(
        DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        localHbReq.SessionId
        );

    hbResp->Status = STATUS_SUCCESS;

    KdPrint(("AVDriver: Heartbeat processed successfully for session\n"));

    WdfRequestSetInformation(Request, sizeof(AV_HEARTBEAT_RESPONSE));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlGetPendingNotification - 获取待处理的进程拦截通知
// IRQL: PASSIVE_LEVEL
//
// 输入: 无
// 输出: AV_PROCESS_NOTIFICATION
//=============================================================================

static
NTSTATUS
AvIoctlGetPendingNotification(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_PROCESS_NOTIFICATION* notification = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    if (OutputBufferSize < sizeof(AV_PROCESS_NOTIFICATION))
    {
        KdPrint(("AVDriver: IOCTL_AV_GET_PENDING_NOTIFICATION buffer too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_PROCESS_NOTIFICATION),
        (PVOID*)&notification,
        NULL
        );

    if (!NT_SUCCESS(status) || notification == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvProcessGetPendingNotification(notification);

    WdfRequestSetInformation(Request, sizeof(AV_PROCESS_NOTIFICATION));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlSendProcessDecision - 处理用户态的进程决策
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_PROCESS_DECISION
// 输出: 无
//=============================================================================

static
NTSTATUS
AvIoctlSendProcessDecision(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_PROCESS_DECISION* decision = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    if (InputBufferSize < sizeof(AV_PROCESS_DECISION))
    {
        KdPrint(("AVDriver: IOCTL_AV_SEND_PROCESS_DECISION input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_PROCESS_DECISION),
        (PVOID*)&decision,
        NULL
        );

    if (!NT_SUCCESS(status) || decision == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvProcessHandleDecision(decision);

    WdfRequestComplete(Request, status);
    return status;
}

//=============================================================================
// AvIoctlAddAllowedPath - 添加路径到白名单
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_ALLOWED_PATH_ENTRY
// 输出: 无
//=============================================================================

static
NTSTATUS
AvIoctlAddAllowedPath(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_ALLOWED_PATH_ENTRY* pathEntry = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    if (InputBufferSize < sizeof(AV_ALLOWED_PATH_ENTRY))
    {
        KdPrint(("AVDriver: IOCTL_AV_ADD_ALLOWED_PATH input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_ALLOWED_PATH_ENTRY),
        (PVOID*)&pathEntry,
        NULL
        );

    if (!NT_SUCCESS(status) || pathEntry == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvProcessAddToAllowList(pathEntry->ImagePath);

    WdfRequestComplete(Request, status);
    return status;
}

//=============================================================================
// AvIoctlGetPendingRegNotification - 获取待处理的注册表拦截通知
// IRQL: PASSIVE_LEVEL
//
// 输入: 无
// 输出: AV_REGISTRY_NOTIFICATION
//=============================================================================

static
NTSTATUS
AvIoctlGetPendingRegNotification(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_REGISTRY_NOTIFICATION* notification = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    if (OutputBufferSize < sizeof(AV_REGISTRY_NOTIFICATION))
    {
        KdPrint(("AVDriver: IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION buffer too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_REGISTRY_NOTIFICATION),
        (PVOID*)&notification,
        NULL
        );

    if (!NT_SUCCESS(status) || notification == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvRegGetPendingNotification(notification);

    WdfRequestSetInformation(Request, sizeof(AV_REGISTRY_NOTIFICATION));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlSendRegDecision - 处理用户态的注册表决策
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_REGISTRY_DECISION
// 输出: 无
//=============================================================================

static
NTSTATUS
AvIoctlSendRegDecision(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_REGISTRY_DECISION* decision = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    if (InputBufferSize < sizeof(AV_REGISTRY_DECISION))
    {
        KdPrint(("AVDriver: IOCTL_AV_SEND_REGISTRY_DECISION input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_REGISTRY_DECISION),
        (PVOID*)&decision,
        NULL
        );

    if (!NT_SUCCESS(status) || decision == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvRegHandleDecision(decision);

    WdfRequestComplete(Request, status);
    return status;
}

//=============================================================================
// AvIoctlGetPendingInjectionNotification - 获取待处理的注入拦截通知
// IRQL: PASSIVE_LEVEL
//
// 输入: 无
// 输出: AV_INJECTION_NOTIFICATION
//=============================================================================

static
NTSTATUS
AvIoctlGetPendingInjectionNotification(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_INJECTION_NOTIFICATION* notification = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    if (OutputBufferSize < sizeof(AV_INJECTION_NOTIFICATION))
    {
        KdPrint(("AVDriver: IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION buffer too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_INJECTION_NOTIFICATION),
        (PVOID*)&notification,
        NULL
        );

    if (!NT_SUCCESS(status) || notification == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvInjectGetPendingNotification(notification);

    WdfRequestSetInformation(Request, sizeof(AV_INJECTION_NOTIFICATION));
    WdfRequestComplete(Request, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

//=============================================================================
// AvIoctlSendInjectionDecision - 处理用户态的注入决策
// IRQL: PASSIVE_LEVEL
//
// 输入: AV_INJECTION_DECISION
// 输出: 无
//=============================================================================

static
NTSTATUS
AvIoctlSendInjectionDecision(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_INJECTION_DECISION* decision = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    if (InputBufferSize < sizeof(AV_INJECTION_DECISION))
    {
        KdPrint(("AVDriver: IOCTL_AV_SEND_INJECTION_DECISION input too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(AV_INJECTION_DECISION),
        (PVOID*)&decision,
        NULL
        );

    if (!NT_SUCCESS(status) || decision == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveInputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvInjectHandleDecision(decision);

    WdfRequestComplete(Request, status);
    return status;
}

//=============================================================================
// AvIoctlGetDebugInfo - 获取驱动诊断信息
// IRQL: PASSIVE_LEVEL
//
// 输出: AV_DEBUG_INFO
//=============================================================================

static
NTSTATUS
AvIoctlGetDebugInfo(
    _In_ PDEVICE_CONTEXT DevContext,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferSize,
    _In_ size_t OutputBufferSize
    )
{
    AV_DEBUG_INFO* debugInfo = NULL;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    if (OutputBufferSize < sizeof(AV_DEBUG_INFO))
    {
        KdPrint(("AVDriver: IOCTL_AV_GET_DEBUG_INFO buffer too small\n"));
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(AV_DEBUG_INFO),
        (PVOID*)&debugInfo,
        NULL
        );

    if (!NT_SUCCESS(status) || debugInfo == NULL)
    {
        KdPrint(("AVDriver: WdfRequestRetrieveOutputBuffer failed 0x%08X\n", status));
        WdfRequestComplete(Request, status);
        return status;
    }

    status = AvProcessGetDebugInfo(debugInfo);

    //
    // 填充注册表保护统计
    //
    AvRegGetDebugInfo(debugInfo);

    //
    // 填充远程线程注入防护统计
    //
    AvInjectGetDebugInfo(debugInfo);

    WdfRequestSetInformation(Request, sizeof(AV_DEBUG_INFO));
    WdfRequestComplete(Request, status);
    return status;
}
