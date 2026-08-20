//=============================================================================
// XIGUASecurityAntiVirus.c - 杀毒驱动 WDM 主文件
//
// 纯 WDM 驱动, 无 KMDF/cng.sys 依赖
// IOCTL 处理均在 PASSIVE_LEVEL 完成, 使用 METHOD_BUFFERED
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVSession.h"
#include "AVProcessNotify.h"
#include "AVRegNotify.h"
#include "AVInjectNotify.h"
#include "AVImageNotify.h"
#include "../AVCommon/AVPoolCompat.h"

//=============================================================================
// 前向声明
//=============================================================================

typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT;

static NTSTATUS AvCreateControlDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

static NTSTATUS AvIoctlAuthInit(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlAuthVerify(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlValidateSession(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlScanFile(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetStatus(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlHeartbeat(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetPendingNotification(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlSendProcessDecision(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlAddAllowedPath(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetPendingRegNotification(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlSendRegDecision(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetPendingInjectionNotification(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlSendInjectionDecision(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetPendingImageNotification(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlSendImageDecision(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);
static NTSTATUS AvIoctlGetDebugInfo(PDEVICE_CONTEXT, PIRP, ULONG, ULONG);

//=============================================================================
// DriverEntry
//=============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    KdPrint(("AVDriver: DriverEntry\n"));

    AVPoolCompatInit();

    DriverObject->MajorFunction[IRP_MJ_CREATE] = AvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AvDispatchDeviceControl;
    DriverObject->DriverUnload = AvDriverUnload;

    status = AvCreateControlDevice(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvCreateControlDevice failed 0x%08X\n", status));
        return status;
    }

    KdPrint(("AVDriver: DriverEntry completed successfully\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// AvCreateControlDevice
//=============================================================================

static NTSTATUS
AvCreateControlDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    PDEVICE_OBJECT deviceObj = NULL;
    PDEVICE_CONTEXT devContext = NULL;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, AV_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(DEVICE_CONTEXT),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObj
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: IoCreateDevice failed 0x%08X\n", status));
        return status;
    }

    deviceObj->Flags |= DO_BUFFERED_IO;
    deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

    devContext = (PDEVICE_CONTEXT)deviceObj->DeviceExtension;
    if (devContext == NULL)
    {
        IoDeleteDevice(deviceObj);
        return STATUS_UNSUCCESSFUL;
    }

    devContext->SessionCount = 0;
    devContext->TotalScans = 0;
    devContext->SequenceCounter = 0;
    RtlZeroMemory(devContext->Sessions, sizeof(devContext->Sessions));
    KeQuerySystemTime(&devContext->StartTime);
    KeInitializeSpinLock(&devContext->SessionLock);

    RtlInitUnicodeString(&symlinkName, AV_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: IoCreateSymbolicLink failed 0x%08X\n", status));
        IoDeleteDevice(deviceObj);
        return status;
    }

    status = AvProcessNotifyInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvProcessNotifyInitialize failed 0x%08X (fatal)\n", status));
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(deviceObj);
        return status;
    }

    status = AvRegNotifyInitialize(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvRegNotifyInitialize failed 0x%08X (non-fatal)\n", status));
    }

    status = AvInjectNotifyInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvInjectNotifyInitialize failed 0x%08X (non-fatal)\n", status));
    }

    status = AvImageNotifyInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvImageNotifyInitialize failed 0x%08X (non-fatal)\n", status));
    }

    KdPrint(("AVDriver: Control device created successfully\n"));
    return STATUS_SUCCESS;
}

//=============================================================================
// AvDriverUnload
//=============================================================================

VOID
AvDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symlinkName;

    PAGED_CODE();

    KdPrint(("AVDriver: AvDriverUnload\n"));

    AvInjectNotifyUninitialize();
    AvImageNotifyUninitialize();
    AvRegNotifyUninitialize();
    AvProcessNotifyUninitialize();

    RtlInitUnicodeString(&symlinkName, AV_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

//=============================================================================
// AvDispatchCreateClose
//=============================================================================

NTSTATUS
AvDispatchCreateClose(
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

//=============================================================================
// AvDispatchDeviceControl
//=============================================================================

NTSTATUS
AvDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp;
    PDEVICE_CONTEXT devContext;
    ULONG ioControlCode;
    ULONG inputBufferSize;
    ULONG outputBufferSize;
    NTSTATUS status;

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    devContext = (PDEVICE_CONTEXT)DeviceObject->DeviceExtension;
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferSize = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferSize = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    AvProcessMarkClientActive();

    switch (ioControlCode)
    {
    case IOCTL_AV_AUTH_INIT:
        status = AvIoctlAuthInit(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_AUTH_VERIFY:
        status = AvIoctlAuthVerify(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_AUTH_VALIDATE_SESSION:
        status = AvIoctlValidateSession(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_SCAN_FILE:
        status = AvIoctlScanFile(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_STATUS:
        status = AvIoctlGetStatus(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_HEARTBEAT:
        status = AvIoctlHeartbeat(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_PENDING_NOTIFICATION:
        status = AvIoctlGetPendingNotification(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_SEND_PROCESS_DECISION:
        status = AvIoctlSendProcessDecision(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_ADD_ALLOWED_PATH:
        status = AvIoctlAddAllowedPath(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION:
        status = AvIoctlGetPendingRegNotification(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_SEND_REGISTRY_DECISION:
        status = AvIoctlSendRegDecision(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION:
        status = AvIoctlGetPendingInjectionNotification(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_SEND_INJECTION_DECISION:
        status = AvIoctlSendInjectionDecision(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_PENDING_IMAGE_NOTIFICATION:
        status = AvIoctlGetPendingImageNotification(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_SEND_IMAGE_DECISION:
        status = AvIoctlSendImageDecision(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    case IOCTL_AV_GET_DEBUG_INFO:
        status = AvIoctlGetDebugInfo(devContext, Irp, inputBufferSize, outputBufferSize);
        break;
    default:
        KdPrint(("AVDriver: Unknown IOCTL 0x%08X\n", ioControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: IOCTL 0x%08X completed with status 0x%08X\n", ioControlCode, status));
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//=============================================================================
// IOCTL 处理函数
// METHOD_BUFFERED: 输入输出共用 Irp->AssociatedIrp.SystemBuffer
//=============================================================================

static NTSTATUS
AvIoctlAuthInit(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_AUTH_CHALLENGE* challenge;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_AUTH_CHALLENGE))
        return STATUS_BUFFER_TOO_SMALL;

    challenge = (AV_AUTH_CHALLENGE*)Irp->AssociatedIrp.SystemBuffer;

    status = AvAuthGenerateChallenge(challenge);
    if (!NT_SUCCESS(status))
        return status;

    challenge->SequenceId = InterlockedIncrement64((PLONG64)&DevContext->SequenceCounter);
    Irp->IoStatus.Information = sizeof(AV_AUTH_CHALLENGE);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlAuthVerify(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_AUTH_RESPONSE* response;
    AV_AUTH_RESPONSE localResponse;
    AV_AUTH_RESULT* result;
    BOOLEAN isValid = FALSE;
    UCHAR expectedHmac[AV_HASH_SIZE];
    NTSTATUS status;

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_AUTH_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputBufferSize < sizeof(AV_AUTH_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    response = (AV_AUTH_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;
    RtlCopyMemory(&localResponse, response, sizeof(AV_AUTH_RESPONSE));

    result = (AV_AUTH_RESULT*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(result, sizeof(AV_AUTH_RESULT));
    RtlZeroMemory(expectedHmac, sizeof(expectedHmac));

    status = AvAuthVerifyResponse(&localResponse, &isValid, expectedHmac);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVDriver: AvAuthVerifyResponse failed 0x%08X\n", status));
        result->Status = status;
        Irp->IoStatus.Information = sizeof(AV_AUTH_RESULT);
        return STATUS_SUCCESS;
    }

    if (!isValid)
    {
        KdPrint(("AVDriver: Authentication failed - invalid HMAC\n"));
        result->Status = STATUS_ACCESS_DENIED;
        RtlCopyMemory(result->SessionId, expectedHmac, 8);
        RtlCopyMemory(result->SessionId + 8, localResponse.Hmac, 8);
        Irp->IoStatus.Information = sizeof(AV_AUTH_RESULT);
        return STATUS_SUCCESS;
    }

    status = AvSessionCreate(
        &DevContext->SessionLock,
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
        AvRegSetTrustedClientPid((UINT32)(ULONG_PTR)PsGetCurrentProcessId());
    }

    Irp->IoStatus.Information = sizeof(AV_AUTH_RESULT);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlValidateSession(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_SESSION_VALIDATE* validate;
    AV_SESSION_RESULT* result;
    NTSTATUS status;

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_SESSION_VALIDATE))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputBufferSize < sizeof(AV_SESSION_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    validate = (AV_SESSION_VALIDATE*)Irp->AssociatedIrp.SystemBuffer;
    result = (AV_SESSION_RESULT*)Irp->AssociatedIrp.SystemBuffer;

    status = AvSessionValidate(
        &DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        validate->SessionId
        );

    result->Status = NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    Irp->IoStatus.Information = sizeof(AV_SESSION_RESULT);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlScanFile(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_SCAN_REQUEST* scanReq;
    AV_SCAN_RESPONSE* scanResp;
    NTSTATUS status;

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_SCAN_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputBufferSize < sizeof(AV_SCAN_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    scanReq = (AV_SCAN_REQUEST*)Irp->AssociatedIrp.SystemBuffer;

    if (scanReq->FilePathLength > AV_MAX_IOCTL_SIZE ||
        (sizeof(AV_SCAN_REQUEST) + scanReq->FilePathLength - sizeof(WCHAR)) > InputBufferSize)
        return STATUS_INVALID_PARAMETER;

    scanResp = (AV_SCAN_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;

    status = AvSessionValidate(
        &DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        scanReq->SessionId
        );

    if (!NT_SUCCESS(status))
    {
        scanResp->RequestId = scanReq->RequestId;
        scanResp->Status = STATUS_ACCESS_DENIED;
        scanResp->ThreatLevel = 0;
        RtlZeroMemory(scanResp->ThreatName, sizeof(scanResp->ThreatName));
        Irp->IoStatus.Information = sizeof(AV_SCAN_RESPONSE);
        return STATUS_SUCCESS;
    }

    AvSessionUpdateActivity(
        &DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        scanReq->SessionId
        );

    DevContext->TotalScans++;
    scanResp->RequestId = scanReq->RequestId;
    scanResp->Status = STATUS_SUCCESS;
    scanResp->ThreatLevel = 0;
    RtlZeroMemory(scanResp->ThreatName, sizeof(scanResp->ThreatName));
    Irp->IoStatus.Information = sizeof(AV_SCAN_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlGetStatus(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_DRIVER_STATUS* statusOut;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER uptimeDelta;
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_DRIVER_STATUS))
        return STATUS_BUFFER_TOO_SMALL;

    statusOut = (AV_DRIVER_STATUS*)Irp->AssociatedIrp.SystemBuffer;

    KeQuerySystemTime(&currentTime);
    uptimeDelta.QuadPart = currentTime.QuadPart - DevContext->StartTime.QuadPart;

    statusOut->Version = AV_DRIVER_VERSION;
    statusOut->ActiveSessions = DevContext->SessionCount;
    statusOut->TotalScans = DevContext->TotalScans;
    statusOut->UptimeMs = (ULONGLONG)(uptimeDelta.QuadPart / 10000);

    AvProcessGetStats(&statusOut->ProcessCallbackTriggers,
                      &statusOut->ProcessBlockAttempts);

    Irp->IoStatus.Information = sizeof(AV_DRIVER_STATUS);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlHeartbeat(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_HEARTBEAT_REQUEST* hbReq;
    AV_HEARTBEAT_REQUEST localHbReq;
    AV_HEARTBEAT_RESPONSE* hbResp;
    BOOLEAN hmacValid = FALSE;
    NTSTATUS status;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_HEARTBEAT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputBufferSize < sizeof(AV_HEARTBEAT_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    hbReq = (AV_HEARTBEAT_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
    RtlCopyMemory(&localHbReq, hbReq, sizeof(AV_HEARTBEAT_REQUEST));

    hbResp = (AV_HEARTBEAT_RESPONSE*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(hbResp, sizeof(AV_HEARTBEAT_RESPONSE));
    KeQuerySystemTime(&currentTime);
    hbResp->ServerTimestamp = (UINT64)currentTime.QuadPart;

    status = AvSessionValidate(
        &DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        localHbReq.SessionId
        );

    if (!NT_SUCCESS(status))
    {
        hbResp->Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = sizeof(AV_HEARTBEAT_RESPONSE);
        return STATUS_SUCCESS;
    }

    status = AvAuthVerifyHeartbeatHmac(&localHbReq, &hmacValid);
    if (!NT_SUCCESS(status) || !hmacValid)
    {
        hbResp->Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = sizeof(AV_HEARTBEAT_RESPONSE);
        return STATUS_SUCCESS;
    }

    AvSessionUpdateActivity(
        &DevContext->SessionLock,
        DevContext->Sessions,
        AV_MAX_SESSIONS,
        localHbReq.SessionId
        );

    hbResp->Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(AV_HEARTBEAT_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlGetPendingNotification(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_PROCESS_NOTIFICATION* notification;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_PROCESS_NOTIFICATION))
        return STATUS_BUFFER_TOO_SMALL;

    notification = (AV_PROCESS_NOTIFICATION*)Irp->AssociatedIrp.SystemBuffer;
    AvProcessGetPendingNotification(notification);
    Irp->IoStatus.Information = sizeof(AV_PROCESS_NOTIFICATION);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlSendProcessDecision(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_PROCESS_DECISION* decision;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_PROCESS_DECISION))
        return STATUS_BUFFER_TOO_SMALL;

    decision = (AV_PROCESS_DECISION*)Irp->AssociatedIrp.SystemBuffer;
    return AvProcessHandleDecision(decision);
}

static NTSTATUS
AvIoctlAddAllowedPath(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_ALLOWED_PATH_ENTRY* pathEntry;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_ALLOWED_PATH_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    pathEntry = (AV_ALLOWED_PATH_ENTRY*)Irp->AssociatedIrp.SystemBuffer;
    return AvProcessAddToAllowList(pathEntry->ImagePath);
}

static NTSTATUS
AvIoctlGetPendingRegNotification(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_REGISTRY_NOTIFICATION* notification;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_REGISTRY_NOTIFICATION))
        return STATUS_BUFFER_TOO_SMALL;

    notification = (AV_REGISTRY_NOTIFICATION*)Irp->AssociatedIrp.SystemBuffer;
    AvRegGetPendingNotification(notification);
    Irp->IoStatus.Information = sizeof(AV_REGISTRY_NOTIFICATION);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlSendRegDecision(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_REGISTRY_DECISION* decision;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_REGISTRY_DECISION))
        return STATUS_BUFFER_TOO_SMALL;

    decision = (AV_REGISTRY_DECISION*)Irp->AssociatedIrp.SystemBuffer;
    return AvRegHandleDecision(decision);
}

static NTSTATUS
AvIoctlGetPendingInjectionNotification(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_INJECTION_NOTIFICATION* notification;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_INJECTION_NOTIFICATION))
        return STATUS_BUFFER_TOO_SMALL;

    notification = (AV_INJECTION_NOTIFICATION*)Irp->AssociatedIrp.SystemBuffer;
    AvInjectGetPendingNotification(notification);
    Irp->IoStatus.Information = sizeof(AV_INJECTION_NOTIFICATION);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlSendInjectionDecision(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_INJECTION_DECISION* decision;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_INJECTION_DECISION))
        return STATUS_BUFFER_TOO_SMALL;

    decision = (AV_INJECTION_DECISION*)Irp->AssociatedIrp.SystemBuffer;
    return AvInjectHandleDecision(decision);
}

static NTSTATUS
AvIoctlGetPendingImageNotification(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_IMAGE_NOTIFICATION* notification;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_IMAGE_NOTIFICATION))
        return STATUS_BUFFER_TOO_SMALL;

    notification = (AV_IMAGE_NOTIFICATION*)Irp->AssociatedIrp.SystemBuffer;
    AvImageGetPendingNotification(notification);
    Irp->IoStatus.Information = sizeof(AV_IMAGE_NOTIFICATION);
    return STATUS_SUCCESS;
}

static NTSTATUS
AvIoctlSendImageDecision(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_IMAGE_DECISION* decision;
    UNREFERENCED_PARAMETER(DevContext);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    PAGED_CODE();

    if (InputBufferSize < sizeof(AV_IMAGE_DECISION))
        return STATUS_BUFFER_TOO_SMALL;

    decision = (AV_IMAGE_DECISION*)Irp->AssociatedIrp.SystemBuffer;
    return AvImageHandleDecision(decision);
}

static NTSTATUS
AvIoctlGetDebugInfo(PDEVICE_CONTEXT DevContext, PIRP Irp, ULONG InputBufferSize, ULONG OutputBufferSize)
{
    AV_DEBUG_INFO* debugInfo;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(InputBufferSize);

    PAGED_CODE();

    if (OutputBufferSize < sizeof(AV_DEBUG_INFO))
        return STATUS_BUFFER_TOO_SMALL;

    debugInfo = (AV_DEBUG_INFO*)Irp->AssociatedIrp.SystemBuffer;
    status = AvProcessGetDebugInfo(debugInfo);
    AvRegGetDebugInfo(debugInfo);
    AvInjectGetDebugInfo(debugInfo);
    Irp->IoStatus.Information = sizeof(AV_DEBUG_INFO);
    return status;
}
