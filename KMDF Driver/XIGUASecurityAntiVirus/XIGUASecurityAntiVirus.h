//=============================================================================
// XIGUASecurityAntiVirus.h - 杀毒驱动 WDM 主头文件
//
// 纯 WDM 驱动, 无 KMDF/cng.sys 依赖, 仅依赖 ntoskrnl.exe
// IRQL: 取决于调用的上下文
//=============================================================================

#pragma once

#include <ntddk.h>

#ifndef BYTE
typedef unsigned char BYTE;
#endif

#include "../AVCommon/AVProtocol.h"

//=============================================================================
// 池标签定义
//=============================================================================

#define AVDR_POOL_TAG       'RVDA'

//=============================================================================
// 驱动版本定义
//=============================================================================

#define AV_DRIVER_VERSION_MAJOR     1
#define AV_DRIVER_VERSION_MINOR     0
#define AV_DRIVER_VERSION_BUILD     1
#define AV_DRIVER_VERSION           ((AV_DRIVER_VERSION_MAJOR << 16) | \
                                     (AV_DRIVER_VERSION_MINOR << 8) | \
                                     AV_DRIVER_VERSION_BUILD)

//=============================================================================
// 会话条目定义 (内部使用)
//=============================================================================

typedef struct _AV_SESSION_ENTRY
{
    BOOLEAN     InUse;
    UCHAR       SessionId[AV_SESSION_ID_SIZE];
    HANDLE      ProcessId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastActivity;
} AV_SESSION_ENTRY;

//=============================================================================
// 设备扩展结构体 (WDM DeviceExtension)
//=============================================================================

typedef struct _DEVICE_CONTEXT
{
    KSPIN_LOCK      SessionLock;                    // 会话列表锁
    AV_SESSION_ENTRY Sessions[AV_MAX_SESSIONS];
    UINT32          SessionCount;
    UINT64          TotalScans;
    LARGE_INTEGER   StartTime;
    UINT64          SequenceCounter;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//=============================================================================
// 驱动入口和分发函数声明
//=============================================================================

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AvDriverUnload;

DRIVER_DISPATCH AvDispatchCreateClose;
DRIVER_DISPATCH AvDispatchDeviceControl;

//=============================================================================
// 鉴权模块函数声明 (AVAuth.c)
//=============================================================================

NTSTATUS
AvAuthGenerateChallenge(
    _Out_ AV_AUTH_CHALLENGE* Challenge
    );

NTSTATUS
AvAuthVerifyResponse(
    _In_ const AV_AUTH_RESPONSE* Response,
    _Out_ BOOLEAN* IsValid,
    _Out_opt_ UCHAR ExpectedHmac[AV_HASH_SIZE]
    );

VOID
AvAuthGenerateSessionId(
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

NTSTATUS
AvAuthVerifyHeartbeatHmac(
    _In_ const AV_HEARTBEAT_REQUEST* Request,
    _Out_ BOOLEAN* IsValid
    );

//=============================================================================
// 会话管理函数声明 (AVSession.c)
//=============================================================================

NTSTATUS
AvSessionCreate(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ HANDLE ProcessId,
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

NTSTATUS
AvSessionValidate(
    _In_ PKSPIN_LOCK SessionLock,
    _In_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

VOID
AvSessionRemove(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

VOID
AvSessionUpdateActivity(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );
