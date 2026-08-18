//=============================================================================
// AVDriver.h - 杀毒驱动 KMDF 主头文件
//
// 包含驱动设备扩展定义及所有回调函数声明
// IRQL: 取决于调用的上下文
//=============================================================================

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <bcrypt.h>

#include "../AVCommon/AVProtocol.h"

//=============================================================================
// 池标签定义
//=============================================================================

#define AVDR_POOL_TAG       'RVDA'  // "AVDR" reversed for little-endian

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
    BOOLEAN     InUse;                              // 是否使用中
    UCHAR       SessionId[AV_SESSION_ID_SIZE];      // 会话 ID
    HANDLE      ProcessId;                          // 创建进程 ID
    LARGE_INTEGER CreationTime;                     // 创建时间
    LARGE_INTEGER LastActivity;                     // 最后活动时间
} AV_SESSION_ENTRY;

//=============================================================================
// 设备扩展结构体
//=============================================================================

typedef struct _DEVICE_CONTEXT
{
    WDFQUEUE        DefaultQueue;                   // 默认 IO 队列
    WDFWAITLOCK     SessionLock;                    // 会话列表锁 (PASSIVE_LEVEL)
    AV_SESSION_ENTRY Sessions[AV_MAX_SESSIONS];     // 会话数组
    UINT32          SessionCount;                   // 当前活跃会话数
    UINT64          TotalScans;                     // 总扫描次数
    LARGE_INTEGER   StartTime;                      // 驱动启动时间
    UINT64          SequenceCounter;                // 挑战序列号计数器 (防止重放)
} DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

//=============================================================================
// 驱动入口回调声明
//=============================================================================

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

//
// 驱动清理回调 (手动声明, 避免宏兼容性问题)
//
VOID
EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    );

//=============================================================================
// 鉴权模块函数声明 (AVAuth.c)
//=============================================================================

//
// AvAuthGenerateChallenge - 生成鉴权挑战码
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvAuthGenerateChallenge(
    _Out_ AV_AUTH_CHALLENGE* Challenge
    );

//
// AvAuthVerifyResponse - 验证鉴权响应 HMAC
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvAuthVerifyResponse(
    _In_ const AV_AUTH_RESPONSE* Response,
    _Out_ BOOLEAN* IsValid,
    _Out_opt_ UCHAR ExpectedHmac[AV_HASH_SIZE]
    );

//
// AvAuthGenerateSessionId - 生成随机会话 ID
// IRQL: PASSIVE_LEVEL
//
VOID
AvAuthGenerateSessionId(
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

//
// AvAuthVerifyHeartbeatHmac - 验证心跳 HMAC
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvAuthVerifyHeartbeatHmac(
    _In_ const AV_HEARTBEAT_REQUEST* Request,
    _Out_ BOOLEAN* IsValid
    );

//=============================================================================
// 会话管理函数声明 (AVSession.c)
//=============================================================================

//
// AvSessionCreate - 创建新会话
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvSessionCreate(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ HANDLE ProcessId,
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

//
// AvSessionValidate - 验证会话是否有效
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvSessionValidate(
    _In_ WDFWAITLOCK SessionLock,
    _In_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

//
// AvSessionRemove - 移除会话
// IRQL: PASSIVE_LEVEL
//
VOID
AvSessionRemove(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );

//
// AvSessionUpdateActivity - 更新会话活动时间
// IRQL: PASSIVE_LEVEL
//
VOID
AvSessionUpdateActivity(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    );
