//=============================================================================
// AVSession.h - 会话管理函数声明
//
// 会话管理模块为驱动提供会话创建、验证、移除功能
// IRQL: 所有函数在 PASSIVE_LEVEL 运行
//=============================================================================

#pragma once

#include "XIGUASecurityAntiVirus.h"

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
