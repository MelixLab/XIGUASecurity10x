//=============================================================================
// AVSession.c - 会话管理模块
//
// 管理驱动内部会话列表, 使用 WDFWAITLOCK 保护并发访问
// 所有函数在 PASSIVE_LEVEL 运行
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVSession.h"

//=============================================================================
// AvSessionCreate - 创建新会话
// IRQL: PASSIVE_LEVEL
//
// 在会话数组中查找空闲条目, 分配 SessionId, 初始化会话信息
//=============================================================================

NTSTATUS
AvSessionCreate(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ HANDLE ProcessId,
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 i;

    if (Sessions == NULL || SessionCount == NULL || SessionId == NULL || SessionLock == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (*SessionCount >= MaxSessions)
    {
        KdPrint(("AVSession: Max sessions reached (%u)\n", *SessionCount));
        return STATUS_TOO_MANY_SESSIONS;
    }

    //
    // 生成随机会话 ID
    //
    AvAuthGenerateSessionId(SessionId);

    //
    // 获取会话锁
    //
    WdfWaitLockAcquire(SessionLock, NULL);

    //
    // 查找空闲会话条目并初始化
    //
    for (i = 0; i < MaxSessions; i++)
    {
        if (!Sessions[i].InUse)
        {
            RtlZeroMemory(&Sessions[i], sizeof(AV_SESSION_ENTRY));
            Sessions[i].InUse = TRUE;
            Sessions[i].ProcessId = ProcessId;
            RtlCopyMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE);
            KeQuerySystemTime(&Sessions[i].CreationTime);
            Sessions[i].LastActivity = Sessions[i].CreationTime;

            (*SessionCount)++;

            KdPrint(("AVSession: Session created at index %u, count=%u\n", i, *SessionCount));
            break;
        }
    }

    if (i >= MaxSessions)
    {
        //
        // 理论上不会发生 (已检查 SessionCount), 但防御性编码
        //
        status = STATUS_TOO_MANY_SESSIONS;
        KdPrint(("AVSession: No free slot found (race condition)\n"));
    }

    WdfWaitLockRelease(SessionLock);

    return status;
}

//=============================================================================
// AvSessionValidate - 验证会话是否有效
// IRQL: PASSIVE_LEVEL
//
// 在会话数组中搜索匹配 SessionId 的条目, 检查是否 InUse
//=============================================================================

NTSTATUS
AvSessionValidate(
    _In_ WDFWAITLOCK SessionLock,
    _In_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;
    BOOLEAN found = FALSE;

    if (Sessions == NULL || SessionId == NULL || SessionLock == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 获取会话锁
    //
    WdfWaitLockAcquire(SessionLock, NULL);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            found = TRUE;
            break;
        }
    }

    WdfWaitLockRelease(SessionLock);

    if (!found)
    {
        KdPrint(("AVSession: Session validation failed - not found\n"));
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// AvSessionRemove - 移除会话
// IRQL: PASSIVE_LEVEL
//
// 从会话数组中移除指定的会话条目
//=============================================================================

VOID
AvSessionRemove(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;

    if (Sessions == NULL || SessionCount == NULL || SessionId == NULL || SessionLock == NULL)
    {
        return;
    }

    //
    // 获取会话锁
    //
    WdfWaitLockAcquire(SessionLock, NULL);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            RtlZeroMemory(&Sessions[i], sizeof(AV_SESSION_ENTRY));

            if (*SessionCount > 0)
            {
                (*SessionCount)--;
            }

            KdPrint(("AVSession: Session removed from index %u, count=%u\n", i, *SessionCount));
            break;
        }
    }

    WdfWaitLockRelease(SessionLock);
}

//=============================================================================
// AvSessionUpdateActivity - 更新会话最后活动时间
// IRQL: PASSIVE_LEVEL
//=============================================================================

VOID
AvSessionUpdateActivity(
    _In_ WDFWAITLOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;

    if (Sessions == NULL || SessionId == NULL || SessionLock == NULL)
    {
        return;
    }

    WdfWaitLockAcquire(SessionLock, NULL);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            KeQuerySystemTime(&Sessions[i].LastActivity);
            break;
        }
    }

    WdfWaitLockRelease(SessionLock);
}
