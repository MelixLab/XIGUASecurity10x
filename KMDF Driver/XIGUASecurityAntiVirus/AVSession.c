//=============================================================================
// AVSession.c - 会话管理模块
//
// 管理驱动内部会话列表, 使用 KSPIN_LOCK 保护并发访问
//=============================================================================

#include "XIGUASecurityAntiVirus.h"
#include "AVSession.h"

NTSTATUS
AvSessionCreate(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ HANDLE ProcessId,
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 i;
    KIRQL oldIrql;

    if (Sessions == NULL || SessionCount == NULL || SessionId == NULL || SessionLock == NULL)
        return STATUS_INVALID_PARAMETER;

    if (*SessionCount >= MaxSessions)
    {
        KdPrint(("AVSession: Max sessions reached (%u)\n", *SessionCount));
        return STATUS_TOO_MANY_SESSIONS;
    }

    AvAuthGenerateSessionId(SessionId);

    oldIrql = KeAcquireSpinLockRaiseToDpc(SessionLock);

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
        status = STATUS_TOO_MANY_SESSIONS;
        KdPrint(("AVSession: No free slot found (race condition)\n"));
    }

    KeReleaseSpinLock(SessionLock, oldIrql);
    return status;
}

NTSTATUS
AvSessionValidate(
    _In_ PKSPIN_LOCK SessionLock,
    _In_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;
    BOOLEAN found = FALSE;
    KIRQL oldIrql;

    if (Sessions == NULL || SessionId == NULL || SessionLock == NULL)
        return STATUS_INVALID_PARAMETER;

    oldIrql = KeAcquireSpinLockRaiseToDpc(SessionLock);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(SessionLock, oldIrql);

    if (!found)
    {
        KdPrint(("AVSession: Session validation failed - not found\n"));
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

VOID
AvSessionRemove(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;
    KIRQL oldIrql;

    if (Sessions == NULL || SessionCount == NULL || SessionId == NULL || SessionLock == NULL)
        return;

    oldIrql = KeAcquireSpinLockRaiseToDpc(SessionLock);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            RtlZeroMemory(&Sessions[i], sizeof(AV_SESSION_ENTRY));
            if (*SessionCount > 0)
                (*SessionCount)--;
            KdPrint(("AVSession: Session removed from index %u, count=%u\n", i, *SessionCount));
            break;
        }
    }

    KeReleaseSpinLock(SessionLock, oldIrql);
}

//
// AvSessionRemoveByProcess - 移除指定进程(会话归属者)的所有会话
// IRQL: PASSIVE_LEVEL
//
// 用于 agent 断开/退出时清理其遗留会话。agent 关闭句柄后会话长期滞留,
// 反复重连会不断累积直到 AV_MAX_SESSIONS 用尽, 导致新会话无法创建。
// 在 IRP_MJ_CLOSE 中按 ProcessId 清理, 保证每次重连都能重新建立会话。
//
VOID
AvSessionRemoveByProcess(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _Inout_ UINT32* SessionCount,
    _In_ HANDLE ProcessId
    )
{
    KIRQL oldIrql;
    UINT32 i;

    if (Sessions == NULL || SessionCount == NULL || SessionLock == NULL)
        return;

    oldIrql = KeAcquireSpinLockRaiseToDpc(SessionLock);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse && Sessions[i].ProcessId == ProcessId)
        {
            RtlZeroMemory(&Sessions[i], sizeof(AV_SESSION_ENTRY));
            if (*SessionCount > 0)
                (*SessionCount)--;
            KdPrint(("AVSession: Session removed by process 0x%p (index %u, count=%u)\n",
                     ProcessId, i, *SessionCount));
        }
    }

    KeReleaseSpinLock(SessionLock, oldIrql);
}

VOID
AvSessionUpdateActivity(
    _In_ PKSPIN_LOCK SessionLock,
    _Inout_ AV_SESSION_ENTRY Sessions[],
    _In_ UINT32 MaxSessions,
    _In_ const UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    UINT32 i;
    KIRQL oldIrql;

    if (Sessions == NULL || SessionId == NULL || SessionLock == NULL)
        return;

    oldIrql = KeAcquireSpinLockRaiseToDpc(SessionLock);

    for (i = 0; i < MaxSessions; i++)
    {
        if (Sessions[i].InUse &&
            RtlEqualMemory(Sessions[i].SessionId, SessionId, AV_SESSION_ID_SIZE))
        {
            KeQuerySystemTime(&Sessions[i].LastActivity);
            break;
        }
    }

    KeReleaseSpinLock(SessionLock, oldIrql);
}
