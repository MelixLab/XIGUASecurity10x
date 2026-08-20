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
