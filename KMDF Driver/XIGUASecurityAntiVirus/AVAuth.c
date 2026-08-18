//=============================================================================
// AVAuth.c - 鉴权模块
//
// 提供挑战-响应鉴权机制:
//   1. 生成随机 Challenge (BCryptGenRandom)
//   2. 验证客户端 HMAC-SHA256 响应
//   3. 生成随机会话 ID
//
// 所有函数在 PASSIVE_LEVEL 运行
//=============================================================================

#include "XIGUASecurityAntiVirus.h"

//=============================================================================
// 局部辅助函数
//=============================================================================

//
// AvpComputeHmac - 计算 HMAC-SHA256
// IRQL: PASSIVE_LEVEL
//
// 使用单步 BCryptHash API, 避免多步调用带来的对象缓冲管理问题
//
static
NTSTATUS
AvpComputeHmac(
    _In_reads_bytes_(DataSize) const PUCHAR Data,
    _In_ ULONG DataSize,
    _In_reads_bytes_(AV_SHARED_KEY_SIZE) const PUCHAR Key,
    _In_ ULONG KeySize,
    _Out_writes_bytes_(AV_HASH_SIZE) PUCHAR Hmac
    )
{
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS status;

    //
    // 打开 HMAC-SHA256 算法提供程序
    //
    status = BCryptOpenAlgorithmProvider(
        &hAlgo,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptOpenAlgorithmProvider(HMAC) failed 0x%08X\n", status));
        return status;
    }

    //
    // 单步完成 HMAC 计算: 密钥 + 数据 -> HMAC 输出
    //
    status = BCryptHash(
        hAlgo,
        (PUCHAR)Key,
        KeySize,
        (PUCHAR)Data,
        DataSize,
        Hmac,
        AV_HASH_SIZE
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptHash failed 0x%08X\n", status));
    }

    BCryptCloseAlgorithmProvider(hAlgo, 0);
    return status;
}

//=============================================================================
// 公开函数实现
//=============================================================================

//
// AvAuthGenerateChallenge - 生成鉴权挑战码
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvAuthGenerateChallenge(
    _Out_ AV_AUTH_CHALLENGE* Challenge
    )
{
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS status;

    if (Challenge == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 打开 RNG 算法提供程序
    //
    status = BCryptOpenAlgorithmProvider(
        &hAlgo,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptOpenAlgorithmProvider(RNG) failed 0x%08X\n", status));
        return status;
    }

    //
    // 生成 32 字节随机挑战码
    //
    status = BCryptGenRandom(
        hAlgo,
        Challenge->Challenge,
        AV_CHALLENGE_SIZE,
        0
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptGenRandom failed 0x%08X\n", status));
        BCryptCloseAlgorithmProvider(hAlgo, 0);
        return status;
    }

    //
    // SequenceId 由调用者设置 (驱动维护计数器防止重放)
    //
    Challenge->SequenceId = 0;

    BCryptCloseAlgorithmProvider(hAlgo, 0);
    return STATUS_SUCCESS;
}

//
// AvAuthVerifyResponse - 验证鉴权响应 HMAC
// IRQL: PASSIVE_LEVEL
//
// 验证客户端返回的 HMAC-SHA256(Challenge || SequenceId, SharedKey)
// 是否正确。若 ExpectedHmac 非 NULL, 返回计算的期望值 (用于调试)。
//
NTSTATUS
AvAuthVerifyResponse(
    _In_ const AV_AUTH_RESPONSE* Response,
    _Out_ BOOLEAN* IsValid,
    _Out_opt_ UCHAR ExpectedHmac[AV_HASH_SIZE]
    )
{
    UCHAR expectedHmac[AV_HASH_SIZE];
    UCHAR hmacData[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    NTSTATUS status;

    if (Response == NULL || IsValid == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *IsValid = FALSE;

    RtlCopyMemory(hmacData, Response->Challenge, AV_CHALLENGE_SIZE);
    RtlCopyMemory(hmacData + AV_CHALLENGE_SIZE, &Response->SequenceId, sizeof(UINT64));

    //
    // 计算期望的 HMAC
    //
    status = AvpComputeHmac(
        hmacData,
        sizeof(hmacData),
        AV_SHARED_KEY,
        AV_SHARED_KEY_SIZE,
        expectedHmac
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: AvpComputeHmac failed 0x%08X\n", status));
        return status;
    }

    //
    // 输出期望值 (调试用)
    //
    if (ExpectedHmac != NULL)
    {
        RtlCopyMemory(ExpectedHmac, expectedHmac, AV_HASH_SIZE);
    }

    //
    // 安全比较 (使用 RtlEqualMemory)
    //
    if (RtlEqualMemory(expectedHmac, Response->Hmac, AV_HASH_SIZE))
    {
        *IsValid = TRUE;
    }
    else
    {
        *IsValid = FALSE;

        //
        // 调试输出: 打印中间值用于定位 HMAC 不匹配问题
        //
        KdPrint(("AVAuth: DBG Seq=%llu Chl0=%02X%02X%02X%02X Chl24=%02X%02X%02X%02X\n",
                 Response->SequenceId,
                 Response->Challenge[0], Response->Challenge[1],
                 Response->Challenge[2], Response->Challenge[3],
                 Response->Challenge[24], Response->Challenge[25],
                 Response->Challenge[26], Response->Challenge[27]));
        KdPrint(("AVAuth: DBG ExpHmac=%02X%02X%02X%02X%02X%02X%02X%02X GotHmac=%02X%02X%02X%02X%02X%02X%02X%02X\n",
                 expectedHmac[0], expectedHmac[1], expectedHmac[2], expectedHmac[3],
                 expectedHmac[4], expectedHmac[5], expectedHmac[6], expectedHmac[7],
                 Response->Hmac[0], Response->Hmac[1], Response->Hmac[2], Response->Hmac[3],
                 Response->Hmac[4], Response->Hmac[5], Response->Hmac[6], Response->Hmac[7]));
    }

    return STATUS_SUCCESS;
}

//
// AvAuthGenerateSessionId - 生成随机会话 ID (16 bytes)
// IRQL: PASSIVE_LEVEL
//
VOID
AvAuthGenerateSessionId(
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    NTSTATUS status;
    LARGE_INTEGER timeFallback;

    if (SessionId == NULL)
    {
        return;
    }

    status = BCryptOpenAlgorithmProvider(
        &hAlgo,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptOpenAlgorithmProvider(RNG) failed 0x%08X\n", status));
        //
        // 如果 RNG 不可用, 使用当前时间作为 fallback (不理想但确保不崩溃)
        //
        KeQuerySystemTime(&timeFallback);
        RtlCopyMemory(SessionId, &timeFallback, min(AV_SESSION_ID_SIZE, sizeof(LARGE_INTEGER)));
        return;
    }

    status = BCryptGenRandom(
        hAlgo,
        SessionId,
        AV_SESSION_ID_SIZE,
        0
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: BCryptGenRandom failed 0x%08X\n", status));
        //
        // Fallback 同上
        //
        KeQuerySystemTime(&timeFallback);
        RtlCopyMemory(SessionId, &timeFallback, min(AV_SESSION_ID_SIZE, sizeof(LARGE_INTEGER)));
    }

    BCryptCloseAlgorithmProvider(hAlgo, 0);
}

//
// AvAuthVerifyHeartbeatHmac - 验证心跳 HMAC
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvAuthVerifyHeartbeatHmac(
    _In_ const AV_HEARTBEAT_REQUEST* Request,
    _Out_ BOOLEAN* IsValid
    )
{
    UCHAR expectedHmac[AV_HASH_SIZE];
    UCHAR hmacData[AV_SESSION_ID_SIZE + sizeof(UINT64)];
    NTSTATUS status;

    if (Request == NULL || IsValid == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *IsValid = FALSE;

    RtlCopyMemory(hmacData, Request->SessionId, AV_SESSION_ID_SIZE);
    RtlCopyMemory(hmacData + AV_SESSION_ID_SIZE, &Request->Timestamp, sizeof(UINT64));

    //
    // 使用共享密钥计算期望的 HMAC
    //
    status = AvpComputeHmac(
        hmacData,
        sizeof(hmacData),
        AV_SHARED_KEY,
        AV_SHARED_KEY_SIZE,
        expectedHmac
        );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("AVAuth: AvpComputeHmac (heartbeat) failed 0x%08X\n", status));
        return status;
    }

    //
    // 安全比较
    //
    if (RtlEqualMemory(expectedHmac, Request->Hmac, AV_HASH_SIZE))
    {
        *IsValid = TRUE;
    }
    else
    {
        *IsValid = FALSE;
    }

    return STATUS_SUCCESS;
}
