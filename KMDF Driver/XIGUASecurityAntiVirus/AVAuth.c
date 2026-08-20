//=============================================================================
// AVAuth.c - 鉴权模块 (无 BCrypt/cng.sys 依赖)
//
// 提供挑战-响应鉴权机制:
//   1. 生成随机 Challenge (KeQueryPerformanceCounter + RtlRandomEx)
//   2. 验证客户端 HMAC-SHA256 响应 (内联 SHA-256 实现)
//   3. 生成随机会话 ID
//
// 所有函数在 PASSIVE_LEVEL 运行
//=============================================================================

#include "XIGUASecurityAntiVirus.h"

//=============================================================================
// 内联 SHA-256 实现 (FIPS 180-4)
//=============================================================================

#define SHA256_ROTR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_SHR(x,n)   ((x) >> (n))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_BSIG0(x)   (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_BSIG1(x)   (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SSIG0(x)   (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ SHA256_SHR(x,3))
#define SHA256_SSIG1(x)   (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ SHA256_SHR(x,10))

typedef struct _SHA256_CTX {
    ULONG       state[8];
    ULONGLONG   bitlen;
    ULONG       datalen;
    UCHAR       data[64];
} SHA256_CTX;

static const ULONG sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const UCHAR *data)
{
    ULONG w[64];
    ULONG a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((ULONG)data[i*4] << 24) | ((ULONG)data[i*4+1] << 16) |
               ((ULONG)data[i*4+2] << 8) | (ULONG)data[i*4+3];

    for (i = 16; i < 64; i++)
        w[i] = SHA256_SSIG1(w[i-2]) + w[i-7] + SHA256_SSIG0(w[i-15]) + w[i-16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA256_BSIG1(e) + SHA256_CH(e,f,g) + sha256_k[i] + w[i];
        t2 = SHA256_BSIG0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const UCHAR *data, ULONG len)
{
    ULONG i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, UCHAR *hash)
{
    ULONG i = ctx->datalen;

    ctx->data[i++] = 0x80;

    if (ctx->datalen < 56) {
        while (i < 56) ctx->data[i++] = 0;
    } else {
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        RtlZeroMemory(ctx->data, 56);
    }

    ctx->bitlen += (ULONGLONG)ctx->datalen * 8;
    ctx->data[63] = (UCHAR)(ctx->bitlen);
    ctx->data[62] = (UCHAR)(ctx->bitlen >> 8);
    ctx->data[61] = (UCHAR)(ctx->bitlen >> 16);
    ctx->data[60] = (UCHAR)(ctx->bitlen >> 24);
    ctx->data[59] = (UCHAR)(ctx->bitlen >> 32);
    ctx->data[58] = (UCHAR)(ctx->bitlen >> 40);
    ctx->data[57] = (UCHAR)(ctx->bitlen >> 48);
    ctx->data[56] = (UCHAR)(ctx->bitlen >> 56);

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; i++) {
        hash[i*4]   = (UCHAR)(ctx->state[i] >> 24);
        hash[i*4+1] = (UCHAR)(ctx->state[i] >> 16);
        hash[i*4+2] = (UCHAR)(ctx->state[i] >> 8);
        hash[i*4+3] = (UCHAR)(ctx->state[i]);
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
}

//=============================================================================
// HMAC-SHA256 实现
//=============================================================================

static void
hmac_sha256(
    _In_reads_bytes_(KeyLen) const UCHAR *Key,
    _In_ ULONG KeyLen,
    _In_reads_bytes_(DataLen) const UCHAR *Data,
    _In_ ULONG DataLen,
    _Out_writes_bytes_(32) UCHAR *Hmac
    )
{
    UCHAR k_ipad[64];
    UCHAR k_opad[64];
    UCHAR tk[32];
    UCHAR inner_hash[32];
    SHA256_CTX ctx;
    ULONG i;

    if (KeyLen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, Key, KeyLen);
        sha256_final(&ctx, tk);
        Key = tk;
        KeyLen = 32;
    }

    RtlZeroMemory(k_ipad, 64);
    RtlZeroMemory(k_opad, 64);
    RtlCopyMemory(k_ipad, Key, KeyLen);
    RtlCopyMemory(k_opad, Key, KeyLen);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, Data, DataLen);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, Hmac);

    RtlZeroMemory(k_ipad, 64);
    RtlZeroMemory(k_opad, 64);
    RtlZeroMemory(inner_hash, 32);
}

//=============================================================================
// 随机数生成 (无 BCryptGenRandom 依赖)
//=============================================================================

static NTSTATUS
AvpGenRandom(
    _Out_writes_bytes_(Size) PUCHAR Buffer,
    _In_ ULONG Size
    )
{
    LARGE_INTEGER sysTime;
    ULONG seed;
    ULONG i;

    KeQuerySystemTime(&sysTime);
    seed = sysTime.LowPart ^
           (ULONG)(ULONG_PTR)PsGetCurrentProcessId() ^
           (ULONG)(ULONG_PTR)&Buffer;

    for (i = 0; i < Size; i += sizeof(ULONG)) {
        seed = seed * 1103515245 + 12345;
        ULONG rand = (seed >> 16) & 0x7FFF;
        rand |= (seed & 0xFFFF) << 15;
        ULONG copyLen = (Size - i < sizeof(ULONG)) ? (Size - i) : sizeof(ULONG);
        RtlCopyMemory(Buffer + i, &rand, copyLen);
    }

    return STATUS_SUCCESS;
}

//=============================================================================
// 局部辅助函数
//=============================================================================

static NTSTATUS
AvpComputeHmac(
    _In_reads_bytes_(DataSize) const PUCHAR Data,
    _In_ ULONG DataSize,
    _In_reads_bytes_(AV_SHARED_KEY_SIZE) const PUCHAR Key,
    _In_ ULONG KeySize,
    _Out_writes_bytes_(AV_HASH_SIZE) PUCHAR Hmac
    )
{
    hmac_sha256(Key, KeySize, Data, DataSize, Hmac);
    return STATUS_SUCCESS;
}

//=============================================================================
// 公开函数实现
//=============================================================================

NTSTATUS
AvAuthGenerateChallenge(
    _Out_ AV_AUTH_CHALLENGE* Challenge
    )
{
    if (Challenge == NULL)
        return STATUS_INVALID_PARAMETER;

    AvpGenRandom(Challenge->Challenge, AV_CHALLENGE_SIZE);
    Challenge->SequenceId = 0;
    return STATUS_SUCCESS;
}

NTSTATUS
AvAuthVerifyResponse(
    _In_ const AV_AUTH_RESPONSE* Response,
    _Out_ BOOLEAN* IsValid,
    _Out_opt_ UCHAR ExpectedHmac[AV_HASH_SIZE]
    )
{
    UCHAR expectedHmac[AV_HASH_SIZE];
    UCHAR hmacData[AV_CHALLENGE_SIZE + sizeof(UINT64)];

    if (Response == NULL || IsValid == NULL)
        return STATUS_INVALID_PARAMETER;

    *IsValid = FALSE;

    RtlCopyMemory(hmacData, Response->Challenge, AV_CHALLENGE_SIZE);
    RtlCopyMemory(hmacData + AV_CHALLENGE_SIZE, &Response->SequenceId, sizeof(UINT64));

    AvpComputeHmac(hmacData, sizeof(hmacData),
                   AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                   expectedHmac);

    if (ExpectedHmac != NULL)
        RtlCopyMemory(ExpectedHmac, expectedHmac, AV_HASH_SIZE);

    if (RtlEqualMemory(expectedHmac, Response->Hmac, AV_HASH_SIZE)) {
        *IsValid = TRUE;
    } else {
        KdPrint(("AVAuth: DBG Seq=%llu Chl0=%02X%02X%02X%02X\n",
                 Response->SequenceId,
                 Response->Challenge[0], Response->Challenge[1],
                 Response->Challenge[2], Response->Challenge[3]));
        KdPrint(("AVAuth: DBG Exp=%02X%02X%02X%02X Got=%02X%02X%02X%02X\n",
                 expectedHmac[0], expectedHmac[1], expectedHmac[2], expectedHmac[3],
                 Response->Hmac[0], Response->Hmac[1], Response->Hmac[2], Response->Hmac[3]));
    }

    return STATUS_SUCCESS;
}

VOID
AvAuthGenerateSessionId(
    _Out_ UCHAR SessionId[AV_SESSION_ID_SIZE]
    )
{
    if (SessionId == NULL)
        return;

    AvpGenRandom(SessionId, AV_SESSION_ID_SIZE);
}

NTSTATUS
AvAuthVerifyHeartbeatHmac(
    _In_ const AV_HEARTBEAT_REQUEST* Request,
    _Out_ BOOLEAN* IsValid
    )
{
    UCHAR expectedHmac[AV_HASH_SIZE];
    UCHAR hmacData[AV_SESSION_ID_SIZE + sizeof(UINT64)];

    if (Request == NULL || IsValid == NULL)
        return STATUS_INVALID_PARAMETER;

    *IsValid = FALSE;

    RtlCopyMemory(hmacData, Request->SessionId, AV_SESSION_ID_SIZE);
    RtlCopyMemory(hmacData + AV_SESSION_ID_SIZE, &Request->Timestamp, sizeof(UINT64));

    AvpComputeHmac(hmacData, sizeof(hmacData),
                   AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                   expectedHmac);

    if (RtlEqualMemory(expectedHmac, Request->Hmac, AV_HASH_SIZE))
        *IsValid = TRUE;

    return STATUS_SUCCESS;
}
