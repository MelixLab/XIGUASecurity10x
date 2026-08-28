//=============================================================================
// XIGUAInjectGuard.c - 进程注入防御驱动
//
// 纯 WDM 驱动, 无 KMDF/cng.sys 依赖
// 三层架构: 驱动 ←IOCTL→ Agent(SYSTEM) ←命名管道→ 主程序
//
// 功能:
//   1. ObRegisterCallbacks 监控跨进程句柄操作 (进程/线程)
//   2. 检测注入链: OpenProcess→VirtualAllocEx→WriteProcessMemory→CreateRemoteThread
//   3. HMAC-SHA256 鉴权 (复用 AVProtocol.h 共享密钥)
//   4. IOCTL 通知 Agent, 等待用户决策后放行/阻断
//=============================================================================

#include "XIGUAInjectGuard.h"
#include "..\AVCommon\AVProtocol.h"
#include "..\AVCommon\AVPoolCompat.h"

//=============================================================================
// 全局变量
//=============================================================================

static PDEVICE_OBJECT      g_DeviceObject = NULL;
static PIG_DEVICE_CONTEXT   g_Context = NULL;
static PVOID               g_ObRegHandle = NULL;
static BOOLEAN             g_ObRegistered = FALSE;

// 注入链跟踪表
static IG_CHAIN_TRACKER    g_ChainTrackers[IG_MAX_CHAIN_TRACKERS];
static KSPIN_LOCK          g_ChainLock;

// 鉴权状态
static BOOLEAN             g_Authenticated = FALSE;
static UCHAR               g_SessionId[AV_SESSION_ID_SIZE];

//=============================================================================
// 内联 SHA-256 + HMAC (复用 AVAuth.c 的实现, 无 cng.sys 依赖)
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
    ULONG w[64], a, b, c, d, e, f, g, h, t1, t2;
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
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
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
    ULONG i;
    i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0;
    } else {
        ctx->data[i++] = 0x80;
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
    for (i = 0; i < 4; i++) {
        hash[i]    = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i+4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i+8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i+12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i+16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i+20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i+24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i+28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static void hmac_sha256(const UCHAR *key, ULONG keyLen,
                        const UCHAR *data, ULONG dataLen, UCHAR *hmac)
{
    UCHAR k_ipad[64], k_opad[64];
    UCHAR tk[AV_HASH_SIZE];
    SHA256_CTX ctx;
    ULONG i;

    if (keyLen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, keyLen);
        sha256_final(&ctx, tk);
        key = tk; keyLen = AV_HASH_SIZE;
    }

    RtlZeroMemory(k_ipad, 64);
    RtlZeroMemory(k_opad, 64);
    RtlCopyMemory(k_ipad, key, keyLen);
    RtlCopyMemory(k_opad, key, keyLen);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, dataLen);
    sha256_final(&ctx, hmac);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, hmac, AV_HASH_SIZE);
    sha256_final(&ctx, hmac);
}

//=============================================================================
// 鉴权
//=============================================================================

static NTSTATUS IgHandleAuthInit(PVOID OutBuf, ULONG OutLen, PULONG BytesReturned)
{
    AV_AUTH_CHALLENGE *challenge;
    LARGE_INTEGER sysTime;
    ULONG seed = 0;
    ULONG i;

    if (OutLen < sizeof(AV_AUTH_CHALLENGE))
        return STATUS_BUFFER_TOO_SMALL;

    challenge = (AV_AUTH_CHALLENGE *)OutBuf;
    RtlZeroMemory(challenge, sizeof(*challenge));

    // 生成随机 Challenge (用系统时间做种子)
    KeQuerySystemTime(&sysTime);
    seed = sysTime.LowPart ^ (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    for (i = 0; i < AV_CHALLENGE_SIZE; i += sizeof(ULONG)) {
        seed = seed * 1103515245 + 12345;
        challenge->Challenge[i]   = (UCHAR)(seed >> 24);
        challenge->Challenge[i+1] = (UCHAR)(seed >> 16);
        challenge->Challenge[i+2] = (UCHAR)(seed >> 8);
        challenge->Challenge[i+3] = (UCHAR)(seed);
    }

    challenge->SequenceId = (UINT64)InterlockedIncrement(&g_Context->SequenceCounter);

    *BytesReturned = sizeof(AV_AUTH_CHALLENGE);
    return STATUS_SUCCESS;
}

static NTSTATUS IgHandleAuthVerify(PVOID InBuf, ULONG InLen, PVOID OutBuf, ULONG OutLen, PULONG BytesReturned)
{
    AV_AUTH_RESPONSE response;   // 局部拷贝: METHOD_BUFFERED 下 InBuf/OutBuf 共用
    AV_AUTH_RESULT *result;      // SystemBuffer, 直接写输出会破坏输入数据
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    UCHAR expectedHmac[AV_HASH_SIZE];

    if (InLen < sizeof(AV_AUTH_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(AV_AUTH_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    // 先拷贝输入到局部变量, 避免输出清零时破坏输入 (EndPoint 同款处理)
    RtlCopyMemory(&response, InBuf, sizeof(AV_AUTH_RESPONSE));

    result = (AV_AUTH_RESULT *)OutBuf;
    RtlZeroMemory(result, sizeof(*result));

    // 计算 HMAC(Challenge || SequenceId, SharedKey)
    RtlCopyMemory(hmacInput, response.Challenge, AV_CHALLENGE_SIZE);
    RtlCopyMemory(hmacInput + AV_CHALLENGE_SIZE, &response.SequenceId, sizeof(UINT64));

    hmac_sha256(AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                hmacInput, sizeof(hmacInput), expectedHmac);

    if (RtlEqualMemory(response.Hmac, expectedHmac, AV_HASH_SIZE))
    {
        result->Status = STATUS_SUCCESS;
        // 生成会话 ID
        result->SessionId[0] = (UCHAR)(InterlockedIncrement(&g_Context->SequenceCounter) & 0xFF);
        result->SessionId[1] = (UCHAR)(InterlockedIncrement(&g_Context->SequenceCounter) & 0xFF);
        result->SessionId[2] = (UCHAR)(InterlockedIncrement(&g_Context->SequenceCounter) & 0xFF);
        result->SessionId[3] = (UCHAR)(InterlockedIncrement(&g_Context->SequenceCounter) & 0xFF);
        RtlCopyMemory(g_SessionId, result->SessionId, AV_SESSION_ID_SIZE);
        g_Authenticated = TRUE;
        DbgPrint("[InjectGuard] Auth SUCCESS\n");
    }
    else
    {
        result->Status = STATUS_ACCESS_DENIED;
        DbgPrint("[InjectGuard] Auth FAILED\n");
    }

    *BytesReturned = sizeof(AV_AUTH_RESULT);
    return STATUS_SUCCESS;
}

//=============================================================================
// 工具函数
//=============================================================================

static ULONG IgGetCurrentPid(void)
{
    return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
}

static void IgGetProcessName(PEPROCESS Process, PWSTR Buffer, ULONG BufferLen)
{
    UCHAR* name = PsGetProcessImageFileName(Process);
    if (name) {
        ULONG i;
        for (i = 0; i < BufferLen - 1 && name[i]; i++)
            Buffer[i] = (WCHAR)name[i];
        Buffer[i] = L'\0';
    } else {
        if (BufferLen > 0) Buffer[0] = L'\0';
    }
}

static BOOLEAN IgIsWhitelisted(PWSTR ProcessName)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    ULONG i;

    KeAcquireSpinLock(&g_Context->WhitelistLock, &oldIrql);
    for (i = 0; i < g_Context->WhitelistCount; i++) {
        if (_wcsicmp(ProcessName, g_Context->Whitelist[i]) == 0) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Context->WhitelistLock, oldIrql);
    return found;
}

//=============================================================================
// 事件队列管理
//=============================================================================

static void IgEnqueueEvent(PIG_NOTIFICATION Event)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_Context->EventQueueLock, &oldIrql);

    Event->SequenceId = (UINT32)InterlockedIncrement(&g_Context->SequenceCounter);
    Event->HasPending = TRUE;

    RtlCopyMemory(&g_Context->Events[g_Context->EventQueueTail], Event, sizeof(IG_NOTIFICATION));
    g_Context->EventQueueTail = (g_Context->EventQueueTail + 1) % IG_MAX_PENDING_EVENTS;
    if (g_Context->EventQueueCount >= IG_MAX_PENDING_EVENTS)
        g_Context->EventQueueHead = (g_Context->EventQueueHead + 1) % IG_MAX_PENDING_EVENTS;
    else
        g_Context->EventQueueCount++;

    InterlockedIncrement(&g_Context->TotalEvents);
    KeReleaseSpinLock(&g_Context->EventQueueLock, oldIrql);
}

static BOOLEAN IgDequeueEvent(PIG_NOTIFICATION OutEvent)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_Context->EventQueueLock, &oldIrql);
    if (g_Context->EventQueueCount > 0) {
        RtlCopyMemory(OutEvent, &g_Context->Events[g_Context->EventQueueHead], sizeof(IG_NOTIFICATION));
        g_Context->EventQueueHead = (g_Context->EventQueueHead + 1) % IG_MAX_PENDING_EVENTS;
        g_Context->EventQueueCount--;
        found = TRUE;
    }
    KeReleaseSpinLock(&g_Context->EventQueueLock, oldIrql);
    return found;
}

static LONG IgGetDecision(ULONG SequenceId)
{
    KIRQL oldIrql;
    LONG decision;
    KeAcquireSpinLock(&g_Context->DecisionLock, &oldIrql);
    decision = g_Context->Decisions[SequenceId % IG_MAX_PENDING_EVENTS];
    KeReleaseSpinLock(&g_Context->DecisionLock, oldIrql);
    return decision;
}

static void IgSetDecision(ULONG SequenceId, LONG Decision)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Context->DecisionLock, &oldIrql);
    g_Context->Decisions[SequenceId % IG_MAX_PENDING_EVENTS] = Decision;
    KeReleaseSpinLock(&g_Context->DecisionLock, oldIrql);
}

//=============================================================================
// 注入链跟踪
//=============================================================================

static void IgChainAddStep(ULONG SourcePid, ULONG TargetPid, ULONG Step)
{
    KIRQL oldIrql;
    int slot = -1, i;
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&g_ChainLock, &oldIrql);

    for (i = 0; i < IG_MAX_CHAIN_TRACKERS; i++) {
        if (g_ChainTrackers[i].SourcePid == SourcePid &&
            g_ChainTrackers[i].TargetPid == TargetPid) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        for (i = 0; i < IG_MAX_CHAIN_TRACKERS; i++) {
            if (g_ChainTrackers[i].SourcePid == 0) {
                slot = i;
                break;
            }
            if (g_ChainTrackers[i].StepCount > 0) {
                LONGLONG diff = now.QuadPart - g_ChainTrackers[i].LastActivityTime.QuadPart;
                if (diff > (LONGLONG)IG_CHAIN_TIMEOUT_SEC * 10000000LL) {
                    slot = i;
                    break;
                }
            }
        }
    }

    if (slot >= 0) {
        PIG_CHAIN_TRACKER t = &g_ChainTrackers[slot];
        if (t->SourcePid == 0) {
            t->SourcePid = SourcePid;
            t->TargetPid = TargetPid;
            t->StepCount = 0;
            RtlZeroMemory(t->Steps, sizeof(t->Steps));
        }
        if (t->StepCount < IG_MAX_CHAIN_STEPS) {
            t->Steps[t->StepCount] = Step;
            t->StepCount++;
        }
        t->LastActivityTime = now;
    }

    KeReleaseSpinLock(&g_ChainLock, oldIrql);
}

static BOOLEAN IgChainCheckComplete(ULONG SourcePid, ULONG TargetPid,
                                     PULONG OutSteps, PULONG OutCount)
{
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    int i;

    *OutCount = 0;
    KeAcquireSpinLock(&g_ChainLock, &oldIrql);

    for (i = 0; i < IG_MAX_CHAIN_TRACKERS; i++) {
        if (g_ChainTrackers[i].SourcePid == SourcePid &&
            g_ChainTrackers[i].TargetPid == TargetPid) {
            PIG_CHAIN_TRACKER t = &g_ChainTrackers[i];
            ULONG j;
            BOOLEAN hasOpen = FALSE, hasWrite = FALSE, hasThread = FALSE;

            for (j = 0; j < t->StepCount; j++) {
                switch (t->Steps[j]) {
                    case IG_STEP_OPEN_PROCESS:  hasOpen = TRUE; break;
                    case IG_STEP_ALLOC_MEM:     /* alloc */ break;
                    case IG_STEP_WRITE_MEM:     hasWrite = TRUE; break;
                    case IG_STEP_CREATE_THREAD: hasThread = TRUE; break;
                    case IG_STEP_SECTION_MAP:   hasWrite = TRUE; break;
                }
            }

            if (hasOpen && hasWrite && hasThread) {
                result = TRUE;
                *OutCount = t->StepCount;
                if (*OutCount > IG_MAX_CHAIN_STEPS) *OutCount = IG_MAX_CHAIN_STEPS;
                for (j = 0; j < *OutCount; j++)
                    OutSteps[j] = t->Steps[j];

                t->SourcePid = 0;
                t->StepCount = 0;
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_ChainLock, oldIrql);
    return result;
}

//=============================================================================
// ObRegisterCallbacks 回调
//=============================================================================

static OB_PREOP_CALLBACK_STATUS
IgProcessPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info
)
{
    ULONG sourcePid, targetPid;
    ACCESS_MASK desired;
    WCHAR srcName[IG_MAX_NAME_LEN];
    WCHAR tgtName[IG_MAX_NAME_LEN];

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Context || !g_Context->ProtectionActive)
        return OB_PREOP_SUCCESS;

    if (Info->Operation != OB_OPERATION_HANDLE_CREATE &&
        Info->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    sourcePid = IgGetCurrentPid();
    targetPid = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)Info->Object);

    if (sourcePid == 0 || sourcePid == targetPid || sourcePid == 4)
        return OB_PREOP_SUCCESS;

    desired = (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        ? Info->Parameters->CreateHandleInformation.DesiredAccess
        : Info->Parameters->DuplicateHandleInformation.DesiredAccess;

    IgGetProcessName((PEPROCESS)Info->Object, tgtName, IG_MAX_NAME_LEN);
    {
        PEPROCESS srcProc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)sourcePid, &srcProc))) {
            IgGetProcessName(srcProc, srcName, IG_MAX_NAME_LEN);
            ObDereferenceObject(srcProc);
        } else {
            srcName[0] = L'\0';
        }
    }

    if (IgIsWhitelisted(srcName) || IgIsWhitelisted(tgtName))
        return OB_PREOP_SUCCESS;

    // 跨进程内存操作
    if (desired & (IG_PROCESS_VM_READ | IG_PROCESS_VM_WRITE | IG_PROCESS_VM_OPERATION)) {
        IG_NOTIFICATION evt;
        RtlZeroMemory(&evt, sizeof(evt));
        evt.EventType = IG_EVENT_PROCESS_OPEN;
        evt.SourcePid = sourcePid;
        evt.TargetPid = targetPid;
        evt.AccessMask = desired;
        RtlCopyMemory(evt.SourceProcessName, srcName, sizeof(srcName));
        RtlCopyMemory(evt.TargetProcessName, tgtName, sizeof(tgtName));
        IgEnqueueEvent(&evt);
        IgChainAddStep(sourcePid, targetPid, IG_STEP_OPEN_PROCESS);

        DbgPrint("[InjectGuard] OpenProcess(0x%X) %ws -> %ws\n", desired, srcName, tgtName);
    }

    // 创建线程权限
    if (desired & IG_PROCESS_CREATE_THREAD) {
        IG_NOTIFICATION evt;
        RtlZeroMemory(&evt, sizeof(evt));
        evt.EventType = IG_EVENT_REMOTE_THREAD;
        evt.SourcePid = sourcePid;
        evt.TargetPid = targetPid;
        evt.AccessMask = desired;
        RtlCopyMemory(evt.SourceProcessName, srcName, sizeof(srcName));
        RtlCopyMemory(evt.TargetProcessName, tgtName, sizeof(tgtName));
        IgEnqueueEvent(&evt);
        IgChainAddStep(sourcePid, targetPid, IG_STEP_CREATE_THREAD);

        // 检查完整注入链
        {
            ULONG chainSteps[IG_MAX_CHAIN_STEPS];
            ULONG chainCount = 0;
            if (IgChainCheckComplete(sourcePid, targetPid, chainSteps, &chainCount)) {
                RtlZeroMemory(&evt, sizeof(evt));
                evt.EventType = IG_EVENT_INJECTION_CHAIN;
                evt.SourcePid = sourcePid;
                evt.TargetPid = targetPid;
                evt.ChainStepCount = chainCount;
                RtlCopyMemory(evt.ChainSteps, chainSteps, sizeof(ULONG) * chainCount);
                RtlCopyMemory(evt.SourceProcessName, srcName, sizeof(srcName));
                RtlCopyMemory(evt.TargetProcessName, tgtName, sizeof(tgtName));
                IgEnqueueEvent(&evt);
                InterlockedIncrement(&g_Context->TotalBlocked);
                DbgPrint("[InjectGuard] INJECTION CHAIN: %ws -> %ws\n", srcName, tgtName);
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS
IgThreadPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info
)
{
    ULONG sourcePid, targetPid;
    PEPROCESS targetProc;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Context || !g_Context->ProtectionActive)
        return OB_PREOP_SUCCESS;

    if (Info->Operation != OB_OPERATION_HANDLE_CREATE)
        return OB_PREOP_SUCCESS;

    sourcePid = IgGetCurrentPid();
    targetProc = IoThreadToProcess((PETHREAD)Info->Object);
    targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProc);

    if (sourcePid == 0 || sourcePid == targetPid || sourcePid == 4)
        return OB_PREOP_SUCCESS;

    if (Info->Parameters->CreateHandleInformation.DesiredAccess & IG_THREAD_SUSPEND_RESUME)
        IgChainAddStep(sourcePid, targetPid, IG_STEP_SUSPEND_THREAD);

    if (Info->Parameters->CreateHandleInformation.DesiredAccess & IG_THREAD_SET_CONTEXT)
        IgChainAddStep(sourcePid, targetPid, IG_STEP_SET_CONTEXT);

    return OB_PREOP_SUCCESS;
}

//=============================================================================
// ObRegisterCallbacks 注册
//=============================================================================

static NTSTATUS IgRegisterObCallbacks(void)
{
    OB_OPERATION_REGISTRATION opRegs[2];
    OB_CALLBACK_REGISTRATION reg;
    UNICODE_STRING altitude;
    NTSTATUS st;

    RtlZeroMemory(opRegs, sizeof(opRegs));

    opRegs[0].ObjectType = PsProcessType;
    opRegs[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opRegs[0].PreOperation = IgProcessPreCallback;
    opRegs[0].PostOperation = NULL;

    opRegs[1].ObjectType = PsThreadType;
    opRegs[1].Operations = OB_OPERATION_HANDLE_CREATE;
    opRegs[1].PreOperation = IgThreadPreCallback;
    opRegs[1].PostOperation = NULL;

    RtlInitUnicodeString(&altitude, L"327010");

    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = opRegs;

    st = ObRegisterCallbacks(&reg, &g_ObRegHandle);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[InjectGuard] ObRegisterCallbacks failed: 0x%08X\n", st);
        return st;
    }

    g_ObRegistered = TRUE;
    DbgPrint("[InjectGuard] ObRegisterCallbacks SUCCESS\n");
    return STATUS_SUCCESS;
}

static void IgUnregisterObCallbacks(void)
{
    if (g_ObRegistered && g_ObRegHandle) {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
        g_ObRegistered = FALSE;
    }
}

//=============================================================================
// IOCTL 处理
//=============================================================================

static NTSTATUS IgDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ioControlCode, inLen, outLen, bytesReturned = 0;
    PVOID inBuf, outBuf;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    inBuf = Irp->AssociatedIrp.SystemBuffer;
    outBuf = Irp->AssociatedIrp.SystemBuffer;

    switch (ioControlCode)
    {
        case IOCTL_IG_AUTH_INIT:
            status = IgHandleAuthInit(outBuf, outLen, &bytesReturned);
            break;

        case IOCTL_IG_AUTH_VERIFY:
            status = IgHandleAuthVerify(inBuf, inLen, outBuf, outLen, &bytesReturned);
            break;

        case IOCTL_IG_GET_NOTIFICATION:
        {
            IG_NOTIFICATION notif;
            RtlZeroMemory(&notif, sizeof(notif));

            if (outLen < sizeof(IG_NOTIFICATION)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (IgDequeueEvent(&notif)) {
                RtlCopyMemory(outBuf, &notif, sizeof(IG_NOTIFICATION));
                bytesReturned = sizeof(IG_NOTIFICATION);
            } else {
                // 无待处理事件: 返回空通知
                RtlZeroMemory(outBuf, sizeof(IG_NOTIFICATION));
                bytesReturned = sizeof(IG_NOTIFICATION);
            }
            break;
        }

        case IOCTL_IG_SEND_DECISION:
        {
            PIG_DECISION dec;
            if (inLen < sizeof(IG_DECISION)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            dec = (PIG_DECISION)inBuf;
            IgSetDecision(dec->SequenceId, (LONG)dec->Decision);
            DbgPrint("[InjectGuard] Decision seq %u: %u\n", dec->SequenceId, dec->Decision);
            break;
        }

        case IOCTL_IG_ENABLE_PROTECTION:
            InterlockedExchange(&g_Context->ProtectionActive, 1);
            DbgPrint("[InjectGuard] Protection ENABLED\n");
            break;

        case IOCTL_IG_DISABLE_PROTECTION:
            InterlockedExchange(&g_Context->ProtectionActive, 0);
            DbgPrint("[InjectGuard] Protection DISABLED\n");
            break;

        case IOCTL_IG_GET_STATUS:
        {
            IG_STATUS *st;
            if (outLen < sizeof(IG_STATUS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            st = (PIG_STATUS)outBuf;
            RtlZeroMemory(st, sizeof(IG_STATUS));
            st->ProtectionActive = g_Context->ProtectionActive;
            st->PendingEventCount = g_Context->EventQueueCount;
            st->TotalEventsProcessed = g_Context->TotalEvents;
            st->TotalBlocked = g_Context->TotalBlocked;
            st->WhitelistCount = g_Context->WhitelistCount;
            bytesReturned = sizeof(IG_STATUS);
            break;
        }

        case IOCTL_IG_ADD_WHITELIST:
        {
            PIG_WHITELIST_ENTRY entry;
            KIRQL oldIrql;
            if (inLen < sizeof(IG_WHITELIST_ENTRY)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            entry = (PIG_WHITELIST_ENTRY)inBuf;
            KeAcquireSpinLock(&g_Context->WhitelistLock, &oldIrql);
            if (g_Context->WhitelistCount < IG_MAX_WHITELIST) {
                RtlCopyMemory(g_Context->Whitelist[g_Context->WhitelistCount],
                              entry->ProcessName, sizeof(WCHAR) * IG_MAX_NAME_LEN);
                g_Context->WhitelistCount++;
                KeReleaseSpinLock(&g_Context->WhitelistLock, oldIrql);
            } else {
                KeReleaseSpinLock(&g_Context->WhitelistLock, oldIrql);
                status = STATUS_QUOTA_EXCEEDED;
            }
            break;
        }

        case IOCTL_IG_REMOVE_WHITELIST:
        {
            PIG_WHITELIST_ENTRY entry;
            KIRQL oldIrql;
            ULONG i;
            if (inLen < sizeof(IG_WHITELIST_ENTRY)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            entry = (PIG_WHITELIST_ENTRY)inBuf;
            KeAcquireSpinLock(&g_Context->WhitelistLock, &oldIrql);
            for (i = 0; i < g_Context->WhitelistCount; i++) {
                if (_wcsicmp(g_Context->Whitelist[i], entry->ProcessName) == 0) {
                    ULONG last = g_Context->WhitelistCount - 1;
                    if (i != last)
                        RtlCopyMemory(g_Context->Whitelist[i],
                                      g_Context->Whitelist[last],
                                      sizeof(WCHAR) * IG_MAX_NAME_LEN);
                    RtlZeroMemory(g_Context->Whitelist[last], sizeof(WCHAR) * IG_MAX_NAME_LEN);
                    g_Context->WhitelistCount--;
                    break;
                }
            }
            KeReleaseSpinLock(&g_Context->WhitelistLock, oldIrql);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//=============================================================================
// IRP 分发
//=============================================================================

static NTSTATUS IgDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//=============================================================================
// 驱动入口/卸载
//=============================================================================

static void IgDriverUnload(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT dev;

    DbgPrint("[InjectGuard] Unloading...\n");
    IgUnregisterObCallbacks();

    IoDeleteSymbolicLink((PUNICODE_STRING)&(UNICODE_STRING)RTL_CONSTANT_STRING(IG_SYMLINK_NAME));

    dev = DriverObject->DeviceObject;
    while (dev) {
        PDEVICE_OBJECT next = dev->NextDevice;
        IoDeleteDevice(dev);
        dev = next;
    }

    DbgPrint("[InjectGuard] Unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT deviceObject;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[InjectGuard] DriverEntry\n");

    AVPoolCompatInit();

    // 创建控制设备
    RtlInitUnicodeString(&devName, IG_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        sizeof(IG_DEVICE_CONTEXT),
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[InjectGuard] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    g_DeviceObject = deviceObject;
    g_Context = (PIG_DEVICE_CONTEXT)deviceObject->DeviceExtension;
    RtlZeroMemory(g_Context, sizeof(IG_DEVICE_CONTEXT));

    KeInitializeSpinLock(&g_Context->EventQueueLock);
    KeInitializeSpinLock(&g_Context->DecisionLock);
    KeInitializeSpinLock(&g_Context->WhitelistLock);
    KeInitializeSpinLock(&g_ChainLock);

    // 创建符号链接
    RtlInitUnicodeString(&symLink, IG_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[InjectGuard] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // 设置分发表
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IgDispatchDeviceControl;
    DriverObject->DriverUnload = IgDriverUnload;

    // 注册 Ob 回调
    status = IgRegisterObCallbacks();
    if (!NT_SUCCESS(status))
        DbgPrint("[InjectGuard] ObRegisterCallbacks failed, continuing\n");

    RtlZeroMemory(g_ChainTrackers, sizeof(g_ChainTrackers));

    DbgPrint("[InjectGuard] DriverEntry SUCCESS\n");
    return STATUS_SUCCESS;
}
