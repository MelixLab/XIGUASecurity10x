//=============================================================================
// AVSystem.cpp - SYSTEM 权限转发程序
//
// 担任驱动层和主程序之间的安全转发层
// 通过 Windows 服务以 SYSTEM 权限运行
//=============================================================================

#include "XIGUASecurityAgent.h"
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <strsafe.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <sddl.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
//
// 启用 ComCtl32 v6 以使用 TaskDialogIndirect (4 按钮弹窗)
//
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

//=============================================================================
// 进程挂起/终止说明
//
// 被拦截进程的冻结与终止全部由驱动层完成 (线程创建回调挂起,
// 决策后恢复或 ZwTerminateProcess), 用户态只负责转发通知和决策,
// 不做任何进程操作。
//=============================================================================

//=============================================================================
// 服务全局变量
//=============================================================================
static SERVICE_STATUS        g_ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
static HANDLE                g_ServiceStopEvent = NULL;

//
// 自保护驱动设备句柄 (保持打开, 句柄关闭时驱动自动解除保护)
//
static HANDLE                g_hSelfProtect = INVALID_HANDLE_VALUE;

//
// 主客户端 (AVMain) 管道句柄
// AVMain 连接并鉴权成功后注册; 断开时清空
// 进程监控线程通过它转发拦截通知并接收决策
// 由 g_MainPipeLock 保护
//
static HANDLE           g_hMainPipe = NULL;
static CRITICAL_SECTION g_MainPipeLock;

//
// 管道决策分发 (进程/注册表两类决策统一路由)
//
// 问题: 进程监控线程和注册表监控线程可能同时等待决策并同时
//       PeekNamedPipe/ReadFile 同一个管道。消息模式下 ReadFile
//       会把消息从管道中移除, 若被错误的线程读走, 决策就丢失,
//       导致对方等待超时 (30 秒卡顿)。
// 方案: 所有管道读取集中到 PipeDecisionReaderThread 单线程完成,
//       读取后按 消息类型+NotificationId 路由到对应的等待者,
//       监控线程通过事件等待自己的决策, 不再直接读管道。
//
#define AV_MAX_PENDING_DECISIONS 8

typedef struct _PENDING_DECISION
{
    BOOLEAN          Active;           // 是否有等待者
    UINT32           MessageType;      // AvPipeMsgProcessDecision / AvPipeMsgRegDecision / AvPipeMsgRansomDecision ...
    UINT64           NotificationId;   // 等待的通知 ID
    UINT32           Decision;         // 收到的决策原始值 (AV_DECISION_TYPE 或 XGS 决策码, 0=未收到)
    HANDLE           hEvent;           // 决策到达事件
} PENDING_DECISION;

static PENDING_DECISION g_PendingDecisions[AV_MAX_PENDING_DECISIONS];
static CRITICAL_SECTION g_DecisionLock;
static volatile BOOL g_ShutdownRequested = FALSE;   // AVMain 发送 shutdown 请求时置位

//=============================================================================
// XOR 校验和计算
//=============================================================================
UINT32
CalculateChecksum(
    _In_reads_bytes_(dataSize) const BYTE* data,
    _In_ DWORD dataSize
)
{
    UINT32 checksum = 0;
    for (DWORD i = 0; i < dataSize; i++)
    {
        checksum ^= data[i];
    }
    return checksum;
}

//=============================================================================
// HMAC-SHA256 计算
//
// 使用 BCrypt 的 HMAC-SHA256 计算消息认证码
//=============================================================================
BOOL
CalculateHmac(
    _In_reads_bytes_(dataSize) const UCHAR* data,
    _In_ DWORD dataSize,
    _In_reads_bytes_(keySize) const UCHAR* key,
    _In_ DWORD keySize,
    _Out_writes_bytes_(AV_HASH_SIZE) UCHAR* hmacOutput
)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    // 打开 HMAC-SHA256 算法提供者
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (!NT_SUCCESS(status))
    {
        printf("[AVSystem] BCryptOpenAlgorithmProvider failed: 0x%08lX\n", status);
        return FALSE;
    }

    // 创建哈希对象，传入密钥作为 HMAC 密钥
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        NULL,       // 使用默认分配
        0,          // 对象大小
        (PUCHAR)key,
        keySize,
        0           // 标志
    );
    if (!NT_SUCCESS(status))
    {
        printf("[AVSystem] BCryptCreateHash failed: 0x%08lX\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 输入数据
    status = BCryptHashData(hHash, (PUCHAR)data, dataSize, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[AVSystem] BCryptHashData failed: 0x%08lX\n", status);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // 完成哈希计算，输出 HMAC 值
    status = BCryptFinishHash(hHash, hmacOutput, AV_HASH_SIZE, 0);
    if (!NT_SUCCESS(status))
    {
        printf("[AVSystem] BCryptFinishHash failed: 0x%08lX\n", status);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

//=============================================================================
// 连接驱动并鉴权
//
// 1. 打开驱动设备 (有重试机制)
// 2. 发送 IOCTL_AV_AUTH_INIT 获取 Challenge
// 3. 计算 HMAC-SHA256(Challenge || SequenceId, SharedKey)
// 4. 发送 IOCTL_AV_AUTH_VERIFY 提交鉴权
// 5. 保存返回的 Session ID
// 6. 发送 IOCTL_AV_GET_STATUS 验证连接
//=============================================================================
BOOL
ConnectToDriver(
    _Out_ HANDLE* phDriver,
    _Out_writes_bytes_(AV_SESSION_ID_SIZE) UCHAR* sessionId
)
{
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    DWORD bytesReturned;
    AV_AUTH_CHALLENGE challenge;
    AV_AUTH_RESPONSE response;
    AV_AUTH_RESULT authResult;
    AV_DRIVER_STATUS driverStatus;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    int retryCount;

    //-------------------------------------------------------------------------
    // 重试机制：打开驱动设备
    //-------------------------------------------------------------------------
    for (retryCount = 0; retryCount < AV_DRIVER_RETRY_MAX; retryCount++)
    {
        hDriver = CreateFileW(
            AV_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDriver != INVALID_HANDLE_VALUE)
        {
            break;
        }

        if (retryCount < AV_DRIVER_RETRY_MAX - 1)
        {
            printf("[AVSystem] Waiting for driver connection... (attempt %d/%d)\n",
                   retryCount + 1, AV_DRIVER_RETRY_MAX);
            Sleep(AV_DRIVER_RETRY_DELAY);
        }
    }

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[AVSystem] Unable to connect to driver (error: %lu)\n", GetLastError());
        return FALSE;
    }

    printf("[AVSystem] Successfully connected to driver\n");

    //-------------------------------------------------------------------------
    // 发送 IOCTL_AV_AUTH_INIT 获取 Challenge
    //-------------------------------------------------------------------------
    ZeroMemory(&challenge, sizeof(challenge));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_AUTH_INIT,
            NULL, 0,
            &challenge, sizeof(challenge),
            &bytesReturned, NULL))
    {
        printf("[AVSystem] IOCTL_AV_AUTH_INIT failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (bytesReturned < sizeof(AV_AUTH_CHALLENGE))
    {
        printf("[AVSystem] IOCTL_AV_AUTH_INIT returned data too small (%lu bytes)\n", bytesReturned);
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[AVSystem] Received Challenge, SequenceId: %llu\n", challenge.SequenceId);

    //-------------------------------------------------------------------------
    // 调试输出: 打印中间值用于定位 HMAC 不匹配问题
    //-------------------------------------------------------------------------
    printf("[AVSystem] DBG Challenge[0..7] : %02X %02X %02X %02X %02X %02X %02X %02X\n",
           challenge.Challenge[0], challenge.Challenge[1], challenge.Challenge[2], challenge.Challenge[3],
           challenge.Challenge[4], challenge.Challenge[5], challenge.Challenge[6], challenge.Challenge[7]);
    printf("[AVSystem] DBG Challenge[8..15] : %02X %02X %02X %02X %02X %02X %02X %02X\n",
           challenge.Challenge[8], challenge.Challenge[9], challenge.Challenge[10], challenge.Challenge[11],
           challenge.Challenge[12], challenge.Challenge[13], challenge.Challenge[14], challenge.Challenge[15]);
    printf("[AVSystem] DBG Challenge[16..23]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           challenge.Challenge[16], challenge.Challenge[17], challenge.Challenge[18], challenge.Challenge[19],
           challenge.Challenge[20], challenge.Challenge[21], challenge.Challenge[22], challenge.Challenge[23]);
    printf("[AVSystem] DBG Challenge[24..31]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           challenge.Challenge[24], challenge.Challenge[25], challenge.Challenge[26], challenge.Challenge[27],
           challenge.Challenge[28], challenge.Challenge[29], challenge.Challenge[30], challenge.Challenge[31]);

    //-------------------------------------------------------------------------
    // 计算 HMAC-SHA256(Challenge || SequenceId, SharedKey)
    //
    // 将 Challenge 和 SequenceId 拼接作为 HMAC 输入
    //-------------------------------------------------------------------------
    CopyMemory(hmacInput, challenge.Challenge, AV_CHALLENGE_SIZE);
    CopyMemory(hmacInput + AV_CHALLENGE_SIZE, &challenge.SequenceId, sizeof(UINT64));

    // 构造鉴权响应
    ZeroMemory(&response, sizeof(response));
    response.SequenceId = challenge.SequenceId;
    CopyMemory(response.Challenge, challenge.Challenge, AV_CHALLENGE_SIZE);

    // 计算 HMAC
    if (!CalculateHmac(
            hmacInput,
            sizeof(hmacInput),
            AV_SHARED_KEY,
            AV_SHARED_KEY_SIZE,
            response.Hmac))
    {
        printf("[AVSystem] HMAC calculation failed\n");
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[AVSystem] DBG Seq(LE bytes)  : %02X %02X %02X %02X %02X %02X %02X %02X\n",
           hmacInput[32], hmacInput[33], hmacInput[34], hmacInput[35],
           hmacInput[36], hmacInput[37], hmacInput[38], hmacInput[39]);
    printf("[AVSystem] DBG Hmac[0..7]    : %02X %02X %02X %02X %02X %02X %02X %02X\n",
           response.Hmac[0], response.Hmac[1], response.Hmac[2], response.Hmac[3],
           response.Hmac[4], response.Hmac[5], response.Hmac[6], response.Hmac[7]);

    //-------------------------------------------------------------------------
    // 发送 IOCTL_AV_AUTH_VERIFY 提交鉴权
    //-------------------------------------------------------------------------
    ZeroMemory(&authResult, sizeof(authResult));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_AUTH_VERIFY,
            &response, sizeof(response),
            &authResult, sizeof(authResult),
            &bytesReturned, NULL))
    {
        printf("[AVSystem] IOCTL_AV_AUTH_VERIFY failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (authResult.Status != STATUS_SUCCESS)
    {
        printf("[AVSystem] Driver auth failed (Status: 0x%08lX)\n", authResult.Status);

        //
        // 调试回显: SessionId[0..7] = 驱动计算的期望 HMAC 前 8 字节
        //           SessionId[8..15] = 驱动收到的 HMAC 前 8 字节
        //
        printf("[AVSystem] DBG DriverExpected[0..7]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
               authResult.SessionId[0], authResult.SessionId[1], authResult.SessionId[2], authResult.SessionId[3],
               authResult.SessionId[4], authResult.SessionId[5], authResult.SessionId[6], authResult.SessionId[7]);
        printf("[AVSystem] DBG DriverReceived[0..7]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
               authResult.SessionId[8], authResult.SessionId[9], authResult.SessionId[10], authResult.SessionId[11],
               authResult.SessionId[12], authResult.SessionId[13], authResult.SessionId[14], authResult.SessionId[15]);

        CloseHandle(hDriver);
        return FALSE;
    }

    // 保存 Session ID
    CopyMemory(sessionId, authResult.SessionId, AV_SESSION_ID_SIZE);
    printf("[AVSystem] Driver auth succeeded\n");

    //-------------------------------------------------------------------------
    // 发送 IOCTL_AV_GET_STATUS 验证连接
    //-------------------------------------------------------------------------
    ZeroMemory(&driverStatus, sizeof(driverStatus));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_GET_STATUS,
            NULL, 0,
            &driverStatus, sizeof(driverStatus),
            &bytesReturned, NULL))
    {
        printf("[AVSystem] IOCTL_AV_GET_STATUS failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[AVSystem] Driver connection verified - "
           "Version: %u, Active Sessions: %u, Total Scans: %llu, "
           "Callback Triggers: %llu, Block Attempts: %llu\n",
           driverStatus.Version,
           driverStatus.ActiveSessions,
           driverStatus.TotalScans,
           driverStatus.ProcessCallbackTriggers,
           driverStatus.ProcessBlockAttempts);

    *phDriver = hDriver;
    return TRUE;
}

//=============================================================================
// 发送管道消息
//
// 构造 AV_PIPE_MSG_HEADER + data，填充 Magic、MessageType、DataSize、Checksum
// 使用 WriteFile 发送完整消息
//=============================================================================
BOOL
SendPipeMessage(
    _In_ HANDLE hPipe,
    _In_ AV_PIPE_MSG_TYPE type,
    _In_reads_bytes_opt_(dataSize) const void* data,
    _In_ DWORD dataSize
)
{
    BOOL result = FALSE;
    DWORD totalSize = sizeof(AV_PIPE_MSG_HEADER) + dataSize;
    BYTE* buffer = NULL;
    DWORD bytesWritten;
    AV_PIPE_MSG_HEADER* header;

    // 分配发送缓冲区
    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize);
    if (buffer == NULL)
    {
        printf("[AVSystem] SendPipeMessage: memory allocation failed\n");
        return FALSE;
    }

    // 填充消息头
    header = (AV_PIPE_MSG_HEADER*)buffer;
    header->Magic = (UINT32)AV_PIPE_MAGIC;
    header->MessageType = (UINT32)type;
    header->DataSize = dataSize;

    // 复制数据部分
    if (data != NULL && dataSize > 0)
    {
        CopyMemory(buffer + sizeof(AV_PIPE_MSG_HEADER), data, dataSize);
    }

    // 计算 XOR 校验和 (对数据部分)
    header->Checksum = CalculateChecksum(
        buffer + sizeof(AV_PIPE_MSG_HEADER),
        dataSize);

    // 发送
    if (!WriteFile(hPipe, buffer, totalSize, &bytesWritten, NULL))
    {
        printf("[AVSystem] SendPipeMessage: WriteFile failed (error: %lu)\n", GetLastError());
        goto Cleanup;
    }

    if (bytesWritten != totalSize)
    {
        printf("[AVSystem] SendPipeMessage: sent data incomplete (%lu/%lu)\n",
               bytesWritten, totalSize);
        goto Cleanup;
    }

    result = TRUE;

Cleanup:
    if (buffer)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
    }
    return result;
}

//=============================================================================
// 接收管道消息
//
// 1. ReadFile 接收完整消息
// 2. 验证 Magic 和 Checksum
// 3. 返回消息头和数据指针
//=============================================================================
BOOL
RecvPipeMessage(
    _In_ HANDLE hPipe,
    _Out_writes_bytes_(bufferSize) BYTE* buffer,
    _In_ DWORD bufferSize,
    _Outptr_ AV_PIPE_MSG_HEADER** ppHeader,
    _Outptr_result_bytebuffer_(*pDataSize) BYTE** ppData,
    _Out_ DWORD* pDataSize
)
{
    DWORD bytesRead;
    AV_PIPE_MSG_HEADER* header;
    UINT32 expectedChecksum;

    // 读取消息
    if (!ReadFile(hPipe, buffer, bufferSize, &bytesRead, NULL))
    {
        DWORD error = GetLastError();
        if (error != ERROR_BROKEN_PIPE && error != ERROR_PIPE_NOT_CONNECTED)
        {
            printf("[AVSystem] RecvPipeMessage: ReadFile failed (error: %lu)\n", error);
        }
        return FALSE;
    }

    // 检查是否读到足够的数据
    if (bytesRead < sizeof(AV_PIPE_MSG_HEADER))
    {
        printf("[AVSystem] RecvPipeMessage: data too short (%lu bytes)\n", bytesRead);
        return FALSE;
    }

    // 解析消息头
    header = (AV_PIPE_MSG_HEADER*)buffer;

    // 验证 Magic
    if (header->Magic != (UINT32)AV_PIPE_MAGIC)
    {
        printf("[AVSystem] RecvPipeMessage: Magic mismatch (expected: 0x%08X, received: 0x%08X)\n",
               (UINT32)AV_PIPE_MAGIC, header->Magic);
        return FALSE;
    }

    // 验证数据大小
    if (sizeof(AV_PIPE_MSG_HEADER) + header->DataSize > bytesRead)
    {
        printf("[AVSystem] RecvPipeMessage: data size mismatch (declared: %u, actual remaining: %lu)\n",
               header->DataSize, bytesRead - sizeof(AV_PIPE_MSG_HEADER));
        return FALSE;
    }

    // 验证 XOR 校验和
    expectedChecksum = CalculateChecksum(
        buffer + sizeof(AV_PIPE_MSG_HEADER),
        header->DataSize);

    if (header->Checksum != expectedChecksum)
    {
        printf("[AVSystem] RecvPipeMessage: Checksum mismatch (expected: 0x%08X, received: 0x%08X)\n",
               expectedChecksum, header->Checksum);
        return FALSE;
    }

    // 返回指针
    *ppHeader = header;
    *ppData = (bytesRead > sizeof(AV_PIPE_MSG_HEADER))
                  ? buffer + sizeof(AV_PIPE_MSG_HEADER)
                  : NULL;
    *pDataSize = header->DataSize;

    return TRUE;
}

//=============================================================================
// 客户端鉴权
//
// 对管道客户端执行鉴权流程:
// 1. 收到 AvPipeMsgAuthInit
// 2. 生成 32 字节随机 Challenge
// 3. 发送 AvPipeMsgAuthChallenge (含 Challenge + SequenceId)
// 4. 收到 AvPipeMsgAuthVerify
// 5. 验证 HMAC
// 6. 发送 AvPipeMsgAuthResult
//=============================================================================
BOOL
AuthenticatePipeClient(
    _In_ HANDLE hPipe,
    _Out_writes_bytes_(AV_SESSION_ID_SIZE) UCHAR* clientSessionId
)
{
    BYTE recvBuffer[AV_PIPE_BUFFER_SIZE];
    AV_PIPE_MSG_HEADER* pHeader = NULL;
    BYTE* pData = NULL;
    DWORD dataSize = 0;
    AV_PIPE_AUTH_INIT* authInit;
    AV_PIPE_AUTH_CHALLENGE_DATA challengeData;
    AV_PIPE_AUTH_VERIFY_DATA* verifyData;
    AV_PIPE_AUTH_RESULT_DATA authResult;
    UCHAR expectedHmac[AV_HASH_SIZE];
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    static volatile LONG64 s_sequenceCounter = 1;

    //-------------------------------------------------------------------------
    // 步骤 1: 接收 AvPipeMsgAuthInit
    //-------------------------------------------------------------------------
    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer),
                         &pHeader, &pData, &dataSize))
    {
        printf("[AVSystem] Auth: receive AuthInit failed\n");
        return FALSE;
    }

    if (pHeader->MessageType != AvPipeMsgAuthInit)
    {
        printf("[AVSystem] Auth: expected AuthInit (0x%04X), received 0x%04X\n",
               AvPipeMsgAuthInit, pHeader->MessageType);
        return FALSE;
    }

    authInit = (AV_PIPE_AUTH_INIT*)pData;
    printf("[AVSystem] Client auth started, protocol version: %u\n", authInit->ProtocolVersion);

    //-------------------------------------------------------------------------
    // 步骤 2: 生成随机 Challenge 和 SequenceId
    //-------------------------------------------------------------------------
    ZeroMemory(&challengeData, sizeof(challengeData));

    // 使用 BCryptGenRandom 生成 32 字节随机 Challenge
    if (!NT_SUCCESS(BCryptGenRandom(
            NULL,
            challengeData.Challenge,
            AV_CHALLENGE_SIZE,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        printf("[AVSystem] Auth: BCryptGenRandom failed\n");
        return FALSE;
    }

    // 生成 SequenceId
    challengeData.SequenceId = InterlockedIncrement64(&s_sequenceCounter);

    //-------------------------------------------------------------------------
    // 步骤 3: 发送 AvPipeMsgAuthChallenge
    //-------------------------------------------------------------------------
    if (!SendPipeMessage(hPipe, AvPipeMsgAuthChallenge,
                         &challengeData, sizeof(challengeData)))
    {
        printf("[AVSystem] Auth: send AuthChallenge failed\n");
        return FALSE;
    }

    //-------------------------------------------------------------------------
    // 步骤 4: 接收 AvPipeMsgAuthVerify
    //-------------------------------------------------------------------------
    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer),
                         &pHeader, &pData, &dataSize))
    {
        printf("[AVSystem] Auth: receive AuthVerify failed\n");
        return FALSE;
    }

    if (pHeader->MessageType != AvPipeMsgAuthVerify)
    {
        printf("[AVSystem] Auth: expected AuthVerify (0x%04X), received 0x%04X\n",
               AvPipeMsgAuthVerify, pHeader->MessageType);
        // 发送鉴权失败结果
        ZeroMemory(&authResult, sizeof(authResult));
        authResult.Success = FALSE;
        authResult.ErrorCode = 1;
        SendPipeMessage(hPipe, AvPipeMsgAuthResult, &authResult, sizeof(authResult));
        return FALSE;
    }

    if (dataSize < sizeof(AV_PIPE_AUTH_VERIFY_DATA))
    {
        printf("[AVSystem] Auth: AuthVerify data too small\n");
        ZeroMemory(&authResult, sizeof(authResult));
        authResult.Success = FALSE;
        authResult.ErrorCode = 2;
        SendPipeMessage(hPipe, AvPipeMsgAuthResult, &authResult, sizeof(authResult));
        return FALSE;
    }

    verifyData = (AV_PIPE_AUTH_VERIFY_DATA*)pData;

    //-------------------------------------------------------------------------
    // 步骤 5: 验证 HMAC
    //
    // 计算期望的 HMAC-SHA256(Challenge || SequenceId, SharedKey)
    // 与客户端提交的 HMAC 比较
    //-------------------------------------------------------------------------

    // 构造 HMAC 输入: Challenge || SequenceId
    CopyMemory(hmacInput, verifyData->Challenge, AV_CHALLENGE_SIZE);
    CopyMemory(hmacInput + AV_CHALLENGE_SIZE, &verifyData->SequenceId, sizeof(UINT64));

    // 计算期望的 HMAC
    if (!CalculateHmac(
            hmacInput,
            sizeof(hmacInput),
            AV_SHARED_KEY,
            AV_SHARED_KEY_SIZE,
            expectedHmac))
    {
        printf("[AVSystem] Auth: HMAC calculation failed\n");
        ZeroMemory(&authResult, sizeof(authResult));
        authResult.Success = FALSE;
        authResult.ErrorCode = 3;
        SendPipeMessage(hPipe, AvPipeMsgAuthResult, &authResult, sizeof(authResult));
        return FALSE;
    }

    // 比较 HMAC
    BOOL hmacMatch = (memcmp(expectedHmac, verifyData->Hmac, AV_HASH_SIZE) == 0);

    ZeroMemory(&authResult, sizeof(authResult));
    authResult.Success = hmacMatch ? TRUE : FALSE;

    if (hmacMatch)
    {
        // 生成客户端 Session ID (使用 BCryptGenRandom)
        if (!NT_SUCCESS(BCryptGenRandom(
                NULL,
                clientSessionId,
                AV_SESSION_ID_SIZE,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            printf("[AVSystem] Auth: generate Session ID failed\n");
            authResult.Success = FALSE;
            authResult.ErrorCode = 4;
            SendPipeMessage(hPipe, AvPipeMsgAuthResult, &authResult, sizeof(authResult));
            return FALSE;
        }

        CopyMemory(authResult.SessionId, clientSessionId, AV_SESSION_ID_SIZE);
        authResult.ErrorCode = 0;
        printf("[AVSystem] Client auth succeeded\n");
    }
    else
    {
        authResult.ErrorCode = 0xAB000001;  // HMAC 不匹配
        printf("[AVSystem] Client auth failed: HMAC mismatch\n");
    }

    //-------------------------------------------------------------------------
    // 步骤 6: 发送 AvPipeMsgAuthResult
    //-------------------------------------------------------------------------
    if (!SendPipeMessage(hPipe, AvPipeMsgAuthResult, &authResult, sizeof(authResult)))
    {
        printf("[AVSystem] Auth: send AuthResult failed\n");
        return FALSE;
    }

    return hmacMatch;
}

//=============================================================================
// 处理管道消息
//
// 根据消息类型转发到驱动或将驱动返回结果转发回客户端
//=============================================================================
BOOL
HandlePipeMessage(
    _In_ HANDLE hPipe,
    _In_ HANDLE hDriver,
    _In_reads_bytes_(AV_SESSION_ID_SIZE) const UCHAR* sessionId,
    _In_ AV_PIPE_MSG_HEADER* pHeader,
    _In_reads_bytes_(pHeader->DataSize) BYTE* pData
)
{
    BOOL result = FALSE;

    switch (pHeader->MessageType)
    {
        case AvPipeMsgScanRequest:
        {
            //-------------------------------------------------------------------------
            // 扫描请求: AvPipeMsgScanRequest -> IOCTL_AV_SCAN_FILE -> 转发结果
            //-------------------------------------------------------------------------
            AV_PIPE_SCAN_REQUEST_DATA* pipeScanReq = (AV_PIPE_SCAN_REQUEST_DATA*)pData;
            AV_SCAN_RESPONSE scanResp;
            AV_PIPE_SCAN_RESPONSE_DATA pipeScanResp;
            DWORD bytesReturned;

            // 构造驱动扫描请求 (结构布局相同，直接使用)
            // 将 SessionId 替换为 AVSystem 的驱动 session
            // 注意：驱动需要的是 AVSystem 的 session，不是客户端的
            // 但扫描请求中携带的 sessionId 用于驱动验证客户端身份
            // 这里使用 AVSystem 的 sessionId 转发
            BYTE* driverRequest = (BYTE*)HeapAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                sizeof(AV_SCAN_REQUEST) + pipeScanReq->FilePathLength);

            if (driverRequest == NULL)
            {
                printf("[AVSystem] HandleMsg: memory allocation failed\n");
                break;
            }

            AV_SCAN_REQUEST* scanReq = (AV_SCAN_REQUEST*)driverRequest;
            CopyMemory(scanReq->SessionId, sessionId, AV_SESSION_ID_SIZE);
            scanReq->RequestId = pipeScanReq->RequestId;
            scanReq->FilePathLength = pipeScanReq->FilePathLength;
            CopyMemory(scanReq->FilePath, pipeScanReq->FilePath, pipeScanReq->FilePathLength);

            // 发送 IOCTL_AV_SCAN_FILE 给驱动
            ZeroMemory(&scanResp, sizeof(scanResp));
            if (!DeviceIoControl(
                    hDriver,
                    IOCTL_AV_SCAN_FILE,
                    driverRequest,
                    sizeof(AV_SCAN_REQUEST) + pipeScanReq->FilePathLength - sizeof(WCHAR),
                    &scanResp, sizeof(scanResp),
                    &bytesReturned, NULL))
            {
                printf("[AVSystem] HandleMsg: IOCTL_AV_SCAN_FILE failed (error: %lu)\n",
                       GetLastError());
                HeapFree(GetProcessHeap(), 0, driverRequest);
                break;
            }

            HeapFree(GetProcessHeap(), 0, driverRequest);

            // 构造管道扫描响应
            ZeroMemory(&pipeScanResp, sizeof(pipeScanResp));
            pipeScanResp.RequestId = scanResp.RequestId;
            pipeScanResp.Success = (scanResp.Status == STATUS_SUCCESS) ? TRUE : FALSE;
            pipeScanResp.ThreatLevel = scanResp.ThreatLevel;
            CopyMemory(pipeScanResp.ThreatName, scanResp.ThreatName,
                       sizeof(pipeScanResp.ThreatName));

            // 发送响应给客户端
            if (!SendPipeMessage(hPipe, AvPipeMsgScanResponse,
                                 &pipeScanResp, sizeof(pipeScanResp)))
            {
                printf("[AVSystem] HandleMsg: send ScanResponse failed\n");
                break;
            }

            result = TRUE;
            break;
        }

        case AvPipeMsgGetStatus:
        {
            //-------------------------------------------------------------------------
            // 状态查询: AvPipeMsgGetStatus -> IOCTL_AV_GET_STATUS -> 转发结果
            //-------------------------------------------------------------------------
            AV_DRIVER_STATUS driverStatus;
            DWORD bytesReturned;

            ZeroMemory(&driverStatus, sizeof(driverStatus));
            if (!DeviceIoControl(
                    hDriver,
                    IOCTL_AV_GET_STATUS,
                    NULL, 0,
                    &driverStatus, sizeof(driverStatus),
                    &bytesReturned, NULL))
            {
                printf("[AVSystem] HandleMsg: IOCTL_AV_GET_STATUS failed (error: %lu)\n",
                       GetLastError());
                break;
            }

            // 转发状态数据给客户端
            if (!SendPipeMessage(hPipe, AvPipeMsgStatusResponse,
                                 &driverStatus, sizeof(driverStatus)))
            {
                printf("[AVSystem] HandleMsg: send StatusResponse failed\n");
                break;
            }

            result = TRUE;
            break;
        }

        case AvPipeMsgHeartbeat:
        {
            //-------------------------------------------------------------------------
            // 心跳: AvPipeMsgHeartbeat -> IOCTL_AV_HEARTBEAT -> 转发结果
            //-------------------------------------------------------------------------
            AV_HEARTBEAT_REQUEST hbRequest;
            AV_HEARTBEAT_RESPONSE hbResponse;
            DWORD bytesReturned;

            if (pData != NULL && pHeader->DataSize >= sizeof(AV_HEARTBEAT_REQUEST))
            {
                CopyMemory(&hbRequest, pData, sizeof(AV_HEARTBEAT_REQUEST));
            }
            else
            {
                // 如果客户端没有提供完整的心跳请求，构造一个默认的
                ZeroMemory(&hbRequest, sizeof(hbRequest));
                CopyMemory(hbRequest.SessionId, sessionId, AV_SESSION_ID_SIZE);
                hbRequest.Timestamp = GetTickCount64();
            }

            ZeroMemory(&hbResponse, sizeof(hbResponse));
            if (!DeviceIoControl(
                    hDriver,
                    IOCTL_AV_HEARTBEAT,
                    &hbRequest, sizeof(hbRequest),
                    &hbResponse, sizeof(hbResponse),
                    &bytesReturned, NULL))
            {
                printf("[AVSystem] HandleMsg: IOCTL_AV_HEARTBEAT failed (error: %lu)\n",
                       GetLastError());
                break;
            }

            // 转发心跳响应
            if (!SendPipeMessage(hPipe, AvPipeMsgHeartbeatResponse,
                                 &hbResponse, sizeof(hbResponse)))
            {
                printf("[AVSystem] HandleMsg: send HeartbeatResponse failed\n");
                break;
            }

            result = TRUE;
            break;
        }

        default:
        {
            printf("[AVSystem] HandleMsg: unknown message type 0x%04X\n", pHeader->MessageType);

            // 发送错误消息
            AV_PIPE_ERROR_DATA errorData;
            ZeroMemory(&errorData, sizeof(errorData));
            errorData.ErrorCode = 0xFFFFFFFF;
            wcscpy_s(errorData.ErrorMessage, 256, L"Unknown message type");
            SendPipeMessage(hPipe, AvPipeMsgError, &errorData, sizeof(errorData));
            break;
        }
    }

    return result;
}

//=============================================================================
// 管道客户端处理线程
//
// 每个连接的客户端分配一个独立线程处理:
// 1. 鉴权
// 2. 消息循环 (接收 -> 处理 -> 转发)
// 3. 断开处理
//=============================================================================
typedef struct _CLIENT_THREAD_PARAM
{
    HANDLE hPipe;
    HANDLE hDriver;
    UCHAR  sessionId[AV_SESSION_ID_SIZE];
} CLIENT_THREAD_PARAM;

DWORD
WINAPI
PipeClientThread(
    _In_ LPVOID lpParam
)
{
    CLIENT_THREAD_PARAM* param = (CLIENT_THREAD_PARAM*)lpParam;
    HANDLE hPipe = param->hPipe;
    UCHAR clientSessionId[AV_SESSION_ID_SIZE];

    printf("[AVSystem] New client connected, starting auth...\n");

    //-------------------------------------------------------------------------
    // 步骤 1: 鉴权
    //-------------------------------------------------------------------------
    if (!AuthenticatePipeClient(hPipe, clientSessionId))
    {
        printf("[AVSystem] Client auth failed, disconnecting\n");
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        HeapFree(GetProcessHeap(), 0, param);
        return 1;
    }

    //-------------------------------------------------------------------------
    // 步骤 2: 注册为主客户端 (AVMain)
    //-------------------------------------------------------------------------
    printf("[AVSystem] Client auth passed, registering as UI client\n");

    //
    // 注册为主客户端: 进程监控线程将使用该句柄转发拦截通知并接收决策
    // 注意: 该线程不再读取管道 (由进程监控线程负责读取决策回复),
    // 仅保持连接并监控断开
    //
    EnterCriticalSection(&g_MainPipeLock);
    g_hMainPipe = hPipe;
    LeaveCriticalSection(&g_MainPipeLock);

    //
    // 保持连接, 监控管道断开
    //
    while (TRUE)
    {
        DWORD avail = 0;

        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL))
        {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)
            {
                printf("[AVSystem] UI client disconnected\n");
            }
            else
            {
                printf("[AVSystem] Pipe check failed (error: %lu)\n", error);
            }
            break;
        }

        Sleep(500);
    }

    //-------------------------------------------------------------------------
    // 步骤 3: 清理
    //-------------------------------------------------------------------------
    EnterCriticalSection(&g_MainPipeLock);
    if (g_hMainPipe == hPipe)
    {
        g_hMainPipe = NULL;
    }
    LeaveCriticalSection(&g_MainPipeLock);

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    HeapFree(GetProcessHeap(), 0, param);

    printf("[AVSystem] Client processing thread exited\n");
    return 0;
}

//=============================================================================
// 运行管道服务器
//
// 创建命名管道并等待客户端连接，每个客户端创建独立线程处理
//=============================================================================
BOOL
RunPipeServer(
    _In_ HANDLE hDriver,
    _In_reads_bytes_(AV_SESSION_ID_SIZE) const UCHAR* sessionId
)
{
    printf("[AVSystem] Starting pipe server...\n");

    //
    // 用 OVERLAPPED 异步等待 ConnectNamedPipe, 这样可以响应 shutdown 请求
    // (否则会阻塞在 ConnectNamedPipe 无法退出)
    //
    HANDLE hConnectEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hConnectEvent == NULL)
    {
        printf("[AVSystem] CreateEvent for connect failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    //
    // 构建管道安全描述符: SYSTEM 完全控制 + Admins 完全控制 + Everyone 读写
    // (普通用户权限的 AVMain 也可连接, 不再报 ERROR_ACCESS_DENIED)
    //
    SECURITY_ATTRIBUTES  sa;
    SECURITY_DESCRIPTOR* pSD = NULL;
    ZeroMemory(&sa, sizeof(sa));
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)",
            SDDL_REVISION_1,
            (PSECURITY_DESCRIPTOR*)&pSD,
            NULL))
    {
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;
        printf("[AVSystem] Pipe SD initialized (Everyone read/write allowed)\n");
    }
    else
    {
        printf("[AVSystem] ConvertStringSecurityDescriptor failed (error: %lu), using NULL SD\n",
               GetLastError());
    }

    while (TRUE)
    {
        //
        // 检查 shutdown 请求 (AVMain 按 'q' 触发)
        //
        if (g_ShutdownRequested)
        {
            printf("[AVSystem] Shutdown requested, exiting pipe server...\n");
            break;
        }

        HANDLE hPipe = CreateNamedPipeW(
            AV_PIPE_FULL_NAME,
            FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            AV_PIPE_BUFFER_SIZE,
            AV_PIPE_BUFFER_SIZE,
            AV_PIPE_TIMEOUT,
            (pSD != NULL) ? &sa : NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            printf("[AVSystem] CreateNamedPipe failed (error: %lu)\n", GetLastError());
            continue;
        }

        //
        // 异步等待客户端连接
        //
        OVERLAPPED ov = { 0 };
        ov.hEvent = hConnectEvent;
        ResetEvent(hConnectEvent);

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        DWORD error = GetLastError();

        if (!connected)
        {
            if (error == ERROR_IO_PENDING)
            {
                //
                // 等待连接或 shutdown 请求
                // (每隔 200ms 检查 shutdown, 避免长时间阻塞)
                //
                while (TRUE)
                {
                    DWORD waitResult = WaitForSingleObject(hConnectEvent, 200);
                    if (waitResult == WAIT_OBJECT_0)
                    {
                        // 客户端连接成功
                        break;
                    }
                    if (g_ShutdownRequested)
                    {
                        // shutdown 请求: 取消等待, 关闭 pipe
                        CancelIo(hPipe);
                        FlushFileBuffers(hPipe);
                        DisconnectNamedPipe(hPipe);
                        CloseHandle(hPipe);
                        printf("[AVSystem] Shutdown during connect wait, exiting...\n");
                        goto shutdown_exit;
                    }
                }
            }
            else if (error != ERROR_PIPE_CONNECTED)
            {
                printf("[AVSystem] ConnectNamedPipe failed (error: %lu)\n", error);
                CloseHandle(hPipe);
                continue;
            }
            // ERROR_PIPE_CONNECTED: 客户端已连接, 继续
        }

        //
        // 连接成功后再次检查 shutdown (避免在 shutdown 后还接受新连接)
        //
        if (g_ShutdownRequested)
        {
            printf("[AVSystem] Shutdown requested, closing new connection...\n");
            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }

        printf("[AVSystem] Client connected\n");

        // 创建客户端处理线程
        CLIENT_THREAD_PARAM* param = (CLIENT_THREAD_PARAM*)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(CLIENT_THREAD_PARAM));

        if (param == NULL)
        {
            printf("[AVSystem] Memory allocation failed\n");
            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            continue;
        }

        param->hPipe = hPipe;
        param->hDriver = hDriver;
        CopyMemory(param->sessionId, sessionId, AV_SESSION_ID_SIZE);

        HANDLE hThread = CreateThread(
            NULL,
            0,
            PipeClientThread,
            param,
            0,
            NULL
        );

        if (hThread == NULL)
        {
            printf("[AVSystem] CreateThread failed (error: %lu)\n", GetLastError());
            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            HeapFree(GetProcessHeap(), 0, param);
            continue;
        }

        // 不等待线程，允许并发处理多个客户端
        CloseHandle(hThread);
    }

shutdown_exit:
    CloseHandle(hConnectEvent);
    if (pSD != NULL)
    {
        LocalFree(pSD);
        pSD = NULL;
    }
    return TRUE;
}

//=============================================================================
// 驱动心跳线程参数
//=============================================================================
typedef struct _AV_HEARTBEAT_THREAD_PARAMS
{
    HANDLE hDriver;
    UCHAR  SessionId[AV_SESSION_ID_SIZE];
} AV_HEARTBEAT_THREAD_PARAMS;

//=============================================================================
// DriverHeartbeatThread - 驱动心跳线程
//
// 每 2 秒向驱动发送 IOCTL_AV_HEARTBEAT, 刷新驱动端客户端活跃时间戳。
// 为什么需要独立心跳线程:
//   进程监控线程在等待 AVMain 决策回复期间 (最长 30 秒) 不会发起任何
//   IOCTL (阻塞在 PeekNamedPipe 轮询), 此时驱动端的客户端活跃时间戳
//   会在约 5 秒后超时。超时后驱动回调对后续新进程直接静默放行,
//   表现为"有些时候拦截不到 / 进程直接打开了"。
//   独立心跳线程保证驱动在任何时刻都能感知 AVSystem 存活。
//=============================================================================
static DWORD
WINAPI
DriverHeartbeatThread(
    _In_ LPVOID lpParam
    )
{
    AV_HEARTBEAT_THREAD_PARAMS* params = (AV_HEARTBEAT_THREAD_PARAMS*)lpParam;
    DWORD bytesReturned;
    DWORD debugCounter = 0;

    printf("[AVHeartbeat] Heartbeat thread started\n");

    while (TRUE)
    {
        Sleep(2000);

        if (params->hDriver == INVALID_HANDLE_VALUE || params->hDriver == NULL)
        {
            break;
        }

        AV_HEARTBEAT_REQUEST hbRequest;
        AV_HEARTBEAT_RESPONSE hbResponse;
        UCHAR hmacInput[AV_SESSION_ID_SIZE + sizeof(UINT64)];
        UCHAR hmac[AV_HASH_SIZE];

        ZeroMemory(&hbRequest, sizeof(hbRequest));
        ZeroMemory(&hbResponse, sizeof(hbResponse));
        CopyMemory(hbRequest.SessionId, params->SessionId, AV_SESSION_ID_SIZE);
        hbRequest.Timestamp = GetTickCount64();

        //
        // HMAC-SHA256(SessionId || Timestamp, SharedKey)
        //
        CopyMemory(hmacInput, hbRequest.SessionId, AV_SESSION_ID_SIZE);
        CopyMemory(hmacInput + AV_SESSION_ID_SIZE,
                   &hbRequest.Timestamp, sizeof(UINT64));

        if (CalculateHmac(hmacInput, sizeof(hmacInput),
                          AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                          hmac))
        {
            CopyMemory(hbRequest.Hmac, hmac, AV_HASH_SIZE);

            if (!DeviceIoControl(params->hDriver, IOCTL_AV_HEARTBEAT,
                                 &hbRequest, sizeof(hbRequest),
                                 &hbResponse, sizeof(hbResponse),
                                 &bytesReturned, NULL))
            {
                printf("[AVHeartbeat] IOCTL_AV_HEARTBEAT failed (error: %lu)\n",
                       GetLastError());
            }
        }

        //
        // 每 10 秒查询一次驱动诊断信息
        // 用于排查拦截未生效: 观察注册表/进程计数与最近动作
        //
        if ((++debugCounter % 5) == 0)
        {
            AV_DEBUG_INFO debugInfo;
            ZeroMemory(&debugInfo, sizeof(debugInfo));

            if (DeviceIoControl(params->hDriver, IOCTL_AV_GET_DEBUG_INFO,
                                NULL, 0,
                                &debugInfo, sizeof(debugInfo),
                                &bytesReturned, NULL))
            {
                printf("[DBG] Proc: Trig=%llu Hit=%llu Blk=%llu Beh=%llu Inj=%llu | Reg: Trig=%llu Hit=%llu Blk=%llu PathFail=%llu Action=%u LastReg=%ls\n",
                       debugInfo.CallbackTriggers,
                       debugInfo.ProtectedHits,
                       debugInfo.BlockAttempts,
                       debugInfo.BehaviorTriggers,
                       debugInfo.InjectionTriggers,
                       debugInfo.RegCallbackTriggers,
                       debugInfo.RegSensitiveHits,
                       debugInfo.RegBlockAttempts,
                       debugInfo.RegPathFailures,
                       debugInfo.LastRegAction,
                       debugInfo.LastRegPath[0] != L'\0' ? debugInfo.LastRegPath : L"(none)");
            }
            else
            {
                printf("[AVHeartbeat] IOCTL_AV_GET_DEBUG_INFO failed (error: %lu)\n",
                       GetLastError());
            }
        }
    }

    return 0;
}

//=============================================================================
// WaitForPipeDecision - 注册决策等待者并等待决策
//
// 由监控线程调用: 注册 (消息类型, NotificationId) 等待项,
// 等待管道决策分发线程送达决策 (事件通知)。
// 超时或无法注册时返回 AvDecisionInvalid, 由调用方决定默认策略。
//=============================================================================
static AV_DECISION_TYPE
WaitForPipeDecision(
    _In_ UINT32 MessageType,
    _In_ UINT64 NotificationId,
    _In_ DWORD TimeoutMs
    )
{
    HANDLE hEvent = NULL;
    int slot = -1;
    int i;

    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return AvDecisionInvalid;
    }

    EnterCriticalSection(&g_DecisionLock);

    for (i = 0; i < AV_MAX_PENDING_DECISIONS; i++)
    {
        if (!g_PendingDecisions[i].Active)
        {
            slot = i;
            break;
        }
    }

    if (slot < 0)
    {
        LeaveCriticalSection(&g_DecisionLock);
        CloseHandle(hEvent);
        return AvDecisionInvalid;   // 等待槽位已满
    }

    g_PendingDecisions[slot].Active = TRUE;
    g_PendingDecisions[slot].MessageType = MessageType;
    g_PendingDecisions[slot].NotificationId = NotificationId;
    g_PendingDecisions[slot].Decision = AvDecisionInvalid;
    g_PendingDecisions[slot].hEvent = hEvent;

    LeaveCriticalSection(&g_DecisionLock);

    //
    // 等待决策 (超时由调用方控制)
    //
    WaitForSingleObject(hEvent, TimeoutMs);

    //
    // 读取决策并注销等待项
    //
    EnterCriticalSection(&g_DecisionLock);
    AV_DECISION_TYPE decision = (AV_DECISION_TYPE)g_PendingDecisions[slot].Decision;
    g_PendingDecisions[slot].Active = FALSE;
    LeaveCriticalSection(&g_DecisionLock);

    CloseHandle(hEvent);
    return decision;
}

//=============================================================================
// WaitForPipeRawDecision - 等待管道决策 (返回原始 UINT32 决策值)
//
// 与 WaitForPipeDecision 逻辑一致, 但返回原始决策数值, 供勒索等
// 非 AV_DECISION_TYPE 枚举的决策类型使用。
// 返回值: 0 表示超时/无法注册 (无决策), 其余为 AVMain 提交的原始值。
//=============================================================================
static UINT32
WaitForPipeRawDecision(
    _In_ UINT32 MessageType,
    _In_ UINT64 NotificationId,
    _In_ DWORD TimeoutMs
    )
{
    HANDLE hEvent = NULL;
    int slot = -1;
    int i;
    UINT32 decision = 0;

    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return 0;
    }

    EnterCriticalSection(&g_DecisionLock);

    for (i = 0; i < AV_MAX_PENDING_DECISIONS; i++)
    {
        if (!g_PendingDecisions[i].Active)
        {
            slot = i;
            break;
        }
    }

    if (slot < 0)
    {
        LeaveCriticalSection(&g_DecisionLock);
        CloseHandle(hEvent);
        return 0;   // 等待槽位已满
    }

    g_PendingDecisions[slot].Active = TRUE;
    g_PendingDecisions[slot].MessageType = MessageType;
    g_PendingDecisions[slot].NotificationId = NotificationId;
    g_PendingDecisions[slot].Decision = 0;
    g_PendingDecisions[slot].hEvent = hEvent;

    LeaveCriticalSection(&g_DecisionLock);

    //
    // 等待决策 (超时由调用方控制)
    //
    WaitForSingleObject(hEvent, TimeoutMs);

    //
    // 读取决策并注销等待项
    //
    EnterCriticalSection(&g_DecisionLock);
    decision = g_PendingDecisions[slot].Decision;
    g_PendingDecisions[slot].Active = FALSE;
    LeaveCriticalSection(&g_DecisionLock);

    CloseHandle(hEvent);
    return decision;
}

//=============================================================================
// PipeDecisionReaderThread - 管道决策分发线程 (唯一管道读取者)
//
// 读取主客户端发来的决策消息 (进程/注册表), 按 消息类型+NotificationId
// 路由到对应的等待者并触发事件。监控线程不再直接读管道,
// 避免两个监控线程互相吃掉对方的决策消息。
//=============================================================================
static DWORD
WINAPI
PipeDecisionReaderThread(
    _In_ LPVOID lpParam
    )
{
    UNREFERENCED_PARAMETER(lpParam);

    printf("[AVDecision] Pipe decision reader thread started\n");

    while (TRUE)
    {
        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        if (hPipe == NULL)
        {
            Sleep(50);
            continue;
        }

        DWORD avail = 0;
        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) || avail == 0)
        {
            Sleep(50);
            continue;
        }

        BYTE recvBuffer[AV_PIPE_BUFFER_SIZE];
        AV_PIPE_MSG_HEADER* header = NULL;
        BYTE* pData = NULL;
        DWORD dataSize = 0;

        if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer),
                             &header, &pData, &dataSize))
        {
            continue;
        }

        //
        // 提取决策内容
        //
        UINT32 msgType = 0;
        UINT64 notifId = 0;
        UINT32 decision = 0;

        if (header->MessageType == AvPipeMsgProcessDecision &&
            pData != NULL && dataSize >= sizeof(AV_PIPE_PROCESS_DECISION_DATA))
        {
            AV_PIPE_PROCESS_DECISION_DATA* d = (AV_PIPE_PROCESS_DECISION_DATA*)pData;
            msgType = AvPipeMsgProcessDecision;
            notifId = d->NotificationId;
            decision = (UINT32)d->Decision;
        }
        else if (header->MessageType == AvPipeMsgRegDecision &&
                 pData != NULL && dataSize >= sizeof(AV_PIPE_REG_DECISION_DATA))
        {
            AV_PIPE_REG_DECISION_DATA* d = (AV_PIPE_REG_DECISION_DATA*)pData;
            msgType = AvPipeMsgRegDecision;
            notifId = d->NotificationId;
            decision = (UINT32)d->Decision;
        }
        else if (header->MessageType == AvPipeMsgInjectionDecision &&
                 pData != NULL && dataSize >= sizeof(AV_PIPE_INJECTION_DECISION_DATA))
        {
            AV_PIPE_INJECTION_DECISION_DATA* d = (AV_PIPE_INJECTION_DECISION_DATA*)pData;
            msgType = AvPipeMsgInjectionDecision;
            notifId = d->NotificationId;
            decision = (UINT32)d->Decision;
        }
        else if (header->MessageType == AvPipeMsgRansomDecision &&
                 pData != NULL && dataSize >= sizeof(AV_PIPE_RANSOM_DECISION_DATA))
        {
            AV_PIPE_RANSOM_DECISION_DATA* d = (AV_PIPE_RANSOM_DECISION_DATA*)pData;
            msgType = AvPipeMsgRansomDecision;
            notifId = d->NotificationId;
            decision = d->Decision;
        }
        else if (header->MessageType == AvPipeMsgEndPointDecision &&
                 pData != NULL && dataSize >= sizeof(AV_PIPE_EP_DECISION_DATA))
        {
            AV_PIPE_EP_DECISION_DATA* d = (AV_PIPE_EP_DECISION_DATA*)pData;
            msgType = AvPipeMsgEndPointDecision;
            notifId = d->NotificationId;
            decision = d->Decision;
        }

        if (msgType == 0)
        {
            //
            // 检查是否为 shutdown 请求 (来自 AVMain)
            //
            if (header->MessageType == AvPipeMsgShutdownRequest)
            {
                printf("[AVDecision] Shutdown request received from AVMain\n");
                EnterCriticalSection(&g_DecisionLock);
                g_ShutdownRequested = TRUE;
                LeaveCriticalSection(&g_DecisionLock);
                break;
            }
            // 非决策消息, 忽略
            continue;
        }

        //
        // 路由到等待者
        //
        EnterCriticalSection(&g_DecisionLock);
        for (int i = 0; i < AV_MAX_PENDING_DECISIONS; i++)
        {
            if (g_PendingDecisions[i].Active &&
                g_PendingDecisions[i].MessageType == msgType &&
                g_PendingDecisions[i].NotificationId == notifId)
            {
                g_PendingDecisions[i].Decision = decision;
                SetEvent(g_PendingDecisions[i].hEvent);
                break;
            }
        }
        LeaveCriticalSection(&g_DecisionLock);
    }

    return 0;
}

//=============================================================================
// SendProcessDecisionToDriver - 把决策发送给驱动
//
// 被冻结进程的恢复/终止由驱动执行 (决策 IOCTL):
//   允许 -> 驱动恢复所有挂起线程
//   拒绝 -> 驱动 ZwTerminateProcess
//=============================================================================
static void
SendProcessDecisionToDriver(
    _In_ HANDLE hDriver,
    _In_ const AV_PROCESS_NOTIFICATION* notification,
    _In_ AV_DECISION_TYPE decisionType
    )
{
    AV_PROCESS_DECISION decision;
    DWORD bytesReturned;

    ZeroMemory(&decision, sizeof(decision));
    decision.NotificationId = notification->NotificationId;
    decision.ProcessId = notification->ProcessId;
    decision.Decision = decisionType;
    StringCbCopyW(decision.ImagePath, sizeof(decision.ImagePath), notification->ImagePath);

    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_SEND_PROCESS_DECISION,
            &decision, sizeof(decision),
            NULL, 0,
            &bytesReturned, NULL))
    {
        printf("[AVMonitor] Send decision failed (error: %lu)\n", GetLastError());
    }
}

//=============================================================================
// 进程保护监控线程
//
// 轮询驱动获取待处理的进程拦截通知，弹窗让用户做决策
//=============================================================================
DWORD
WINAPI
ProcessMonitorThread(
    _In_ LPVOID lpParam
)
{
    HANDLE hDriver = *(HANDLE*)lpParam;
    DWORD bytesReturned;
    AV_PROCESS_NOTIFICATION notification;

    printf("[AVMonitor] Process monitor thread started\n");

    while (TRUE)
    {
        ZeroMemory(&notification, sizeof(notification));

        if (!DeviceIoControl(
                hDriver,
                IOCTL_AV_GET_PENDING_NOTIFICATION,
                NULL, 0,
                &notification, sizeof(notification),
                &bytesReturned, NULL))
        {
            printf("[AVMonitor] GET_PENDING_NOTIFICATION failed (error: %lu)\n", GetLastError());
            Sleep(200);
            continue;
        }

        if (!notification.HasPending)
        {
            //
            // 轮询间隔: 50ms
            //
            Sleep(50);
            continue;
        }

        printf("[AVMonitor] Received notification: PID=%u Parent=%u ID=%llu Reason=%u Path=%ls\n",
               notification.ProcessId, notification.ParentProcessId,
               notification.NotificationId, notification.BlockReason,
               notification.ImagePath);

        if (notification.BlockReason == AvBlockReasonBehaviorCmdline)
        {
            printf("[AVMonitor] Behavior rule: %ls | Cmd: %ls\n",
                   notification.RuleDescription, notification.CommandLine);
        }

        //
        // 进程已被驱动在出生时冻结 (驱动线程创建回调挂起其所有线程),
        // 用户态无需挂起; 等待用户决策后由驱动恢复或终止
        //
        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hMainPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        if (hMainPipe == NULL)
        {
            // AVMain 未连接: 无人弹窗, 放行 (发送 AllowOnce 让驱动恢复进程)
            printf("[AVMonitor] No AVMain connected, allowing PID %u\n",
                   notification.ProcessId);
            SendProcessDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }

        //
        // 转发拦截通知给 AVMain (由 AVMain 弹窗决策)
        //
        AV_PIPE_PROCESS_NOTIFY_DATA notifyMsg;
        ZeroMemory(&notifyMsg, sizeof(notifyMsg));
        notifyMsg.NotificationId = notification.NotificationId;
        notifyMsg.ProcessId = notification.ProcessId;
        notifyMsg.ParentProcessId = notification.ParentProcessId;
        notifyMsg.BlockReason = notification.BlockReason;
        StringCbCopyW(notifyMsg.ImagePath, sizeof(notifyMsg.ImagePath), notification.ImagePath);
        StringCbCopyW(notifyMsg.CommandLine, sizeof(notifyMsg.CommandLine), notification.CommandLine);
        StringCbCopyW(notifyMsg.RuleDescription, sizeof(notifyMsg.RuleDescription), notification.RuleDescription);

        if (!SendPipeMessage(hMainPipe, AvPipeMsgProcessNotify,
                             &notifyMsg, sizeof(notifyMsg)))
        {
            printf("[AVMonitor] Send notify to AVMain failed, allowing PID %u\n",
                   notification.ProcessId);
            SendProcessDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }
        printf("[AVMonitor] Notification forwarded to AVMain, waiting decision...\n");

        //
        // 等待 AVMain 决策回复 (由统一的管道决策分发线程读取并路由,
        // 超时 30 秒默认放行)
        //
        AV_DECISION_TYPE decisionType = WaitForPipeDecision(
            AvPipeMsgProcessDecision,
            notification.NotificationId,
            AV_NOTIFICATION_TIMEOUT_MS);

        if (decisionType == AvDecisionInvalid)
        {
            decisionType = AvDecisionAllowOnce;   // 超时/异常默认放行
        }

        const wchar_t* decisionDesc =
            (decisionType == AvDecisionAllowAlways) ? L"ALLOW ALWAYS" :
            (decisionType == AvDecisionDenyAlways)  ? L"DENY ALWAYS" :
            (decisionType == AvDecisionAllowOnce)   ? L"ALLOW ONCE" :
                                                      L"DENY ONCE";
        printf("[AVMonitor] User decision %ls for: %ls\n", decisionDesc, notification.ImagePath);

        //
        // 把决策交给驱动执行: 允许 -> 驱动恢复进程; 拒绝 -> 驱动 Zw 终止
        //
        SendProcessDecisionToDriver(hDriver, &notification, decisionType);

        //
        // 处理完一条通知后立即开始下一轮轮询, 不额外休眠
        //
    }

    return 0;
}

//=============================================================================
// SendRegDecisionToDriver - 把注册表决策发送给驱动
//
// 驱动回调 (CM) 正在同步等待该决策:
//   允许 -> 回调返回 STATUS_SUCCESS (注册表操作继续)
//   拒绝 -> 回调返回 STATUS_ACCESS_DENIED (注册表操作被拦截)
//=============================================================================
static void
SendRegDecisionToDriver(
    _In_ HANDLE hDriver,
    _In_ const AV_REGISTRY_NOTIFICATION* notification,
    _In_ AV_DECISION_TYPE decisionType
    )
{
    AV_REGISTRY_DECISION decision;
    DWORD bytesReturned;

    ZeroMemory(&decision, sizeof(decision));
    decision.NotificationId = notification->NotificationId;
    decision.Decision = decisionType;
    StringCbCopyW(decision.KeyPath, sizeof(decision.KeyPath), notification->KeyPath);

    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_SEND_REGISTRY_DECISION,
            &decision, sizeof(decision),
            NULL, 0,
            &bytesReturned, NULL))
    {
        printf("[AVRegMonitor] Send registry decision failed (error: %lu)\n", GetLastError());
    }
}

//=============================================================================
// 注册表保护监控线程
//
// 轮询驱动获取待处理的注册表拦截通知, 转发 AVMain 弹窗决策,
// 决策通过 IOCTL 送回驱动唤醒正在阻塞的 CM 回调。
// 注意: 驱动 CM 回调只有 30 秒超时, 等待 AVMain 决策的时间
//       必须小于 30 秒 (取 25 秒), 否则回调会自行超时拒绝。
//=============================================================================
DWORD
WINAPI
RegistryMonitorThread(
    _In_ LPVOID lpParam
)
{
    HANDLE hDriver = *(HANDLE*)lpParam;
    DWORD bytesReturned;
    AV_REGISTRY_NOTIFICATION notification;

    printf("[AVRegMonitor] Registry monitor thread started\n");

    while (TRUE)
    {
        ZeroMemory(&notification, sizeof(notification));

        if (!DeviceIoControl(
                hDriver,
                IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION,
                NULL, 0,
                &notification, sizeof(notification),
                &bytesReturned, NULL))
        {
            printf("[AVRegMonitor] GET_PENDING_REGISTRY_NOTIFICATION failed (error: %lu)\n",
                   GetLastError());
            Sleep(200);
            continue;
        }

        if (!notification.HasPending)
        {
            //
            // 轮询间隔: 50ms
            //
            Sleep(50);
            continue;
        }

        printf("[AVRegMonitor] Registry notification: PID=%u Op=%u Key=%ls Value=%ls ID=%llu\n",
               notification.ProcessId, notification.OperationType,
               notification.KeyPath, notification.ValueName, notification.NotificationId);

        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hMainPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        if (hMainPipe == NULL)
        {
            // AVMain 未连接: 无人弹窗, 放行 (驱动回调恢复注册表操作)
            printf("[AVRegMonitor] No AVMain connected, allowing registry op on %ls\n",
                   notification.KeyPath);
            SendRegDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }

        //
        // 转发拦截通知给 AVMain (由 AVMain 弹窗决策)
        //
        AV_PIPE_REG_NOTIFY_DATA notifyMsg;
        ZeroMemory(&notifyMsg, sizeof(notifyMsg));
        notifyMsg.NotificationId = notification.NotificationId;
        notifyMsg.ProcessId = notification.ProcessId;
        notifyMsg.OperationType = notification.OperationType;
        StringCbCopyW(notifyMsg.KeyPath, sizeof(notifyMsg.KeyPath), notification.KeyPath);
        StringCbCopyW(notifyMsg.ValueName, sizeof(notifyMsg.ValueName), notification.ValueName);

        if (!SendPipeMessage(hMainPipe, AvPipeMsgRegNotify,
                             &notifyMsg, sizeof(notifyMsg)))
        {
            printf("[AVRegMonitor] Send reg notify to AVMain failed, allowing op on %ls\n",
                   notification.KeyPath);
            SendRegDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }
        printf("[AVRegMonitor] Notification forwarded to AVMain, waiting decision...\n");

        //
        // 等待 AVMain 决策回复 (由统一的管道决策分发线程读取并路由)
        // 超时 25 秒: 必须小于驱动 CM 回调的 30 秒超时,
        // 否则回调自行超时拒绝后, 迟到的决策将被驱动忽略
        //
        AV_DECISION_TYPE decisionType = WaitForPipeDecision(
            AvPipeMsgRegDecision,
            notification.NotificationId,
            AV_NOTIFICATION_TIMEOUT_MS - 5000);

        if (decisionType == AvDecisionInvalid)
        {
            decisionType = AvDecisionDenyOnce;    // 超时/异常默认拒绝
        }

        printf("[AVRegMonitor] Registry decision %d for key: %ls\n",
               (int)decisionType, notification.KeyPath);

        //
        // 把决策送回驱动, 唤醒阻塞中的 CM 回调
        //
        SendRegDecisionToDriver(hDriver, &notification, decisionType);

        //
        // 处理完一条通知后立即开始下一轮轮询
        //
    }

    return 0;
}

//=============================================================================
// SendInjectionDecisionToDriver - 把注入决策发送给驱动
//
// 驱动工作线程正在等待该决策:
//   允许 -> 恢复被注入线程
//   拒绝 -> 终止被注入线程
//=============================================================================
static void
SendInjectionDecisionToDriver(
    _In_ HANDLE hDriver,
    _In_ const AV_INJECTION_NOTIFICATION* notification,
    _In_ AV_DECISION_TYPE decisionType
    )
{
    AV_INJECTION_DECISION decision;
    DWORD bytesReturned;

    ZeroMemory(&decision, sizeof(decision));
    decision.NotificationId = notification->NotificationId;
    decision.Decision = decisionType;
    StringCbCopyW(decision.SourceImagePath, sizeof(decision.SourceImagePath),
                  notification->SourceImagePath);

    if (!DeviceIoControl(
            hDriver,
            IOCTL_AV_SEND_INJECTION_DECISION,
            &decision, sizeof(decision),
            NULL, 0,
            &bytesReturned, NULL))
    {
        printf("[AVInjectMonitor] Send injection decision failed (error: %lu)\n",
               GetLastError());
    }
}

//=============================================================================
// 远程线程注入监控线程
//
// 轮询驱动获取待处理的注入通知, 转发 AVMain 弹窗决策。
// 驱动工作线程只有 30 秒超时, 等待 AVMain 决策的时间必须小于 30 秒
// (取 25 秒), 否则驱动自行超时终止被注入线程。
//=============================================================================
DWORD
WINAPI
InjectionMonitorThread(
    _In_ LPVOID lpParam
)
{
    HANDLE hDriver = *(HANDLE*)lpParam;
    DWORD bytesReturned;
    AV_INJECTION_NOTIFICATION notification;

    printf("[AVInjectMonitor] Injection monitor thread started\n");

    while (TRUE)
    {
        ZeroMemory(&notification, sizeof(notification));

        if (!DeviceIoControl(
                hDriver,
                IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION,
                NULL, 0,
                &notification, sizeof(notification),
                &bytesReturned, NULL))
        {
            printf("[AVInjectMonitor] GET_PENDING_INJECTION_NOTIFICATION failed (error: %lu)\n",
                   GetLastError());
            Sleep(200);
            continue;
        }

        if (!notification.HasPending)
        {
            Sleep(50);
            continue;
        }

        printf("[AVInjectMonitor] Injection detected: src=%u tgt=%u tid=%u start=0x%llX srcPath=%ls\n",
               notification.SourceProcessId, notification.TargetProcessId,
               notification.ThreadId, notification.StartAddress,
               notification.SourceImagePath);

        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hMainPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        if (hMainPipe == NULL)
        {
            // AVMain 未连接: 无人弹窗, 放行 (驱动恢复被注入线程)
            printf("[AVInjectMonitor] No AVMain connected, allowing injection\n");
            SendInjectionDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }

        //
        // 转发注入通知给 AVMain (由 AVMain 弹窗决策)
        //
        AV_PIPE_INJECTION_NOTIFY_DATA notifyMsg;
        ZeroMemory(&notifyMsg, sizeof(notifyMsg));
        notifyMsg.NotificationId = notification.NotificationId;
        notifyMsg.SourceProcessId = notification.SourceProcessId;
        notifyMsg.TargetProcessId = notification.TargetProcessId;
        notifyMsg.ThreadId = notification.ThreadId;
        notifyMsg.StartAddress = notification.StartAddress;
        StringCbCopyW(notifyMsg.SourceImagePath, sizeof(notifyMsg.SourceImagePath),
                      notification.SourceImagePath);

        if (!SendPipeMessage(hMainPipe, AvPipeMsgInjectionNotify,
                             &notifyMsg, sizeof(notifyMsg)))
        {
            printf("[AVInjectMonitor] Send injection notify to AVMain failed, allowing\n");
            SendInjectionDecisionToDriver(hDriver, &notification, AvDecisionAllowOnce);
            Sleep(50);
            continue;
        }
        printf("[AVInjectMonitor] Notification forwarded to AVMain, waiting decision...\n");

        //
        // 等待 AVMain 决策回复 (由统一的管道决策分发线程读取并路由)
        // 超时 25 秒: 必须小于驱动工作线程的 30 秒超时
        //
        AV_DECISION_TYPE decisionType = WaitForPipeDecision(
            AvPipeMsgInjectionDecision,
            notification.NotificationId,
            AV_NOTIFICATION_TIMEOUT_MS - 5000);

        if (decisionType == AvDecisionInvalid)
        {
            decisionType = AvDecisionDenyOnce;    // 超时/异常默认拒绝
        }

        printf("[AVInjectMonitor] Injection decision %d for src=%u\n",
               (int)decisionType, notification.SourceProcessId);

        //
        // 把决策送回驱动: 允许=恢复线程, 拒绝=终止被注入线程
        //
        SendInjectionDecisionToDriver(hDriver, &notification, decisionType);
    }

    return 0;
}

//=============================================================================
// 服务安装
//=============================================================================
BOOL
InstallService(VOID)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    WCHAR modulePath[MAX_PATH];
    BOOL result = FALSE;

    // 获取当前程序路径
    if (!GetModuleFileNameW(NULL, modulePath, MAX_PATH))
    {
        printf("[AVSystem] GetModuleFileNameW failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // 打开服务控制管理器
    hSCManager = OpenSCManagerW(
        NULL,
        NULL,
        SC_MANAGER_CREATE_SERVICE
    );

    if (hSCManager == NULL)
    {
        printf("[AVSystem] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // 创建服务
    hService = CreateServiceW(
        hSCManager,
        L"AVSystem",
        L"AVSystem - Antivirus Driver System Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        modulePath,
        NULL,
        NULL,
        L"",
        NULL,
        NULL
    );

    if (hService == NULL)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS)
        {
            printf("[AVSystem] Service already exists\n");
        }
        else
        {
            printf("[AVSystem] CreateService failed (error: %lu)\n", error);
        }
        goto Cleanup;
    }

    printf("[AVSystem] Service install succeeded\n");
    result = TRUE;

Cleanup:
    if (hService)
    {
        CloseServiceHandle(hService);
    }
    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
    }
    return result;
}

//=============================================================================
// 服务卸载
//=============================================================================
BOOL
UninstallService(VOID)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS serviceStatus;
    BOOL result = FALSE;

    // 打开服务控制管理器
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        printf("[AVSystem] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // 打开服务
    hService = OpenServiceW(
        hSCManager,
        L"AVSystem",
        SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS
    );

    if (hService == NULL)
    {
        printf("[AVSystem] OpenService failed (error: %lu)\n", GetLastError());
        goto Cleanup;
    }

    // 先尝试停止服务
    ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);

    // 删除服务
    if (!DeleteService(hService))
    {
        printf("[AVSystem] DeleteService failed (error: %lu)\n", GetLastError());
        goto Cleanup;
    }

    printf("[AVSystem] Service uninstall succeeded\n");
    result = TRUE;

Cleanup:
    if (hService)
    {
        CloseServiceHandle(hService);
    }
    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
    }
    return result;
}

//=============================================================================
// 服务控制处理器
//=============================================================================
DWORD
WINAPI
ServiceCtrlHandler(
    _In_ DWORD control,
    _In_ DWORD eventType,
    _In_ LPVOID eventData,
    _In_ LPVOID context
)
{
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    switch (control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
            if (g_ServiceStopEvent)
            {
                SetEvent(g_ServiceStopEvent);
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

//=============================================================================
// 服务入口
//=============================================================================
VOID
WINAPI
ServiceMain(
    _In_ DWORD argc,
    _In_reads_(argc) LPWSTR* argv
)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // 注册服务控制处理器
    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
        L"AVSystem",
        ServiceCtrlHandler,
        NULL
    );

    if (g_ServiceStatusHandle == NULL)
    {
        printf("[AVSystem] RegisterServiceCtrlHandlerEx failed (error: %lu)\n", GetLastError());
        return;
    }

    // 初始化服务状态
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = NO_ERROR;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 5000;

    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    // 创建停止事件
    g_ServiceStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        return;
    }

    // 通知 SCM 服务正在运行
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    // 运行服务主逻辑
    RunService();

    // 服务停止
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    if (g_ServiceStopEvent)
    {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = NULL;
    }
}

//=============================================================================
// DriverExists - 检查驱动服务是否已安装
//=============================================================================
BOOL
DriverExists(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL exists = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[AVDriverMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"AVDriver", SERVICE_QUERY_STATUS);
    if (hSvc != NULL)
    {
        exists = TRUE;
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    return exists;
}

//=============================================================================
// GetDriverServiceImagePath - 获取当前驱动服务的二进制路径
//
// 返回 TRUE 表示服务存在, pImagePath 为服务当前指向的驱动路径
//=============================================================================
static BOOL
GetDriverServiceImagePath(
    _In_ SC_HANDLE hSvc,
    _Out_ WCHAR* pImagePath,
    _In_ DWORD cbImagePath
)
{
    DWORD bytesNeeded = 0;
    LPQUERY_SERVICE_CONFIGW pConfig = NULL;

    if (pImagePath == NULL || cbImagePath == 0)
    {
        return FALSE;
    }

    pImagePath[0] = L'\0';

    // 第一次调用获取所需大小
    if (!QueryServiceConfigW(hSvc, NULL, 0, &bytesNeeded))
    {
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("[AVDriverMgr] QueryServiceConfig failed (error: %lu)\n", err);
            return FALSE;
        }
    }

    pConfig = (LPQUERY_SERVICE_CONFIGW)malloc(bytesNeeded);
    if (pConfig == NULL)
    {
        printf("[AVDriverMgr] Out of memory\n");
        return FALSE;
    }

    if (!QueryServiceConfigW(hSvc, pConfig, bytesNeeded, &bytesNeeded))
    {
        printf("[AVDriverMgr] QueryServiceConfig failed (error: %lu)\n", GetLastError());
        free(pConfig);
        return FALSE;
    }

    StringCbCopyW(pImagePath, cbImagePath, pConfig->lpBinaryPathName);
    free(pConfig);
    return TRUE;
}

//=============================================================================
// InstallDriver - 安装/更新驱动服务
//
// 从 AVSystem.exe 同目录查找 XIGUASecurityAntiVirus.sys:
//   1. 复制到 %SystemRoot%\System32\drivers\ 目录 (标准驱动目录)
//   2. 服务 ImagePath 使用 NT 路径格式 \SystemRoot\System32\drivers\XIGUASecurityAntiVirus.sys
//      (内核加载驱动必须使用 NT 对象路径, 普通 C:\ 路径会导致错误 2 文件找不到)
//   3. 若服务已存在但路径不同, 自动修正服务指向
//=============================================================================
BOOL
InstallDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    WCHAR sysPath[MAX_PATH];
    WCHAR sourceDriverPath[MAX_PATH];          // 源: AVSystem.exe 同目录
    WCHAR targetDriverPath[MAX_PATH];          // 目标: %SystemRoot%\drivers
    WCHAR targetNtPath[MAX_PATH];              // NT 格式: \SystemRoot\drivers\...
    WCHAR currentImagePath[MAX_PATH];
    WCHAR systemRoot[MAX_PATH];
    BOOL result = FALSE;
    BOOL serviceExists = FALSE;

    // 获取 AVSystem.exe 所在目录
    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH))
    {
        printf("[AVDriverMgr] GetModuleFileNameW failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // 截取目录部分
    WCHAR* pSlash = wcsrchr(sysPath, L'\\');
    if (pSlash == NULL)
    {
        printf("[AVDriverMgr] Unable to parse path\n");
        return FALSE;
    }
    *(pSlash + 1) = L'\0';

    // 拼接源驱动路径 (AVSystem.exe 同目录)
    StringCbCopyW(sourceDriverPath, sizeof(sourceDriverPath), sysPath);
    StringCbCatW(sourceDriverPath, sizeof(sourceDriverPath), L"XIGUASecurityAntiVirus.sys");

    printf("[AVDriverMgr] Source driver: %ls\n", sourceDriverPath);

    // 检查源驱动文件是否存在
    if (GetFileAttributesW(sourceDriverPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[AVDriverMgr] Driver file not found: %ls\n", sourceDriverPath);
        printf("[AVDriverMgr] Please place XIGUASecurityAntiVirus.sys in the same directory as AVSystem.exe\n");
        return FALSE;
    }

    // 获取系统目录
    if (GetSystemDirectoryW(systemRoot, MAX_PATH) == 0)
    {
        printf("[AVDriverMgr] GetSystemDirectory failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // 目标路径: %SystemRoot%\drivers\XIGUASecurityAntiVirus.sys (标准驱动目录)
    StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
    StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUASecurityAntiVirus.sys");

    // NT 路径格式: \SystemRoot\System32\drivers\XIGUASecurityAntiVirus.sys
    StringCbCopyW(targetNtPath, sizeof(targetNtPath), L"\\SystemRoot\\System32\\drivers\\XIGUASecurityAntiVirus.sys");

    printf("[AVDriverMgr] Installing to: %ls\n", targetDriverPath);

    // Step 1: 复制驱动文件到系统驱动目录
    // 注意: 驱动可能正在运行占用文件导致复制失败, 此时若服务已就绪则继续,
    //       否则驱动一旦启动便无法热更新, 复制失败不应阻止连接现有驱动
    BOOL copyOk = CopyFileW(sourceDriverPath, targetDriverPath, FALSE);
    if (!copyOk)
    {
        DWORD err = GetLastError();
        printf("[AVDriverMgr] CopyFile failed (error: %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED)
        {
            printf("[AVDriverMgr] Need ADMIN privileges to copy to drivers directory!\n");
        }
        printf("[AVDriverMgr] Driver file may be locked by running driver, checking service state...\n");
    }
    else
    {
        printf("[AVDriverMgr] Driver file copied to system drivers directory\n");
    }

    // 打开 SCM
    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCM == NULL)
    {
        printf("[AVDriverMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    // Step 2: 检查服务是否已存在
    hSvc = OpenServiceW(hSCM, L"AVDriver", SERVICE_ALL_ACCESS);
    if (hSvc != NULL)
    {
        serviceExists = TRUE;

        // 获取服务当前指向的驱动路径
        if (GetDriverServiceImagePath(hSvc, currentImagePath, sizeof(currentImagePath)))
        {
            printf("[AVDriverMgr] Service currently points to: %ls\n", currentImagePath);

            // 路径不一致 → 修正服务指向标准 NT 路径
            if (_wcsicmp(currentImagePath, targetNtPath) != 0)
            {
                printf("[AVDriverMgr] Path mismatch, updating service config...\n");

                // 先停止旧驱动 (若在运行), 否则无法更新已加载的驱动
                SERVICE_STATUS svcStatus;
                ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);

                if (ChangeServiceConfigW(
                        hSvc,
                        SERVICE_NO_CHANGE,       // 类型不变
                        SERVICE_NO_CHANGE,       // 启动类型不变
                        SERVICE_NO_CHANGE,       // 错误控制不变
                        targetNtPath,            // 新的驱动路径 (NT 格式)
                        NULL,                    // LoadOrderGroup
                        NULL,                    // TagId
                        NULL,                    // Dependencies
                        NULL,                    // ServiceStartName
                        NULL,                    // Password
                        NULL))                   // DisplayName
                {
                    printf("[AVDriverMgr] Service config updated to: %ls\n", targetNtPath);
                }
                else
                {
                    printf("[AVDriverMgr] ChangeServiceConfig failed (error: %lu)\n", GetLastError());
                    // 失败则删除重建
                    printf("[AVDriverMgr] Deleting and recreating service...\n");
                    DeleteService(hSvc);
                    CloseServiceHandle(hSvc);
                    hSvc = NULL;
                    serviceExists = FALSE;
                }
            }
            else
            {
                printf("[AVDriverMgr] Service path is up to date\n");
            }
        }

        if (hSvc != NULL)
        {
            printf("[AVDriverMgr] Driver service ready\n");
            result = TRUE;
        }
    }

    // 复制失败且服务不存在 → 没有驱动文件可安装, 中止
    if (!copyOk && !serviceExists)
    {
        printf("[AVDriverMgr] Driver file copy failed and no existing service, install aborted\n");
        goto Cleanup;
    }

    // Step 3: 服务不存在或已删除 → 创建新服务
    if (!serviceExists || hSvc == NULL)
    {
        hSvc = CreateServiceW(
            hSCM,
            L"AVDriver",                        // 服务名称
            L"AVDriver AntiVirus Driver",       // 显示名称
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,              // 内核驱动类型
            SERVICE_DEMAND_START,               // 手动启动
            SERVICE_ERROR_NORMAL,
            targetNtPath,                       // NT 格式驱动路径
            NULL, NULL, NULL, NULL, NULL
        );

        if (hSvc == NULL)
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                printf("[AVDriverMgr] Driver service already exists\n");
                result = TRUE;
            }
            else
            {
                printf("[AVDriverMgr] CreateService failed (error: %lu)\n", err);
            }
        }
        else
        {
            printf("[AVDriverMgr] Driver service created\n");
            result = TRUE;
        }
    }

    // Step 4: 写 WDF 框架配置 (KMDF 驱动加载必需)
    // 手动 CreateService 不会自动创建 Wdf 注册表项, 必须手动写入
    // 否则加载时找不到 Wdf01000.sys 对应版本 → 错误 2
    if (result)
    {
        HKEY hWdfKey = NULL;
        DWORD wdfVersion = 0x0001001F;   // KMDF 1.31 (0x1F = 31)

        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\AVDriver\\Wdf",
                            0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_SET_VALUE, NULL, &hWdfKey, NULL) == ERROR_SUCCESS)
        {
            if (RegSetValueExW(hWdfKey, L"Version", 0, REG_DWORD,
                               (BYTE*)&wdfVersion, sizeof(wdfVersion)) == ERROR_SUCCESS)
            {
                printf("[AVDriverMgr] WDF config written (KMDF 1.31, Version=0x%08X)\n",
                       wdfVersion);
            }
            else
            {
                printf("[AVDriverMgr] RegSetValueEx(Version) failed (error: %lu)\n",
                       GetLastError());
            }
            RegCloseKey(hWdfKey);
        }
        else
        {
            printf("[AVDriverMgr] RegCreateKeyEx(Wdf) failed (error: %lu)\n", GetLastError());
        }
    }

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// UninstallDriver - 卸载驱动服务
//=============================================================================
BOOL
UninstallDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    SERVICE_STATUS svcStatus;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[AVDriverMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"AVDriver", SERVICE_STOP | DELETE);
    if (hSvc == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("[AVDriverMgr] Driver service not installed\n");
            result = TRUE;
        }
        else
        {
            printf("[AVDriverMgr] OpenService failed (error: %lu)\n", err);
        }
        goto Cleanup;
    }

    // 先停止驱动
    ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);
    printf("[AVDriverMgr] Driver stopped\n");

    // 删除服务
    if (!DeleteService(hSvc))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            printf("[AVDriverMgr] DeleteService failed (error: %lu)\n", err);
            goto Cleanup;
        }
    }

    printf("[AVDriverMgr] Driver service uninstall succeeded\n");

    // 删除 Wdf 配置注册表项
    RegDeleteTreeW(HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\AVDriver\\Wdf");

    // 删除系统驱动目录中的文件
    WCHAR systemRoot[MAX_PATH];
    WCHAR targetDriverPath[MAX_PATH];
    if (GetSystemDirectoryW(systemRoot, MAX_PATH) > 0)
    {
        StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
        StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUASecurityAntiVirus.sys");
        DeleteFileW(targetDriverPath);
        printf("[AVDriverMgr] Removed %ls\n", targetDriverPath);
    }

    result = TRUE;

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// StopDriverIfRunning - 若驱动在运行则先停止 (卸载旧驱动)
//=============================================================================
static void
StopDriverIfRunning(
    _In_ SC_HANDLE hSvc
)
{
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;

    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
    {
        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING)
        {
            SERVICE_STATUS svcStatus;
            if (ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus))
            {
                printf("[AVDriverMgr] Stopped old driver instance\n");
            }
            else
            {
                printf("[AVDriverMgr] ControlService(STOP) failed (error: %lu)\n", GetLastError());
            }
        }
    }
}

//=============================================================================
// StartDriver - 启动驱动服务
//
// 先停止旧实例(若有), 再启动当前驱动文件, 确保加载的是最新版本
//=============================================================================
BOOL
StartDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[AVDriverMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"AVDriver",
                        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (hSvc == NULL)
    {
        printf("[AVDriverMgr] OpenService failed (error: %lu)\n", GetLastError());
        goto Cleanup;
    }

    // 若驱动已在运行, 先停止以卸载旧版本
    StopDriverIfRunning(hSvc);

    // 启动驱动
    if (!StartServiceW(hSvc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[AVDriverMgr] Driver already running\n");
            result = TRUE;
        }
        else
        {
            printf("[AVDriverMgr] StartService failed (error: %lu)\n", err);

            // 打印最近 Kernel-PnP 219 事件获取确切失败原因
            printf("[AVDriverMgr] --- Recent Kernel-PnP error details ---\n");
            _flushall();
            system("wevtutil qe System \"/q:*[System[(ProviderName='Microsoft-Windows-Kernel-PnP') and (EventID=219)]]\" /c:2 /rd:true /f:text 2>nul");
            system("wevtutil qe System \"/q:*[System[(ProviderName='Service Control Manager') and (EventID=7000)]]\" /c:2 /rd:true /f:text 2>nul");
            printf("[AVDriverMgr] ----------------------------------------\n");
        }
        goto Cleanup;
    }

    printf("[AVDriverMgr] Driver started successfully\n");
    result = TRUE;

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// EnsureDriverRunning - 确保驱动已安装并运行
//
// 自动完成：检查 → 安装 → 启动 全流程
//=============================================================================
BOOL
EnsureDriverRunning(VOID)
{
    printf("[AVDriverMgr] ========================================\n");
    printf("[AVDriverMgr]   AVDriver Driver Manager\n");
    printf("[AVDriverMgr] ========================================\n");

    // Step 1: 安装/更新驱动服务 (始终修正服务指向当前同目录驱动文件)
    if (!InstallDriver())
    {
        printf("[AVDriverMgr] Driver install failed!\n");
        return FALSE;
    }

    // Step 2: 启动驱动 (先停止旧实例再启动, 确保加载最新签名版本)
    printf("[AVDriverMgr] Starting driver...\n");
    if (!StartDriver())
    {
        printf("[AVDriverMgr] Driver start failed!\n");
        return FALSE;
    }

    printf("[AVDriverMgr] ========================================\n");
    printf("[AVDriverMgr]   Driver ready\n");
    printf("[AVDriverMgr] ========================================\n");
    return TRUE;
}

//=============================================================================
// XGSRansomFilter 驱动管理 (传统 minifilter, 非 KMDF)
//
// XGS 驱动不需要 Wdf 注册表项 (传统驱动), 但必须写 Instances 注册表
// (minifilter altitude/instance 配置), 否则 FltRegisterFilter 无法挂载。
//=============================================================================

//
// 写 XGS 驱动的 minifilter Instances 注册表
//
static BOOL
WriteXgsInstancesRegistry(VOID)
{
    HKEY hKey = NULL;
    BOOL ok = TRUE;
    DWORD flags = 0;

    //
    // Instances\DefaultInstance
    //
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\XGSRansomFilter\\Instances",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        const WCHAR* defInst = L"XGSRansomFilterInstance";
        RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ,
                       (const BYTE*)defInst,
                       (DWORD)((wcslen(defInst) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
    }
    else
    {
        printf("[XGSMgr] RegCreateKeyEx(Instances) failed (error: %lu)\n", GetLastError());
        ok = FALSE;
    }

    //
    // Instances\XGSRansomFilterInstance: Altitude + Flags
    // Altitude 328000 属于 FSFilter Anti-Virus 高度带
    //
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\XGSRansomFilter\\Instances\\XGSRansomFilterInstance",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        const WCHAR* altitude = L"328000";
        RegSetValueExW(hKey, L"Altitude", 0, REG_SZ,
                       (const BYTE*)altitude,
                       (DWORD)((wcslen(altitude) + 1) * sizeof(WCHAR)));
        RegSetValueExW(hKey, L"Flags", 0, REG_DWORD,
                       (const BYTE*)&flags, sizeof(flags));
        RegCloseKey(hKey);
        printf("[XGSMgr] Instances registry written (Altitude=328000)\n");
    }
    else
    {
        printf("[XGSMgr] RegCreateKeyEx(Instance) failed (error: %lu)\n", GetLastError());
        ok = FALSE;
    }

    return ok;
}

//=============================================================================
// InstallXgsDriver - 安装/更新 XGS 勒索防护驱动服务
//
// 1. 复制 XIGUAFileProtect.sys 到 %SystemRoot%\System32\drivers\
// 2. 创建/修正服务 (NT 路径格式)
// 3. 写 minifilter Instances 注册表
//=============================================================================
BOOL
InstallXgsDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    WCHAR sysPath[MAX_PATH];
    WCHAR sourceDriverPath[MAX_PATH];
    WCHAR targetDriverPath[MAX_PATH];
    WCHAR targetNtPath[MAX_PATH];
    WCHAR currentImagePath[MAX_PATH];
    WCHAR systemRoot[MAX_PATH];
    BOOL result = FALSE;
    BOOL serviceExists = FALSE;

    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH))
    {
        printf("[XGSMgr] GetModuleFileNameW failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    WCHAR* pSlash = wcsrchr(sysPath, L'\\');
    if (pSlash == NULL)
    {
        printf("[XGSMgr] Unable to parse path\n");
        return FALSE;
    }
    *(pSlash + 1) = L'\0';

    StringCbCopyW(sourceDriverPath, sizeof(sourceDriverPath), sysPath);
    StringCbCatW(sourceDriverPath, sizeof(sourceDriverPath), L"XIGUAFileProtect.sys");

    printf("[XGSMgr] Source driver: %ls\n", sourceDriverPath);

    if (GetFileAttributesW(sourceDriverPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[XGSMgr] Driver file not found: %ls\n", sourceDriverPath);
        return FALSE;
    }

    if (GetSystemDirectoryW(systemRoot, MAX_PATH) == 0)
    {
        printf("[XGSMgr] GetSystemDirectory failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
    StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUAFileProtect.sys");

    StringCbCopyW(targetNtPath, sizeof(targetNtPath),
                  L"\\SystemRoot\\System32\\drivers\\XIGUAFileProtect.sys");

    BOOL copyOk = CopyFileW(sourceDriverPath, targetDriverPath, FALSE);
    if (!copyOk)
    {
        DWORD err = GetLastError();
        printf("[XGSMgr] CopyFile failed (error: %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED)
        {
            printf("[XGSMgr] Need ADMIN privileges!\n");
        }
    }
    else
    {
        printf("[XGSMgr] Driver copied to system drivers directory\n");
    }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCM == NULL)
    {
        printf("[XGSMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSRansomFilter", SERVICE_ALL_ACCESS);
    if (hSvc != NULL)
    {
        serviceExists = TRUE;

        if (GetDriverServiceImagePath(hSvc, currentImagePath, sizeof(currentImagePath)))
        {
            printf("[XGSMgr] Service currently points to: %ls\n", currentImagePath);

            if (_wcsicmp(currentImagePath, targetNtPath) != 0)
            {
                printf("[XGSMgr] Path mismatch, updating service config...\n");
                SERVICE_STATUS svcStatus;
                ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);

                if (ChangeServiceConfigW(hSvc,
                        SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                        targetNtPath, NULL, NULL, NULL, NULL, NULL, NULL))
                {
                    printf("[XGSMgr] Service config updated\n");
                }
                else
                {
                    printf("[XGSMgr] ChangeServiceConfig failed (error: %lu)\n", GetLastError());
                    DeleteService(hSvc);
                    CloseServiceHandle(hSvc);
                    hSvc = NULL;
                    serviceExists = FALSE;
                }
            }
        }

        if (hSvc != NULL)
        {
            printf("[XGSMgr] Driver service ready\n");
            result = TRUE;
        }
    }

    if (!copyOk && !serviceExists)
    {
        printf("[XGSMgr] Copy failed and no existing service, install aborted\n");
        goto Cleanup;
    }

    if (!serviceExists || hSvc == NULL)
    {
        hSvc = CreateServiceW(
            hSCM,
            L"XGSRansomFilter",
            L"XGS Ransomware Protection Filter Driver",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            targetNtPath,
            NULL, NULL, NULL, NULL, NULL
        );

        if (hSvc == NULL)
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                printf("[XGSMgr] Driver service already exists\n");
                result = TRUE;
            }
            else
            {
                printf("[XGSMgr] CreateService failed (error: %lu)\n", err);
            }
        }
        else
        {
            printf("[XGSMgr] Driver service created\n");
            result = TRUE;
        }
    }

    //
    // 写 minifilter Instances 注册表 (传统 minifilter 挂载必需)
    //
    if (result)
    {
        WriteXgsInstancesRegistry();
    }

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// UninstallXgsDriver - 卸载 XGS 驱动服务
//=============================================================================
BOOL
UninstallXgsDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    SERVICE_STATUS svcStatus;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[XGSMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSRansomFilter", SERVICE_STOP | DELETE);
    if (hSvc == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("[XGSMgr] Driver service not installed\n");
            result = TRUE;
        }
        else
        {
            printf("[XGSMgr] OpenService failed (error: %lu)\n", err);
        }
        goto Cleanup;
    }

    ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);
    printf("[XGSMgr] Driver stopped\n");

    if (!DeleteService(hSvc))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            printf("[XGSMgr] DeleteService failed (error: %lu)\n", err);
            goto Cleanup;
        }
    }

    printf("[XGSMgr] Driver service uninstall succeeded\n");

    //
    // 清理 Instances 注册表
    //
    RegDeleteTreeW(HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\XGSRansomFilter\\Instances");

    //
    // 删除系统驱动目录中的文件
    //
    WCHAR systemRoot[MAX_PATH];
    WCHAR targetDriverPath[MAX_PATH];
    if (GetSystemDirectoryW(systemRoot, MAX_PATH) > 0)
    {
        StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
        StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUAFileProtect.sys");
        DeleteFileW(targetDriverPath);
    }

    result = TRUE;

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// StartXgsDriver - 启动 XGS 驱动服务
//=============================================================================
BOOL
StartXgsDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[XGSMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSRansomFilter",
                        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (hSvc == NULL)
    {
        printf("[XGSMgr] OpenService failed (error: %lu)\n", GetLastError());
        goto Cleanup;
    }

    StopDriverIfRunning(hSvc);

    if (!StartServiceW(hSvc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[XGSMgr] Driver already running\n");
            result = TRUE;
        }
        else
        {
            printf("[XGSMgr] StartService failed (error: %lu)\n", err);
            _flushall();
            system("wevtutil qe System \"/q:*[System[(ProviderName='Microsoft-Windows-Kernel-PnP') and (EventID=219)]]\" /c:2 /rd:true /f:text 2>nul");
            system("wevtutil qe System \"/q:*[System[(ProviderName='Service Control Manager') and (EventID=7000)]]\" /c:2 /rd:true /f:text 2>nul");
        }
        goto Cleanup;
    }

    printf("[XGSMgr] Driver started successfully\n");
    result = TRUE;

Cleanup:
    if (hSvc) CloseServiceHandle(hSvc);
    if (hSCM) CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// EnsureXgsDriverRunning - 确保 XGS 驱动已安装并运行
//=============================================================================
BOOL
EnsureXgsDriverRunning(VOID)
{
    printf("[XGSMgr] ========================================\n");
    printf("[XGSMgr]   XGS Ransomware Filter Driver Manager\n");
    printf("[XGSMgr] ========================================\n");

    if (!InstallXgsDriver())
    {
        printf("[XGSMgr] Driver install failed!\n");
        return FALSE;
    }

    printf("[XGSMgr] Starting driver...\n");
    if (!StartXgsDriver())
    {
        printf("[XGSMgr] Driver start failed!\n");
        return FALSE;
    }

    printf("[XGSMgr] ========================================\n");
    printf("[XGSMgr]   XGS driver ready\n");
    printf("[XGSMgr] ========================================\n");
    return TRUE;
}

//=============================================================================
// ConnectToXgsDriver - 连接 XGS 驱动并鉴权
//
// 与 AVDriver 相同的 Challenge-Response + HMAC-SHA256 鉴权流程
//=============================================================================
BOOL
ConnectToXgsDriver(
    _Out_ HANDLE* phDriver
)
{
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    DWORD bytesReturned;
    AV_AUTH_CHALLENGE challenge;
    AV_AUTH_RESPONSE response;
    AV_AUTH_RESULT authResult;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    int retryCount;

    for (retryCount = 0; retryCount < AV_DRIVER_RETRY_MAX; retryCount++)
    {
        hDriver = CreateFileW(
            XGS_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDriver != INVALID_HANDLE_VALUE)
        {
            break;
        }

        if (retryCount < AV_DRIVER_RETRY_MAX - 1)
        {
            printf("[XGSMgr] Waiting for XGS driver connection... (attempt %d/%d)\n",
                   retryCount + 1, AV_DRIVER_RETRY_MAX);
            Sleep(AV_DRIVER_RETRY_DELAY);
        }
    }

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[XGSMgr] Unable to connect to XGS driver (error: %lu)\n", GetLastError());
        return FALSE;
    }

    printf("[XGSMgr] Connected to XGS driver\n");

    ZeroMemory(&challenge, sizeof(challenge));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_AUTH_INIT,
            NULL, 0,
            &challenge, sizeof(challenge),
            &bytesReturned, NULL))
    {
        printf("[XGSMgr] IOCTL_XGS_AUTH_INIT failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (bytesReturned < sizeof(AV_AUTH_CHALLENGE))
    {
        printf("[XGSMgr] IOCTL_XGS_AUTH_INIT returned data too small\n");
        CloseHandle(hDriver);
        return FALSE;
    }

    CopyMemory(hmacInput, challenge.Challenge, AV_CHALLENGE_SIZE);
    CopyMemory(hmacInput + AV_CHALLENGE_SIZE, &challenge.SequenceId, sizeof(UINT64));

    ZeroMemory(&response, sizeof(response));
    response.SequenceId = challenge.SequenceId;
    CopyMemory(response.Challenge, challenge.Challenge, AV_CHALLENGE_SIZE);

    if (!CalculateHmac(
            hmacInput,
            sizeof(hmacInput),
            AV_SHARED_KEY,
            AV_SHARED_KEY_SIZE,
            response.Hmac))
    {
        printf("[XGSMgr] HMAC calculation failed\n");
        CloseHandle(hDriver);
        return FALSE;
    }

    ZeroMemory(&authResult, sizeof(authResult));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_AUTH_VERIFY,
            &response, sizeof(response),
            &authResult, sizeof(authResult),
            &bytesReturned, NULL))
    {
        printf("[XGSMgr] IOCTL_XGS_AUTH_VERIFY failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (authResult.Status != STATUS_SUCCESS)
    {
        printf("[XGSMgr] XGS driver auth failed (Status: 0x%08lX)\n", authResult.Status);
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[XGSMgr] XGS driver auth succeeded\n");

    //
    // 验证连接: 查询 XGS 状态
    //
    XGS_STATUS xgsStatus;
    ZeroMemory(&xgsStatus, sizeof(xgsStatus));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_GET_STATUS,
            NULL, 0,
            &xgsStatus, sizeof(xgsStatus),
            &bytesReturned, NULL))
    {
        printf("[XGSMgr] IOCTL_XGS_GET_STATUS failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[XGSMgr] XGS connection verified - Version: %u, Writes: %llu, "
           "Deletes: %llu, Backups: %llu, Suspected: %u\n",
           xgsStatus.Version,
           xgsStatus.DocWrites,
           xgsStatus.DocDeletes,
           xgsStatus.BackupsCreated,
           xgsStatus.RansomSuspected);

    *phDriver = hDriver;
    return TRUE;
}

//=============================================================================
// 勒索防护监控线程
//
// 轮询 XGS 驱动获取勒索触发通知 (多维评分: 进程级跟踪+熵分析+扩展名变更+
// 文件操作多样性, 评分达到阈值 100 触发阻断),
// 转发 AVMain 弹窗决策, 决策通过 IOCTL 送回 XGS 驱动:
//   1=放行继续 2=保持阻断 3=仅恢复
// AVMain 未连接或决策超时 -> 默认保持阻断 (驱动 60 秒无决策自动放行兜底)
//=============================================================================
typedef struct _RANSOM_MONITOR_PARAMS
{
    HANDLE hXgs;
} RANSOM_MONITOR_PARAMS;

DWORD
WINAPI
RansomMonitorThread(
    _In_ LPVOID lpParam
)
{
    RANSOM_MONITOR_PARAMS* params = (RANSOM_MONITOR_PARAMS*)lpParam;
    HANDLE hXgs = params->hXgs;
    DWORD bytesReturned;
    XGS_RANSOM_NOTIFICATION notification;
    UINT64 lastNotifId = 0;

    printf("[AVRansom] Ransom monitor thread started\n");

    while (TRUE)
    {
        ZeroMemory(&notification, sizeof(notification));

        if (!DeviceIoControl(
                hXgs,
                IOCTL_XGS_GET_NOTIFICATION,
                NULL, 0,
                &notification, sizeof(notification),
                &bytesReturned, NULL))
        {
            printf("[AVRansom] GET_NOTIFICATION failed (error: %lu)\n", GetLastError());
            Sleep(200);
            continue;
        }

        if (!notification.HasPending || notification.NotificationId == lastNotifId)
        {
            //
            // 轮询间隔: 50ms
            //
            Sleep(50);
            continue;
        }

        lastNotifId = notification.NotificationId;
        printf("[AVRansom] Ransomware suspected! PID=%lu name=%ws score=%u flags=0x%02X "
               "%u files affected, ID=%llu\n",
               notification.ProcessId,
               notification.ProcessName[0] ? notification.ProcessName : L"(unknown)",
               notification.ThreatScore, notification.DetectionFlags,
               notification.FileCount, notification.NotificationId);

        for (UINT32 i = 0; i < notification.FileCount; i++)
        {
            const char* opDesc =
                (notification.Files[i].Operation == XGS_OP_DELETE)    ? "DEL" :
                (notification.Files[i].Operation == XGS_OP_RENAME)    ? "REN" :
                (notification.Files[i].Operation == XGS_OP_EXT_CHANGE) ? "EXT" :
                                                                        "MOD";
            printf("[AVRansom]   [%u] %s %ls\n",
                   i, opDesc, notification.Files[i].OriginalPath);
        }

        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hMainPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        AV_PIPE_RANSOM_NOTIFY_DATA notifyMsg;
        ZeroMemory(&notifyMsg, sizeof(notifyMsg));
        notifyMsg.NotificationId = notification.NotificationId;
        notifyMsg.ProcessId = notification.ProcessId;
        CopyMemory(notifyMsg.ProcessName, notification.ProcessName, sizeof(notifyMsg.ProcessName));
        notifyMsg.ThreatScore = notification.ThreatScore;
        notifyMsg.DetectionFlags = notification.DetectionFlags;
        notifyMsg.FileCount = notification.FileCount;
        CopyMemory(notifyMsg.Files, notification.Files, sizeof(notifyMsg.Files));

        //
        // 默认决策: 保持阻断 (勒索场景保守处理, 驱动 60 秒无决策自动放行兜底)
        //
        UINT32 decision = XGS_DECISION_STAY_BLOCK;

        if (hMainPipe == NULL)
        {
            printf("[AVRansom] No AVMain connected, keeping block\n");
        }
        else if (!SendPipeMessage(hMainPipe, AvPipeMsgRansomNotify,
                                  &notifyMsg, sizeof(notifyMsg)))
        {
            printf("[AVRansom] Send notify to AVMain failed, keeping block\n");
        }
        else
        {
            printf("[AVRansom] Notification forwarded to AVMain, waiting decision...\n");

            UINT32 userDecision = WaitForPipeRawDecision(
                AvPipeMsgRansomDecision,
                notification.NotificationId,
                AV_NOTIFICATION_TIMEOUT_MS);

            if (userDecision != 0)
            {
                decision = userDecision;
            }
            else
            {
                printf("[AVRansom] Decision timeout, keeping block\n");
            }
        }

        //
        // 发送决策给 XGS 驱动
        //
        XGS_RANSOM_DECISION decisionMsg;
        ZeroMemory(&decisionMsg, sizeof(decisionMsg));
        decisionMsg.NotificationId = notification.NotificationId;
        decisionMsg.Decision = decision;
        decisionMsg.ProcessId = notification.ProcessId;

        if (!DeviceIoControl(
                hXgs,
                IOCTL_XGS_SEND_DECISION,
                &decisionMsg, sizeof(decisionMsg),
                NULL, 0,
                &bytesReturned, NULL))
        {
            printf("[AVRansom] SEND_DECISION failed (error: %lu)\n", GetLastError());
        }
        else
        {
            const wchar_t* decisionDesc =
                (decision == XGS_DECISION_ALLOW)       ? L"ALLOW" :
                (decision == XGS_DECISION_RESTORE)     ? L"RESTORE" :
                                                         L"STAY BLOCK";
            printf("[AVRansom] Decision %ls sent to driver\n", decisionDesc);
        }
    }

    return 0;
}

//=============================================================================
// XGSEndPoint 驱动管理 (传统 minifilter, 非 KMDF)
//
// EndPoint 端点防护驱动与 XGSRansomFilter 同为传统 minifilter,
// 需写 Instances 注册表 (minifilter altitude 配置), 服务名 XGSEndPoint
//=============================================================================

//
// 写 EndPoint 驱动的 minifilter Instances 注册表
//
static BOOL
WriteEndpointInstancesRegistry(VOID)
{
    HKEY hKey = NULL;
    BOOL ok = TRUE;
    DWORD flags = 0;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\XGSEndPoint\\Instances",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        const WCHAR* defInst = L"XGSEndPointInstance";
        RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ,
                       (const BYTE*)defInst,
                       (DWORD)((wcslen(defInst) + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
    }
    else
    {
        printf("[EPMgr] RegCreateKeyEx(Instances) failed (error: %lu)\n", GetLastError());
        ok = FALSE;
    }

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\XGSEndPoint\\Instances\\XGSEndPointInstance",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        const WCHAR* altitude = L"327000";
        RegSetValueExW(hKey, L"Altitude", 0, REG_SZ,
                       (const BYTE*)altitude,
                       (DWORD)((wcslen(altitude) + 1) * sizeof(WCHAR)));
        RegSetValueExW(hKey, L"Flags", 0, REG_DWORD,
                       (const BYTE*)&flags, sizeof(flags));
        RegCloseKey(hKey);
        printf("[EPMgr] Instances registry written (Altitude=327000)\n");
    }
    else
    {
        printf("[EPMgr] RegCreateKeyEx(Instance) failed (error: %lu)\n", GetLastError());
        ok = FALSE;
    }

    return ok;
}

//=============================================================================
// InstallEndpointDriver - 安装/更新 EndPoint 驱动服务
//=============================================================================
BOOL
InstallEndpointDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    WCHAR sysPath[MAX_PATH];
    WCHAR sourceDriverPath[MAX_PATH];
    WCHAR targetDriverPath[MAX_PATH];
    WCHAR targetNtPath[MAX_PATH];
    WCHAR currentImagePath[MAX_PATH];
    WCHAR systemRoot[MAX_PATH];
    BOOL result = FALSE;
    BOOL serviceExists = FALSE;

    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH))
    {
        printf("[EPMgr] GetModuleFileNameW failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    WCHAR* pSlash = wcsrchr(sysPath, L'\\');
    if (pSlash == NULL)
    {
        printf("[EPMgr] Unable to parse path\n");
        return FALSE;
    }
    *(pSlash + 1) = L'\0';

    StringCbCopyW(sourceDriverPath, sizeof(sourceDriverPath), sysPath);
    StringCbCatW(sourceDriverPath, sizeof(sourceDriverPath), L"XIGUAEndPoint.sys");

    printf("[EPMgr] Source driver: %ls\n", sourceDriverPath);

    if (GetFileAttributesW(sourceDriverPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[EPMgr] Driver file not found: %ls\n", sourceDriverPath);
        return FALSE;
    }

    if (GetSystemDirectoryW(systemRoot, MAX_PATH) == 0)
    {
        printf("[EPMgr] GetSystemDirectory failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
    StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUAEndPoint.sys");

    StringCbCopyW(targetNtPath, sizeof(targetNtPath),
                  L"\\SystemRoot\\System32\\drivers\\XIGUAEndPoint.sys");

    BOOL copyOk = CopyFileW(sourceDriverPath, targetDriverPath, FALSE);
    if (!copyOk)
    {
        DWORD err = GetLastError();
        printf("[EPMgr] CopyFile failed (error: %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED)
        {
            printf("[EPMgr] Need ADMIN privileges!\n");
        }
    }
    else
    {
        printf("[EPMgr] Driver copied to system drivers directory\n");
    }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCM == NULL)
    {
        printf("[EPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSEndPoint", SERVICE_ALL_ACCESS);
    if (hSvc != NULL)
    {
        serviceExists = TRUE;

        if (GetDriverServiceImagePath(hSvc, currentImagePath, sizeof(currentImagePath)))
        {
            printf("[EPMgr] Service currently points to: %ls\n", currentImagePath);

            if (_wcsicmp(currentImagePath, targetNtPath) != 0)
            {
                printf("[EPMgr] Path mismatch, updating service config...\n");
                SERVICE_STATUS svcStatus;
                ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);

                if (ChangeServiceConfigW(hSvc,
                        SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                        targetNtPath, NULL, NULL, NULL, NULL, NULL, NULL))
                {
                    printf("[EPMgr] Service config updated\n");
                }
                else
                {
                    printf("[EPMgr] ChangeServiceConfig failed (error: %lu)\n", GetLastError());
                    DeleteService(hSvc);
                    CloseServiceHandle(hSvc);
                    hSvc = NULL;
                    serviceExists = FALSE;
                }
            }
        }

        if (hSvc != NULL)
        {
            printf("[EPMgr] Driver service ready\n");
            result = TRUE;
        }
    }

    if (!copyOk && !serviceExists)
    {
        printf("[EPMgr] Copy failed and no existing service, install aborted\n");
        goto Cleanup;
    }

    if (!serviceExists || hSvc == NULL)
    {
        hSvc = CreateServiceW(
            hSCM,
            L"XGSEndPoint",
            L"XGS EndPoint Protection Driver",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            targetNtPath,
            NULL, NULL, NULL, NULL, NULL
        );

        if (hSvc == NULL)
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                printf("[EPMgr] Driver service already exists\n");
                hSvc = OpenServiceW(hSCM, L"XGSEndPoint", SERVICE_ALL_ACCESS);
                result = (hSvc != NULL);
            }
            else
            {
                printf("[EPMgr] CreateService failed (error: %lu)\n", err);
                goto Cleanup;
            }
        }
        else
        {
            printf("[EPMgr] Driver service created\n");
            result = TRUE;
        }
    }

    WriteEndpointInstancesRegistry();

Cleanup:
    if (hSvc != NULL)
    {
        CloseServiceHandle(hSvc);
    }
    if (hSCM != NULL)
    {
        CloseServiceHandle(hSCM);
    }

    return result;
}

//=============================================================================
// UninstallEndpointDriver - 卸载 EndPoint 驱动服务
//=============================================================================
BOOL
UninstallEndpointDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        printf("[EPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSEndPoint", SERVICE_STOP | DELETE);
    if (hSvc == NULL)
    {
        printf("[EPMgr] OpenService failed (error: %lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS svcStatus;
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus))
    {
        printf("[EPMgr] Driver stopped\n");
    }

    if (DeleteService(hSvc))
    {
        printf("[EPMgr] Driver service uninstall succeeded\n");
        result = TRUE;
    }
    else
    {
        printf("[EPMgr] DeleteService failed (error: %lu)\n", GetLastError());
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// StartEndpointDriver - 启动 EndPoint 驱动服务
//=============================================================================
BOOL
StartEndpointDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[EPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XGSEndPoint",
                        SERVICE_START | SERVICE_QUERY_STATUS);
    if (hSvc == NULL)
    {
        printf("[EPMgr] OpenService failed (error: %lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    if (StartServiceW(hSvc, 0, NULL))
    {
        printf("[EPMgr] Driver started successfully\n");
        result = TRUE;
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[EPMgr] Driver already running\n");
            result = TRUE;
        }
        else
        {
            printf("[EPMgr] StartService failed (error: %lu)\n", err);
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// EnsureEndpointDriverRunning - 确保 EndPoint 驱动已安装并运行
//=============================================================================
BOOL
EnsureEndpointDriverRunning(VOID)
{
    printf("[EPMgr] ========================================\n");
    printf("[EPMgr]   XGS EndPoint Protection Driver Manager\n");
    printf("[EPMgr] ========================================\n");

    if (!InstallEndpointDriver())
    {
        printf("[EPMgr] Driver install failed!\n");
        return FALSE;
    }

    printf("[EPMgr] Starting driver...\n");
    if (!StartEndpointDriver())
    {
        printf("[EPMgr] Driver start failed!\n");
        return FALSE;
    }

    printf("[EPMgr] ========================================\n");
    printf("[EPMgr]   EndPoint driver ready\n");
    printf("[EPMgr] ========================================\n");
    return TRUE;
}

//=============================================================================
// InstallSelfProtectDriver - 安装/更新 XIGUASelfProtect 自保护驱动服务
//
// 该驱动为传统型驱动 (非 minifilter), 无需 Instances 注册表和 IOCTL 通信
//=============================================================================
BOOL
InstallSelfProtectDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    WCHAR sysPath[MAX_PATH];
    WCHAR sourceDriverPath[MAX_PATH];
    WCHAR targetDriverPath[MAX_PATH];
    WCHAR targetNtPath[MAX_PATH];
    WCHAR currentImagePath[MAX_PATH];
    WCHAR systemRoot[MAX_PATH];
    BOOL result = FALSE;
    BOOL serviceExists = FALSE;

    if (!GetModuleFileNameW(NULL, sysPath, MAX_PATH))
    {
        printf("[SPMgr] GetModuleFileNameW failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    WCHAR* pSlash = wcsrchr(sysPath, L'\\');
    if (pSlash == NULL)
    {
        printf("[SPMgr] Unable to parse path\n");
        return FALSE;
    }
    *(pSlash + 1) = L'\0';

    StringCbCopyW(sourceDriverPath, sizeof(sourceDriverPath), sysPath);
    StringCbCatW(sourceDriverPath, sizeof(sourceDriverPath), L"XIGUASelfProtect.sys");

    printf("[SPMgr] ========================================\n");
    printf("[SPMgr]   XIGUA Self Protection Driver Manager\n");
    printf("[SPMgr] ========================================\n");
    printf("[SPMgr] Source driver: %ls\n", sourceDriverPath);

    if (GetFileAttributesW(sourceDriverPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[SPMgr] Driver file not found: %ls\n", sourceDriverPath);
        return FALSE;
    }

    if (GetSystemDirectoryW(systemRoot, MAX_PATH) == 0)
    {
        printf("[SPMgr] GetSystemDirectory failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    StringCbCopyW(targetDriverPath, sizeof(targetDriverPath), systemRoot);
    StringCbCatW(targetDriverPath, sizeof(targetDriverPath), L"\\drivers\\XIGUASelfProtect.sys");

    StringCbCopyW(targetNtPath, sizeof(targetNtPath),
                  L"\\SystemRoot\\System32\\drivers\\XIGUASelfProtect.sys");

    BOOL copyOk = CopyFileW(sourceDriverPath, targetDriverPath, FALSE);
    if (!copyOk)
    {
        DWORD err = GetLastError();
        printf("[SPMgr] CopyFile failed (error: %lu)\n", err);
        if (err == ERROR_ACCESS_DENIED)
        {
            printf("[SPMgr] Need ADMIN privileges!\n");
        }
    }
    else
    {
        printf("[SPMgr] Driver copied to system drivers directory\n");
    }

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCM == NULL)
    {
        printf("[SPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XIGUASelfProtect", SERVICE_ALL_ACCESS);
    if (hSvc != NULL)
    {
        serviceExists = TRUE;

        if (GetDriverServiceImagePath(hSvc, currentImagePath, sizeof(currentImagePath)))
        {
            printf("[SPMgr] Service currently points to: %ls\n", currentImagePath);

            if (_wcsicmp(currentImagePath, targetNtPath) != 0)
            {
                printf("[SPMgr] Path mismatch, updating service config...\n");
                SERVICE_STATUS svcStatus;
                ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);

                if (ChangeServiceConfigW(hSvc,
                        SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                        targetNtPath, NULL, NULL, NULL, NULL, NULL, NULL))
                {
                    printf("[SPMgr] Service config updated\n");
                }
                else
                {
                    printf("[SPMgr] ChangeServiceConfig failed (error: %lu)\n", GetLastError());
                    DeleteService(hSvc);
                    CloseServiceHandle(hSvc);
                    hSvc = NULL;
                    serviceExists = FALSE;
                }
            }
        }

        if (hSvc != NULL)
        {
            printf("[SPMgr] Driver service ready\n");
            result = TRUE;
        }
    }

    if (!copyOk && !serviceExists)
    {
        printf("[SPMgr] Copy failed and no existing service, install aborted\n");
        goto SP_Cleanup;
    }

    if (!serviceExists || hSvc == NULL)
    {
        hSvc = CreateServiceW(
            hSCM,
            L"XIGUASelfProtect",
            L"XIGUA Self Protection Driver",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            targetNtPath,
            NULL, NULL, NULL, NULL, NULL
        );

        if (hSvc == NULL)
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_EXISTS)
            {
                printf("[SPMgr] Driver service already exists\n");
                hSvc = OpenServiceW(hSCM, L"XIGUASelfProtect", SERVICE_ALL_ACCESS);
                result = (hSvc != NULL);
            }
            else
            {
                printf("[SPMgr] CreateService failed (error: %lu)\n", err);
                goto SP_Cleanup;
            }
        }
        else
        {
            printf("[SPMgr] Driver service created\n");
            result = TRUE;
        }
    }

SP_Cleanup:
    if (hSvc != NULL)
    {
        CloseServiceHandle(hSvc);
    }
    if (hSCM != NULL)
    {
        CloseServiceHandle(hSCM);
    }

    return result;
}

//=============================================================================
// StartSelfProtectDriver - 启动自保护驱动服务
//=============================================================================
BOOL
StartSelfProtectDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        printf("[SPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XIGUASelfProtect",
                        SERVICE_START | SERVICE_QUERY_STATUS);
    if (hSvc == NULL)
    {
        printf("[SPMgr] OpenService failed (error: %lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    if (StartServiceW(hSvc, 0, NULL))
    {
        printf("[SPMgr] Driver started successfully\n");
        result = TRUE;
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[SPMgr] Driver already running\n");
            result = TRUE;
        }
        else
        {
            printf("[SPMgr] StartService failed (error: %lu)\n", err);
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// EnsureSelfProtectDriverRunning - 确保自保护驱动已安装并运行
//=============================================================================
BOOL
EnsureSelfProtectDriverRunning(VOID)
{
    if (!InstallSelfProtectDriver())
    {
        printf("[SPMgr] Driver install failed!\n");
        return FALSE;
    }

    printf("[SPMgr] Starting driver...\n");
    if (!StartSelfProtectDriver())
    {
        printf("[SPMgr] Driver start failed!\n");
        return FALSE;
    }

    printf("[SPMgr] ========================================\n");
    printf("[SPMgr]   Self protection driver ready\n");
    printf("[SPMgr] ========================================\n");
    return TRUE;
}

//=============================================================================
// RegisterProtectedPids - 向自保护驱动注册受保护 PID
// 收集自身 + AVMain + msedgewebview2 的 PID 并移交给驱动
// 保持设备句柄打开, 句柄关闭时驱动自动解除保护
//=============================================================================
BOOL
RegisterProtectedPids(VOID)
{
    HANDLE hDevice;
    XGS_SP_REGISTER_PIDS_INPUT input = { 0 };
    DWORD bytesReturned = 0;
    DWORD selfPid;
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    ULONG i;

    //
    // 受保护进程名列表 (大小写不敏感匹配)
    //   XIGUASecurityAgent.exe  - SYSTEM 服务程序 (自身)
    //   XIGUASecurity.exe       - 真正的主程序 (UI 入口)
    //   avmain.exe              - 当前模拟用的主程序, 兼容
    //   avsystem.exe            - AVSystem 旧名兼容
    //   msedgewebview2.exe      - WebView2 UI 渲染进程
    //
    static const WCHAR* const protectedNames[] = {
        L"XIGUASecurityAgent.exe",
        L"XIGUASecurity.exe",
        L"avmain.exe",
        L"avsystem.exe",
        L"msedgewebview2.exe"
    };

    //
    // 打开自保护驱动设备
    //
    hDevice = CreateFileW(L"\\\\.\\XGSSelfProtect",
                          GENERIC_READ | GENERIC_WRITE,
                          0,
                          NULL,
                          OPEN_EXISTING,
                          0,
                          NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[SPMgr] Open device failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    //
    // 自身 PID 必须注册
    //
    selfPid = GetCurrentProcessId();
    input.Pids[input.PidCount++] = selfPid;

    //
    // 枚举进程, 查找其他受保护进程的 PID
    //
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                //
                // 跳过自身 (已注册)
                //
                if (pe.th32ProcessID == selfPid)
                {
                    continue;
                }

                for (i = 0; i < ARRAYSIZE(protectedNames); i++)
                {
                    if (_wcsicmp(pe.szExeFile, protectedNames[i]) == 0)
                    {
                        if (input.PidCount < XGS_SP_REGISTER_PIDS_MAX)
                        {
                            input.Pids[input.PidCount++] = pe.th32ProcessID;
                            printf("[SPMgr] Found %ls (PID %lu)\n",
                                   pe.szExeFile, pe.th32ProcessID);
                        }
                        break;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    printf("[SPMgr] Registering %u protected PIDs with driver\n", input.PidCount);

    //
    // 发送注册 IOCTL
    //
    if (!DeviceIoControl(hDevice,
                         IOCTL_XGS_SP_REGISTER_PIDS,
                         &input,
                         sizeof(input),
                         NULL,
                         0,
                         &bytesReturned,
                         NULL))
    {
        printf("[SPMgr] Register IOCTL failed (error: %lu)\n", GetLastError());
        CloseHandle(hDevice);
        return FALSE;
    }

    //
    // 保持句柄打开 (存入全局变量)
    // Agent 退出时句柄自动关闭, 驱动 IRP_MJ_CLOSE 清理会话
    //
    g_hSelfProtect = hDevice;

    printf("[SPMgr] ========================================\n");
    printf("[SPMgr]   Self protection ACTIVE (PID %lu protected)\n", selfPid);
    printf("[SPMgr] ========================================\n");
    return TRUE;
}

//=============================================================================
// UninstallSelfProtectDriver - 卸载自保护驱动服务
//=============================================================================
BOOL
UninstallSelfProtectDriver(VOID)
{
    SC_HANDLE hSCM = NULL;
    SC_HANDLE hSvc = NULL;
    BOOL result = FALSE;

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        printf("[SPMgr] OpenSCManager failed (error: %lu)\n", GetLastError());
        return FALSE;
    }

    hSvc = OpenServiceW(hSCM, L"XIGUASelfProtect", SERVICE_STOP | DELETE);
    if (hSvc == NULL)
    {
        printf("[SPMgr] OpenService failed (error: %lu)\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    SERVICE_STATUS svcStatus;
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus))
    {
        printf("[SPMgr] Driver stopped\n");
    }

    if (DeleteService(hSvc))
    {
        printf("[SPMgr] Driver service uninstall succeeded\n");
        result = TRUE;
    }
    else
    {
        printf("[SPMgr] DeleteService failed (error: %lu)\n", GetLastError());
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return result;
}

//=============================================================================
// ConnectToEndpointDriver - 连接 EndPoint 驱动并鉴权
//
// 与 XGS 驱动相同的 Challenge-Response + HMAC-SHA256 鉴权流程
//=============================================================================
BOOL
ConnectToEndpointDriver(
    _Out_ HANDLE* phDriver
)
{
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    DWORD bytesReturned;
    AV_AUTH_CHALLENGE challenge;
    AV_AUTH_RESPONSE response;
    AV_AUTH_RESULT authResult;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    int retryCount;

    for (retryCount = 0; retryCount < AV_DRIVER_RETRY_MAX; retryCount++)
    {
        hDriver = CreateFileW(
            XGS_EP_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDriver != INVALID_HANDLE_VALUE)
        {
            break;
        }

        if (retryCount < AV_DRIVER_RETRY_MAX - 1)
        {
            printf("[EPMgr] Waiting for EndPoint driver connection... (attempt %d/%d)\n",
                   retryCount + 1, AV_DRIVER_RETRY_MAX);
            Sleep(AV_DRIVER_RETRY_DELAY);
        }
    }

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        printf("[EPMgr] Unable to connect to EndPoint driver (error: %lu)\n", GetLastError());
        return FALSE;
    }

    printf("[EPMgr] Connected to EndPoint driver\n");

    ZeroMemory(&challenge, sizeof(challenge));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_EP_AUTH_INIT,
            NULL, 0,
            &challenge, sizeof(challenge),
            &bytesReturned, NULL))
    {
        printf("[EPMgr] IOCTL_XGS_EP_AUTH_INIT failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (bytesReturned < sizeof(AV_AUTH_CHALLENGE))
    {
        printf("[EPMgr] IOCTL_XGS_EP_AUTH_INIT returned data too small\n");
        CloseHandle(hDriver);
        return FALSE;
    }

    CopyMemory(hmacInput, challenge.Challenge, AV_CHALLENGE_SIZE);
    CopyMemory(hmacInput + AV_CHALLENGE_SIZE, &challenge.SequenceId, sizeof(UINT64));

    ZeroMemory(&response, sizeof(response));
    response.SequenceId = challenge.SequenceId;
    CopyMemory(response.Challenge, challenge.Challenge, AV_CHALLENGE_SIZE);

    if (!CalculateHmac(
            hmacInput,
            sizeof(hmacInput),
            AV_SHARED_KEY,
            AV_SHARED_KEY_SIZE,
            response.Hmac))
    {
        printf("[EPMgr] HMAC calculation failed\n");
        CloseHandle(hDriver);
        return FALSE;
    }

    ZeroMemory(&authResult, sizeof(authResult));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_EP_AUTH_VERIFY,
            &response, sizeof(response),
            &authResult, sizeof(authResult),
            &bytesReturned, NULL))
    {
        printf("[EPMgr] IOCTL_XGS_EP_AUTH_VERIFY failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    if (authResult.Status != STATUS_SUCCESS)
    {
        printf("[EPMgr] EndPoint driver auth failed (Status: 0x%08lX)\n", authResult.Status);
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[EPMgr] EndPoint driver auth succeeded\n");

    //
    // 验证连接: 查询 EndPoint 状态
    //
    XGS_EP_STATUS epStatus;
    ZeroMemory(&epStatus, sizeof(epStatus));
    if (!DeviceIoControl(
            hDriver,
            IOCTL_XGS_EP_GET_STATUS,
            NULL, 0,
            &epStatus, sizeof(epStatus),
            &bytesReturned, NULL))
    {
        printf("[EPMgr] IOCTL_XGS_EP_GET_STATUS failed (error: %lu)\n", GetLastError());
        CloseHandle(hDriver);
        return FALSE;
    }

    printf("[EPMgr] EndPoint connection verified - Version: %u, Behaviors: %llu, "
           "Threats: %llu, Suspended: %llu\n",
           epStatus.Version,
           epStatus.BehaviorsRecorded,
           epStatus.ThreatsDetected,
           epStatus.ProcessesSuspended);

    *phDriver = hDriver;
    return TRUE;
}

//=============================================================================
// EndPoint 端点防护监控线程
//
// 轮询 EndPoint 驱动获取威胁通知 (IOA 评分触发, 威胁进程已挂起),
// 转发 AVMain 弹窗决策, 决策通过 IOCTL 送回驱动:
//   1=放行(恢复进程) 2=终止进程
// AVMain 未连接或决策超时 -> 默认放行 (驱动 60 秒无决策自动放行兜底)
//
// 用户选择终止时, 自动拉取该进程的完整行为链并生成威胁报告:
//   路径: C:\ProgramData\XIGUASecurity\Reports\
//   文件名: <PID>_<报告ID>_<进程名>_<时间>.log
//   内容: IOA 检测原因 + 命中规则 + 完整行为链 + T-Code 映射
//=============================================================================
typedef struct _ENDPOINT_MONITOR_PARAMS
{
    HANDLE hEndpoint;
} ENDPOINT_MONITOR_PARAMS;

//
// 行为类型 -> MITRE ATT&CK T-Code 映射
//
static
const wchar_t*
EpBehaviorTCode(
    UINT32 behaviorType
    )
{
    switch (behaviorType)
    {
    case XgsEpProcessCreate:    return L"T1057";        // Process Discovery
    case XgsEpProcessExit:      return L"-";            // 正常退出
    case XgsEpRemoteThread:     return L"T1055";        // Process Injection
    case XgsEpRwxMapping:       return L"T1055.012";    // Process Hollowing
    case XgsEpRegWrite:         return L"T1547.001";    // Registry Run Keys
    case XgsEpRegDelete:        return L"T1485";        // Data Destruction
    case XgsEpFileWrite:        return L"T1105";        // Ingress Tool Transfer
    case XgsEpFileDelete:       return L"T1485";        // Data Destruction
    case XgsEpProcessControl:   return L"T1106";        // Native API
    case XgsEpThreadCreate:     return L"T1055";        // Process Injection
    case XgsEpModuleLoad:       return L"T1055.001";    // DLL Injection
    case XgsEpCrossMem:         return L"T1055";        // Process Injection
    case XgsEpFileRename:       return L"T1036";        // Masquerading
    case XgsEpBootWrite:        return L"T1542";        // Pre-OS Boot: Modify Boot Record
    default:                    return L"T0000";        // Unknown
    }
}

//
// 行为类型 -> 中文名称
//
static
const wchar_t*
EpBehaviorName(
    UINT32 behaviorType
    )
{
    switch (behaviorType)
    {
    case XgsEpProcessCreate:    return L"进程创建";
    case XgsEpProcessExit:      return L"进程退出";
    case XgsEpRemoteThread:     return L"远程线程注入";
    case XgsEpRwxMapping:       return L"RWX内存映射";
    case XgsEpRegWrite:         return L"注册表写入";
    case XgsEpRegDelete:        return L"注册表删除";
    case XgsEpFileWrite:        return L"文件写入";
    case XgsEpFileDelete:       return L"文件删除";
    case XgsEpProcessControl:   return L"跨进程控制";
    case XgsEpThreadCreate:     return L"线程创建";
    case XgsEpModuleLoad:       return L"模块加载";
    case XgsEpCrossMem:         return L"跨进程内存读写";
    case XgsEpFileRename:       return L"文件重命名";
    default:                    return L"未知行为";
    }
}

//
// 从镜像路径提取进程名 (不含路径和扩展名)
//
static
VOID
EpExtractProcessName(
    _In_ const wchar_t* imagePath,
    _Out_writes_(maxChars) wchar_t* procName,
    _In_ SIZE_T maxChars
    )
{
    const wchar_t* base = imagePath;
    const wchar_t* p;
    SIZE_T len;
    SIZE_T copyLen;

    if (procName == NULL || maxChars == 0)
    {
        return;
    }
    procName[0] = L'\0';

    if (imagePath == NULL)
    {
        StringCchCopyW(procName, maxChars, L"unknown");
        return;
    }

    // 找最后一个反斜杠
    for (p = imagePath; *p != L'\0'; p++)
    {
        if (*p == L'\\' || *p == L'/')
        {
            base = p + 1;
        }
    }

    // 复制, 去掉 .exe 扩展名
    len = wcslen(base);
    copyLen = len;
    if (copyLen >= 4 &&
        (base[copyLen - 4] == L'.') &&
        (base[copyLen - 3] == L'e' || base[copyLen - 3] == L'E') &&
        (base[copyLen - 2] == L'x' || base[copyLen - 2] == L'X') &&
        (base[copyLen - 1] == L'e' || base[copyLen - 1] == L'E'))
    {
        copyLen -= 4;
    }
    if (copyLen >= maxChars)
    {
        copyLen = maxChars - 1;
    }
    CopyMemory(procName, base, copyLen * sizeof(wchar_t));
    procName[copyLen] = L'\0';
}

//
// 生成威胁行为链报告文件
// 在用户选择终止进程后调用, 从驱动拉取完整行为链并写入磁盘
//
static
BOOL
GenerateThreatReport(
    _In_ HANDLE hEndpoint,
    _In_ const XGS_EP_NOTIFICATION* notification
    )
{
    XGS_EP_BEHAVIOR_CHAIN chainOut;
    XGS_EP_BEHAVIOR_CHAIN_REQUEST req;
    DWORD bytesReturned;
    wchar_t reportDir[MAX_PATH];
    wchar_t fileName[MAX_PATH];
    wchar_t procName[128];
    wchar_t timeStr[64];
    FILE* fp = NULL;
    errno_t err;
    SYSTEMTIME st;
    ULONG i;

    //
    // 1. 从驱动拉取完整行为链
    //
    ZeroMemory(&req, sizeof(req));
    req.ProcessId = notification->ProcessId;

    if (!DeviceIoControl(
            hEndpoint,
            IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN,
            &req, sizeof(req),
            &chainOut, sizeof(chainOut),
            &bytesReturned, NULL))
    {
        printf("[AVEndpoint] GET_BEHAVIOR_CHAIN failed (error: %lu)\n",
               GetLastError());
        return FALSE;
    }

    printf("[AVEndpoint] Behavior chain retrieved: %u behaviors for PID %u\n",
           chainOut.BehaviorCount, notification->ProcessId);

    //
    // 2. 准备报告目录和文件名
    //    文件名: <PID>_<报告ID>_<进程名>_<yyyyMMdd_HHmmss>.log
    //
    StringCchCopyW(reportDir, MAX_PATH, L"C:\\ProgramData\\XIGUASecurity\\Reports");
    CreateDirectoryW(reportDir, NULL);

    EpExtractProcessName(notification->ImagePath, procName, ARRAYSIZE(procName));

    GetLocalTime(&st);
    StringCchPrintfW(timeStr, ARRAYSIZE(timeStr),
                      L"%04d%02d%02d_%02d%02d%02d",
                      st.wYear, st.wMonth, st.wDay,
                      st.wHour, st.wMinute, st.wSecond);

    StringCchPrintfW(fileName, MAX_PATH,
                     L"%s\\%u_%llu_%ls_%ls.log",
                     reportDir,
                     notification->ProcessId,
                     notification->NotificationId,
                     procName,
                     timeStr);

    //
    // 3. 写入报告 (UTF-8 文本)
    //
    err = _wfopen_s(&fp, fileName, L"w, ccs=UTF-8");
    if (err != 0 || fp == NULL)
    {
        printf("[AVEndpoint] Failed to create report file: %ls (error: %d)\n",
               fileName, err);
        return FALSE;
    }

    // 报告头
    fwprintf(fp, L"=========================================================\n");
    fwprintf(fp, L"  XIGUASecurity 端点防护威胁行为链报告\n");
    fwprintf(fp, L"=========================================================\n\n");

    fwprintf(fp, L"[基本信息]\n");
    fwprintf(fp, L"  报告 ID:     %llu\n", notification->NotificationId);
    fwprintf(fp, L"  生成时间:    %04d-%02d-%02d %02d:%02d:%02d\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fwprintf(fp, L"  进程 ID:     %u\n", notification->ProcessId);
    fwprintf(fp, L"  父进程 ID:   %u\n", notification->ParentProcessId);
    fwprintf(fp, L"  镜像路径:    %ls\n", notification->ImagePath);
    fwprintf(fp, L"  进程名称:    %ls\n", procName);
    fwprintf(fp, L"  威胁评分:    %u / 100 (阈值)\n\n", notification->TotalScore);

    // IOA 检测原因
    fwprintf(fp, L"[IOA 检测原因 - 命中规则]\n");
    fwprintf(fp, L"  %-8ls %-8ls %ls\n", L"规则ID", L"权重", L"描述");
    fwprintf(fp, L"  %-8ls %-8ls %ls\n", L"------", L"------", L"----");
    for (i = 0; i < notification->RuleCount && i < XGS_EP_RULE_MAX; i++)
    {
        fwprintf(fp, L"  %-8u %-8u %ls\n",
                notification->Rules[i].RuleId,
                notification->Rules[i].Score,
                notification->Rules[i].Description);
    }
    fwprintf(fp, L"\n  合计评分: %u (达到阈值 100, 触发拦截)\n\n",
             notification->TotalScore);

    // 完整行为链
    fwprintf(fp, L"[完整行为链 - 按时间顺序]\n");
    fwprintf(fp, L"  %-6ls %-20ls %-12ls %-14ls %ls\n",
             L"序号", L"时间(UTC)", L"T-Code", L"行为类型", L"详情");
    fwprintf(fp, L"  %-6ls %-20ls %-12ls %-14ls %ls\n",
             L"----", L"----", L"------", L"--------", L"----");

    for (i = 0; i < chainOut.BehaviorCount; i++)
    {
        XGS_EP_BEHAVIOR* b = &chainOut.Behaviors[i];
        FILETIME ft;
        SYSTEMTIME bst;
        ULARGE_INTEGER uli;

        // 时间戳转换 (100ns ticks -> FILETIME -> SYSTEMTIME)
        uli.QuadPart = b->Timestamp100ns;
        ft.dwLowDateTime = uli.LowPart;
        ft.dwHighDateTime = uli.HighPart;
        FileTimeToSystemTime(&ft, &bst);

        fwprintf(fp, L"  %-6u %04d-%02d-%02d %02d:%02d:%02d.%03u %-12ls %-14ls %ls\n",
                 i + 1,
                 bst.wYear, bst.wMonth, bst.wDay,
                 bst.wHour, bst.wMinute, bst.wSecond, bst.wMilliseconds,
                 EpBehaviorTCode(b->Type),
                 EpBehaviorName(b->Type),
                 b->Detail);
    }

    fwprintf(fp, L"\n  行为总数: %u\n\n", chainOut.BehaviorCount);

    // 报告尾
    fwprintf(fp, L"[处置结果]\n");
    fwprintf(fp, L"  用户决策:    终止进程 (KILL)\n");
    fwprintf(fp, L"  执行动作:    ZwTerminateProcess (STATUS_ACCESS_DENIED)\n");
    fwprintf(fp, L"  进程状态:    已终止\n\n");

    fwprintf(fp, L"=========================================================\n");
    fwprintf(fp, L"  报告由 XIGUASecurity EndPoint Protection 自动生成\n");
    fwprintf(fp, L"=========================================================\n");

    fclose(fp);

    printf("[AVEndpoint] Threat report saved: %ls\n", fileName);
    return TRUE;
}

DWORD
WINAPI
EndPointMonitorThread(
    _In_ LPVOID lpParam
)
{
    ENDPOINT_MONITOR_PARAMS* params = (ENDPOINT_MONITOR_PARAMS*)lpParam;
    HANDLE hEndpoint = params->hEndpoint;
    DWORD bytesReturned;
    XGS_EP_NOTIFICATION notification;
    UINT64 lastNotifId = 0;

    printf("[AVEndpoint] EndPoint monitor thread started\n");

    while (TRUE)
    {
        ZeroMemory(&notification, sizeof(notification));

        if (!DeviceIoControl(
                hEndpoint,
                IOCTL_XGS_EP_GET_NOTIFICATION,
                NULL, 0,
                &notification, sizeof(notification),
                &bytesReturned, NULL))
        {
            printf("[AVEndpoint] GET_NOTIFICATION failed (error: %lu)\n", GetLastError());
            Sleep(200);
            continue;
        }

        if (!notification.HasPending || notification.NotificationId == lastNotifId)
        {
            Sleep(50);
            continue;
        }

        lastNotifId = notification.NotificationId;
        printf("[AVEndpoint] Threat detected! PID=%u (score %u), ID=%llu\n",
               notification.ProcessId, notification.TotalScore,
               notification.NotificationId);

        for (UINT32 i = 0; i < notification.RuleCount && i < XGS_EP_RULE_MAX; i++)
        {
            printf("[AVEndpoint]   [rule %u] +%u %ls\n",
                   notification.Rules[i].RuleId,
                   notification.Rules[i].Score,
                   notification.Rules[i].Description);
        }

        EnterCriticalSection(&g_MainPipeLock);
        HANDLE hMainPipe = g_hMainPipe;
        LeaveCriticalSection(&g_MainPipeLock);

        AV_PIPE_EP_NOTIFY_DATA notifyMsg;
        ZeroMemory(&notifyMsg, sizeof(notifyMsg));
        notifyMsg.NotificationId = notification.NotificationId;
        notifyMsg.ProcessId = notification.ProcessId;
        notifyMsg.ParentProcessId = notification.ParentProcessId;
        notifyMsg.TotalScore = notification.TotalScore;
        notifyMsg.RuleCount = notification.RuleCount;
        CopyMemory(notifyMsg.Rules, notification.Rules, sizeof(notifyMsg.Rules));
        CopyMemory(notifyMsg.ImagePath, notification.ImagePath, sizeof(notifyMsg.ImagePath));

        //
        // 默认决策: 放行 (端点是启发式检测, 误报风险高于勒索, 保守放行,
        // 用户弹窗可明确选择终止; 驱动 60 秒无决策自动放行兜底)
        //
        UINT32 decision = XGS_EP_DECISION_ALLOW;

        if (hMainPipe == NULL)
        {
            printf("[AVEndpoint] No AVMain connected, defaulting to allow\n");
        }
        else if (!SendPipeMessage(hMainPipe, AvPipeMsgEndPointNotify,
                                  &notifyMsg, sizeof(notifyMsg)))
        {
            printf("[AVEndpoint] Send notify to AVMain failed, defaulting to allow\n");
        }
        else
        {
            printf("[AVEndpoint] Notification forwarded to AVMain, waiting decision...\n");

            UINT32 userDecision = WaitForPipeRawDecision(
                AvPipeMsgEndPointDecision,
                notification.NotificationId,
                AV_NOTIFICATION_TIMEOUT_MS);

            if (userDecision != 0)
            {
                decision = userDecision;
            }
            else
            {
                printf("[AVEndpoint] Decision timeout, defaulting to allow\n");
            }
        }

        //
        // 发送决策给 EndPoint 驱动
        //
        XGS_EP_DECISION decisionMsg;
        ZeroMemory(&decisionMsg, sizeof(decisionMsg));
        decisionMsg.NotificationId = notification.NotificationId;
        decisionMsg.Decision = decision;

        if (!DeviceIoControl(
                hEndpoint,
                IOCTL_XGS_EP_SEND_DECISION,
                &decisionMsg, sizeof(decisionMsg),
                NULL, 0,
                &bytesReturned, NULL))
        {
            printf("[AVEndpoint] SEND_DECISION failed (error: %lu)\n", GetLastError());
        }
        else
        {
            const wchar_t* decisionDesc =
                (decision == XGS_EP_DECISION_KILL) ? L"KILL" : L"ALLOW";
            printf("[AVEndpoint] Decision %ls sent to driver\n", decisionDesc);

            //
            // 用户选择终止时, 拉取完整行为链并生成威胁报告
            // 报告路径: C:\ProgramData\XIGUASecurity\Reports\
            // 文件名: <PID>_<报告ID>_<进程名>_<时间>.log
            //
            if (decision == XGS_EP_DECISION_KILL)
            {
                GenerateThreatReport(hEndpoint, &notification);
            }
        }
    }

    return 0;
}

//=============================================================================
// RunDiagnostics - 诊断模式
//
// 连接驱动后循环打印进程通知诊断信息, 用于定位拦截不生效问题
//=============================================================================
VOID
RunDiagnostics(VOID)
{
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    UCHAR sessionId[AV_SESSION_ID_SIZE];

    if (!EnsureDriverRunning())
    {
        printf("[Diag] Driver init failed\n");
        return;
    }

    if (!ConnectToDriver(&hDriver, sessionId))
    {
        printf("[Diag] Driver connection failed\n");
        return;
    }

    printf("[Diag] Polling driver diagnostics every 2 seconds...\n");
    printf("[Diag] Launch a program now, then watch LastPath below\n");
    printf("[Diag] Press Ctrl+C to stop\n");

    while (TRUE)
    {
        AV_DEBUG_INFO info;
        DWORD bytesReturned;

        ZeroMemory(&info, sizeof(info));
        if (DeviceIoControl(hDriver, IOCTL_AV_GET_DEBUG_INFO, NULL, 0,
                            &info, sizeof(info), &bytesReturned, NULL))
        {
            printf("[Diag] Triggers=%llu ProtectedHits=%llu Block=%llu | LastProtected=%s | %ls\n",
                   info.CallbackTriggers,
                   info.ProtectedHits,
                   info.BlockAttempts,
                   info.LastWasProtected ? "YES" : "no",
                   info.LastImagePath);
        }
        else
        {
            printf("[Diag] IOCTL_AV_GET_DEBUG_INFO failed (error: %lu)\n", GetLastError());
        }

        Sleep(2000);
    }
}

//=============================================================================
// 运行服务主逻辑
//=============================================================================
VOID
RunService(VOID)
{
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    UCHAR sessionId[AV_SESSION_ID_SIZE];
    HANDLE hMonitorThread = NULL;

    InitializeCriticalSection(&g_MainPipeLock);
    InitializeCriticalSection(&g_DecisionLock);
    ZeroMemory(g_PendingDecisions, sizeof(g_PendingDecisions));

    //
    // 首先启动自保护驱动 (必须在其他驱动和服务之前)
    // 然后立即注册自身 + 其他受保护进程的 PID
    // 注意: 必须在驱动加载后再注册, 否则系统进程初始化 Agent 时会被拦截
    //
    if (!EnsureSelfProtectDriverRunning())
    {
        printf("[AVSystem] Self protection driver init failed, continuing without self protection\n");
    }
    else
    {
        //
        // 注册受保护 PID (Agent 自身 + 当前运行的 AVMain/msedgewebview2)
        // 句柄保持打开, Agent 退出时驱动自动解除保护
        //
        RegisterProtectedPids();
    }

    // 自动安装并启动驱动
    if (!EnsureDriverRunning())
    {
        printf("[AVSystem] Driver init failed, service exiting\n");
        return;
    }

    // 连接驱动并鉴权
    if (!ConnectToDriver(&hDriver, sessionId))
    {
        printf("[AVSystem] Driver connection failed, service exiting\n");
        return;
    }

    //
    // XGS 勒索防护驱动 — 已禁用 (临时关闭, 修复误报后取消注释即可恢复)
    // 取消下方注释并删除 "DISABLED" 行即可恢复勒索防护
    //
    // DISABLED: EnsureXgsDriverRunning / ConnectToXgsDriver
    HANDLE hXgs = INVALID_HANDLE_VALUE;
    printf("[AVSystem] XGS ransomware protection DISABLED (skipped driver init)\n");
#if 0
    if (!EnsureXgsDriverRunning())
    {
        printf("[AVSystem] XGS driver init failed, continuing without ransomware protection\n");
    }
    else if (!ConnectToXgsDriver(&hXgs))
    {
        printf("[AVSystem] XGS driver connection failed, continuing without ransomware protection\n");
        hXgs = INVALID_HANDLE_VALUE;
    }
#endif

    //
    // 自动安装并启动 EndPoint 端点防护驱动
    //
    HANDLE hEndpoint = INVALID_HANDLE_VALUE;
    if (!EnsureEndpointDriverRunning())
    {
        printf("[AVSystem] EndPoint driver init failed, continuing without endpoint protection\n");
    }
    else if (!ConnectToEndpointDriver(&hEndpoint))
    {
        printf("[AVSystem] EndPoint driver connection failed, continuing without endpoint protection\n");
        hEndpoint = INVALID_HANDLE_VALUE;
    }

    //
    // 启动管道决策分发线程 (唯一管道读取者, 路由进程/注册表决策)
    //
    HANDLE hDecisionThread = CreateThread(
        NULL, 0,
        PipeDecisionReaderThread,
        NULL,
        0, NULL
    );

    if (hDecisionThread == NULL)
    {
        printf("[AVSystem] Start decision reader thread failed (error: %lu)\n", GetLastError());
    }
    else
    {
        CloseHandle(hDecisionThread);
    }

    // 启动进程保护监控线程
    hMonitorThread = CreateThread(
        NULL, 0,
        ProcessMonitorThread,
        &hDriver,
        0, NULL
    );

    if (hMonitorThread == NULL)
    {
        printf("[AVSystem] Start process monitor thread failed (error: %lu)\n", GetLastError());
    }
    else
    {
        printf("[AVSystem] Process monitor thread started\n");
    }

    //
    // 启动注册表保护监控线程
    //
    HANDLE hRegMonitorThread = CreateThread(
        NULL, 0,
        RegistryMonitorThread,
        &hDriver,
        0, NULL
    );

    if (hRegMonitorThread == NULL)
    {
        printf("[AVSystem] Start registry monitor thread failed (error: %lu)\n", GetLastError());
    }
    else
    {
        printf("[AVSystem] Registry monitor thread started\n");
    }

    //
    // 启动远程线程注入监控线程
    //
    HANDLE hInjectMonitorThread = CreateThread(
        NULL, 0,
        InjectionMonitorThread,
        &hDriver,
        0, NULL
    );

    if (hInjectMonitorThread == NULL)
    {
        printf("[AVSystem] Start injection monitor thread failed (error: %lu)\n", GetLastError());
    }
    else
    {
        printf("[AVSystem] Injection monitor thread started\n");
    }

    //
    // 启动勒索防护监控线程 (需 XGS 驱动连接成功)
    //
    HANDLE hRansomMonitorThread = NULL;
    if (hXgs != INVALID_HANDLE_VALUE)
    {
        RANSOM_MONITOR_PARAMS ransomParams;
        ransomParams.hXgs = hXgs;

        hRansomMonitorThread = CreateThread(
            NULL, 0,
            RansomMonitorThread,
            &ransomParams,
            0, NULL
        );

        if (hRansomMonitorThread == NULL)
        {
            printf("[AVSystem] Start ransom monitor thread failed (error: %lu)\n", GetLastError());
        }
        else
        {
            printf("[AVSystem] Ransom monitor thread started\n");
            CloseHandle(hRansomMonitorThread);
        }
    }

    //
    // 启动 EndPoint 端点防护监控线程 (需 EndPoint 驱动连接成功)
    //
    HANDLE hEndpointMonitorThread = NULL;
    if (hEndpoint != INVALID_HANDLE_VALUE)
    {
        ENDPOINT_MONITOR_PARAMS endpointParams;
        endpointParams.hEndpoint = hEndpoint;

        hEndpointMonitorThread = CreateThread(
            NULL, 0,
            EndPointMonitorThread,
            &endpointParams,
            0, NULL
        );

        if (hEndpointMonitorThread == NULL)
        {
            printf("[AVSystem] Start endpoint monitor thread failed (error: %lu)\n", GetLastError());
        }
        else
        {
            printf("[AVSystem] Endpoint monitor thread started\n");
            CloseHandle(hEndpointMonitorThread);
        }
    }

    //
    // 启动驱动心跳线程
    // 决策等待期间监控线程不发 IOCTL, 驱动 5 秒超时会误判客户端离线
    // 并静默放行新进程; 心跳线程每 2 秒刷新驱动端活跃时间戳
    //
    AV_HEARTBEAT_THREAD_PARAMS hbParams;
    hbParams.hDriver = hDriver;
    CopyMemory(hbParams.SessionId, sessionId, AV_SESSION_ID_SIZE);

    HANDLE hHeartbeatThread = CreateThread(
        NULL, 0,
        DriverHeartbeatThread,
        &hbParams,
        0, NULL
    );

    if (hHeartbeatThread == NULL)
    {
        printf("[AVSystem] Start heartbeat thread failed (error: %lu)\n", GetLastError());
    }
    else
    {
        CloseHandle(hHeartbeatThread);
    }

    // 启动管道服务器 (阻塞, 直到服务停止)
    RunPipeServer(hDriver, sessionId);

    //
    // 清理: 关闭所有驱动句柄和线程
    // (监控线程会被 OS 在进程退出时终止, 这里只关闭已持有的句柄)
    //
    if (hMonitorThread)
    {
        CloseHandle(hMonitorThread);
    }

    if (hRegMonitorThread)
    {
        CloseHandle(hRegMonitorThread);
    }

    if (hInjectMonitorThread)
    {
        CloseHandle(hInjectMonitorThread);
    }

    if (hEndpoint != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hEndpoint);
    }

    if (hXgs != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hXgs);
    }

    if (hDriver != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDriver);
    }

    DeleteCriticalSection(&g_MainPipeLock);
    DeleteCriticalSection(&g_DecisionLock);

    printf("[AVSystem] Service exiting (drivers stay loaded)\n");
}

//=============================================================================
// 主函数
//
// 无参数: 自动安装驱动 → 启动 → 提供服务 (开发/测试模式)
// 带参数: 见 help
//=============================================================================
int
wmain(
    _In_ int argc,
    _In_reads_(argc) LPWSTR* argv
)
{
    //
    // SubSystem=Windows 下默认无控制台窗口。
    // 命令行带参数时 (如 -install/-diag) 附加到父进程控制台, 方便看到输出。
    // 无参数直接运行 (服务模式/双击启动) 不创建控制台, 完全静默。
    //
    BOOL hasParentConsole = FALSE;
    if (argc > 1)
    {
        if (AttachConsole(ATTACH_PARENT_PROCESS))
        {
            hasParentConsole = TRUE;
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
        }
    }

    // 带参数时按命令处理
    if (argc > 1)
    {
        if (_wcsicmp(argv[1], L"-install") == 0)
        {
            // 安装系统服务
            if (InstallService())
            {
                wprintf(L"AVSystem service install succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"AVSystem service install failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-uninstall") == 0)
        {
            // 卸载系统服务
            if (UninstallService())
            {
                wprintf(L"AVSystem service uninstall succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"AVSystem service uninstall failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-installdriver") == 0)
        {
            // 安装驱动
            if (InstallDriver())
            {
                wprintf(L"Driver install succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"Driver install failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-uninstalldriver") == 0)
        {
            // 卸载驱动
            if (UninstallDriver())
            {
                wprintf(L"Driver uninstall succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"Driver uninstall failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-installdriverxgs") == 0)
        {
            // 安装 XGS 勒索防护驱动
            if (InstallXgsDriver())
            {
                wprintf(L"XGS driver install succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"XGS driver install failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-uninstalldriverxgs") == 0)
        {
            // 卸载 XGS 勒索防护驱动
            if (UninstallXgsDriver())
            {
                wprintf(L"XGS driver uninstall succeeded\n");
                return 0;
            }
            else
            {
                wprintf(L"XGS driver uninstall failed\n");
                return 1;
            }
        }
        else if (_wcsicmp(argv[1], L"-run") == 0 ||
                 _wcsicmp(argv[1], L"/run") == 0)
        {
            // 控制台模式运行（和默认无参数行为一致）
            wprintf(L"AVSystem started (console mode)\n");
            wprintf(L"===========================\n\n");

            RunService();

            wprintf(L"\nAVSystem exited, press any key to close...\n");
            if (argc == 2) _getwch();
            return 0;
        }
        else if (_wcsicmp(argv[1], L"-diag") == 0 ||
                 _wcsicmp(argv[1], L"/diag") == 0)
        {
            // 诊断模式: 打印进程通知诊断信息
            wprintf(L"AVSystem started (diagnostics mode)\n");
            wprintf(L"===========================\n\n");

            RunDiagnostics();
            return 0;
        }
        else
        {
            wprintf(L"Usage:\n");
            wprintf(L"  AVSystem.exe                     Run directly (auto install/start driver)\n");
            wprintf(L"  AVSystem.exe -run                Same as no arguments\n");
            wprintf(L"  AVSystem.exe -install            Install system service\n");
            wprintf(L"  AVSystem.exe -uninstall          Uninstall system service\n");
            wprintf(L"  AVSystem.exe -installdriver      Install driver only\n");
            wprintf(L"  AVSystem.exe -uninstalldriver    Uninstall driver\n");
            wprintf(L"  AVSystem.exe -installdriverxgs   Install XGS ransomware driver\n");
            wprintf(L"  AVSystem.exe -uninstalldriverxgs Uninstall XGS ransomware driver\n");
            return 1;
        }
    }

    //
    // 无参数: 默认行为 — 直接运行，自动处理驱动安装/启动
    //
    wprintf(L"========================================\n");
    wprintf(L"  AVDriver System Service\n");
    wprintf(L"========================================\n\n");

    RunService();

    wprintf(L"\nProgram exited, press any key to close...\n");
    _getwch();
    return 0;
}
