//=============================================================================
// AVMain.cpp - 杀毒软件主程序 Mock
//
// 功能：连接到 AVSystem 命名管道，鉴权后发送模拟扫描请求
// 编译：cl AVMain.cpp /Fe:AVMain.exe /link bcrypt.lib
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS

#include "AVMain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <commctrl.h>
#include <strsafe.h>
#include <psapi.h>
#include <conio.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
//
// 启用 ComCtl32 v6 以使用 TaskDialogIndirect (4 按钮弹窗)
//
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

//=============================================================================
// 工具函数：XOR 校验和计算
//=============================================================================
UINT32 XorChecksum(const void* data, DWORD size)
{
    UINT32 checksum = 0;
    const BYTE* bytes = (const BYTE*)data;
    for (DWORD i = 0; i < size; i++)
    {
        checksum ^= bytes[i];
    }
    return checksum;
}

//=============================================================================
// 工具函数：打印错误信息
//=============================================================================
void PrintError(const wchar_t* context)
{
    DWORD err = GetLastError();
    wprintf(L"[ERROR] %s failed, error code: %u (0x%08X)\n", context, err, err);
}

//=============================================================================
// 管道客户端模块 - 连接到命名管道
//=============================================================================
HANDLE ConnectToPipe()
{
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    wprintf(L"[INFO] Connecting to pipe %s ...\n", AV_PIPE_FULL_NAME);

    // 等待管道可用
    if (!WaitNamedPipeW(AV_PIPE_FULL_NAME, NMPWAIT_WAIT_FOREVER))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SUCCESS && err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND)
        {
            PrintError(L"WaitNamedPipe");
            return INVALID_HANDLE_VALUE;
        }
        // 如果是 ERROR_FILE_NOT_FOUND，管道可能还没创建，尝试直接 CreateFile
    }

    // 连接管道
    hPipe = CreateFileW(
        AV_PIPE_FULL_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,                      // 无共享
        NULL,                   // 默认安全属性
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        PrintError(L"CreateFile connect to pipe");
        return INVALID_HANDLE_VALUE;
    }

    // 设置管道读取模式为消息模式
    DWORD pipeMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if (!SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL))
    {
        PrintError(L"SetNamedPipeHandleState");
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    wprintf(L"[OK] Pipe connected!\n");
    return hPipe;
}

//=============================================================================
// 管道消息发送辅助函数
//=============================================================================
BOOL SendPipeMessage(HANDLE hPipe, AV_PIPE_MSG_TYPE type,
                     const void* data, DWORD dataSize)
{
    // 分配发送缓冲区: 头部 + 数据
    DWORD totalSize = sizeof(AV_PIPE_MSG_HEADER) + dataSize;
    BYTE* buffer = (BYTE*)malloc(totalSize);
    if (!buffer)
    {
        wprintf(L"[ERROR] Memory allocation failed\n");
        return FALSE;
    }

    // 填充消息头
    AV_PIPE_MSG_HEADER* header = (AV_PIPE_MSG_HEADER*)buffer;
    header->Magic = AV_PIPE_MAGIC;
    header->MessageType = (UINT32)type;
    header->DataSize = dataSize;

    // 复制数据部分
    if (data && dataSize > 0)
    {
        memcpy(buffer + sizeof(AV_PIPE_MSG_HEADER), data, dataSize);
        header->Checksum = XorChecksum(data, dataSize);
    }
    else
    {
        header->Checksum = 0;
    }

    // 发送
    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hPipe, buffer, totalSize, &bytesWritten, NULL);
    if (!result || bytesWritten != totalSize)
    {
        if (!result)
        {
            PrintError(L"WriteFile send message");
        }
        else
        {
            wprintf(L"[ERROR] Incomplete data sent: expected %u bytes, actual %u bytes\n",
                    totalSize, bytesWritten);
        }
        free(buffer);
        return FALSE;
    }

    free(buffer);
    return TRUE;
}

//=============================================================================
// 管道消息接收辅助函数
//=============================================================================
BOOL RecvPipeMessage(HANDLE hPipe, BYTE* buffer, DWORD bufferSize,
                     AV_PIPE_MSG_HEADER** ppHeader, void** ppData)
{
    // 读取消息
    DWORD bytesRead = 0;
    BOOL result = ReadFile(hPipe, buffer, bufferSize, &bytesRead, NULL);

    if (!result)
    {
        PrintError(L"ReadFile receive message");
        return FALSE;
    }

    if (bytesRead < sizeof(AV_PIPE_MSG_HEADER))
    {
        wprintf(L"[ERROR] Received message too short: %u bytes\n", bytesRead);
        return FALSE;
    }

    // 解析头部
    AV_PIPE_MSG_HEADER* header = (AV_PIPE_MSG_HEADER*)buffer;

    // 验证 Magic
    if (header->Magic != AV_PIPE_MAGIC)
    {
        wprintf(L"[ERROR] Invalid message magic: 0x%08X\n", header->Magic);
        return FALSE;
    }

    // 验证数据大小
    if (sizeof(AV_PIPE_MSG_HEADER) + header->DataSize > bytesRead)
    {
        wprintf(L"[ERROR] Incomplete message data: header claims %u bytes, received %u bytes\n",
                header->DataSize, bytesRead - sizeof(AV_PIPE_MSG_HEADER));
        return FALSE;
    }

    // 验证 XOR 校验和
    if (header->DataSize > 0)
    {
        void* data = buffer + sizeof(AV_PIPE_MSG_HEADER);
        UINT32 calcChecksum = XorChecksum(data, header->DataSize);
        if (calcChecksum != header->Checksum)
        {
            wprintf(L"[ERROR] Checksum mismatch: calculated 0x%08X, message 0x%08X\n",
                    calcChecksum, header->Checksum);
            return FALSE;
        }
    }

    if (ppHeader)
        *ppHeader = header;
    if (ppData)
        *ppData = (header->DataSize > 0) ? (buffer + sizeof(AV_PIPE_MSG_HEADER)) : NULL;

    return TRUE;
}

//=============================================================================
// HMAC-SHA256 计算辅助函数
//=============================================================================
BOOL CalculateHmac(const UCHAR* data, DWORD dataSize,
                   const UCHAR* key, DWORD keySize,
                   UCHAR* hmacOutput)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    DWORD hashObjectSize = 0;
    DWORD resultSize = 0;
    UCHAR* hashObject = NULL;
    BOOL success = FALSE;

    // 打开 HMAC-SHA256 算法提供者
    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG
    );
    if (!BCRYPT_SUCCESS(status))
    {
        wprintf(L"[ERROR] BCryptOpenAlgorithmProvider failed, status: 0x%08X\n", status);
        goto cleanup;
    }

    // 获取 hash 对象大小
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&hashObjectSize,
        sizeof(DWORD),
        &resultSize,
        0
    );
    if (!BCRYPT_SUCCESS(status))
    {
        wprintf(L"[ERROR] BCryptGetProperty(ObjectLength) failed, status: 0x%08X\n", status);
        goto cleanup;
    }

    // 分配 hash 对象缓冲区
    hashObject = (UCHAR*)malloc(hashObjectSize);
    if (!hashObject)
    {
        wprintf(L"[ERROR] Memory allocation failed\n");
        goto cleanup;
    }

    // 创建 HMAC 哈希句柄
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        hashObject,
        hashObjectSize,
        (PUCHAR)key,
        keySize,
        0
    );
    if (!BCRYPT_SUCCESS(status))
    {
        wprintf(L"[ERROR] BCryptCreateHash failed, status: 0x%08X\n", status);
        goto cleanup;
    }

    // 输入数据
    status = BCryptHashData(
        hHash,
        (PUCHAR)data,
        dataSize,
        0
    );
    if (!BCRYPT_SUCCESS(status))
    {
        wprintf(L"[ERROR] BCryptHashData failed, status: 0x%08X\n", status);
        goto cleanup;
    }

    // 获取哈希结果
    status = BCryptFinishHash(
        hHash,
        hmacOutput,
        AV_HASH_SIZE,
        0
    );
    if (!BCRYPT_SUCCESS(status))
    {
        wprintf(L"[ERROR] BCryptFinishHash failed, status: 0x%08X\n", status);
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hashObject)
        free(hashObject);

    return success;
}

//=============================================================================
// 鉴权模块
//=============================================================================
BOOL Authenticate(HANDLE hPipe, UCHAR sessionId[AV_SESSION_ID_SIZE])
{
    BYTE recvBuffer[AV_MAX_PIPE_MSG_SIZE];

    wprintf(L"\n[AUTH] Starting authentication...\n");

    // Step 1: 发送鉴权初始化请求
    // -------------------------------------------
    AV_PIPE_AUTH_INIT authInit;
    authInit.ProtocolVersion = 1;

    if (!SendPipeMessage(hPipe, AvPipeMsgAuthInit, &authInit, sizeof(authInit)))
    {
        wprintf(L"[AUTH] Send AuthInit failed\n");
        return FALSE;
    }
    wprintf(L"[AUTH] Sent AuthInit request (protocol version: %u)\n", authInit.ProtocolVersion);

    // Step 2: 接收 Challenge
    // -------------------------------------------
    AV_PIPE_MSG_HEADER* header = NULL;
    AV_PIPE_AUTH_CHALLENGE_DATA* challengeData = NULL;

    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, (void**)&challengeData))
    {
        wprintf(L"[AUTH] Receive Challenge failed\n");
        return FALSE;
    }

    if (header->MessageType != AvPipeMsgAuthChallenge)
    {
        wprintf(L"[AUTH] Expected AuthChallenge(0x%04X), received 0x%04X\n",
                AvPipeMsgAuthChallenge, header->MessageType);
        return FALSE;
    }

    wprintf(L"[AUTH] Received Challenge (SequenceId: %llu)\n", challengeData->SequenceId);

    // Step 3: 计算 HMAC
    //    HMAC = HMAC-SHA256(challenge || sequenceId(小端), shared_key)
    // -------------------------------------------
    // 构造 HMAC 输入数据: challenge(32 bytes) + sequenceId(8 bytes, 小端)
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    memcpy(hmacInput, challengeData->Challenge, AV_CHALLENGE_SIZE);
    memcpy(hmacInput + AV_CHALLENGE_SIZE, &challengeData->SequenceId, sizeof(UINT64));

    UCHAR hmacResult[AV_HASH_SIZE];
    if (!CalculateHmac(hmacInput, sizeof(hmacInput),
                       AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                       hmacResult))
    {
        wprintf(L"[AUTH] HMAC calculation failed\n");
        return FALSE;
    }
    wprintf(L"[AUTH] HMAC calculated\n");

    // Step 4: 发送鉴权验证
    // -------------------------------------------
    AV_PIPE_AUTH_VERIFY_DATA authVerify;
    authVerify.SequenceId = challengeData->SequenceId;
    memcpy(authVerify.Challenge, challengeData->Challenge, AV_CHALLENGE_SIZE);
    memcpy(authVerify.Hmac, hmacResult, AV_HASH_SIZE);

    if (!SendPipeMessage(hPipe, AvPipeMsgAuthVerify, &authVerify, sizeof(authVerify)))
    {
        wprintf(L"[AUTH] Send AuthVerify failed\n");
        return FALSE;
    }
    wprintf(L"[AUTH] Sent auth verification\n");

    // Step 5: 接收鉴权结果
    // -------------------------------------------
    AV_PIPE_AUTH_RESULT_DATA* authResult = NULL;

    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, (void**)&authResult))
    {
        wprintf(L"[AUTH] Receive auth result failed\n");
        return FALSE;
    }

    if (header->MessageType != AvPipeMsgAuthResult)
    {
        wprintf(L"[AUTH] Expected AuthResult(0x%04X), received 0x%04X\n",
                AvPipeMsgAuthResult, header->MessageType);
        return FALSE;
    }

    if (!authResult->Success)
    {
        wprintf(L"[AUTH] Authentication failed! Error code: %u\n", authResult->ErrorCode);
        return FALSE;
    }

    // 保存 SessionId
    memcpy(sessionId, authResult->SessionId, AV_SESSION_ID_SIZE);

    wprintf(L"[AUTH] Authentication successful! SessionId: ");
    for (int i = 0; i < AV_SESSION_ID_SIZE; i++)
    {
        wprintf(L"%02X", sessionId[i]);
    }
    wprintf(L"\n");

    return TRUE;
}

//=============================================================================
// 模拟业务模块 - 发送扫描请求
//=============================================================================
BOOL SendScanRequest(HANDLE hPipe, const UCHAR sessionId[AV_SESSION_ID_SIZE],
                     const wchar_t* filePath)
{
    BYTE recvBuffer[AV_MAX_PIPE_MSG_SIZE];

    // 计算文件路径长度 (含 null 终止符)
    DWORD filePathLen = (DWORD)(wcslen(filePath) + 1); // 字符数, 含 null
    DWORD filePathBytes = filePathLen * sizeof(wchar_t);

    // 构造变长扫描请求
    // totalSize = 固定部分 + 文件路径字节 - 1个 WCHAR (因为 ANYSIZE_ARRAY = 1)
    DWORD msgDataSize = sizeof(AV_PIPE_SCAN_REQUEST_DATA) - sizeof(wchar_t) + filePathBytes;
    BYTE* requestBuffer = (BYTE*)malloc(msgDataSize);
    if (!requestBuffer)
    {
        wprintf(L"[ERROR] Memory allocation failed\n");
        return FALSE;
    }

    AV_PIPE_SCAN_REQUEST_DATA* scanReq = (AV_PIPE_SCAN_REQUEST_DATA*)requestBuffer;
    memcpy(scanReq->SessionId, sessionId, AV_SESSION_ID_SIZE);
    scanReq->RequestId = (UINT64)GetTickCount64(); // 使用当前 Tick 作为请求 ID
    scanReq->FilePathLength = filePathBytes;
    memcpy(scanReq->FilePath, filePath, filePathBytes);

    // 发送扫描请求
    if (!SendPipeMessage(hPipe, AvPipeMsgScanRequest, requestBuffer, msgDataSize))
    {
        wprintf(L"[SCAN] Send scan request failed\n");
        free(requestBuffer);
        return FALSE;
    }
    wprintf(L"[SCAN] Sent scan request (RequestId: %llu, path: %ls)\n",
            scanReq->RequestId, filePath);

    free(requestBuffer);

    // 接收扫描结果
    AV_PIPE_MSG_HEADER* header = NULL;
    AV_PIPE_SCAN_RESPONSE_DATA* scanResp = NULL;

    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, (void**)&scanResp))
    {
        wprintf(L"[SCAN] Receive scan result failed\n");
        return FALSE;
    }

    if (header->MessageType != AvPipeMsgScanResponse)
    {
        wprintf(L"[SCAN] Expected ScanResponse(0x%04X), received 0x%04X\n",
                AvPipeMsgScanResponse, header->MessageType);
        return FALSE;
    }

    // 显示扫描结果
    wprintf(L"\n========== SCAN RESULT ==========\n");
    wprintf(L"  Request ID:    %llu\n", scanResp->RequestId);
    wprintf(L"  Status:       %s\n", scanResp->Success ? L"OK" : L"FAILED");
    wprintf(L"  Threat Level:   %u\n", scanResp->ThreatLevel);
    wprintf(L"  Threat Name:   %ls\n", scanResp->ThreatName);
    wprintf(L"==============================\n");

    return TRUE;
}

//=============================================================================
// 模拟业务模块 - 查询驱动状态
//=============================================================================
BOOL QueryStatus(HANDLE hPipe)
{
    BYTE recvBuffer[AV_MAX_PIPE_MSG_SIZE];

    // 发送状态查询请求
    if (!SendPipeMessage(hPipe, AvPipeMsgGetStatus, NULL, 0))
    {
        wprintf(L"[STATUS] Send status query failed\n");
        return FALSE;
    }
    wprintf(L"[STATUS] Sent status query\n");

    // 接收状态响应
    AV_PIPE_MSG_HEADER* header = NULL;
    AV_DRIVER_STATUS* statusData = NULL;

    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, (void**)&statusData))
    {
        wprintf(L"[STATUS] Receive status response failed\n");
        return FALSE;
    }

    if (header->MessageType != AvPipeMsgStatusResponse)
    {
        wprintf(L"[STATUS] Expected StatusResponse(0x%04X), received 0x%04X\n",
                AvPipeMsgStatusResponse, header->MessageType);
        return FALSE;
    }

    // 显示状态
    wprintf(L"\n========== DRIVER STATUS ==========\n");
    wprintf(L"  Driver Version:       %u\n", statusData->Version);
    wprintf(L"  Active Sessions:     %u\n", statusData->ActiveSessions);
    wprintf(L"  Total Scans:     %llu\n", statusData->TotalScans);
    wprintf(L"  Uptime (ms):   %llu\n", statusData->UptimeMs);
    wprintf(L"==============================\n");

    return TRUE;
}

//=============================================================================
// 模拟业务模块 - 发送心跳
//=============================================================================
BOOL SendHeartbeat(HANDLE hPipe, const UCHAR sessionId[AV_SESSION_ID_SIZE])
{
    BYTE recvBuffer[AV_MAX_PIPE_MSG_SIZE];

    AV_HEARTBEAT_REQUEST hbReq;
    memcpy(hbReq.SessionId, sessionId, AV_SESSION_ID_SIZE);
    hbReq.Timestamp = GetTickCount64();

    // 计算 HMAC: HMAC-SHA256(SessionId || Timestamp, SessionKey)
    // 注意: 实际应用中应该使用会话密钥, 这里简化使用共享密钥
    UCHAR hmacInput[AV_SESSION_ID_SIZE + sizeof(UINT64)];
    memcpy(hmacInput, sessionId, AV_SESSION_ID_SIZE);
    memcpy(hmacInput + AV_SESSION_ID_SIZE, &hbReq.Timestamp, sizeof(UINT64));

    if (!CalculateHmac(hmacInput, sizeof(hmacInput),
                       AV_SHARED_KEY, AV_SHARED_KEY_SIZE,
                       hbReq.Hmac))
    {
        wprintf(L"[HEARTBEAT] HMAC calculation failed\n");
        return FALSE;
    }

    // 发送心跳请求
    if (!SendPipeMessage(hPipe, AvPipeMsgHeartbeat, &hbReq, sizeof(hbReq)))
    {
        wprintf(L"[HEARTBEAT] Send heartbeat failed\n");
        return FALSE;
    }
    wprintf(L"[HEARTBEAT] Sent heartbeat (Timestamp: %llu)\n", hbReq.Timestamp);

    // 接收心跳响应
    AV_PIPE_MSG_HEADER* header = NULL;
    AV_HEARTBEAT_RESPONSE* hbResp = NULL;

    if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, (void**)&hbResp))
    {
        wprintf(L"[HEARTBEAT] Receive heartbeat response failed\n");
        return FALSE;
    }

    if (header->MessageType != AvPipeMsgHeartbeatResponse)
    {
        wprintf(L"[HEARTBEAT] Expected HeartbeatResponse(0x%04X), received 0x%04X\n",
                AvPipeMsgHeartbeatResponse, header->MessageType);
        return FALSE;
    }

    wprintf(L"[HEARTBEAT] Heartbeat Response: Status=0x%08X, ServerTimestamp=%llu\n",
            hbResp->Status, hbResp->ServerTimestamp);

    return TRUE;
}

//=============================================================================
// 显示 SessionId 的辅助函数
//=============================================================================
static void PrintSessionId(const UCHAR sessionId[AV_SESSION_ID_SIZE])
{
    for (int i = 0; i < AV_SESSION_ID_SIZE; i++)
    {
        wprintf(L"%02X", sessionId[i]);
    }
}

//=============================================================================
// 交互式菜单
//=============================================================================
static void ShowMenu()
{
    wprintf(L"\n");
    wprintf(L"=== AVDriver Main Program Mock ===\n");
    wprintf(L"Authenticated successfully\n");
    wprintf(L"\n");
    wprintf(L"1. Scan file (enter path)\n");
    wprintf(L"2. Query driver status\n");
    wprintf(L"3. Send heartbeat\n");
    wprintf(L"q. Quit\n");
    wprintf(L"\nChoice: ");
}

//=============================================================================
// EnableDpiAwareness - 启用高 DPI 感知
//
// 默认程序未声明 DPI 感知时, Windows 会对进程做 DPI 虚拟化
// (按位图拉伸), 高分屏下界面发虚。此处优先启用每显示器 V2 感知
// (Win10 1703+), 回退到系统级 DPI 感知。
// 必须在创建任何窗口之前调用。
//=============================================================================
static void EnableDpiAwareness(void)
{
    typedef BOOL(WINAPI* pfnSetProcessDpiAwarenessContext)(HANDLE value);
    pfnSetProcessDpiAwarenessContext pfn = (pfnSetProcessDpiAwarenessContext)
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDpiAwarenessContext");

    if (pfn != NULL)
    {
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        if (pfn((HANDLE)(LONG_PTR)-4))
        {
            return;
        }
    }

    SetProcessDPIAware();
}

//=============================================================================
// GetProcessImagePath - 按 PID 解析进程完整路径
//=============================================================================
static BOOL GetProcessImagePath(DWORD pid, wchar_t* out, DWORD outBytes)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == NULL)
    {
        StringCbPrintfW(out, outBytes, L"(PID %u, 无法访问)", pid);
        return FALSE;
    }

    DWORD len = (DWORD)(outBytes / sizeof(wchar_t));
    BOOL ok = QueryFullProcessImageNameW(h, 0, out, &len);
    CloseHandle(h);

    if (!ok)
    {
        StringCbPrintfW(out, outBytes, L"(PID %u, 名称不可用)", pid);
        return FALSE;
    }
    return TRUE;
}

//=============================================================================
// AnalyzeStartAddress - 分析线程起始地址是否在目标进程已加载模块内
//
// 这是"不误报"的核心判据:
//   正常注入 (CreateRemoteThread + LoadLibrary) 的起始地址必然指向
//   目标进程某个已加载模块内的导出函数;
//   恶意注入 (原始 shellcode / 手动映射) 指向未映射的私有内存。
//
// 返回: 0=无法判断, 1=在已加载模块内 (正常注入特征), 2=不在任何模块
//       (原始代码注入特征, 高危)
//=============================================================================
static int AnalyzeStartAddress(DWORD targetPid, UINT64 startAddr,
                               wchar_t* moduleName, DWORD moduleNameBytes)
{
    if (moduleName != NULL)
    {
        moduleName[0] = L'\0';
    }

    if (startAddr == 0)
    {
        return 0;
    }

    HANDLE hTarget = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                 FALSE, targetPid);
    if (hTarget == NULL)
    {
        return 0;
    }

    HMODULE mods[256];
    DWORD needed = 0;
    BOOL scanned = FALSE;
    int result = 0;

    if (EnumProcessModules(hTarget, mods, sizeof(mods), &needed))
    {
        DWORD count = min(needed / sizeof(HMODULE), 256);
        scanned = TRUE;

        for (DWORD i = 0; i < count; i++)
        {
            MODULEINFO mi;
            if (GetModuleInformation(hTarget, mods[i], &mi, sizeof(mi)))
            {
                UINT64 base = (UINT64)(ULONG_PTR)mi.lpBaseOfDll;
                UINT64 end = base + mi.SizeOfImage;

                if (startAddr >= base && startAddr < end)
                {
                    result = 1;
                    if (moduleName != NULL)
                    {
                        GetModuleFileNameExW(hTarget, mods[i], moduleName,
                                             moduleNameBytes / sizeof(wchar_t));
                    }
                    break;
                }
            }
        }
    }

    if (result == 0 && scanned)
    {
        // 模块扫描成功但起始地址不在任何模块内 -> 原始代码注入特征
        result = 2;
    }

    CloseHandle(hTarget);
    return result;
}

//=============================================================================
// main 函数
//=============================================================================
int wmain(int argc, wchar_t* argv[])
{
    UCHAR sessionId[AV_SESSION_ID_SIZE];
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    BOOL authenticated = FALSE;

    // 启用高 DPI 感知, 避免高分屏下界面模糊
    EnableDpiAwareness();

    wprintf(L"========================================\n");
    wprintf(L"  AVDriver Antivirus - Main Program Mock v1.0\n");
    wprintf(L"========================================\n");

    // 检查命令行参数
    if (argc >= 3 && _wcsicmp(argv[1], L"scan") == 0)
    {
        // 命令行模式: AVMain.exe scan "C:\path\to\file"
        hPipe = ConnectToPipe();
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[ERROR] Cannot connect to pipe, make sure AVSystem is running\n");
            return 1;
        }

        if (!Authenticate(hPipe, sessionId))
        {
            wprintf(L"[ERROR] Authentication failed\n");
            CloseHandle(hPipe);
            return 1;
        }

        wprintf(L"\n[CMD] Scan file: %ls\n", argv[2]);
        SendScanRequest(hPipe, sessionId, argv[2]);

        CloseHandle(hPipe);
        return 0;
    }

    // 连接管道
    wprintf(L"\nPress any key to connect to AVSystem...\n");
    system("pause>nul");

    hPipe = ConnectToPipe();
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        wprintf(L"\n[ERROR] Cannot connect to pipe, make sure AVSystem is running.\n");
        wprintf(L"Please start AVSystem first before running AVMain.\n");
        system("pause");
        return 1;
    }

    // 鉴权
    authenticated = Authenticate(hPipe, sessionId);
    if (!authenticated)
    {
        wprintf(L"\n[ERROR] Authentication failed, exiting.\n");
        CloseHandle(hPipe);
        system("pause");
        return 1;
    }

    //-------------------------------------------------------------------------
    // 消息循环: 接收 AVSystem 转发的进程拦截通知并弹窗决策
    //-------------------------------------------------------------------------
    wprintf(L"\n[MAIN] Entering message loop, waiting for process notifications...\n");
    wprintf(L"[MAIN] Press 'q' to shutdown AVSystem (driver stays loaded)\n");
    wprintf(L"[MAIN] Close this window to disconnect from AVSystem\n\n");

    BYTE recvBuffer[AV_MAX_PIPE_MSG_SIZE];
    BOOL running = TRUE;

    //
    // 键盘监听线程: 监听 'q' 键, 收到后发送 shutdown 请求并退出主循环
    // (主线程阻塞在 ReadFile 等待 AVSystem 通知, 无法直接响应键盘)
    //
    typedef struct _KEY_LISTEN_CTX {
        HANDLE hPipe;
        HANDLE hShutdownEvent;
    } KEY_LISTEN_CTX;

    HANDLE hShutdownEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hShutdownEvent != NULL)
    {
        KEY_LISTEN_CTX* ctx = (KEY_LISTEN_CTX*)malloc(sizeof(KEY_LISTEN_CTX));
        if (ctx)
        {
            ctx->hPipe = hPipe;
            ctx->hShutdownEvent = hShutdownEvent;

            HANDLE hKeyThread = CreateThread(NULL, 0, [](LPVOID param) -> DWORD {
                KEY_LISTEN_CTX* p = (KEY_LISTEN_CTX*)param;
                while (WaitForSingleObject(p->hShutdownEvent, 50) == WAIT_TIMEOUT)
                {
                    if (_kbhit())
                    {
                        int ch = _getch();
                        if (ch == 'q' || ch == 'Q')
                        {
                            wprintf(L"\n[MAIN] Sending shutdown request to AVSystem...\n");
                            SendPipeMessage(p->hPipe, AvPipeMsgShutdownRequest, NULL, 0);
                            SetEvent(p->hShutdownEvent);
                            break;
                        }
                    }
                }
                free(p);
                return 0;
            }, ctx, 0, NULL);

            if (hKeyThread)
            {
                CloseHandle(hKeyThread);
            }
            else
            {
                free(ctx);
            }
        }
    }

    while (running)
    {
        AV_PIPE_MSG_HEADER* header = NULL;
        void* pData = NULL;

        if (!RecvPipeMessage(hPipe, recvBuffer, sizeof(recvBuffer), &header, &pData))
        {
            wprintf(L"[MAIN] Connection to AVSystem closed\n");
            break;
        }

        switch (header->MessageType)
        {
        case AvPipeMsgProcessNotify:
        {
            AV_PIPE_PROCESS_NOTIFY_DATA* notify = (AV_PIPE_PROCESS_NOTIFY_DATA*)pData;
            if (notify == NULL)
            {
                break;
            }

            wprintf(L"[MAIN] Process blocked notification: PID=%u Path=%ls Reason=%u\n",
                    notify->ProcessId, notify->ImagePath, notify->BlockReason);

            // 4 按钮决策弹窗 (行为防护/目录保护不同标题与内容)
            wchar_t title[128];
            wchar_t message[2048];

            if (notify->BlockReason == AvBlockReasonBehaviorCmdline)
            {
                swprintf_s(title, 128,
                           L"AVDriver - 行为防护拦截");

                swprintf_s(message, 2048,
                    L"AVDriver 已拦截一个可疑行为!\n\n"
                    L"命中规则: %ls\n"
                    L"进程 ID: %u\n"
                    L"父进程 ID: %u\n"
                    L"程序路径: %ls\n"
                    L"命令行: %ls\n"
                    L"通知 ID: %llu\n\n"
                    L"请选择如何处理该程序:",
                    notify->RuleDescription[0] != L'\0' ? notify->RuleDescription : L"(未知规则)",
                    notify->ProcessId, notify->ParentProcessId,
                    notify->ImagePath, notify->CommandLine, notify->NotificationId);
            }
            else
            {
                swprintf_s(title, 128,
                           L"AVDriver - 进程拦截");

                swprintf_s(message, 2048,
                    L"AVDriver 已拦截一个程序启动!\n\n"
                    L"进程 ID: %u\n"
                    L"父进程 ID: %u\n"
                    L"程序路径: %ls\n"
                    L"命令行: %ls\n"
                    L"通知 ID: %llu\n\n"
                    L"请选择如何处理该程序:",
                    notify->ProcessId, notify->ParentProcessId,
                    notify->ImagePath, notify->CommandLine, notify->NotificationId);
            }

            TASKDIALOG_BUTTON taskButtons[] = {
                { 100, L"始终允许" },
                { 101, L"始终拒绝" },
                { 102, L"允许一次" },
                { 103, L"拒绝一次" },
            };

            TASKDIALOGCONFIG taskCfg = { 0 };
            taskCfg.cbSize = sizeof(taskCfg);
            taskCfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
            taskCfg.pButtons = taskButtons;
            taskCfg.cButtons = ARRAYSIZE(taskButtons);
            taskCfg.pszWindowTitle = title;
            taskCfg.pszMainIcon = TD_WARNING_ICON;
            taskCfg.pszMainInstruction = title;
            taskCfg.pszContent = message;

            int taskButton = 0;
            HRESULT tdResult = TaskDialogIndirect(&taskCfg, &taskButton, NULL, NULL);
            if (FAILED(tdResult))
            {
                wprintf(L"[MAIN] TaskDialogIndirect failed (HRESULT: 0x%08lX), defaulting to allow\n",
                        (unsigned long)tdResult);
            }

            AV_PIPE_PROCESS_DECISION_DATA decision;
            ZeroMemory(&decision, sizeof(decision));
            decision.NotificationId = notify->NotificationId;
            decision.Decision = AvDecisionAllowOnce;   // 默认: 关闭/取消 -> 放行
            StringCbCopyW(decision.ImagePath, sizeof(decision.ImagePath), notify->ImagePath);
            switch (taskButton)
            {
            case 100: decision.Decision = AvDecisionAllowAlways; break;
            case 101: decision.Decision = AvDecisionDenyAlways;  break;
            case 102: decision.Decision = AvDecisionAllowOnce;   break;
            case 103: decision.Decision = AvDecisionDenyOnce;    break;
            default:  decision.Decision = AvDecisionAllowOnce;   break; // 关闭 -> 放行
            }

            if (!SendPipeMessage(hPipe, AvPipeMsgProcessDecision,
                                 &decision, sizeof(decision)))
            {
                wprintf(L"[MAIN] Send decision failed\n");
            }
            else
            {
                wprintf(L"[MAIN] Decision sent to AVSystem\n");
            }
            break;
        }

        case AvPipeMsgRegNotify:
        {
            AV_PIPE_REG_NOTIFY_DATA* notify = (AV_PIPE_REG_NOTIFY_DATA*)pData;
            if (notify == NULL)
            {
                break;
            }

            wprintf(L"[MAIN] Registry blocked notification: PID=%u Key=%ls\n",
                    notify->ProcessId, notify->KeyPath);

            const wchar_t* opDesc = L"未知操作";
            switch (notify->OperationType)
            {
            case AvRegOpSetValueKey:    opDesc = L"写入值";    break;
            case AvRegOpDeleteValueKey: opDesc = L"删除值"; break;
            case AvRegOpDeleteKey:      opDesc = L"删除键";   break;
            case AvRegOpCreateKey:      opDesc = L"创建键";   break;
            }

            // 4 按钮决策弹窗
            wchar_t title[128];
            wchar_t message[2048];

            swprintf_s(title, 128,
                       L"AVDriver - 注册表防护拦截");

            swprintf_s(message, 2048,
                L"AVDriver 已拦截一次注册表修改!\n\n"
                L"操作类型: %ls\n"
                L"进程 ID: %u\n"
                L"注册表键: %ls\n"
                L"值名称: %ls\n"
                L"通知 ID: %llu\n\n"
                L"请选择如何处理该修改:",
                opDesc, notify->ProcessId, notify->KeyPath,
                (notify->ValueName[0] != L'\0') ? notify->ValueName : L"(默认)",
                notify->NotificationId);

            TASKDIALOG_BUTTON taskButtons[] = {
                { 100, L"始终允许" },
                { 101, L"始终拒绝" },
                { 102, L"允许一次" },
                { 103, L"拒绝一次" },
            };

            TASKDIALOGCONFIG taskCfg = { 0 };
            taskCfg.cbSize = sizeof(taskCfg);
            taskCfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
            taskCfg.pButtons = taskButtons;
            taskCfg.cButtons = ARRAYSIZE(taskButtons);
            taskCfg.pszWindowTitle = title;
            taskCfg.pszMainIcon = TD_WARNING_ICON;
            taskCfg.pszMainInstruction = title;
            taskCfg.pszContent = message;

            int taskButton = 0;
            HRESULT tdResult = TaskDialogIndirect(&taskCfg, &taskButton, NULL, NULL);
            if (FAILED(tdResult))
            {
                wprintf(L"[MAIN] TaskDialogIndirect failed (HRESULT: 0x%08lX), defaulting to allow\n",
                        (unsigned long)tdResult);
            }

            AV_PIPE_REG_DECISION_DATA decision;
            ZeroMemory(&decision, sizeof(decision));
            decision.NotificationId = notify->NotificationId;
            decision.Decision = AvDecisionAllowOnce;   // 默认: 关闭/取消 -> 放行
            StringCbCopyW(decision.KeyPath, sizeof(decision.KeyPath), notify->KeyPath);
            switch (taskButton)
            {
            case 100: decision.Decision = AvDecisionAllowAlways; break;
            case 101: decision.Decision = AvDecisionDenyAlways;  break;
            case 102: decision.Decision = AvDecisionAllowOnce;   break;
            case 103: decision.Decision = AvDecisionDenyOnce;    break;
            default:  decision.Decision = AvDecisionAllowOnce;   break; // 关闭 -> 放行
            }

            if (!SendPipeMessage(hPipe, AvPipeMsgRegDecision,
                                 &decision, sizeof(decision)))
            {
                wprintf(L"[MAIN] Send registry decision failed\n");
            }
            else
            {
                wprintf(L"[MAIN] Registry decision sent to AVSystem\n");
            }
            break;
        }

        case AvPipeMsgInjectionNotify:
        {
            AV_PIPE_INJECTION_NOTIFY_DATA* notify = (AV_PIPE_INJECTION_NOTIFY_DATA*)pData;
            if (notify == NULL)
            {
                break;
            }

            wprintf(L"[MAIN] Injection blocked notification: src=%u tgt=%u tid=%u start=0x%llX\n",
                    notify->SourceProcessId, notify->TargetProcessId,
                    notify->ThreadId, notify->StartAddress);

            wchar_t srcName[AV_MAX_PROCESS_PATH_LEN];
            wchar_t tgtName[AV_MAX_PROCESS_PATH_LEN];
            wchar_t modName[AV_MAX_PROCESS_PATH_LEN];
            GetProcessImagePath(notify->SourceProcessId, srcName, sizeof(srcName));
            GetProcessImagePath(notify->TargetProcessId, tgtName, sizeof(tgtName));

            int startType = AnalyzeStartAddress(notify->TargetProcessId,
                                                notify->StartAddress,
                                                modName, sizeof(modName));

            wchar_t startInfo[AV_MAX_PROCESS_PATH_LEN + 128];
            if (startType == 1)
            {
                swprintf_s(startInfo, ARRAYSIZE(startInfo),
                           L"线程起始地址: 0x%llX (模块: %ls)",
                           notify->StartAddress,
                           modName[0] != L'\0' ? modName : L"已加载模块");
            }
            else if (startType == 2)
            {
                swprintf_s(startInfo, ARRAYSIZE(startInfo),
                           L"线程起始地址: 0x%llX (警告: 不在任何已加载模块内 - 原始代码注入特征!)",
                           notify->StartAddress);
            }
            else
            {
                swprintf_s(startInfo, ARRAYSIZE(startInfo),
                           L"线程起始地址: 0x%llX",
                           notify->StartAddress);
            }

            wchar_t title[128];
            wchar_t message[3072];

            swprintf_s(title, 128,
                       L"AVDriver - 远程线程注入防护");

            swprintf_s(message, 3072,
                L"AVDriver 检测到一次跨进程线程创建!\n\n"
                L"发起进程: %ls (PID %u)\n"
                L"被注入进程: %ls (PID %u)\n"
                L"被注入线程 ID: %u\n"
                L"%ls\n\n"
                L"请选择如何处理该注入:",
                srcName, notify->SourceProcessId,
                tgtName, notify->TargetProcessId,
                notify->ThreadId, startInfo);

            TASKDIALOG_BUTTON taskButtons[] = {
                { 100, L"始终允许(该程序)" },
                { 101, L"始终拒绝" },
                { 102, L"允许一次" },
                { 103, L"拒绝一次" },
            };

            TASKDIALOGCONFIG taskCfg = { 0 };
            taskCfg.cbSize = sizeof(taskCfg);
            taskCfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
            taskCfg.pButtons = taskButtons;
            taskCfg.cButtons = ARRAYSIZE(taskButtons);
            taskCfg.pszWindowTitle = title;
            taskCfg.pszMainIcon = TD_WARNING_ICON;
            taskCfg.pszMainInstruction = title;
            taskCfg.pszContent = message;

            int taskButton = 0;
            HRESULT tdResult = TaskDialogIndirect(&taskCfg, &taskButton, NULL, NULL);
            if (FAILED(tdResult))
            {
                wprintf(L"[MAIN] TaskDialogIndirect failed (HRESULT: 0x%08lX), defaulting to allow\n",
                        (unsigned long)tdResult);
            }

            AV_PIPE_INJECTION_DECISION_DATA decision;
            ZeroMemory(&decision, sizeof(decision));
            decision.NotificationId = notify->NotificationId;
            decision.Decision = AvDecisionAllowOnce;   // 默认: 关闭/取消 -> 放行
            switch (taskButton)
            {
            case 100: decision.Decision = AvDecisionAllowAlways; break;
            case 101: decision.Decision = AvDecisionDenyAlways;  break;
            case 102: decision.Decision = AvDecisionAllowOnce;   break;
            case 103: decision.Decision = AvDecisionDenyOnce;    break;
            default:  decision.Decision = AvDecisionAllowOnce;   break; // 关闭 -> 放行
            }

            if (!SendPipeMessage(hPipe, AvPipeMsgInjectionDecision,
                                 &decision, sizeof(decision)))
            {
                wprintf(L"[MAIN] Send injection decision failed\n");
            }
            else
            {
                wprintf(L"[MAIN] Injection decision sent to AVSystem\n");
            }
            break;
        }

        case AvPipeMsgRansomNotify:
        {
            AV_PIPE_RANSOM_NOTIFY_DATA* notify = (AV_PIPE_RANSOM_NOTIFY_DATA*)pData;
            if (notify == NULL)
            {
                break;
            }

            wprintf(L"[MAIN] Ransomware suspected notification: %u files affected, ID=%llu\n",
                    notify->FileCount, notify->NotificationId);

            //
            // 构建文件列表消息 (最多显示 XGS_RANSOM_LIST_MAX 条)
            //
            wchar_t fileList[12000];
            fileList[0] = L'\0';

            UINT32 listCount = notify->FileCount;
            if (listCount > XGS_RANSOM_LIST_MAX)
            {
                listCount = XGS_RANSOM_LIST_MAX;
            }

            for (UINT32 i = 0; i < listCount; i++)
            {
                const wchar_t* opDesc =
                    (notify->Files[i].Operation == 2) ? L"删除" :
                    (notify->Files[i].Operation == 1) ? L"修改" : L"操作";

                if (notify->Files[i].OriginalPath[0] != L'\0')
                {
                    StringCchCatW(fileList, ARRAYSIZE(fileList), L"  ");
                    StringCchCatW(fileList, ARRAYSIZE(fileList), opDesc);
                    StringCchCatW(fileList, ARRAYSIZE(fileList), L": ");
                    StringCchCatW(fileList, ARRAYSIZE(fileList), notify->Files[i].OriginalPath);
                    StringCchCatW(fileList, ARRAYSIZE(fileList), L"\n");
                }
            }

            if (notify->FileCount > XGS_RANSOM_LIST_MAX)
            {
                wchar_t more[64];
                swprintf_s(more, ARRAYSIZE(more),
                           L"  ... 共 %u 个文件受影响\n", notify->FileCount);
                StringCchCatW(fileList, ARRAYSIZE(fileList), more);
            }

            //
            // 勒索防护弹窗 (3 按钮决策)
            //
            wchar_t title[128];
            wchar_t message[13000];

            swprintf_s(title, 128,
                       L"XIGUASecurity - 勒索软件防护");

            swprintf_s(message, ARRAYSIZE(message),
                L"检测到疑似勒索软件行为!\n\n"
                L"短时间内有 %u 个文档被修改或删除 (通知 ID: %llu)\n\n"
                L"以下文件已在修改前自动备份到:\n"
                L"C:\\Windows\\Temp\\XGS\\Backup\\\n\n"
                L"%ls\n"
                L"请选择处理方式:",
                notify->FileCount, notify->NotificationId, fileList);

            TASKDIALOG_BUTTON taskButtons[] = {
                { 200, L"放行继续" },
                { 201, L"保持阻断" },
                { 202, L"恢复文件" },
            };

            TASKDIALOGCONFIG taskCfg = { 0 };
            taskCfg.cbSize = sizeof(taskCfg);
            taskCfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
            taskCfg.pButtons = taskButtons;
            taskCfg.cButtons = ARRAYSIZE(taskButtons);
            taskCfg.pszWindowTitle = title;
            taskCfg.pszMainIcon = TD_WARNING_ICON;
            taskCfg.pszMainInstruction = title;
            taskCfg.pszContent = message;

            int taskButton = 0;
            HRESULT tdResult = TaskDialogIndirect(&taskCfg, &taskButton, NULL, NULL);
            if (FAILED(tdResult))
            {
                wprintf(L"[MAIN] TaskDialogIndirect failed (HRESULT: 0x%08lX), keeping block\n",
                        (unsigned long)tdResult);
            }

            AV_PIPE_RANSOM_DECISION_DATA decision;
            ZeroMemory(&decision, sizeof(decision));
            decision.NotificationId = notify->NotificationId;
            decision.Decision = XGS_DECISION_STAY_BLOCK;   // 默认: 关闭/取消 -> 保持阻断
            switch (taskButton)
            {
            case 200: decision.Decision = XGS_DECISION_ALLOW;      break;
            case 201: decision.Decision = XGS_DECISION_STAY_BLOCK; break;
            case 202: decision.Decision = XGS_DECISION_RESTORE;    break;
            default:  decision.Decision = XGS_DECISION_STAY_BLOCK; break;
            }

            const wchar_t* decisionDesc =
                (decision.Decision == XGS_DECISION_ALLOW)      ? L"ALLOW" :
                (decision.Decision == XGS_DECISION_RESTORE)    ? L"RESTORE" :
                                                                 L"STAY BLOCK";
            wprintf(L"[MAIN] Ransom decision: %ls\n", decisionDesc);

            if (!SendPipeMessage(hPipe, AvPipeMsgRansomDecision,
                                 &decision, sizeof(decision)))
            {
                wprintf(L"[MAIN] Send ransom decision failed\n");
            }
            else
            {
                wprintf(L"[MAIN] Ransom decision sent to AVSystem\n");
            }
            break;
        }

        case AvPipeMsgEndPointNotify:
        {
            AV_PIPE_EP_NOTIFY_DATA* notify = (AV_PIPE_EP_NOTIFY_DATA*)pData;
            if (notify == NULL)
            {
                break;
            }

            wprintf(L"[MAIN] EndPoint threat notification: PID=%u (score %u), ID=%llu\n",
                    notify->ProcessId, notify->TotalScore, notify->NotificationId);

            for (UINT32 i = 0; i < notify->RuleCount && i < XGS_EP_RULE_MAX; i++)
            {
                wprintf(L"[MAIN]   [rule %u] +%u %ls\n",
                        notify->Rules[i].RuleId,
                        notify->Rules[i].Score,
                        notify->Rules[i].Description);
            }

            //
            // 构建规则命中列表
            //
            wchar_t ruleList[1024];
            ruleList[0] = L'\0';
            for (UINT32 i = 0; i < notify->RuleCount && i < XGS_EP_RULE_MAX; i++)
            {
                if (notify->Rules[i].Description[0] != L'\0')
                {
                    wchar_t line[160];
                    swprintf_s(line, ARRAYSIZE(line),
                               L"  - %ls (+%u 分)\n",
                               notify->Rules[i].Description,
                               notify->Rules[i].Score);
                    StringCchCatW(ruleList, ARRAYSIZE(ruleList), line);
                }
            }
            if (ruleList[0] == L'\0')
            {
                StringCchCatW(ruleList, ARRAYSIZE(ruleList),
                              L"  - 综合行为评分超过阈值\n");
            }

            //
            // EndPoint 威胁弹窗 (允许/拦截 2 按钮决策)
            //
            wchar_t title[128];
            wchar_t message[2600];

            swprintf_s(title, 128,
                       L"XIGUASecurity EndPoint - 检测到威胁");

            swprintf_s(message, ARRAYSIZE(message),
                L"XIGUASecurity EndPoint 已侦测到威胁。\n\n"
                L"在指定时间内，您可以选择对此威胁的处理方式。\n"
                L"如果您不确定该程序是否安全，请单击“拦截该程序”。\n\n"
                L"程序: %ls\n"
                L"进程 ID: %u (父进程: %u)\n"
                L"威胁评分: %u\n\n"
                L"命中行为规则:\n%ls\n"
                L"进程已被挂起，等待您的决定。",
                notify->ImagePath[0] != L'\0' ? notify->ImagePath : L"未知",
                notify->ProcessId,
                notify->ParentProcessId,
                notify->TotalScore,
                ruleList);

            TASKDIALOG_BUTTON taskButtons[] = {
                { 300, L"拦截该程序" },
                { 301, L"允许该程序" },
            };

            TASKDIALOGCONFIG taskCfg = { 0 };
            taskCfg.cbSize = sizeof(taskCfg);
            taskCfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
            taskCfg.pButtons = taskButtons;
            taskCfg.cButtons = ARRAYSIZE(taskButtons);
            taskCfg.pszWindowTitle = title;
            taskCfg.pszMainIcon = TD_WARNING_ICON;
            taskCfg.pszMainInstruction = title;
            taskCfg.pszContent = message;

            int taskButton = 0;
            HRESULT tdResult = TaskDialogIndirect(&taskCfg, &taskButton, NULL, NULL);
            if (FAILED(tdResult))
            {
                wprintf(L"[MAIN] TaskDialogIndirect failed (HRESULT: 0x%08lX), defaulting to allow\n",
                        (unsigned long)tdResult);
            }

            AV_PIPE_EP_DECISION_DATA decision;
            ZeroMemory(&decision, sizeof(decision));
            decision.NotificationId = notify->NotificationId;
            decision.Decision = XGS_EP_DECISION_ALLOW;   // 默认: 关闭/取消 -> 放行
            switch (taskButton)
            {
            case 300: decision.Decision = XGS_EP_DECISION_KILL;  break;
            case 301: decision.Decision = XGS_EP_DECISION_ALLOW; break;
            default:  decision.Decision = XGS_EP_DECISION_ALLOW; break;
            }

            const wchar_t* decisionDesc =
                (decision.Decision == XGS_EP_DECISION_KILL) ? L"KILL PROCESS" : L"ALLOW";
            wprintf(L"[MAIN] EndPoint decision: %ls\n", decisionDesc);

            if (!SendPipeMessage(hPipe, AvPipeMsgEndPointDecision,
                                 &decision, sizeof(decision)))
            {
                wprintf(L"[MAIN] Send EndPoint decision failed\n");
            }
            else
            {
                wprintf(L"[MAIN] EndPoint decision sent to AVSystem\n");
            }
            break;
        }

        case AvPipeMsgError:
        {
            AV_PIPE_ERROR_DATA* err = (AV_PIPE_ERROR_DATA*)pData;
            if (err != NULL)
            {
                wprintf(L"[MAIN] Error from AVSystem: %u - %ls\n",
                        err->ErrorCode, err->ErrorMessage);
            }
            break;
        }

        default:
            wprintf(L"[MAIN] Unknown message type: 0x%04X\n", header->MessageType);
            break;
        }
    }

    // 清理
    if (hShutdownEvent != NULL)
    {
        SetEvent(hShutdownEvent);   // 通知键盘线程退出
        CloseHandle(hShutdownEvent);
    }

    if (hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe);
        wprintf(L"[INFO] Pipe connection closed\n");
    }

    wprintf(L"Program exited.\n");
    return 0;
}
