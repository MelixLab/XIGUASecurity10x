//=============================================================================
// AVMain.h - 杀毒软件主程序 Mock 头文件
//
// 功能：连接到 AVSystem 命名管道，鉴权后发送模拟扫描请求
//=============================================================================

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include "..\AVCommon\AVProtocol.h"

#pragma comment(lib, "bcrypt.lib")

//=============================================================================
// 函数声明
//=============================================================================

//
// 管道客户端模块
//
HANDLE ConnectToPipe();

//
// 鉴权模块
//
BOOL Authenticate(HANDLE hPipe, UCHAR sessionId[AV_SESSION_ID_SIZE]);

//
// 管道消息收发辅助函数
//
BOOL SendPipeMessage(HANDLE hPipe, AV_PIPE_MSG_TYPE type, const void* data, DWORD dataSize);
BOOL RecvPipeMessage(HANDLE hPipe, BYTE* buffer, DWORD bufferSize,
                     AV_PIPE_MSG_HEADER** ppHeader, void** ppData);

//
// HMAC 计算辅助函数
//
BOOL CalculateHmac(const UCHAR* data, DWORD dataSize,
                   const UCHAR* key, DWORD keySize,
                   UCHAR* hmacOutput);

//
// 模拟业务模块
//
BOOL SendScanRequest(HANDLE hPipe, const UCHAR sessionId[AV_SESSION_ID_SIZE],
                     const wchar_t* filePath);
BOOL QueryStatus(HANDLE hPipe);
BOOL SendHeartbeat(HANDLE hPipe, const UCHAR sessionId[AV_SESSION_ID_SIZE]);

//
// 工具函数
//
UINT32 XorChecksum(const void* data, DWORD size);
void PrintError(const wchar_t* context);
