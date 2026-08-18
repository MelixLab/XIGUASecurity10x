//=============================================================================
// AVSystem.h - SYSTEM 权限转发程序头文件
//
// 担任驱动层和主程序之间的安全转发层
//=============================================================================

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include "../AVCommon/AVProtocol.h"

#pragma comment(lib, "bcrypt.lib")

//=============================================================================
// 常量定义
//=============================================================================

#define AV_DRIVER_RETRY_MAX      10
#define AV_DRIVER_RETRY_DELAY    1000    // 毫秒
#define AV_PIPE_INSTANCES        5       // 最大并发管道客户端数
#define AV_PIPE_TIMEOUT          5000    // 管道操作超时 (毫秒)
#define AV_PIPE_BUFFER_SIZE      AV_MAX_PIPE_MSG_SIZE

//=============================================================================
// 函数声明
//=============================================================================

//
// HMAC-SHA256 计算
//
BOOL
CalculateHmac(
    _In_reads_bytes_(dataSize) const UCHAR* data,
    _In_ DWORD dataSize,
    _In_reads_bytes_(keySize) const UCHAR* key,
    _In_ DWORD keySize,
    _Out_writes_bytes_(AV_HASH_SIZE) UCHAR* hmacOutput
);

//
// 连接驱动并鉴权
//
BOOL
ConnectToDriver(
    _Out_ HANDLE* phDriver,
    _Out_writes_bytes_(AV_SESSION_ID_SIZE) UCHAR* sessionId
);

//
// 发送管道消息
//
BOOL
SendPipeMessage(
    _In_ HANDLE hPipe,
    _In_ AV_PIPE_MSG_TYPE type,
    _In_reads_bytes_opt_(dataSize) const void* data,
    _In_ DWORD dataSize
);

//
// 接收管道消息
//
BOOL
RecvPipeMessage(
    _In_ HANDLE hPipe,
    _Out_writes_bytes_(bufferSize) BYTE* buffer,
    _In_ DWORD bufferSize,
    _Outptr_ AV_PIPE_MSG_HEADER** ppHeader,
    _Outptr_result_bytebuffer_(*pDataSize) BYTE** ppData,
    _Out_ DWORD* pDataSize
);

//
// 处理管道消息 (转发到驱动或从驱动转发回来)
//
BOOL
HandlePipeMessage(
    _In_ HANDLE hPipe,
    _In_ HANDLE hDriver,
    _In_reads_bytes_(AV_SESSION_ID_SIZE) const UCHAR* sessionId,
    _In_ AV_PIPE_MSG_HEADER* pHeader,
    _In_reads_bytes_(pHeader->DataSize) BYTE* pData
);

//
// 管道客户端鉴权
//
BOOL
AuthenticatePipeClient(
    _In_ HANDLE hPipe,
    _Out_writes_bytes_(AV_SESSION_ID_SIZE) UCHAR* clientSessionId
);

//
// 管道客户端处理线程
//
DWORD
WINAPI
PipeClientThread(
    _In_ LPVOID lpParam
);

//
// 运行管道服务器
//
BOOL
RunPipeServer(
    _In_ HANDLE hDriver,
    _In_reads_bytes_(AV_SESSION_ID_SIZE) const UCHAR* sessionId
);

//
// 服务管理
//
BOOL
InstallService(
    VOID
);

BOOL
UninstallService(
    VOID
);

//
// 服务入口
//
VOID
WINAPI
ServiceMain(
    _In_ DWORD argc,
    _In_reads_(argc) LPWSTR* argv
);

//
// 服务控制处理器
//
DWORD
WINAPI
ServiceCtrlHandler(
    _In_ DWORD control,
    _In_ DWORD eventType,
    _In_ LPVOID eventData,
    _In_ LPVOID context
);

//
// 运行服务主逻辑
//
VOID
RunService(
    VOID
);

//
// 计算 XOR 校验和
//
UINT32
CalculateChecksum(
    _In_reads_bytes_(dataSize) const BYTE* data,
    _In_ DWORD dataSize
);

//
// 进程保护监控线程
//
DWORD
WINAPI
ProcessMonitorThread(
    _In_ LPVOID lpParam
);

//
// 注册表保护监控线程
//
DWORD
WINAPI
RegistryMonitorThread(
    _In_ LPVOID lpParam
);

//
// 远程线程注入监控线程
//
DWORD
WINAPI
InjectionMonitorThread(
    _In_ LPVOID lpParam
);

//
// 勒索防护监控线程
//
DWORD
WINAPI
RansomMonitorThread(
    _In_ LPVOID lpParam
);

//
// EndPoint 端点防护监控线程
//
DWORD
WINAPI
EndPointMonitorThread(
    _In_ LPVOID lpParam
);

//
// EndPoint 端点防护驱动管理
//
BOOL
InstallEndpointDriver(
    VOID
);

BOOL
UninstallEndpointDriver(
    VOID
);

BOOL
StartEndpointDriver(
    VOID
);

BOOL
EnsureEndpointDriverRunning(
    VOID
);

//
// 连接 XGSEndPoint 驱动并鉴权
//
BOOL
ConnectToEndpointDriver(
    _Out_ HANDLE* phDriver
);

//
// 连接 XGS 勒索防护驱动并鉴权
//
BOOL
ConnectToXgsDriver(
    _Out_ HANDLE* phDriver
);

//
// XGS 勒索防护驱动管理
//
BOOL
InstallXgsDriver(
    VOID
);

BOOL
UninstallXgsDriver(
    VOID
);

BOOL
StartXgsDriver(
    VOID
);

BOOL
EnsureXgsDriverRunning(
    VOID
);

//
// 驱动管理
//
BOOL
DriverExists(
    VOID
);

BOOL
InstallDriver(
    VOID
);

BOOL
UninstallDriver(
    VOID
);

BOOL
StartDriver(
    VOID
);

BOOL
EnsureDriverRunning(
    VOID
);

//
// SelfProtect 自保护驱动管理
//
BOOL
InstallSelfProtectDriver(
    VOID
);

BOOL
UninstallSelfProtectDriver(
    VOID
);

BOOL
StartSelfProtectDriver(
    VOID
);

BOOL
EnsureSelfProtectDriverRunning(
    VOID
);

//
// 向自保护驱动注册受保护 PID
// 收集自身 + AVMain + msedgewebview2 的 PID 并移交给驱动
// 保持设备句柄打开, 句柄关闭时驱动自动解除保护
//
BOOL
RegisterProtectedPids(
    VOID
);
