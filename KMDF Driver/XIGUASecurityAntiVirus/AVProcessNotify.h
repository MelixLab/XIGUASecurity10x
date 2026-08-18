//=============================================================================
// AVProcessNotify.h - 进程通知回调声明
//
// 拦截系统目录中的进程启动，通过 IOCTL 通知用户态做决策
// IRQL: 大部分函数在 PASSIVE_LEVEL 运行
//=============================================================================

#pragma once

#include "XIGUASecurityAntiVirus.h"

//
// 受保护系统目录列表 (全局)
//
extern AV_PROTECTED_DIR g_ProtectedDirs[AV_MAX_PROTECTED_DIRS];
extern UINT32           g_ProtectedDirCount;

//
// AvProcessNotifyInitialize - 初始化进程通知模块
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessNotifyInitialize(
    VOID
    );

//
// AvProcessNotifyUninitialize - 卸载进程通知模块
// IRQL: PASSIVE_LEVEL
//
VOID
AvProcessNotifyUninitialize(
    VOID
    );

//
// AvProcessIsPathProtected - 检查路径是否在受保护目录中
// IRQL: PASSIVE_LEVEL (在回调中运行于 APC_LEVEL, 仅访问非分页内存)
//
// 注意: 使用 UNICODE_STRING.Length 判断长度, 不依赖 null 终止符
//       (内核 UNICODE_STRING 不保证 Buffer 以 null 终止)
//
BOOLEAN
AvProcessIsPathProtected(
    _In_ const UNICODE_STRING* ImageFileName
    );

//
// AvProcessAddToAllowList - 添加路径到白名单
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessAddToAllowList(
    _In_ const WCHAR* ImagePath
    );

//
// AvProcessAddToDenyList - 添加路径到黑名单
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessAddToDenyList(
    _In_ const WCHAR* ImagePath
    );

//
// AvProcessIsInAllowList - 检查路径是否在白名单中
// IRQL: APC_LEVEL 或 PASSIVE_LEVEL
//
BOOLEAN
AvProcessIsInAllowList(
    _In_ const UNICODE_STRING* ImageFileName
    );

//
// AvProcessIsInDenyList - 检查路径是否在黑名单中
// IRQL: APC_LEVEL 或 PASSIVE_LEVEL
//
BOOLEAN
AvProcessIsInDenyList(
    _In_ const UNICODE_STRING* ImageFileName
    );

//
// AvProcessGetPendingNotification - 获取待处理通知
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessGetPendingNotification(
    _Out_ AV_PROCESS_NOTIFICATION* Notification
    );

//
// AvProcessGetStats - 获取进程通知统计 (回调触发/拦截次数)
// IRQL: PASSIVE_LEVEL
//
VOID
AvProcessGetStats(
    _Out_opt_ UINT64* CallbackTriggers,
    _Out_opt_ UINT64* BlockAttempts
    );

//
// AvProcessGetDebugInfo - 获取进程通知诊断信息
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessGetDebugInfo(
    _Out_ AV_DEBUG_INFO* Info
    );

//
// AvProcessMarkClientActive - 标记客户端活跃 (每次 IOCTL 分发时调用)
// IRQL: PASSIVE_LEVEL
//
VOID
AvProcessMarkClientActive(VOID);

//
// AvProcessIsClientActive - 客户端是否活跃 (基于心跳超时)
// IRQL: APC_LEVEL (回调中) 或 PASSIVE_LEVEL
//
BOOLEAN
AvProcessIsClientActive(VOID);

//
// AvProcessHandleDecision - 处理用户态决策
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvProcessHandleDecision(
    _In_ const AV_PROCESS_DECISION* Decision
    );
