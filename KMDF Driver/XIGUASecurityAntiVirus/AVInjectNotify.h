//=============================================================================
// AVInjectNotify.h - 远程线程注入防护声明
//
// 基于 PsSetCreateThreadNotifyRoutine (微软文档 ntddk.h 标准回调) 检测
// 远程线程注入:
//   线程创建回调在"创建线程的进程"上下文中执行,
//   回调参数 ProcessId 为线程所属进程 (目标), PsGetCurrentProcessId()
//   为发起进程 (来源), 两者不同即跨进程线程创建 (CreateRemoteThread)。
//
// 防误报设计:
//   - 排除系统进程来源 (镜像位于 \Windows\ 下 / System / services.exe)
//   - 排除新进程初始线程 (父进程为新创建子进程创建首个线程属正常)
//   - 其余跨进程注入冻结被注入线程 -> 通知用户态弹窗 -> 允许=恢复,
//     拒绝=终止被注入线程
//=============================================================================

#pragma once

#include "XIGUASecurityAntiVirus.h"

//
// AvInjectNotifyInitialize - 初始化注入防护模块
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvInjectNotifyInitialize(
    VOID
    );

//
// AvInjectNotifyUninitialize - 卸载注入防护模块
// IRQL: PASSIVE_LEVEL
//
VOID
AvInjectNotifyUninitialize(
    VOID
    );

//
// AvInjectGetPendingNotification - 获取待处理注入通知
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvInjectGetPendingNotification(
    _Out_ AV_INJECTION_NOTIFICATION* Notification
    );

//
// AvInjectHandleDecision - 处理用户态注入决策
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvInjectHandleDecision(
    _In_ const AV_INJECTION_DECISION* Decision
    );

//
// AvInjectGetDebugInfo - 获取注入防护诊断信息
// IRQL: PASSIVE_LEVEL
//
VOID
AvInjectGetDebugInfo(
    _Inout_ AV_DEBUG_INFO* Info
    );
