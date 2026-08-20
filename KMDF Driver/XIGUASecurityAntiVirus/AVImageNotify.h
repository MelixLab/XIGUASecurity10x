//=============================================================================
// AVImageNotify.h - 镜像加载监控模块声明
//
// 使用 PsSetLoadImageNotifyRoutine 监控 DLL/驱动加载:
//   1. 白加黑检测: 进程加载同目录下非系统 DLL (银狐核心投递手法)
//   2. 系统进程注入: explorer/svchost 等加载非 \Windows\ 目录的 DLL
//   3. 可疑路径: 从 Temp/Downloads/Desktop 加载 DLL
//   4. 反射式注入: 无文件背书的内存镜像
//
// 注意: PsSetLoadImageNotifyRoutine 是通知回调, 无法阻止加载。
// 检测到异常后通知用户态弹窗, 用户选择"拒绝"时终止加载者进程。
//
// IRQL: 回调运行在 PASSIVE_LEVEL
//=============================================================================

#pragma once

#include "XIGUASecurityAntiVirus.h"

//
// AvImageNotifyInitialize - 初始化镜像加载监控模块
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvImageNotifyInitialize(
    VOID
    );

//
// AvImageNotifyUninitialize - 卸载镜像加载监控模块
// IRQL: PASSIVE_LEVEL
//
VOID
AvImageNotifyUninitialize(
    VOID
    );

//
// AvImageGetPendingNotification - 获取待处理镜像加载通知
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvImageGetPendingNotification(
    _Out_ AV_IMAGE_NOTIFICATION* Notification
    );

//
// AvImageHandleDecision - 处理用户态镜像加载决策
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvImageHandleDecision(
    _In_ const AV_IMAGE_DECISION* Decision
    );
