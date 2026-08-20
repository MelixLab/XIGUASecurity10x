//=============================================================================
// AVRegNotify.h - 注册表通知回调声明
//
// 使用 CmRegisterCallbackEx 拦截敏感注册表操作 (Run 键 / Services 等),
// 通过 IOCTL 通知用户态弹窗决策。
// 回调内同步等待用户决策, 30 秒超时默认拒绝 (CM 回调阻塞会拖住
// 其他进程的注册表操作, 必须设置超时避免系统永久卡死)。
//=============================================================================

#pragma once

#include "XIGUASecurityAntiVirus.h"

//
// AvRegNotifyInitialize - 初始化注册表通知模块
// IRQL: PASSIVE_LEVEL
//
// RegistryPath: 驱动服务注册表键路径 (DriverEntry 传入),
//               用于持久化"始终允许/始终拒绝"规则, 驱动重启后恢复
//
NTSTATUS
AvRegNotifyInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

//
// AvRegNotifyUninitialize - 卸载注册表通知模块
// IRQL: PASSIVE_LEVEL
//
VOID
AvRegNotifyUninitialize(
    VOID
    );

//
// AvRegGetDebugInfo - 获取注册表保护诊断信息
// IRQL: PASSIVE_LEVEL
//
VOID
AvRegGetDebugInfo(
    _Inout_ AV_DEBUG_INFO* Info
    );

//
// AvRegGetPendingNotification - 获取待处理注册表通知
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvRegGetPendingNotification(
    _Out_ AV_REGISTRY_NOTIFICATION* Notification
    );

//
// AvRegHandleDecision - 处理用户态注册表决策
// IRQL: PASSIVE_LEVEL
//
NTSTATUS
AvRegHandleDecision(
    _In_ const AV_REGISTRY_DECISION* Decision
    );

//
// AvRegSetTrustedClientPid - 记录信任客户端 (AVSystem) 进程 ID
// 信任进程自身的注册表操作直接放行, 避免自锁死
// IRQL: PASSIVE_LEVEL
//
VOID
AvRegSetTrustedClientPid(
    _In_ UINT32 ProcessId
    );

//
// AvRegIsTrustedProcess - 当前进程是否为可信系统进程
// (信任客户端 / System / 关键系统进程名精确匹配: winlogon/svchost/csrss/
//  services/lsass/smss/wininit/dwm)
// 注: reg.exe/regedit.exe/cmd.exe/powershell.exe/explorer.exe 等用户工具
//     不在信任名单, 其注册表写操作会正常弹窗由用户决策。
// IRQL: PASSIVE_LEVEL (回调中亦可)
//
BOOLEAN
AvRegIsTrustedProcess(
    VOID
    );
