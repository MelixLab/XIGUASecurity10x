//=============================================================================
// XGSEndPoint.h - XIGUASecurity EndPoint 端点防护驱动
//
// 传统型 Minifilter + 系统回调混合架构 (非 KMDF):
//   - minifilter 预操作回调: 文件写入 / 文件删除采集
//   - PsSetCreateProcessNotifyRoutineEx: 进程创建/退出 (父进程链)
//   - PsSetCreateThreadNotifyRoutine: 线程创建 (远程线程注入信号)
//   - ObRegisterCallbacks: 可写可执行映射 (RWX) / 跨进程控制
//   - CmRegisterCallbackEx: 注册表写入 (自启动项检测)
//
// IOA 评分规则引擎: 行为事件按进程聚合评分, 60 秒窗口内评分 >= 阈值
// -> 挂起威胁进程 -> 通知用户态决策 (放行恢复 / 终止进程)
//=============================================================================

#pragma once

#include <fltkernel.h>
#include <wdmsec.h>
#include <ntstrsafe.h>

#include "../AVCommon/AVProtocol.h"

//=============================================================================
// 池标签
//=============================================================================
#define EP_POOL_TAG    'pGX_'   // "XGp"

//=============================================================================
// IOA 规则 ID / 权重 / 阈值
//
// IOA (Indicator of Attack) 检测原则:
//   - 同一规则只计一次分 (去重), 防止单行为重复累积触发
//   - 单一行为不触发, 必须多指标组合才达阈值
//   - 信任来源 (System / Windows 系统目录进程) 豁免, 不评分
//   - 注入类信号需配合内存操纵/RWX映射才视为恶意
//
// 典型组合 (阈值 100):
//   RWX(50) + 远程线程(50)         = 100  注入执行 (经典恶意)
//   RWX(50) + 跨进程内存(40)       = 90   接近阈值, 配合模块加载(30) = 120
//   远程线程(50) + 跨进程内存(40)  = 90   配合模块加载(30) = 120
//   自启动(30) + RWX(50) + 模块(30)= 110  持久化 + 注入
//
// 单行为最大权重 50, 不足阈值 100, 确保单行为不误报
//=============================================================================
#define EP_RULE_REMOTE_THREAD   1   // 远程线程注入
#define EP_RULE_RWX_MAPPING     2   // 可写可执行映射
#define EP_RULE_REG_RUNKEY      3   // 注册表自启动项写入
#define EP_RULE_PROC_CONTROL    4   // 跨进程终止/挂起
#define EP_RULE_MODULE_LOAD     5   // 加载非系统目录模块
#define EP_RULE_CROSS_MEM       6   // 跨进程内存读写
#define EP_RULE_BOOT_MODIFY     7   // 引导区修改 (BCD/MBR/GPT) - 满分 200

#define EP_SCORE_REMOTE_THREAD  50  // 远程线程注入 (高权重, 需组合)
#define EP_SCORE_RWX_MAPPING    50  // RWX 映射 (高权重, 需组合)
#define EP_SCORE_REG_RUNKEY     30  // 自启动项写入 (持久化信号)
#define EP_SCORE_PROC_CONTROL   25  // 跨进程控制
#define EP_SCORE_MODULE_LOAD    30  // 非系统模块加载 (辅助信号)
#define EP_SCORE_CROSS_MEM      40  // 跨进程内存读写 (注入前置)
#define EP_SCORE_PROC_CREATE    0   // 子进程创建不评分 (过于普遍)
#define EP_SCORE_BOOT_MODIFY     200 // 引导区修改 (满分, 单独触发, 仅在用户拒绝时计入)

#define EP_TRIGGER_SCORE        100     // 触发挂起的评分阈值 (组合行为才可达)
#define EP_SUSPEND_THREADS_MAX  64      // 单进程挂起线程句柄上限
#define EP_SUSPECT_RULES_MAX    6       // 嫌疑进程记录的命中规则数

//=============================================================================
// 驱动入口 / 卸载
//=============================================================================

DRIVER_INITIALIZE DriverEntry;

VOID
EpUnload(
    _In_ PDRIVER_OBJECT DriverObject
    );

//=============================================================================
// 回调声明 (供 FltRegisterFilter / ObRegisterCallbacks 使用)
//=============================================================================

DRIVER_DISPATCH EpDispatchCreateClose;
DRIVER_DISPATCH EpDispatchDeviceControl;

FLT_PREOP_CALLBACK_STATUS
EpPreWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
EpPreSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

// EOF
