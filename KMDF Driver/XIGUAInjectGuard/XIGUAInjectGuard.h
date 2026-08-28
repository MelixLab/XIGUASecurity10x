//=============================================================================
// XIGUAInjectGuard.h - 进程注入防御驱动头文件
//
// 纯 WDM 驱动，通过 ObRegisterCallbacks 监控跨进程句柄操作，
// 检测进程注入链并通知用户态 (三层架构: 驱动←IOCTL→Agent←管道→主程序)
//=============================================================================

#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include "../AVCommon/AVProtocol.h"

//
// 内核函数手动声明 (WDK 头文件可能未导出)
//
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
);

//=============================================================================
// 容量常量
//=============================================================================

#define IG_MAX_PENDING_EVENTS   16
#define IG_MAX_WHITELIST        32
#define IG_MAX_NAME_LEN          260
#define IG_MAX_CHAIN_STEPS       8
#define IG_MAX_CHAIN_TRACKERS   64

//=============================================================================
// 进程/线程访问权限掩码 (内核态自定义)
//=============================================================================

#define IG_PROCESS_VM_READ        0x0010
#define IG_PROCESS_VM_WRITE       0x0020
#define IG_PROCESS_VM_OPERATION   0x0008
#define IG_PROCESS_CREATE_THREAD  0x0002
#define IG_PROCESS_TERMINATE      0x0001
#define IG_PROCESS_SUSPEND_RESUME 0x0800

#define IG_THREAD_SUSPEND_RESUME  0x0002
#define IG_THREAD_GET_CONTEXT     0x0008
#define IG_THREAD_SET_CONTEXT     0x0010

//=============================================================================
// 注入链跟踪
//=============================================================================

typedef struct _IG_CHAIN_TRACKER {
    ULONG       SourcePid;
    ULONG       TargetPid;
    ULONG       Steps[IG_MAX_CHAIN_STEPS];
    ULONG       StepCount;
    LARGE_INTEGER   LastActivityTime;
} IG_CHAIN_TRACKER, *PIG_CHAIN_TRACKER;

#define IG_CHAIN_TIMEOUT_SEC    30

//=============================================================================
// 设备扩展结构
//=============================================================================

typedef struct _IG_DEVICE_CONTEXT {
    // 保护开关
    LONG        ProtectionActive;

    // 事件队列 (环形缓冲区)
    KSPIN_LOCK  EventQueueLock;
    IG_NOTIFICATION  Events[IG_MAX_PENDING_EVENTS];
    ULONG       EventQueueHead;
    ULONG       EventQueueTail;
    ULONG       EventQueueCount;

    // 决策等待表 (序列号 -> 决策结果)
    KSPIN_LOCK  DecisionLock;
    LONG        Decisions[IG_MAX_PENDING_EVENTS];

    // 白名单
    KSPIN_LOCK  WhitelistLock;
    ULONG       WhitelistCount;
    WCHAR       Whitelist[IG_MAX_WHITELIST][IG_MAX_NAME_LEN];

    // 计数器
    LONG        TotalEvents;
    LONG        TotalBlocked;

    // 序列号
    LONG        SequenceCounter;

} IG_DEVICE_CONTEXT, *PIG_DEVICE_CONTEXT;
