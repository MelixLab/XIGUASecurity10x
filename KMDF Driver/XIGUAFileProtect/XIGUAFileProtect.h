//=============================================================================
// XGSRansomFilter.h - XIGUASecurity 勒索防护过滤驱动
//
// 文件系统微过滤器 (Minifilter):
//   - IRP_MJ_CREATE: 文档文件以写/删能力打开时, 首次备份原始内容
//   - IRP_MJ_WRITE: 计数 + 记录 + 阻断判定
//   - IRP_MJ_SET_INFORMATION: 删除前备份 (若尚未备份) + 计数 + 阻断
//   - 时间窗内文档改动次数 >= 阈值 -> 疑似勒索 -> 阻断 + 通知用户态
//
// 同时注册传统控制设备 (非 KMDF), 供 AVSystem 通过 IOCTL 获取通知/下发决策
//=============================================================================

#pragma once

#include <fltkernel.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

#include "../AVCommon/AVProtocol.h"

//=============================================================================
// 池标签
//=============================================================================
#define XGS_POOL_TAG    'sgX_'   // "XGS_"

//=============================================================================
// 内部常量
//=============================================================================
#define XGS_OP_MODIFY   1        // 修改
#define XGS_OP_DELETE   2        // 删除
#define XGS_DOC_EVENTS_MAX   512 // 检测时间窗事件环大小
#define XGS_BACKEDUP_MAX     512 // 已备份文件哈希环大小
#define XGS_CHUNK_SIZE       4096
#define XGS_MAX_PATH_BUFFER  560  // 带盘符前缀的路径缓冲

//=============================================================================
// 驱动入口 / 卸载
//=============================================================================

DRIVER_INITIALIZE DriverEntry;

VOID
XgsUnload(
    _In_ PDRIVER_OBJECT DriverObject
    );

//
// 创建备份目录 (DriverEntry 中调用)
//
NTSTATUS
XgsCreateBackupDirectory(
    VOID
    );
