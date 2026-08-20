//=============================================================================
// XGSRansomFilter.h - XIGUASecurity 勒索防护过滤驱动
//
// 多维行为检测引擎:
//   - 进程级跟踪: 每个进程独立计分, 避免多进程合法操作累积误报
//   - 多维评分: 文件修改/删除/重命名/扩展名变更/熵分析/类型多样性/目录多样性
//   - 熵分析: 采样写入缓冲区, 检测高熵数据 (疑似加密)
//   - 文件重命名监控: 检测扩展名变更 (勒索软件强特征)
//   - 滑动窗口: 60 秒窗口内行为计数, 旧数据自动过期
//   - 修改前备份 + 用户态决策 (放行/阻断/恢复)
//   - 进程级阻断: 仅阻断触发进程, 不影响其他进程
//
// 同时注册传统控制设备, 供 AVSystem 通过 IOCTL 获取通知/下发决策
// IOCTL 采用 METHOD_BUFFERED, Challenge-Response + HMAC-SHA256 双向鉴权
//=============================================================================

#pragma once

#include <fltkernel.h>
#include <wdmsec.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

//
// PsGetProcessImageFileName 在 ntddk.h 中声明, 但 ntddk.h 与 fltkernel.h
// 同时包含会导致 PEPROCESS 重定义冲突, 这里手动声明
//
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

#include "../AVCommon/AVProtocol.h"

//=============================================================================
// 池标签
//=============================================================================
#define XGS_POOL_TAG    'sgX_'   // "XGS_"

//=============================================================================
// 内部常量
//=============================================================================

// 文件操作事件环 (已移除, 改用进程级跟踪)

// 备份相关
#define XGS_BACKEDUP_MAX     512 // 已备份文件哈希环大小
#define XGS_CHUNK_SIZE       4096
#define XGS_MAX_PATH_BUFFER  560  // 带盘符前缀的路径缓冲

// 进程跟踪表
#define XGS_PROCESS_TABLE_SIZE  64    // 最大跟踪进程数
#define XGS_PROCESS_EXPIRE_SEC  120   // 进程条目过期时间 (秒)

// 滑动窗口
#define XGS_WINDOW_100NS    (600000000ULL)   // 评分时间窗 (60 秒)
#define XGS_SHORT_WINDOW_100NS (300000000ULL) // 短窗口 (30 秒, 用于高频检测)
#define XGS_TIMEOUT_100NS   (600000000ULL)   // 无决策超时 (60 秒自动恢复)

// 多样性跟踪
#define XGS_DIVERSITY_SLOTS   16   // 目录/扩展名哈希槽数

// 操作时间戳环 (每进程)
#define XGS_OP_TIMES_MAX      64   // 操作时间戳环大小

// 熵分析
#define XGS_ENTROPY_SAMPLE_MIN  512   // 最小采样写入大小
#define XGS_ENTROPY_SAMPLE_MAX  4096  // 最大采样大小
#define XGS_ENTROPY_THRESHOLD   230   // 随机性阈值 (0-255, 越高越随机)
#define XGS_ENTROPY_CHECK_INTERVAL  3  // 每隔 N 次写入检查一次熵

// 评分规则权重
//
// 误报优化说明:
//   高熵写入是正常软件常见行为 (压缩/加密数据库/Office 保存),
//   权重从 15/次(上限60) 降为 8/次(上限40), 仅作辅助信号;
//   单次扩展名变更权重 35 -> 30, 并依赖"变更后立即重写"等组合信号;
//   判定阈值从 100 提高到 120, 确保需要多个信号叠加才触发阻断,
//   单信号 (如仅高熵/仅批量写) 不会误报。
//
#define XGS_SCORE_EXT_CHANGE        30   // 单次扩展名变更
#define XGS_SCORE_MASS_MODIFY_BASE  20   // 大量修改基础分 (>10 文件/30 秒)
#define XGS_SCORE_MASS_MODIFY_PER   2    // 每超 1 个文件追加
#define XGS_SCORE_MASS_DELETE_BASE  15   // 大量删除基础分 (>8 文件/30 秒)
#define XGS_SCORE_MASS_DELETE_PER   2    // 每超 1 个文件追加
#define XGS_SCORE_MASS_RENAME_BASE  25   // 大量重命名基础分 (>5 文件/30 秒)
#define XGS_SCORE_MASS_RENAME_PER   3    // 每超 1 个文件追加
#define XGS_SCORE_ENTROPY_PER       8    // 每次高熵写入 (辅助信号)
#define XGS_SCORE_ENTROPY_MAX       40   // 高熵写入得分上限
#define XGS_SCORE_TYPE_DIVERSITY    15   // 文件类型多样性 (>5 种/30 秒)
#define XGS_SCORE_DIR_DIVERSITY     10   // 目录多样性 (>8 个/30 秒)
#define XGS_SCORE_RAPID_WRITES      10   // 快速连续写入 (>30 次/60 秒)

// 大量操作阈值 (短窗口 30 秒内)
#define XGS_MASS_MODIFY_THRESHOLD   10   // 修改
#define XGS_MASS_DELETE_THRESHOLD   8    // 删除
#define XGS_MASS_RENAME_THRESHOLD   5    // 重命名
#define XGS_TYPE_DIVERSITY_THRESHOLD 5   // 文件类型数
#define XGS_DIR_DIVERSITY_THRESHOLD  8   // 目录数
#define XGS_RAPID_WRITE_THRESHOLD    30  // 快速写入次数

// 备份文件大小上限 (超过则不备份, 避免性能问题)
#define XGS_BACKUP_MAX_SIZE  (100 * 1024 * 1024)  // 100 MB

//=============================================================================
// 进程跟踪条目
//=============================================================================
typedef struct _XGS_PROCESS_ENTRY
{
    HANDLE    ProcessId;              // 进程 ID
    ULONGLONG FirstOpTime;            // 首次操作时间 (100ns)
    ULONGLONG LastOpTime;             // 最近操作时间 (100ns)

    // 操作计数 (滑动窗口内)
    UINT32    FileWrites;             // 文件写入次数
    UINT32    FileDeletes;            // 文件删除次数
    UINT32    FileRenames;            // 文件重命名次数
    UINT32    ExtChanges;             // 扩展名变更次数
    UINT32    EntropyAlerts;          // 高熵写入次数
    UINT32    WriteCount;             // 总写入次数 (用于熵采样间隔)

    // 多样性跟踪
    ULONGLONG DirHashes[XGS_DIVERSITY_SLOTS];   // 目录哈希槽
    UINT32    DirCount;               // 唯一目录数
    ULONGLONG ExtHashes[XGS_DIVERSITY_SLOTS];   // 扩展名哈希槽
    UINT32    ExtTypeCount;           // 唯一文件类型数

    // 评分
    UINT32    ThreatScore;            // 当前威胁评分
    UINT32    DetectionFlags;         // 命中的检测标志 (XGS_DETECT_*)
    UINT32    EntropyScoreAccum;      // 高熵写入累计得分 (用于上限控制)

    // 状态
    BOOLEAN   IsActive;               // 槽位是否在用
    BOOLEAN   IsBlocked;              // 是否已阻断
    ULONGLONG BlockTime;              // 阻断开始时间 (100ns)

    // 操作时间戳环 (用于滑动窗口计数)
    ULONGLONG OpTimes[XGS_OP_TIMES_MAX];
    UINT32    OpTimeHead;             // 环头
    UINT32    OpTimeCount;            // 有效时间戳数
} XGS_PROCESS_ENTRY;

//=============================================================================
// 全局状态
//=============================================================================
typedef struct _XGS_GLOBAL_STATE
{
    KSPIN_LOCK Lock;

    // 进程跟踪表
    XGS_PROCESS_ENTRY Processes[XGS_PROCESS_TABLE_SIZE];
    UINT32 ActiveProcessCount;
    UINT32 BlockedProcessCount;

    // 全局统计
    UINT32 DocWrites;
    UINT32 DocDeletes;
    UINT32 DocRenames;
    UINT32 BackupsCreated;
    UINT32 BlockedOps;
    UINT64 TotalDetections;

    // 通知状态
    BOOLEAN    NotificationPending;
    UINT64     NotificationId;
    BOOLEAN    Restoring;

    XGS_RANSOM_NOTIFICATION Notification;

    // 已备份文件哈希环
    ULONGLONG BackedUpHashes[XGS_BACKEDUP_MAX];
    UINT32 BackedUpHead;
    UINT32 BackedUpCount;

    // 受影响文件记录环
    XGS_MODIFIED_FILE Modified[XGS_MODIFIED_MAX];
    UINT32 ModifiedHead;
    UINT32 ModifiedCount;

    // 鉴权
    BOOLEAN  Authed;
    BOOLEAN  ChallengeValid;
    UINT64   ChallengeSeq;
    UCHAR    Challenge[AV_CHALLENGE_SIZE];

    // 客户端连接状态 (IRP_MJ_CREATE/CLEANUP 维护)
    volatile LONG ClientRefCount;   // 已连接的客户端句柄计数 (>0 表示有代理在线)
} XGS_GLOBAL_STATE;

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
