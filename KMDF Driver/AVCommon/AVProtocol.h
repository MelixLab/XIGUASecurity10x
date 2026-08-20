//=============================================================================
// AVProtocol.h - 杀毒驱动三层架构共享协议定义
//
// 本头文件被以下三项目共用：
//   1. AVDriver (KMDF 驱动, 内核态 C)
//   2. AVSystem (SYSTEM 权限转发程序, 用户态 C++)
//   3. AVMain   (主程序 Mock, 用户态 C++)
//
// 包含：IOCTL 控制码、管道消息协议、鉴权结构体、共享密钥定义
//=============================================================================

#pragma once

//
// 根据编译模式选择正确的头文件
//
#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winternl.h>
#endif

//=============================================================================
// 常量定义
//=============================================================================

//
// HMAC-SHA256 摘要长度 (32 bytes)
//
#define AV_HASH_SIZE            32

//
// 随机 Challenge 长度
//
#define AV_CHALLENGE_SIZE       32

//
// Session ID 长度 (16 bytes, 相当于 128-bit)
//
#define AV_SESSION_ID_SIZE      16

//
// 共享密钥长度
//
#define AV_SHARED_KEY_SIZE      32

//
// 最大会话数量
//
#define AV_MAX_SESSIONS         64

//
// 最大管道消息大小 (勒索通知需携带文件列表, 提高到 64KB)
//
#define AV_MAX_PIPE_MSG_SIZE    65536

//
// IOCTL 缓冲区最大大小
//
#define AV_MAX_IOCTL_SIZE       4096

//
// 设备名称
//
#define AV_DEVICE_NAME          L"\\Device\\AVDriver"
#define AV_SYMLINK_NAME         L"\\DosDevices\\AVDriver"
#define AV_WIN32_DEVICE_NAME    L"\\\\.\\AVDriver"

//
// 命名管道名称
//
#define AV_PIPE_NAME            L"\\\\.\\pipe\\AVSystemPipe"
#define AV_PIPE_FULL_NAME       L"\\\\.\\pipe\\AVSystemPipe"

//
// 勒索防护过滤驱动 (XGSRansomFilter) 设备名称
//
#define XGS_DEVICE_NAME         L"\\Device\\XGSRansomFilter"
#define XGS_SYMLINK_NAME        L"\\DosDevices\\XGSRansomFilter"
#define XGS_WIN32_DEVICE_NAME   L"\\\\.\\XGSRansomFilter"

//
// EndPoint 端点防护驱动 (XGSEndPoint) 设备名称
//
#define XGS_EP_DEVICE_NAME      L"\\Device\\XGSEndPoint"
#define XGS_EP_SYMLINK_NAME     L"\\DosDevices\\XGSEndPoint"
#define XGS_EP_WIN32_DEVICE_NAME L"\\\\.\\XGSEndPoint"

//
// 勒索防护常量
//
#define XGS_MAX_FILE_PATH_LEN   520         // 文件路径最大长度
#define XGS_RANSOM_LIST_MAX     12          // 单次通知携带的最大文件数 (弹窗展示)
#define XGS_MODIFIED_MAX        256         // 驱动维护的受影响文件记录数
#define XGS_RANSOM_WINDOW_MS    60000       // 检测时间窗 (毫秒)
#define XGS_BACKUP_DIR_NT       L"\\??\\C:\\Windows\\Temp\\XGS\\Backup\\"  // 备份目录 (NT 路径)
#define XGS_BACKUP_DIR_WIN32    L"C:\\Windows\\Temp\\XGS\\Backup\\"         // 备份目录 (Win32 路径)

//
// 勒索防护操作类型 (XGS_MODIFIED_FILE.Operation)
//
#define XGS_OP_MODIFY            1   // 文件修改 (写入)
#define XGS_OP_DELETE            2   // 文件删除
#define XGS_OP_RENAME            3   // 文件重命名
#define XGS_OP_EXT_CHANGE        4   // 扩展名变更 (勒索软件特征)

//
// 勒索防护检测标志 (XGS_RANSOM_NOTIFICATION.DetectionFlags 位掩码)
// 标识触发检测的具体规则组合
//
#define XGS_DETECT_MASS_MODIFY     0x01   // 大量文件修改 (>10 文件/30 秒)
#define XGS_DETECT_MASS_DELETE     0x02   // 大量文件删除 (>8 文件/30 秒)
#define XGS_DETECT_MASS_RENAME     0x04   // 大量文件重命名 (>5 文件/30 秒)
#define XGS_DETECT_EXT_CHANGE      0x08   // 文件扩展名变更
#define XGS_DETECT_ENTROPY         0x10   // 高熵写入 (疑似加密)
#define XGS_DETECT_TYPE_DIVERSITY  0x20   // 文件类型多样性 (>5 种类型/30 秒)
#define XGS_DETECT_DIR_DIVERSITY   0x40   // 目录多样性 (>8 个目录/30 秒)
#define XGS_DETECT_RAPID_WRITES    0x80   // 快速连续写入 (>30 次/60 秒)

//
// 勒索防护评分阈值
// 120 分: 需要多个威胁信号叠加才触发阻断 (如批量写+高熵+类型多样),
// 单信号 (仅高熵/仅批量写) 不足以触发, 有效降低正常软件误报。
//
#define XGS_RANSOM_SCORE_THRESHOLD  120   // 阻断阈值 (达到此分数触发阻断)

//
// 勒索防护决策码 (用户态 -> 驱动)
//
#define XGS_DECISION_ALLOW       1   // 放行继续
#define XGS_DECISION_STAY_BLOCK  2   // 保持阻断
#define XGS_DECISION_RESTORE     3   // 仅恢复 (从备份恢复文件)

//
// EndPoint 端点防护常量
//
#define XGS_EP_RULE_MAX          6           // 单次通知携带的命中规则数上限
#define XGS_EP_RULE_DESC_LEN     128         // 规则描述长度
#define XGS_EP_DETAIL_LEN        260         // 行为详情字符串长度
#define XGS_EP_BEHAVIORS_MAX     1024        // 驱动行为记录环大小
#define XGS_EP_REPORT_BEHAVIORS_MAX  128     // 行为链报告携带的行为上限
#define XGS_EP_SUSPECT_MAX       64          // 驱动内嫌疑进程记录数
#define XGS_EP_EVENTS_MAX        512         // IOA 评分事件环大小
#define XGS_EP_WINDOW_100NS      (600000000ULL)  // 评分时间窗 (60 秒, 100ns 单位)
#define XGS_EP_TIMEOUT_100NS     (600000000ULL)  // 无决策超时 (60 秒自动恢复)

//
// EndPoint 决策码 (用户态 -> 驱动)
//
#define XGS_EP_DECISION_ALLOW    1   // 放行 (恢复挂起的进程)
#define XGS_EP_DECISION_KILL     2   // 终止进程 (拦截威胁)

//
// EndPoint 行为类型 (XGS_EP_BEHAVIOR.Type)
//
typedef enum _XGS_EP_BEHAVIOR_TYPE
{
    XgsEpBehaviorNone         = 0,
    XgsEpProcessCreate        = 1,   // 进程创建
    XgsEpProcessExit          = 2,   // 进程退出
    XgsEpRemoteThread         = 3,   // 远程线程注入 (跨进程线程创建)
    XgsEpRwxMapping           = 4,   // 可写可执行内存映射 (RWX)
    XgsEpRegWrite             = 5,   // 注册表写入 (自启动相关)
    XgsEpRegDelete            = 6,   // 注册表键/值删除
    XgsEpFileWrite            = 7,   // 文件写入
    XgsEpFileDelete           = 8,   // 文件删除
    XgsEpProcessControl       = 9,   // 跨进程控制 (终止/挂起其他进程)
    XgsEpThreadCreate         = 10,  // 线程创建
    XgsEpModuleLoad           = 11,  // 模块加载 (DLL/EXE)
    XgsEpCrossMem             = 12,  // 跨进程内存读写 (内存操纵)
    XgsEpFileRename           = 13,  // 文件重命名
    XgsEpBootWrite            = 14,  // 引导区写入 (BCD/MBR/GPT)
} XGS_EP_BEHAVIOR_TYPE;

//=============================================================================
// IOCTL 控制码定义 (适用于驱动 <-> 系统程序通信)
//=============================================================================

//
// IOCTL 控制码使用 METHOD_BUFFERED
//
#define AV_IOCTL_DEVICE_TYPE    0x8002

#define IOCTL_AV_AUTH_INIT \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_AUTH_VERIFY \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_AUTH_VALIDATE_SESSION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SCAN_FILE \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SCAN_CANCEL \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_GET_STATUS \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_HEARTBEAT \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x813, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 进程保护相关 IOCTL
//
#define IOCTL_AV_GET_PENDING_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SEND_PROCESS_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x821, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_ADD_ALLOWED_PATH \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x822, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 注册表保护相关 IOCTL
//
#define IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x823, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SEND_REGISTRY_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x824, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 远程线程注入防护相关 IOCTL
//
#define IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x825, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SEND_INJECTION_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x826, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 镜像加载监控相关 IOCTL
//
#define IOCTL_AV_GET_PENDING_IMAGE_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x827, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_AV_SEND_IMAGE_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x828, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 勒索防护 (XGSRansomFilter) IOCTL
//
#define IOCTL_XGS_AUTH_INIT \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_AUTH_VERIFY \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x901, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_GET_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x910, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_SEND_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x911, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 完整受影响文件列表按索引逐条获取 (XGS_MODIFIED_LIST 整体约 521KB, 不适合作为
// IOCTL 输出缓冲区, 故改为单条读取)
//
#define IOCTL_XGS_GET_MODIFIED_FILE \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x912, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_GET_STATUS \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x913, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// EndPoint 端点防护 (XGSEndPoint) IOCTL
//
#define IOCTL_XGS_EP_AUTH_INIT \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A0, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_AUTH_VERIFY \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A1, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_GET_NOTIFICATION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A2, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_SEND_DECISION \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A3, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_GET_STATUS \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A4, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_GET_BEHAVIOR \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A5, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9A6, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// SelfProtect 自保护驱动 IOCTL
//
// 架构: 显式注册 + 连接保活
//   - Agent 启动后打开驱动设备句柄, 发送 REGISTER 注册受保护 PID
//   - 驱动用文件对象关联会话, 句柄关闭 (IRP_MJ_CLOSE) 时自动清理
//   - 不依赖镜像名匹配, 避免系统进程初始化被拦截
//
#define IOCTL_XGS_SP_REGISTER_PIDS \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9B0, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_XGS_SP_UNREGISTER_PIDS \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x9B1, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// 单次注册最大 PID 数 (Agent 自身 + AVMain + msedgewebview2 实例)
//
#define XGS_SP_REGISTER_PIDS_MAX  16

typedef struct _XGS_SP_REGISTER_PIDS_INPUT {
    UINT32 PidCount;                                  // 实际 PID 数量
    UINT32 Pids[XGS_SP_REGISTER_PIDS_MAX];           // 受保护 PID 数组
} XGS_SP_REGISTER_PIDS_INPUT, *PXGS_SP_REGISTER_PIDS_INPUT;

//
// 诊断信息 IOCTL (调试用)
//
#define IOCTL_AV_GET_DEBUG_INFO \
    CTL_CODE(AV_IOCTL_DEVICE_TYPE, 0x830, METHOD_BUFFERED, FILE_READ_DATA)

//
// 受保护系统目录最大数量
//
#define AV_MAX_PROTECTED_DIRS    8

//
// 受保护目录前缀最大长度
//
#define AV_MAX_DIR_PATH_LEN     260

//
// 进程路径最大长度
//
#define AV_MAX_PROCESS_PATH_LEN 520

//
// 白名单路径最大数量
//
#define AV_ALLOW_LIST_MAX       128

//
// 注册表键路径最大长度
//
#define AV_MAX_REG_PATH_LEN     520

//
// 注册表值名最大长度
//
#define AV_MAX_REG_VALUE_LEN    260

//
// 进程通知超时相关
//
#define AV_NOTIFICATION_TIMEOUT_MS 30000   // 30秒

//=============================================================================
// 进程保护结构体
//=============================================================================

//
// 受保护目录条目
//
typedef struct _AV_PROTECTED_DIR
{
    BOOLEAN  Active;
    WCHAR    DirectoryPath[AV_MAX_DIR_PATH_LEN]; // 例如 L"C:\\Windows\\System32\\"
    SIZE_T   PathLength;                          // 字符长度
} AV_PROTECTED_DIR;

//
// 进程拦截原因
//
typedef enum _AV_BLOCK_REASON
{
    AvBlockReasonNone            = 0,   // 无
    AvBlockReasonPathProtect     = 1,   // 目录保护 (受保护目录)
    AvBlockReasonBehaviorCmdline = 2,   // 行为防护 (可疑命令行工具调用)
    AvBlockReasonImageLoad       = 3,   // 镜像加载异常 (白加黑/可疑DLL注入)
} AV_BLOCK_REASON;

//
// 进程通知数据 (IOCTL_AV_GET_PENDING_NOTIFICATION 输出)
//
typedef struct _AV_PROCESS_NOTIFICATION
{
    BOOLEAN  HasPending;                         // 是否有待处理通知
    UINT64   NotificationId;                     // 通知唯一 ID
    UINT32   ProcessId;                          // 被拦截进程 ID
    UINT32   ParentProcessId;                    // 父进程 ID
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 镜像全路径
    WCHAR    CommandLine[AV_MAX_PROCESS_PATH_LEN];// 命令行
    UINT32   BlockReason;                        // AV_BLOCK_REASON 拦截原因
    WCHAR    RuleDescription[128];               // 命中的行为防护规则描述 (行为防护时有效)
} AV_PROCESS_NOTIFICATION;

//
// 进程决策类型
//
typedef enum _AV_DECISION_TYPE
{
    AvDecisionInvalid   = 0,
    AvDecisionAllowOnce = 1,    // 本次允许
    AvDecisionDenyOnce  = 2,    // 本次拒绝
    AvDecisionAllowAlways = 3,  // 始终允许 (加入白名单)
    AvDecisionDenyAlways  = 4,  // 始终拒绝 (加入黑名单)
} AV_DECISION_TYPE;

//
// 进程决策 (IOCTL_AV_SEND_PROCESS_DECISION 输入)
//
typedef struct _AV_PROCESS_DECISION
{
    UINT64         NotificationId;      // 对应通知 ID
    UINT32         ProcessId;           // 决策针对的进程 (驱动据此恢复/终止)
    AV_DECISION_TYPE Decision;          // 决策类型 (本次/始终, 允许/拒绝)
    WCHAR          ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 决策进程的镜像路径 (用于白/黑名单)
} AV_PROCESS_DECISION;

//
// 添加白名单路径 (IOCTL_AV_ADD_ALLOWED_PATH 输入)
//
typedef struct _AV_ALLOWED_PATH_ENTRY
{
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN];
} AV_ALLOWED_PATH_ENTRY;

//=============================================================================
// 注册表保护结构体
//=============================================================================

//
// 注册表操作类型 (AV_REGISTRY_NOTIFICATION.OperationType)
//
typedef enum _AV_REG_OPERATION_TYPE
{
    AvRegOpInvalid        = 0,
    AvRegOpSetValueKey    = 1,   // 写入/修改值
    AvRegOpDeleteValueKey = 2,   // 删除值
    AvRegOpDeleteKey      = 3,   // 删除键
    AvRegOpCreateKey      = 4,   // 创建键
} AV_REG_OPERATION_TYPE;

//
// 注册表拦截通知 (IOCTL_AV_GET_PENDING_REGISTRY_NOTIFICATION 输出)
//
typedef struct _AV_REGISTRY_NOTIFICATION
{
    BOOLEAN  HasPending;                        // 是否有待处理通知
    UINT64   NotificationId;                    // 通知唯一 ID
    UINT32   ProcessId;                         // 发起注册表操作的进程 ID
    UINT32   OperationType;                     // AV_REG_OPERATION_TYPE
    WCHAR    KeyPath[AV_MAX_REG_PATH_LEN];      // 被操作的注册表键完整路径
    WCHAR    ValueName[AV_MAX_REG_VALUE_LEN];   // 被操作的值名 (键操作时为空)
} AV_REGISTRY_NOTIFICATION;

//
// 注册表决策 (IOCTL_AV_SEND_REGISTRY_DECISION 输入)
//
typedef struct _AV_REGISTRY_DECISION
{
    UINT64          NotificationId;             // 对应通知 ID
    AV_DECISION_TYPE Decision;                  // 决策类型 (本次/始终, 允许/拒绝)
    WCHAR           KeyPath[AV_MAX_REG_PATH_LEN]; // 决策针对的注册表键路径 (用于规则)
} AV_REGISTRY_DECISION;

//
// 远程线程注入通知 (IOCTL_AV_GET_PENDING_INJECTION_NOTIFICATION 输出)
//
typedef struct _AV_INJECTION_NOTIFICATION
{
    BOOLEAN  HasPending;                         // 是否有待处理通知
    UINT64   NotificationId;                     // 通知唯一 ID
    UINT32   SourceProcessId;                    // 发起注入的进程 ID
    UINT32   TargetProcessId;                    // 被注入的进程 ID
    UINT32   ThreadId;                           // 被创建的远程线程 ID
    UINT64   StartAddress;                       // 远程线程起始地址
    WCHAR    SourceImagePath[AV_MAX_PROCESS_PATH_LEN]; // 发起进程镜像路径 (用于规则)
} AV_INJECTION_NOTIFICATION;

//
// 远程线程注入决策 (IOCTL_AV_SEND_INJECTION_DECISION 输入)
//
typedef struct _AV_INJECTION_DECISION
{
    UINT64          NotificationId;             // 对应通知 ID
    AV_DECISION_TYPE Decision;                  // 决策类型 (本次/始终, 允许/拒绝)
    WCHAR           SourceImagePath[AV_MAX_PROCESS_PATH_LEN]; // 发起进程镜像路径 (用于规则)
} AV_INJECTION_DECISION;

//
// 镜像加载异常类型
//
typedef enum _AV_IMAGE_ANOMALY_TYPE
{
    AvImageAnomalyNone            = 0,
    AvImageAnomalySideLoading     = 1,   // 白加黑: 同目录DLL侧加载
    AvImageAnomalySystemInject    = 2,   // 系统进程加载非系统目录DLL
    AvImageAnomalySuspiciousPath  = 3,   // 从Temp/Downloads/Desktop加载DLL
    AvImageAnomalyUnsignedDriver  = 4,   // 加载未签名内核驱动
} AV_IMAGE_ANOMALY_TYPE;

//
// 镜像加载通知 (IOCTL_AV_GET_PENDING_IMAGE_NOTIFICATION 输出)
//
typedef struct _AV_IMAGE_NOTIFICATION
{
    BOOLEAN  HasPending;                         // 是否有待处理通知
    UINT64   NotificationId;                     // 通知唯一 ID
    UINT32   ProcessId;                          // 加载镜像的进程 ID
    UINT32   AnomalyType;                        // AV_IMAGE_ANOMALY_TYPE
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 被加载的镜像全路径
    WCHAR    ProcessImagePath[AV_MAX_PROCESS_PATH_LEN]; // 加载者进程镜像路径
    WCHAR    RuleDescription[128];               // 异常描述
} AV_IMAGE_NOTIFICATION;

//
// 镜像加载决策 (IOCTL_AV_SEND_IMAGE_DECISION 输入)
//
typedef struct _AV_IMAGE_DECISION
{
    UINT64          NotificationId;             // 对应通知 ID
    UINT32          ProcessId;                  // 决策针对的进程
    AV_DECISION_TYPE Decision;                  // 决策类型 (本次/始终, 允许/拒绝)
} AV_IMAGE_DECISION;

//
// 勒索防护: 受影响文件条目 (修改/删除/重命名 + 备份)
//
typedef struct _XGS_MODIFIED_FILE
{
    UINT32 Operation;                     // XGS_OP_MODIFY / DELETE / RENAME / EXT_CHANGE
    UINT32 ProcessId;                     // 发起操作的进程 ID
    WCHAR  OriginalPath[XGS_MAX_FILE_PATH_LEN];  // 原始路径
    WCHAR  BackupPath[XGS_MAX_FILE_PATH_LEN];    // 备份路径 (重命名时存新路径)
} XGS_MODIFIED_FILE;

//
// 勒索防护: 触发通知 (IOCTL_XGS_GET_NOTIFICATION 输出)
// 包含触发进程信息和评分明细
//
typedef struct _XGS_RANSOM_NOTIFICATION
{
    BOOLEAN  HasPending;                   // 是否有待处理通知
    UINT64   NotificationId;               // 通知唯一 ID
    UINT32   ProcessId;                    // 触发进程 ID
    WCHAR    ProcessName[32];              // 触发进程名 (截断到 15 字符)
    UINT32   ThreatScore;                  // 当前威胁评分
    UINT32   DetectionFlags;               // 检测标志 (XGS_DETECT_* 位掩码)
    UINT32   FileCount;                    // 受影响文件数
    XGS_MODIFIED_FILE Files[XGS_RANSOM_LIST_MAX];
} XGS_RANSOM_NOTIFICATION;

//
// 勒索防护: 决策 (IOCTL_XGS_SEND_DECISION 输入)
//
typedef struct _XGS_RANSOM_DECISION
{
    UINT64  NotificationId;                // 对应通知 ID
    UINT32  Decision;                      // 1=放行继续 2=保持阻断 3=仅恢复
    UINT32  ProcessId;                     // 目标进程 ID (对指定进程生效)
} XGS_RANSOM_DECISION;

//
// 勒索防护: 状态 (IOCTL_XGS_GET_STATUS 输出)
//
typedef struct _XGS_STATUS
{
    UINT32  Version;
    UINT32  RansomSuspected;               // 当前阻断中的进程数
    UINT64  DocWrites;                     // 文档写操作总数
    UINT64  DocDeletes;                    // 文档删除操作总数
    UINT64  DocRenames;                    // 文档重命名操作总数
    UINT64  BackupsCreated;                // 已创建备份数
    UINT32  PendingNotification;           // 是否有待处理通知
    UINT32  ModifiedCount;                 // 已记录的受影响文件数
    UINT32  ActiveProcesses;               // 活跃跟踪进程数
    UINT32  BlockedProcesses;              // 阻断中的进程数
    UINT64  TotalDetections;               // 累计勒索检测次数
} XGS_STATUS;

//
// EndPoint 端点防护: 行为记录条目 (驱动记录环)
//
typedef struct _XGS_EP_BEHAVIOR
{
    UINT32  Type;                          // XGS_EP_BEHAVIOR_TYPE
    UINT32  ProcessId;                     // 发起行为/行为所属进程
    UINT32  ParentProcessId;               // 该进程的父进程 ID (行为链关键)
    UINT64  Timestamp100ns;                // 行为时间戳 (100ns)
    WCHAR   Detail[XGS_EP_DETAIL_LEN];     // 行为详情 (路径/键名/起始地址等)
} XGS_EP_BEHAVIOR;

//
// EndPoint 端点防护: 命中规则条目
//
typedef struct _XGS_EP_RULE_HIT
{
    UINT32  RuleId;                        // 规则 ID
    UINT32  Score;                         // 规则权重
    WCHAR   Description[XGS_EP_RULE_DESC_LEN]; // 规则描述
} XGS_EP_RULE_HIT;

//
// EndPoint 端点防护: 威胁通知 (IOCTL_XGS_EP_GET_NOTIFICATION 输出)
//
typedef struct _XGS_EP_NOTIFICATION
{
    BOOLEAN  HasPending;                   // 是否有待处理通知
    UINT64   NotificationId;               // 通知唯一 ID
    UINT32   ProcessId;                    // 威胁进程 (已挂起)
    UINT32   ParentProcessId;              // 威胁进程的父进程 ID
    UINT32   TotalScore;                   // 累计威胁评分
    UINT32   RuleCount;                    // 命中规则数
    XGS_EP_RULE_HIT Rules[XGS_EP_RULE_MAX];// 命中的规则
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 威胁进程镜像路径
} XGS_EP_NOTIFICATION;

//
// EndPoint 端点防护: 决策 (IOCTL_XGS_EP_SEND_DECISION 输入)
//
typedef struct _XGS_EP_DECISION
{
    UINT64   NotificationId;                // 对应通知 ID
    UINT32   Decision;                      // 1=放行(恢复) 2=终止进程
} XGS_EP_DECISION;

//
// EndPoint 端点防护: 行为链请求 (IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN 输入)
//
typedef struct _XGS_EP_BEHAVIOR_CHAIN_REQUEST
{
    UINT32   ProcessId;                     // 要查询行为链的目标进程 PID
    UINT32   Reserved;                      // 对齐保留
} XGS_EP_BEHAVIOR_CHAIN_REQUEST;

//
// EndPoint 端点防护: 行为链输出 (IOCTL_XGS_EP_GET_BEHAVIOR_CHAIN 输出)
// 驱动遍历行为记录环, 返回该 PID 的全部行为 (按时间顺序)
//
typedef struct _XGS_EP_BEHAVIOR_CHAIN
{
    UINT32          ProcessId;              // 查询的进程 PID
    UINT32          BehaviorCount;          // 返回的行为数量
    XGS_EP_BEHAVIOR Behaviors[XGS_EP_REPORT_BEHAVIORS_MAX];  // 行为数组
} XGS_EP_BEHAVIOR_CHAIN;

//
// EndPoint 端点防护: 状态 (IOCTL_XGS_EP_GET_STATUS 输出)
//
typedef struct _XGS_EP_STATUS
{
    UINT32  Version;
    UINT32  PendingNotification;           // 是否有待处理通知
    UINT64  BehaviorsRecorded;             // 已记录行为总数
    UINT64  ThreatsDetected;               // 已检测威胁总数
    UINT64  ProcessesSuspended;            // 已挂起进程数
    UINT32  SuspendedCount;                // 当前挂起中的威胁进程数
} XGS_EP_STATUS;

//
// 注册表处理动作 (AV_DEBUG_INFO.LastRegAction)
//
#define AV_REG_ACTION_NONE           0   // 未处理
#define AV_REG_ACTION_ALLOW_NOMATCH  1   // 非敏感路径放行
#define AV_REG_ACTION_ALLOW_TRUSTED  2   // 信任进程放行
#define AV_REG_ACTION_ALLOW_INACTIVE 3   // 无活跃客户端放行
#define AV_REG_ACTION_BLOCKED        4   // 已拦截等待决策
#define AV_REG_ACTION_ALLOW_RULE     5   // 命中允许规则放行
#define AV_REG_ACTION_DENY_RULE      6   // 命中拒绝规则拒绝
#define AV_REG_ACTION_ALLOW_PATHFAIL 7   // 路径提取失败放行

//=============================================================================
// 鉴权相关结构体 (Driver <-> System)
//=============================================================================

#pragma pack(push, 1)

//
// IOCTL_AV_AUTH_INIT 输出: 驱动返回的 Challenge
//
typedef struct _AV_AUTH_CHALLENGE
{
    UINT64  SequenceId;                         // 序列号, 防止重放
    UCHAR   Challenge[AV_CHALLENGE_SIZE];       // 32-byte 随机挑战码
} AV_AUTH_CHALLENGE;

//
// IOCTL_AV_AUTH_VERIFY 输入: 系统程序提交鉴权响应
//
typedef struct _AV_AUTH_RESPONSE
{
    UINT64  SequenceId;                         // 和 Challenge 中的一致
    UCHAR   Challenge[AV_CHALLENGE_SIZE];       // 原 Challenge 回传
    UCHAR   Hmac[AV_HASH_SIZE];                 // HMAC-SHA256(Challenge || SequenceId, SharedKey)
} AV_AUTH_RESPONSE;

//
// IOCTL_AV_AUTH_VERIFY 输出: 鉴权结果 + Session
//
typedef struct _AV_AUTH_RESULT
{
    NTSTATUS Status;                            // 鉴权结果
    UCHAR    SessionId[AV_SESSION_ID_SIZE];     // 会话 ID (成功后有效)
} AV_AUTH_RESULT;

//
// IOCTL_AV_AUTH_VALIDATE_SESSION 输入
//
typedef struct _AV_SESSION_VALIDATE
{
    UCHAR    SessionId[AV_SESSION_ID_SIZE];     // 要验证的会话 ID
} AV_SESSION_VALIDATE;

//
// IOCTL_AV_AUTH_VALIDATE_SESSION 输出
//
typedef struct _AV_SESSION_RESULT
{
    NTSTATUS Status;                            // 验证结果
} AV_SESSION_RESULT;

//
// IOCTL_AV_SCAN_FILE 输入
//
typedef struct _AV_SCAN_REQUEST
{
    UCHAR    SessionId[AV_SESSION_ID_SIZE];     // 会话 ID (鉴权后有效)
    UINT64   RequestId;                         // 请求 ID
    UINT32   FilePathLength;                    // 文件路径长度 (bytes, 含 null)
    WCHAR    FilePath[1];                       // 文件路径 (变长)
} AV_SCAN_REQUEST;

//
// IOCTL_AV_SCAN_FILE 输出
//
typedef struct _AV_SCAN_RESPONSE
{
    UINT64   RequestId;                         // 对应请求 ID
    NTSTATUS Status;                            // 扫描状态
    UINT32   ThreatLevel;                       // 威胁等级 (0=安全, >0=威胁)
    WCHAR    ThreatName[128];                   // 威胁名称
} AV_SCAN_RESPONSE;

//
// IOCTL_AV_GET_STATUS 输出
//
typedef struct _AV_DRIVER_STATUS
{
    UINT32   Version;                           // 驱动版本
    UINT32   ActiveSessions;                    // 活跃会话数
    UINT64   TotalScans;                        // 总扫描次数
    UINT64   UptimeMs;                          // 运行时间 (ms)
    UINT64   ProcessCallbackTriggers;           // 进程回调触发总次数
    UINT64   ProcessBlockAttempts;              // 进程拦截尝试次数 (进入等待决策)
} AV_DRIVER_STATUS;

//
// IOCTL_AV_GET_DEBUG_INFO 输出 (调试用)
//
typedef struct _AV_DEBUG_INFO
{
    UINT64   CallbackTriggers;          // 进程回调触发总次数
    UINT64   BlockAttempts;             // 进程拦截尝试次数 (进入等待决策)
    UINT64   ProtectedHits;             // 进程命中受保护目录次数
    BOOLEAN  LastWasProtected;          // 最近处理的进程是否命中受保护目录
    WCHAR    LastImagePath[256];        // 最近处理的进程镜像路径 (null 终止)

    //
    // 行为防护统计
    //
    UINT64   BehaviorTriggers;          // 行为防护规则命中总次数 (可疑命令行调用)

    //
    // 远程线程注入防护统计
    //
    UINT64   InjectionTriggers;         // 检测到的远程线程注入次数

    //
    // 注册表保护统计
    //
    UINT64   RegCallbackTriggers;       // 注册表回调处理总次数 (写操作)
    UINT64   RegSensitiveHits;          // 命中敏感路径次数
    UINT64   RegBlockAttempts;          // 拦截等待决策次数
    UINT64   RegPathFailures;           // 键路径提取失败次数
    UINT32   LastRegAction;             // 最近一次注册表处理动作 (AV_REG_ACTION_*)
    WCHAR    LastRegPath[AV_MAX_REG_PATH_LEN]; // 最近处理的注册表键路径
} AV_DEBUG_INFO;

//
// IOCTL_AV_HEARTBEAT 输入
//
typedef struct _AV_HEARTBEAT_REQUEST
{
    UCHAR    SessionId[AV_SESSION_ID_SIZE];     // 会话 ID
    UINT64   Timestamp;                         // 时间戳
    UCHAR    Hmac[AV_HASH_SIZE];                // HMAC-SHA256(SessionId || Timestamp, SessionKey)
} AV_HEARTBEAT_REQUEST;

//
// IOCTL_AV_HEARTBEAT 输出
//
typedef struct _AV_HEARTBEAT_RESPONSE
{
    NTSTATUS Status;
    UINT64   ServerTimestamp;
} AV_HEARTBEAT_RESPONSE;

#pragma pack(pop)

//=============================================================================
// 命名管道消息协议 (System <-> Main)
//=============================================================================

//
// 管道消息类型
//
typedef enum _AV_PIPE_MSG_TYPE
{
    AvPipeMsgInvalid = 0,

    // 鉴权阶段
    AvPipeMsgAuthInit          = 0x1001,   // Main -> System: 请求鉴权
    AvPipeMsgAuthChallenge     = 0x1002,   // System -> Main: 返回 Challenge
    AvPipeMsgAuthVerify        = 0x1003,   // Main -> System: 提交鉴权响应
    AvPipeMsgAuthResult        = 0x1004,   // System -> Main: 鉴权结果

    // 业务阶段
    AvPipeMsgScanRequest       = 0x2001,   // Main -> System: 扫描请求
    AvPipeMsgScanResponse      = 0x2002,   // System -> Main: 扫描结果
    AvPipeMsgGetStatus         = 0x2003,   // Main -> System: 查询状态
    AvPipeMsgStatusResponse    = 0x2004,   // System -> Main: 状态响应
    AvPipeMsgHeartbeat         = 0x2005,   // Main -> System: 心跳
    AvPipeMsgHeartbeatResponse = 0x2006,   // System -> Main: 心跳响应

    // 进程保护 (System <-> Main)
    AvPipeMsgProcessNotify     = 0x2010,   // System -> Main: 进程拦截通知 (要求 Main 弹窗决策)
    AvPipeMsgProcessDecision   = 0x2011,   // Main -> System: 进程决策回复

    // 注册表保护 (System <-> Main)
    AvPipeMsgRegNotify         = 0x2020,   // System -> Main: 注册表拦截通知 (要求 Main 弹窗决策)
    AvPipeMsgRegDecision       = 0x2021,   // Main -> System: 注册表决策回复

    // 远程线程注入防护 (System <-> Main)
    AvPipeMsgInjectionNotify   = 0x2030,   // System -> Main: 远程线程注入通知 (要求 Main 弹窗决策)
    AvPipeMsgInjectionDecision = 0x2031,   // Main -> System: 注入决策回复

    // 镜像加载监控 (System <-> Main)
    AvPipeMsgImageNotify       = 0x2060,   // System -> Main: 镜像加载异常通知 (要求 Main 弹窗决策)
    AvPipeMsgImageDecision     = 0x2061,   // Main -> System: 镜像加载决策回复

    // 勒索防护 (System <-> Main)
    AvPipeMsgRansomNotify      = 0x2040,   // System -> Main: 勒索防护通知 (要求 Main 弹窗决策)
    AvPipeMsgRansomDecision    = 0x2041,   // Main -> System: 勒索防护决策回复

    // EndPoint 端点防护 (System <-> Main)
    AvPipeMsgEndPointNotify    = 0x2050,   // System -> Main: EndPoint 威胁通知 (要求 Main 弹窗决策)
    AvPipeMsgEndPointDecision  = 0x2051,   // Main -> System: EndPoint 决策回复

    // 系统控制 (Main -> System)
    AvPipeMsgShutdownRequest   = 0x3000,   // Main -> System: 请求 AVSystem 退出 (驱动保持加载)

    // 错误
    AvPipeMsgError             = 0xFFFF,   // System -> Main: 错误消息

} AV_PIPE_MSG_TYPE;

//
// 管道消息头 (所有管道消息以该结构开头)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_MSG_HEADER
{
    UINT32          Magic;              // 魔数: 0xAV2024
    UINT32          MessageType;        // AV_PIPE_MSG_TYPE
    UINT32          DataSize;           // 数据部分大小 (不包含头部)
    UINT32          Checksum;           // 数据部分 XOR 校验和 (简单校验)
} AV_PIPE_MSG_HEADER;
#pragma pack(pop)

#define AV_PIPE_MAGIC           0x41564452       // "AVDR"

//
// 管道消息: 鉴权初始化 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_AUTH_INIT
{
    UINT32  ProtocolVersion;                     // 协议版本
} AV_PIPE_AUTH_INIT;
#pragma pack(pop)

//
// 管道消息: 鉴权 Challenge (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_AUTH_CHALLENGE
{
    UINT64  SequenceId;
    UCHAR   Challenge[AV_CHALLENGE_SIZE];
} AV_PIPE_AUTH_CHALLENGE_DATA;
#pragma pack(pop)

//
// 管道消息: 鉴权验证 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_AUTH_VERIFY
{
    UINT64  SequenceId;
    UCHAR   Challenge[AV_CHALLENGE_SIZE];
    UCHAR   Hmac[AV_HASH_SIZE];
} AV_PIPE_AUTH_VERIFY_DATA;
#pragma pack(pop)

//
// 管道消息: 鉴权结果 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_AUTH_RESULT
{
    BOOLEAN Success;
    UCHAR   SessionId[AV_SESSION_ID_SIZE];       // 仅 Success 时有效
    UINT32  ErrorCode;                           // 错误码
} AV_PIPE_AUTH_RESULT_DATA;
#pragma pack(pop)

//
// 管道消息: 扫描请求 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_SCAN_REQUEST
{
    UCHAR    SessionId[AV_SESSION_ID_SIZE];
    UINT64   RequestId;
    UINT32   FilePathLength;                     // bytes, 含 null
    WCHAR    FilePath[ANYSIZE_ARRAY];            // 变长
} AV_PIPE_SCAN_REQUEST_DATA;
#pragma pack(pop)

//
// 管道消息: 扫描响应 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_SCAN_RESPONSE
{
    UINT64   RequestId;
    BOOLEAN  Success;
    UINT32   ThreatLevel;
    WCHAR    ThreatName[128];
} AV_PIPE_SCAN_RESPONSE_DATA;
#pragma pack(pop)

//
// 管道消息: 进程拦截通知 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_PROCESS_NOTIFY
{
    UINT64   NotificationId;                  // 通知唯一 ID
    UINT32   ProcessId;                       // 被拦截进程 ID
    UINT32   ParentProcessId;                 // 父进程 ID
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 镜像全路径
    WCHAR    CommandLine[AV_MAX_PROCESS_PATH_LEN];// 命令行
    UINT32   BlockReason;                     // AV_BLOCK_REASON 拦截原因
    WCHAR    RuleDescription[128];            // 命中的行为防护规则描述
} AV_PIPE_PROCESS_NOTIFY_DATA;
#pragma pack(pop)

//
// 管道消息: 进程决策回复 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_PROCESS_DECISION
{
    UINT64         NotificationId;            // 对应通知 ID
    AV_DECISION_TYPE Decision;               // 决策类型
    WCHAR          ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 决策进程的镜像路径
} AV_PIPE_PROCESS_DECISION_DATA;
#pragma pack(pop)

//
// 管道消息: 注册表拦截通知 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_REG_NOTIFY
{
    UINT64   NotificationId;                 // 通知唯一 ID
    UINT32   ProcessId;                      // 发起注册表操作的进程 ID
    UINT32   OperationType;                  // AV_REG_OPERATION_TYPE
    WCHAR    KeyPath[AV_MAX_REG_PATH_LEN];   // 被操作的注册表键完整路径
    WCHAR    ValueName[AV_MAX_REG_VALUE_LEN];// 被操作的值名 (键操作时为空)
} AV_PIPE_REG_NOTIFY_DATA;
#pragma pack(pop)

//
// 管道消息: 注册表决策回复 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_REG_DECISION
{
    UINT64          NotificationId;          // 对应通知 ID
    AV_DECISION_TYPE Decision;               // 决策类型
    WCHAR           KeyPath[AV_MAX_REG_PATH_LEN]; // 决策针对的注册表键路径
} AV_PIPE_REG_DECISION_DATA;
#pragma pack(pop)

//
// 管道消息: 远程线程注入通知 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_INJECTION_NOTIFY
{
    UINT64   NotificationId;                 // 通知唯一 ID
    UINT32   SourceProcessId;                // 发起注入的进程 ID
    UINT32   TargetProcessId;                // 被注入的进程 ID
    UINT32   ThreadId;                       // 被创建的远程线程 ID
    UINT64   StartAddress;                   // 远程线程起始地址
    WCHAR    SourceImagePath[AV_MAX_PROCESS_PATH_LEN]; // 发起进程镜像路径
} AV_PIPE_INJECTION_NOTIFY_DATA;
#pragma pack(pop)

//
// 管道消息: 远程线程注入决策回复 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_INJECTION_DECISION
{
    UINT64          NotificationId;          // 对应通知 ID
    AV_DECISION_TYPE Decision;               // 决策类型
} AV_PIPE_INJECTION_DECISION_DATA;
#pragma pack(pop)

//
// 管道消息: 勒索防护通知 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_RANSOM_NOTIFY
{
    UINT64   NotificationId;                 // 通知唯一 ID
    UINT32   ProcessId;                      // 触发进程 ID
    WCHAR    ProcessName[32];                // 触发进程名
    UINT32   ThreatScore;                    // 威胁评分
    UINT32   DetectionFlags;                 // 检测标志 (XGS_DETECT_* 位掩码)
    UINT32   FileCount;                      // 受影响文件数
    XGS_MODIFIED_FILE Files[XGS_RANSOM_LIST_MAX];
} AV_PIPE_RANSOM_NOTIFY_DATA;
#pragma pack(pop)

//
// 管道消息: 勒索防护决策回复 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_RANSOM_DECISION
{
    UINT64   NotificationId;                 // 对应通知 ID
    UINT32   Decision;                       // 1=放行继续 2=保持阻断 3=仅恢复
    UINT32   ProcessId;                      // 目标进程 ID
} AV_PIPE_RANSOM_DECISION_DATA;
#pragma pack(pop)

//
// 管道消息: EndPoint 威胁通知 (System -> Main)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_EP_NOTIFY
{
    UINT64   NotificationId;                 // 通知唯一 ID
    UINT32   ProcessId;                      // 威胁进程 (已挂起)
    UINT32   ParentProcessId;                // 威胁进程的父进程 ID
    UINT32   TotalScore;                     // 累计威胁评分
    UINT32   RuleCount;                      // 命中规则数
    XGS_EP_RULE_HIT Rules[XGS_EP_RULE_MAX];  // 命中的规则
    WCHAR    ImagePath[AV_MAX_PROCESS_PATH_LEN]; // 威胁进程镜像路径
} AV_PIPE_EP_NOTIFY_DATA;
#pragma pack(pop)

//
// 管道消息: EndPoint 决策回复 (Main -> System)
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_EP_DECISION
{
    UINT64   NotificationId;                 // 对应通知 ID
    UINT32   Decision;                       // 1=放行(恢复) 2=终止进程
} AV_PIPE_EP_DECISION_DATA;
#pragma pack(pop)

//
// 管道消息: 错误
//
#pragma pack(push, 1)
typedef struct _AV_PIPE_ERROR
{
    UINT32  ErrorCode;
    WCHAR   ErrorMessage[256];
} AV_PIPE_ERROR_DATA;
#pragma pack(pop)

//=============================================================================
// 共享密钥 (开发阶段使用, 发布前需替换为安全密钥交换机制)
//=============================================================================

//
// 32-byte 共享密钥
// 注意: 此密钥仅用于开发阶段! 正式发布必须通过安全渠道分发或使用证书签名。
//
static const UCHAR AV_SHARED_KEY[AV_SHARED_KEY_SIZE] =
{
    0x4A, 0x6F, 0x69, 0x6E, 0x74, 0x41, 0x56, 0x54,
    0x65, 0x61, 0x6D, 0x4B, 0x65, 0x79, 0x32, 0x30,
    0x32, 0x34, 0x5F, 0x53, 0x65, 0x63, 0x75, 0x72,
    0x65, 0x41, 0x76, 0x44, 0x72, 0x69, 0x76, 0x65
};

//=============================================================================
// NTSTATUS 定义 (供用户态代码使用)
//=============================================================================

#ifndef STATUS_SUCCESS
typedef LONG NTSTATUS;
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#endif

// EOF
