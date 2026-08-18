//=============================================================================
// XGSSelfProtect.h - XIGUASecurity 自我保护驱动头文件
//
// 保护 XIGUASecurity 自身进程不被外部终止:
//   - ObRegisterCallbacks 拦截 PsProcessType 句柄打开
//   - 外部进程打开受保护进程时, 去掉终止/挂起/内存写入等危险权限
//   - 受保护进程之间互相打开时完全放行 (AVSystem <-> Agent <-> WebView2)
//
// 受保护进程列表 (按镜像名匹配):
//   XIGUASecurityAgent.exe  (主程序)
//   AVMain.exe               (主程序当前名, 兼容)
//   AVSystem.exe             (SYSTEM 服务)
//   msedgewebview2.exe       (WebView2 UI 渲染)
//=============================================================================

#ifndef _XGSSELFCRETECT_H_
#define _XGSSELFCRETECT_H_

#include <ntddk.h>

//=============================================================================
// 配置
//=============================================================================

//
// 受保护进程最大数量 (msedgewebview2 会有多个实例)
//
#define XGS_SP_PROTECTED_MAX        64

//
// 受保护进程名最大长度 (字符)
//
#define XGS_SP_NAME_LEN             64

//
// 最大并发注册会话数 (Agent 实例数)
//
#define XGS_SP_SESSIONS_MAX         4

//
// 单会话最多注册的 PID 数
//
#define XGS_SP_SESSION_PIDS_MAX     16

//
// 外部进程被剥离的权限 (阻止终止/挂起/注入/内存操纵)
//
#define XGS_SP_STRIP_MASK   (PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | \
                             PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                             PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)

//
// 外部进程保留的权限 (允许查询/读取, 保证正常枚举/诊断)
//
#define XGS_SP_KEEP_MASK    (PROCESS_QUERY_INFORMATION | \
                             PROCESS_QUERY_LIMITED_INFORMATION | \
                             PROCESS_VM_READ | SYNCHRONIZE)

//=============================================================================
// 受保护进程条目
//=============================================================================
typedef struct _XGS_SP_ENTRY
{
    BOOLEAN  Active;            // 条目是否有效
    UINT32   Pid;               // 受保护进程 PID
    WCHAR    ImageName[XGS_SP_NAME_LEN];  // 镜像名 (小写, 含 .exe)
} XGS_SP_ENTRY, *PXGS_SP_ENTRY;

//=============================================================================
// 注册会话 (Agent 连接保活)
//
// 每次 Agent 打开设备句柄并发送 REGISTER, 创建一个会话;
// 句柄关闭 (IRP_MJ_CLOSE) 时整个会话被清理, 对应 PID 从保护表移除。
// 进程通知回调作为兜底: 注册者 PID 退出时也清理会话。
//=============================================================================
typedef struct _XGS_SP_SESSION
{
    BOOLEAN      Active;
    PFILE_OBJECT FileObject;                              // 关联的文件对象
    UINT32       RegistrarPid;                            // 注册者 PID (Agent)
    UINT32       ProtectedPids[XGS_SP_SESSION_PIDS_MAX];  // 该会话注册的 PID
    UINT32       ProtectedCount;
} XGS_SP_SESSION, *PXGS_SP_SESSION;

#endif // _XGSSELFCRETECT_H_
