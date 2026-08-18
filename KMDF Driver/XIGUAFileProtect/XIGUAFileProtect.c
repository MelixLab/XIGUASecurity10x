//=============================================================================
// XGSRansomFilter.c - XIGUASecurity 勒索防护过滤驱动
//
// 文件系统微过滤器 (传统型 Minifilter, 非 KMDF):
//   - IRP_MJ_CREATE: 文档文件以写/删能力打开时, 首次备份原始内容到
//     C:\Windows\Temp\XGS\Backup\ (修改前备份)
//   - IRP_MJ_WRITE: 计数 + 记录 + 阻断判定
//   - IRP_MJ_SET_INFORMATION: 删除前计数 + 记录 + 阻断判定
//   - 时间窗 (60 秒) 内文档改动次数 >= 20 判定疑似勒索
//     -> 阻断后续文档写/删 + 记录受影响文件 + 通知用户态
//   - 用户态决策: 放行 / 保持阻断 / 恢复文件
//   - 阻断状态 60 秒无决策自动放行, 防止用户态故障导致系统锁死
//
// 同时注册传统控制设备 (IoCreateDeviceSecure), 供 AVSystem 通过 IOCTL
// 获取通知/下发决策。IOCTL 采用 METHOD_BUFFERED, 全链路与 AVDriver 相同
// 的 Challenge-Response + HMAC-SHA256 双向鉴权。
//
// 安全设计:
//   - 备份目录自身 / 分页 IO / 非 PASSIVE IRQL 一律不处理
//   - 备份文件写入会重新进入本过滤器, 已通过备份目录前缀豁免
//   - 恢复文件期间置 Restoring 标志, 豁免备份目录外文档的备份/计数/阻断
//=============================================================================

#include "XIGUAFileProtect.h"

//=============================================================================
// 全局状态
//=============================================================================
static PDRIVER_OBJECT g_DriverObject = NULL;
static PFLT_FILTER g_XgsFilter = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;

//
// 控制设备扩展 (目前无实际内容, 预留)
//
typedef struct _XGS_DEVICE_EXTENSION
{
    BOOLEAN Dummy;
} XGS_DEVICE_EXTENSION;

//
// 全部可变状态集中在一个非分页结构中, 由 g_Xgs.Lock 保护
//
typedef struct _XGS_GLOBAL_STATE
{
    KSPIN_LOCK Lock;
    BOOLEAN    RansomSuspected;         // 是否处于阻断状态
    ULONGLONG  SuspicionTicks;          // 进入阻断状态的时间戳 (100ns)
    BOOLEAN    NotificationPending;     // 是否有待处理通知
    UINT64     NotificationId;          // 通知唯一 ID (单调递增)
    BOOLEAN    Restoring;               // 恢复文件进行中 (豁免标志)
    UINT32     DocWrites;               // 文档写操作总数
    UINT32     DocDeletes;              // 文档删除操作总数
    UINT32     BackupsCreated;          // 已创建备份数
    UINT32     BlockedOps;              // 阻断的文档操作数

    XGS_MODIFIED_FILE Modified[XGS_MODIFIED_MAX];   // 受影响文件环
    UINT32  ModifiedHead;               // 下一个写入槽
    UINT32  ModifiedCount;              // 已记录数量

    XGS_RANSOM_NOTIFICATION Notification; // 通知快照

    ULONGLONG EventTicks[XGS_DOC_EVENTS_MAX];   // 检测事件时间戳环 (100ns)
    UINT32 EventHead;
    UINT32 EventCount;

    ULONGLONG BackedUpHashes[XGS_BACKEDUP_MAX]; // 已备份文件哈希环
    UINT32 BackedUpHead;
    UINT32 BackedUpCount;

    BOOLEAN  Authed;                    // 是否已鉴权
    BOOLEAN  ChallengeValid;            // 是否有有效 Challenge
    UINT64   ChallengeSeq;              // Challenge 序列号
    UCHAR    Challenge[AV_CHALLENGE_SIZE];
} XGS_GLOBAL_STATE;

static XGS_GLOBAL_STATE g_Xgs = { 0 };

//
// 时间常量 (100ns 单位)
//
#define XGS_WINDOW_100NS    (600000000ULL)   // 60 秒
#define XGS_TIMEOUT_100NS   (600000000ULL)   // 60 秒

//=============================================================================
// 文档扩展名表 (小写, 含点)
//=============================================================================
static const WCHAR* const g_DocExts[] =
{
    // 通用办公文档
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".pdf",
    L".txt", L".rtf",
    // OpenDocument
    L".odt", L".ods", L".odp",
    // 纯文本/标记
    L".csv", L".md",
    // WPS 办公套件
    L".wps", L".et", L".dps",
    // 邮件/笔记
    L".eml", L".msg", L".one",
    // 流程图/设计
    L".vsd", L".vsdx",
    // 压缩包
    L".zip", L".rar", L".7z",
    // 图片
    L".jpg", L".jpeg", L".png", L".bmp", L".gif", L".tiff",
    // 音视频
    L".mp3", L".mp4", L".avi", L".mkv",
    // Outlook 数据
    L".pst"
};

//=============================================================================
// 小型工具函数 (不使用 CRT, 全部手写)
//=============================================================================

//
// 当前时间 (100ns 单位, 从系统启动起, 不受睡眠调整影响)
//
static
ULONGLONG
XgsNow(
    VOID
    )
{
    return KeQueryUnbiasedInterruptTime();
}

//
// 宽字符串长度
//
static
SIZE_T
XgsStrLenW(
    _In_ PCWSTR s
    )
{
    SIZE_T n = 0;
    while (s[n] != L'\0')
    {
        n++;
    }
    return n;
}

//
// 复制宽字符串并确保 null 终止
//
static
VOID
XgsStrNCpyW(
    _Out_writes_(maxChars) PWCHAR dst,
    _In_ PCWSTR src,
    _In_ SIZE_T maxChars
    )
{
    SIZE_T i;

    if (maxChars == 0)
    {
        return;
    }
    for (i = 0; i + 1 < maxChars && src[i] != L'\0'; i++)
    {
        dst[i] = src[i];
    }
    dst[i] = L'\0';
}

//
// 大小写不敏感比较前 n 个字符
//
static
BOOLEAN
XgsWcsCaseCmp(
    _In_ PCWSTR a,
    _In_ PCWSTR b,
    _In_ SIZE_T n
    )
{
    SIZE_T i;
    for (i = 0; i < n; i++)
    {
        WCHAR ca = a[i];
        WCHAR cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb)
        {
            return FALSE;
        }
    }
    return TRUE;
}

//
// 文件路径 FNV-1a 64 位哈希 (小写化, 用于去重)
//
static
ULONGLONG
XgsHashPath(
    _In_ PCWSTR path
    )
{
    ULONGLONG h = 1469598103934665603ULL;
    while (*path != L'\0')
    {
        WCHAR c = *path;
        if (c >= L'A' && c <= L'Z') c += 32;
        h ^= (ULONGLONG)c;
        h *= 1099511628211ULL;
        path++;
    }
    return h;
}

//
// 是否为文档扩展名
//
static
BOOLEAN
XgsIsDocExtension(
    _In_ PCWSTR path
    )
{
    SIZE_T len = XgsStrLenW(path);
    ULONG i;

    if (len < 2 || path[len - 1] == L'\\')
    {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(g_DocExts); i++)
    {
        SIZE_T el = XgsStrLenW(g_DocExts[i]);
        if (len >= el && XgsWcsCaseCmp(path + len - el, g_DocExts[i], el))
        {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 是否位于备份目录内 (豁免)
//
static
BOOLEAN
XgsIsBackupDirPath(
    _In_ PCWSTR path
    )
{
    SIZE_T prefixLen = XgsStrLenW(XGS_BACKUP_DIR_NT);
    if (XgsStrLenW(path) >= prefixLen &&
        XgsWcsCaseCmp(path, XGS_BACKUP_DIR_NT, prefixLen))
    {
        return TRUE;
    }
    return FALSE;
}

//
// 构建备份路径: <备份目录><16位十六进制hash>.bak
//
static
VOID
XgsBuildBackupPath(
    _In_ ULONGLONG hash,
    _Out_writes_(buflen) PWCHAR buf,
    _In_ ULONG buflen
    )
{
    static const WCHAR hexDigits[] = L"0123456789ABCDEF";
    static const WCHAR suffix[] = L".bak";
    PCWSTR prefix = XGS_BACKUP_DIR_NT;
    ULONG p = 0;
    ULONG i;

    if (buflen == 0)
    {
        return;
    }

    while (prefix[p] != L'\0' && p + 1 < buflen)
    {
        buf[p] = prefix[p];
        p++;
    }
    for (i = 0; i < 16 && p + 1 < buflen; i++)
    {
        ULONG shift = (ULONG)(60 - i * 4);
        buf[p++] = hexDigits[(hash >> shift) & 0xF];
    }
    for (i = 0; suffix[i] != L'\0' && p + 1 < buflen; i++)
    {
        buf[p++] = suffix[i];
    }
    buf[p] = L'\0';
}

//=============================================================================
// 状态操作
//=============================================================================

//
// 是否已备份 (带锁)
//
static
BOOLEAN
XgsIsBackedUp(
    _In_ ULONGLONG hash
    )
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    for (i = 0; i < g_Xgs.BackedUpCount; i++)
    {
        if (g_Xgs.BackedUpHashes[i] == hash)
        {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return found;
}

//
// 标记已备份 (带锁)
//
static
VOID
XgsMarkBackedUp(
    _In_ ULONGLONG hash
    )
{
    KIRQL irql;
    ULONG i;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    for (i = 0; i < g_Xgs.BackedUpCount; i++)
    {
        if (g_Xgs.BackedUpHashes[i] == hash)
        {
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            return;
        }
    }
    if (g_Xgs.BackedUpCount < XGS_BACKEDUP_MAX)
    {
        g_Xgs.BackedUpHashes[g_Xgs.BackedUpCount++] = hash;
    }
    else
    {
        g_Xgs.BackedUpHashes[g_Xgs.BackedUpHead] = hash;
        g_Xgs.BackedUpHead = (g_Xgs.BackedUpHead + 1) % XGS_BACKEDUP_MAX;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
}

//
// 记录受影响文件 (带锁)
//
static
VOID
XgsRecordModified(
    _In_ PCWSTR originalPath,
    _In_ PCWSTR backupPath,
    _In_ ULONG op
    )
{
    KIRQL irql;
    ULONG idx;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);

    if (g_Xgs.ModifiedCount < XGS_MODIFIED_MAX)
    {
        g_Xgs.ModifiedCount++;
    }
    idx = g_Xgs.ModifiedHead;

    g_Xgs.Modified[idx].Operation = op;
    XgsStrNCpyW(g_Xgs.Modified[idx].OriginalPath, originalPath,
                XGS_MAX_FILE_PATH_LEN);
    if (backupPath != NULL && backupPath[0] != L'\0')
    {
        XgsStrNCpyW(g_Xgs.Modified[idx].BackupPath, backupPath,
                    XGS_MAX_FILE_PATH_LEN);
    }
    else
    {
        g_Xgs.Modified[idx].BackupPath[0] = L'\0';
    }

    g_Xgs.ModifiedHead = (g_Xgs.ModifiedHead + 1) % XGS_MODIFIED_MAX;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
}

//
// 填充通知快照 (调用者已持有锁)
//
static
VOID
XgsFillNotificationLocked(
    VOID
    )
{
    ULONG n;
    ULONG i;

    n = g_Xgs.ModifiedCount;
    if (n > XGS_RANSOM_LIST_MAX)
    {
        n = XGS_RANSOM_LIST_MAX;
    }

    g_Xgs.Notification.HasPending = TRUE;
    g_Xgs.Notification.NotificationId = g_Xgs.NotificationId;
    g_Xgs.Notification.FileCount = n;

    for (i = 0; i < n; i++)
    {
        // 最新在前
        ULONG idx = (g_Xgs.ModifiedHead + XGS_MODIFIED_MAX - 1 - i) %
                    XGS_MODIFIED_MAX;
        g_Xgs.Notification.Files[i] = g_Xgs.Modified[idx];
    }
}

//
// 检测勒索: 记录事件并统计时间窗内次数
// 触发时置 RansomSuspected 并填充通知
//
static
BOOLEAN
XgsCheckSuspicion(
    VOID
    )
{
    ULONGLONG now = XgsNow();
    KIRQL irql;
    ULONG i;
    ULONG count = 0;
    BOOLEAN trigger = FALSE;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);

    if (g_Xgs.RansomSuspected)
    {
        trigger = TRUE;
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
        return trigger;
    }

    g_Xgs.EventTicks[g_Xgs.EventHead] = now;
    g_Xgs.EventHead = (g_Xgs.EventHead + 1) % XGS_DOC_EVENTS_MAX;
    if (g_Xgs.EventCount < XGS_DOC_EVENTS_MAX)
    {
        g_Xgs.EventCount++;
    }

    for (i = 0; i < g_Xgs.EventCount; i++)
    {
        ULONG idx = (g_Xgs.EventHead + XGS_DOC_EVENTS_MAX - g_Xgs.EventCount + i) %
                    XGS_DOC_EVENTS_MAX;
        if ((now - g_Xgs.EventTicks[idx]) <= XGS_WINDOW_100NS)
        {
            count++;
        }
    }

    if (count >= XGS_RANSOM_THRESHOLD)
    {
        g_Xgs.RansomSuspected = TRUE;
        g_Xgs.SuspicionTicks = now;
        g_Xgs.NotificationPending = TRUE;
        g_Xgs.NotificationId++;
        XgsFillNotificationLocked();
        trigger = TRUE;
    }

    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return trigger;
}

//
// 阻断状态自动超时: 无决策 60 秒自动放行
//
static
BOOLEAN
XgsSuspicionTimedOut(
    VOID
    )
{
    ULONGLONG now = XgsNow();
    KIRQL irql;
    BOOLEAN timedOut = FALSE;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (g_Xgs.RansomSuspected &&
        (now - g_Xgs.SuspicionTicks) > XGS_TIMEOUT_100NS)
    {
        g_Xgs.RansomSuspected = FALSE;
        g_Xgs.NotificationPending = FALSE;
        timedOut = TRUE;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return timedOut;
}

//=============================================================================
// 文件复制 (备份/恢复共用)
//=============================================================================

//
// 复制文件内容: src -> dst
// 使用 FILE_NO_INTERMEDIATE_BUFFERING 读取磁盘原始内容,
// 保证备份的是"修改前"版本 (脏缓存不会污染备份)
//
static
NTSTATUS
XgsCopyFile(
    _In_ PCWSTR src,
    _In_ PCWSTR dst,
    _In_ ULONG dstDisposition
    )
{
    UNICODE_STRING su;
    UNICODE_STRING du;
    OBJECT_ATTRIBUTES soa;
    OBJECT_ATTRIBUTES doa;
    IO_STATUS_BLOCK iosb;
    HANDLE hSrc = NULL;
    HANDLE hDst = NULL;
    PVOID rawBuf = NULL;
    PUCHAR alignedBuf = NULL;
    LARGE_INTEGER offset;
    NTSTATUS st;

    RtlInitUnicodeString(&su, src);
    RtlInitUnicodeString(&du, dst);
    InitializeObjectAttributes(&soa, &su,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&doa, &du,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = ZwCreateFile(&hSrc, GENERIC_READ | SYNCHRONIZE, &soa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
                      NULL, 0);
    if (!NT_SUCCESS(st))
    {
        return st;
    }

    st = ZwCreateFile(&hDst, GENERIC_WRITE | SYNCHRONIZE, &doa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, 0,
                      dstDisposition,
                      FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st))
    {
        ZwClose(hSrc);
        return st;
    }

    //
    // 无缓冲读需要扇区对齐的缓冲区, 多分配并手动对齐到 4096
    //
    rawBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, XGS_CHUNK_SIZE + 512, XGS_POOL_TAG);
    if (rawBuf == NULL)
    {
        ZwClose(hSrc);
        ZwClose(hDst);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    alignedBuf = (PUCHAR)ALIGN_UP((ULONG_PTR)rawBuf, 4096);

    offset.QuadPart = 0;
    for (;;)
    {
        ULONG readLen;

        st = ZwReadFile(hSrc, NULL, NULL, NULL, &iosb, alignedBuf,
                        XGS_CHUNK_SIZE, &offset, NULL);
        if (st == STATUS_END_OF_FILE)
        {
            st = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(st))
        {
            break;
        }
        readLen = (ULONG)iosb.Information;
        if (readLen == 0)
        {
            st = STATUS_SUCCESS;
            break;
        }
        st = ZwWriteFile(hDst, NULL, NULL, NULL, &iosb, alignedBuf,
                         readLen, &offset, NULL);
        if (!NT_SUCCESS(st))
        {
            break;
        }
        offset.QuadPart += readLen;
        if (readLen < XGS_CHUNK_SIZE)
        {
            st = STATUS_SUCCESS;
            break;
        }
    }

    ExFreePoolWithTag(rawBuf, XGS_POOL_TAG);
    ZwClose(hSrc);
    ZwClose(hDst);
    return st;
}

//=============================================================================
// 获取文件路径 (打开名, 可重新打开, 代价低)
//=============================================================================

static
BOOLEAN
XgsGetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_writes_(buflen) PWCHAR out,
    _In_ ULONG buflen
    )
{
    NTSTATUS st;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG charCount;

    UNREFERENCED_PARAMETER(FltObjects);

    st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL)
    {
        return FALSE;
    }

    charCount = nameInfo->Name.Length / sizeof(WCHAR);
    if (charCount >= buflen)
    {
        charCount = buflen - 1;
    }
    RtlCopyMemory(out, nameInfo->Name.Buffer, charCount * sizeof(WCHAR));
    out[charCount] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return TRUE;
}

//=============================================================================
// 拒绝当前操作
//=============================================================================

static
FLT_PREOP_CALLBACK_STATUS
XgsDeny(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

//=============================================================================
// 文档操作统一处理 (写/删)
// 备份已在 IRP_MJ_CREATE 预操作中完成, 此处只做计数/记录/阻断判定
//=============================================================================

static
FLT_PREOP_CALLBACK_STATUS
XgsHandleDocOp(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG op
    )
{
    WCHAR path[XGS_MAX_PATH_BUFFER];
    ULONGLONG hash;
    KIRQL irql;
    BOOLEAN suspected;

    if (!XgsGetFilePath(Data, FltObjects, path, XGS_MAX_PATH_BUFFER))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XgsIsBackupDirPath(path) || !XgsIsDocExtension(path))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 持锁期间完成计数 + 读取阻断状态 (自锁内直接操作, 避免嵌套加锁)
    //
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (op == XGS_OP_MODIFY)
    {
        g_Xgs.DocWrites++;
    }
    else
    {
        g_Xgs.DocDeletes++;
    }
    suspected = g_Xgs.RansomSuspected;
    hash = XgsHashPath(path);
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    //
    // 阻断状态处理 (带 60 秒自动放行保护)
    //
    if (suspected)
    {
        if (XgsSuspicionTimedOut())
        {
            suspected = FALSE;   // 超时自动放行, 继续正常处理
        }
        else
        {
            KeAcquireSpinLock(&g_Xgs.Lock, &irql);
            g_Xgs.BlockedOps++;
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            XgsRecordModified(path, L"", op);
            return XgsDeny(Data);
        }
    }

    XgsRecordModified(path, L"", op);

    if (XgsCheckSuspicion())
    {
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        g_Xgs.BlockedOps++;
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
        return XgsDeny(Data);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//=============================================================================
// 预操作回调: 创建 (文档以写/删能力打开时首次备份)
//=============================================================================

static
FLT_PREOP_CALLBACK_STATUS
XgsPreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PIO_SECURITY_CONTEXT secCtx = iopb->Parameters.Create.SecurityContext;
    ULONG options = iopb->Parameters.Create.Options;
    ULONG disposition;
    ACCESS_MASK desired;
    WCHAR path[XGS_MAX_PATH_BUFFER];
    WCHAR backup[XGS_MAX_PATH_BUFFER];
    ULONGLONG hash;
    KIRQL irql;
    ULONG i;
    BOOLEAN restoring;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 恢复文件进行中: 所有打开放行
    //
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 新建文件 (FILE_CREATE) 无原始内容可备份
    //
    disposition = (options >> 24) & 0xFF;
    if (disposition == FILE_CREATE)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 无安全上下文 (内核创建) 或非写/删能力打开 -> 不处理
    //
    if (secCtx == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    desired = secCtx->DesiredAccess;
    if (!(desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!XgsGetFilePath(Data, FltObjects, path, XGS_MAX_PATH_BUFFER))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (XgsIsBackupDirPath(path) || !XgsIsDocExtension(path))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    hash = XgsHashPath(path);

    //
    // 持锁检查是否已备份过
    //
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    for (i = 0; i < g_Xgs.BackedUpCount; i++)
    {
        if (g_Xgs.BackedUpHashes[i] == hash)
        {
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    //
    // 执行备份 (源文件不存在时 FILE_OPEN 失败, 忽略即可)
    //
    XgsBuildBackupPath(hash, backup, XGS_MAX_PATH_BUFFER);
    st = XgsCopyFile(path, backup, FILE_CREATE);
    if (NT_SUCCESS(st))
    {
        XgsMarkBackedUp(hash);
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        g_Xgs.BackupsCreated++;
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//=============================================================================
// 预操作回调: 写
//=============================================================================

static
FLT_PREOP_CALLBACK_STATUS
XgsPreWrite(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    KIRQL irql;
    BOOLEAN restoring;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (iopb->Parameters.Write.Length == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 分页 IO / 非 PASSIVE 一律不处理 (防止递归与死锁)
    //
    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        (iopb->IrpFlags & IRP_PAGING_IO))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // 恢复文件进行中: 放行
    //
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return XgsHandleDocOp(Data, FltObjects, XGS_OP_MODIFY);
}

//=============================================================================
// 预操作回调: 设置文件信息 (仅处理删除)
//=============================================================================

static
FLT_PREOP_CALLBACK_STATUS
XgsPreSetInformation(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PFILE_DISPOSITION_INFORMATION dispInfo;
    KIRQL irql;
    BOOLEAN restoring;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (iopb->Parameters.SetFileInformation.FileInformationClass !=
            FileDispositionInformation)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    dispInfo = (PFILE_DISPOSITION_INFORMATION)
        iopb->Parameters.SetFileInformation.InfoBuffer;
    if (dispInfo == NULL || !dispInfo->DeleteFile)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return XgsHandleDocOp(Data, FltObjects, XGS_OP_DELETE);
}

//=============================================================================
// 过滤操作注册表
//=============================================================================

static
const
FLT_OPERATION_REGISTRATION
XgsCallbacks[] =
{
    { IRP_MJ_CREATE, 0, XgsPreCreate, NULL, NULL },
    { IRP_MJ_WRITE, 0, XgsPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, XgsPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static
const
FLT_REGISTRATION
XgsReg =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                        // Flags
    NULL,                     // ContextRegistration
    XgsCallbacks,             // OperationRegistration
    NULL,                     // FilterUnloadCallback (由 XgsUnload 手动 FltUnregisterFilter)
    NULL,                     // InstanceSetupCallback
    NULL,                     // InstanceQueryTeardownCallback
    NULL,                     // InstanceTeardownStartCallback
    NULL,                     // InstanceTeardownCompleteCallback
    NULL,                     // GenerateFileNameCallback
    NULL,                     // NormalizeNameComponentCallback
    NULL,                     // NormalizeContextCleanupCallback
    NULL,                     // TransactionNotificationCallback
    NULL,                     // NormalizeNameComponentExCallback
    NULL                      // SectionNotificationCallback
};

//=============================================================================
// HMAC-SHA256 (BCrypt)
//=============================================================================

static
NTSTATUS
XgsHmac(
    _In_reads_bytes_(dataLen) const UCHAR* data,
    _In_ ULONG dataLen,
    _Out_writes_bytes_(AV_HASH_SIZE) UCHAR* out
    )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st))
    {
        return st;
    }
    st = BCryptCreateHash(alg, &hash, NULL, 0,
                          (PUCHAR)AV_SHARED_KEY, AV_SHARED_KEY_SIZE, 0);
    if (!NT_SUCCESS(st))
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }
    st = BCryptHashData(hash, (PUCHAR)data, dataLen, 0);
    if (!NT_SUCCESS(st))
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }
    st = BCryptFinishHash(hash, out, AV_HASH_SIZE, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st;
}

//=============================================================================
// IOCTL 处理 (传统 IRP, METHOD_BUFFERED)
//=============================================================================

//
// 恢复文件 (从备份复制回原路径)
// 调用前必须已置 g_Xgs.Restoring = TRUE
//
static
VOID
XgsRestoreFiles(
    VOID
    );

static
BOOLEAN
XgsIsAuthed(
    VOID
    )
{
    KIRQL irql;
    BOOLEAN authed;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    authed = g_Xgs.Authed;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return authed;
}

static
NTSTATUS
XgsIoctlAuthInit(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    AV_AUTH_CHALLENGE* out = (AV_AUTH_CHALLENGE*)systemBuffer;
    NTSTATUS st;
    KIRQL irql;
    BCRYPT_ALG_HANDLE hRng = NULL;

    KdPrint(("XGS: XgsIoctlAuthInit ENTER, outLen=%lu\n", outLen));

    *info = 0;

    if (outLen < sizeof(AV_AUTH_CHALLENGE))
    {
        KdPrint(("XGS: XgsIoctlAuthInit -> BUFFER_TOO_SMALL\n"));
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // 打开 RNG 算法提供者（不能传 NULL，某些内核配置下会返回 STATUS_INVALID_HANDLE）
    //
    st = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGS: BCryptOpenAlgorithmProvider(RNG) failed 0x%08lX\n", st));
        return st;
    }

    st = BCryptGenRandom(hRng, g_Xgs.Challenge, AV_CHALLENGE_SIZE, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);

    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGS: BCryptGenRandom failed 0x%08lX\n", st));
        return st;
    }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    g_Xgs.ChallengeSeq++;
    g_Xgs.ChallengeValid = TRUE;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    out->SequenceId = g_Xgs.ChallengeSeq;
    RtlCopyMemory(out->Challenge, g_Xgs.Challenge, AV_CHALLENGE_SIZE);
    *info = sizeof(AV_AUTH_CHALLENGE);
    KdPrint(("XGS: XgsIoctlAuthInit -> SUCCESS, seq=%llu\n", g_Xgs.ChallengeSeq));
    return STATUS_SUCCESS;
}

static
NTSTATUS
XgsIoctlAuthVerify(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    AV_AUTH_RESPONSE resp;        // 本地副本 (METHOD_BUFFERED 输入输出共用缓冲!)
    AV_AUTH_RESULT* out;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    UCHAR hmac[AV_HASH_SIZE];
    NTSTATUS st = STATUS_SUCCESS;
    BOOLEAN valid = FALSE;
    KIRQL irql;

    *info = 0;

    if (inLen < sizeof(AV_AUTH_RESPONSE) ||
        outLen < sizeof(AV_AUTH_RESULT))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&resp, systemBuffer, sizeof(AV_AUTH_RESPONSE));

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (g_Xgs.ChallengeValid && resp.SequenceId == g_Xgs.ChallengeSeq)
    {
        valid = TRUE;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    if (valid)
    {
        RtlCopyMemory(hmacInput, g_Xgs.Challenge, AV_CHALLENGE_SIZE);
        RtlCopyMemory(hmacInput + AV_CHALLENGE_SIZE, &resp.SequenceId,
                      sizeof(UINT64));
        st = XgsHmac(hmacInput, sizeof(hmacInput), hmac);
        if (NT_SUCCESS(st) &&
            RtlEqualMemory(hmac, resp.Hmac, AV_HASH_SIZE))
        {
            KeAcquireSpinLock(&g_Xgs.Lock, &irql);
            g_Xgs.Authed = TRUE;
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
        }
        else
        {
            st = STATUS_SUCCESS;   // 继续走失败输出
            valid = FALSE;
        }
    }

    out = (AV_AUTH_RESULT*)systemBuffer;
    if (valid)
    {
        out->Status = STATUS_SUCCESS;
        RtlCopyMemory(out->SessionId, hmac, AV_SESSION_ID_SIZE);
    }
    else
    {
        out->Status = STATUS_ACCESS_DENIED;
        RtlZeroMemory(out->SessionId, AV_SESSION_ID_SIZE);
    }
    *info = sizeof(AV_AUTH_RESULT);
    return st;
}

static
NTSTATUS
XgsIoctlGetNotification(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    XGS_RANSOM_NOTIFICATION* out = (XGS_RANSOM_NOTIFICATION*)systemBuffer;
    KIRQL irql;

    *info = 0;

    if (outLen < sizeof(XGS_RANSOM_NOTIFICATION))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    RtlCopyMemory(out, &g_Xgs.Notification, sizeof(XGS_RANSOM_NOTIFICATION));
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    *info = sizeof(XGS_RANSOM_NOTIFICATION);
    return STATUS_SUCCESS;
}

static
NTSTATUS
XgsIoctlSendDecision(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _Out_ PULONG info
    )
{
    XGS_RANSOM_DECISION decision;
    KIRQL irql;
    BOOLEAN doRestore = FALSE;
    NTSTATUS st = STATUS_SUCCESS;

    *info = 0;

    if (inLen < sizeof(XGS_RANSOM_DECISION))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&decision, systemBuffer, sizeof(XGS_RANSOM_DECISION));

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (g_Xgs.NotificationPending &&
        decision.NotificationId == g_Xgs.Notification.NotificationId)
    {
        switch (decision.Decision)
        {
        case XGS_DECISION_ALLOW:
            g_Xgs.RansomSuspected = FALSE;
            g_Xgs.NotificationPending = FALSE;
            break;

        case XGS_DECISION_STAY_BLOCK:
            g_Xgs.NotificationPending = FALSE;
            break;

        case XGS_DECISION_RESTORE:
            g_Xgs.RansomSuspected = FALSE;
            g_Xgs.NotificationPending = FALSE;
            g_Xgs.Restoring = TRUE;
            doRestore = TRUE;
            break;

        default:
            st = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    else
    {
        st = STATUS_NOT_FOUND;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    //
    // 恢复文件 (从备份目录复制回原路径)
    // Restoring 标志使恢复写入豁免过滤, 完成后清除
    //
    if (doRestore)
    {
        XgsRestoreFiles();
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        g_Xgs.Restoring = FALSE;
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
    }

    return st;
}

static
NTSTATUS
XgsIoctlGetModifiedFile(
    _In_ PVOID systemBuffer,
    _In_ ULONG inLen,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    UINT32 index;
    XGS_MODIFIED_FILE* out;
    KIRQL irql;

    *info = 0;

    if (inLen < sizeof(UINT32) || outLen < sizeof(XGS_MODIFIED_FILE))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(&index, systemBuffer, sizeof(index));

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (index >= g_Xgs.ModifiedCount)
    {
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
        return STATUS_NOT_FOUND;
    }
    out = (XGS_MODIFIED_FILE*)systemBuffer;
    RtlCopyMemory(out, &g_Xgs.Modified[index], sizeof(XGS_MODIFIED_FILE));
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    *info = sizeof(XGS_MODIFIED_FILE);
    return STATUS_SUCCESS;
}

static
NTSTATUS
XgsIoctlGetStatus(
    _In_ PVOID systemBuffer,
    _In_ ULONG outLen,
    _Out_ PULONG info
    )
{
    XGS_STATUS* out = (XGS_STATUS*)systemBuffer;
    KIRQL irql;

    *info = 0;

    if (outLen < sizeof(XGS_STATUS))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    out->Version = 1;
    out->RansomSuspected = g_Xgs.RansomSuspected ? 1 : 0;
    out->DocWrites = g_Xgs.DocWrites;
    out->DocDeletes = g_Xgs.DocDeletes;
    out->BackupsCreated = g_Xgs.BackupsCreated;
    out->PendingNotification = g_Xgs.NotificationPending ? 1 : 0;
    out->ModifiedCount = g_Xgs.ModifiedCount;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    *info = sizeof(XGS_STATUS);
    return STATUS_SUCCESS;
}

//=============================================================================
// 恢复文件 (从备份复制回原路径)
// 调用前必须已置 g_Xgs.Restoring = TRUE
//=============================================================================

static
VOID
XgsRestoreFiles(
    VOID
    )
{
    KIRQL irql;
    UINT32 count;
    UINT32 i;
    WCHAR original[XGS_MAX_PATH_BUFFER];
    WCHAR backup[XGS_MAX_PATH_BUFFER];
    NTSTATUS st;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    count = g_Xgs.ModifiedCount;
    if (count > XGS_MODIFIED_MAX)
    {
        count = XGS_MODIFIED_MAX;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    for (i = 0; i < count; i++)
    {
        BOOLEAN canRestore = FALSE;

        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        if (g_Xgs.Modified[i].Operation == XGS_OP_MODIFY &&
            g_Xgs.Modified[i].BackupPath[0] != L'\0')
        {
            XgsStrNCpyW(original, g_Xgs.Modified[i].OriginalPath,
                        XGS_MAX_PATH_BUFFER);
            XgsStrNCpyW(backup, g_Xgs.Modified[i].BackupPath,
                        XGS_MAX_PATH_BUFFER);
            canRestore = TRUE;
        }
        KeReleaseSpinLock(&g_Xgs.Lock, irql);

        if (canRestore)
        {
            st = XgsCopyFile(backup, original, FILE_OVERWRITE_IF);
            if (!NT_SUCCESS(st))
            {
                KdPrint(("XGSRansomFilter: restore %ws failed 0x%08X\n",
                         original, st));
            }
        }
    }
}

//=============================================================================
// 传统控制设备
//=============================================================================

static
NTSTATUS
XgsDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static
NTSTATUS
XgsDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (systemBuffer == NULL)
    {
        st = STATUS_INVALID_PARAMETER;
    }
    else
    {
        switch (ctl)
        {
        case IOCTL_XGS_AUTH_INIT:
            st = XgsIoctlAuthInit(systemBuffer, outLen, &info);
            break;

        case IOCTL_XGS_AUTH_VERIFY:
            st = XgsIoctlAuthVerify(systemBuffer, inLen, outLen, &info);
            break;

        case IOCTL_XGS_GET_NOTIFICATION:
            if (!XgsIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = XgsIoctlGetNotification(systemBuffer, outLen, &info);
            }
            break;

        case IOCTL_XGS_SEND_DECISION:
            if (!XgsIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = XgsIoctlSendDecision(systemBuffer, inLen, &info);
            }
            break;

        case IOCTL_XGS_GET_MODIFIED_FILE:
            if (!XgsIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = XgsIoctlGetModifiedFile(systemBuffer, inLen, outLen, &info);
            }
            break;

        case IOCTL_XGS_GET_STATUS:
            if (!XgsIsAuthed())
            {
                st = STATUS_ACCESS_DENIED;
            }
            else
            {
                st = XgsIoctlGetStatus(systemBuffer, outLen, &info);
            }
            break;

        default:
            st = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

//
// 删除控制设备 (卸载/初始化失败时)
//
static
VOID
XgsDeleteControlDevice(
    VOID
    )
{
    UNICODE_STRING symlinkName;

    if (g_ControlDevice == NULL)
    {
        return;
    }

    RtlInitUnicodeString(&symlinkName, XGS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(g_ControlDevice);
    g_ControlDevice = NULL;
}

//
// 创建控制设备 (传统 IoCreateDeviceSecure)
//
static
NTSTATUS
XgsCreateControlDevice(
    VOID
    )
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT device = NULL;
    NTSTATUS st;

    RtlInitUnicodeString(&deviceName, XGS_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, XGS_SYMLINK_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    st = IoCreateDeviceSecure(g_DriverObject,
                              sizeof(XGS_DEVICE_EXTENSION),
                              &deviceName,
                              FILE_DEVICE_UNKNOWN,
                              0,
                              FALSE,
                              &sddl,
                              NULL,
                              &device);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSRansomFilter: IoCreateDeviceSecure failed 0x%08X\n", st));
        return st;
    }

    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    st = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(st))
    {
        IoDeleteDevice(device);
        KdPrint(("XGSRansomFilter: IoCreateSymbolicLink failed 0x%08X\n", st));
        return st;
    }

    g_ControlDevice = device;
    return STATUS_SUCCESS;
}

//=============================================================================
// 备份目录创建
//=============================================================================

NTSTATUS
XgsCreateBackupDirectory(
    VOID
    )
{
    UNICODE_STRING dirPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDir = NULL;
    NTSTATUS st;
    static const WCHAR* const dirs[] =
    {
        L"\\??\\C:\\Windows\\Temp\\XGS",
        L"\\??\\C:\\Windows\\Temp\\XGS\\Backup"
    };
    ULONG i;

    for (i = 0; i < ARRAYSIZE(dirs); i++)
    {
        RtlInitUnicodeString(&dirPath, dirs[i]);
        InitializeObjectAttributes(&oa, &dirPath,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = ZwCreateFile(&hDir, GENERIC_WRITE, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, 0,
                          FILE_CREATE,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                          NULL, 0);
        if (!NT_SUCCESS(st) && st != STATUS_OBJECT_NAME_COLLISION)
        {
            return st;
        }
        if (hDir != NULL)
        {
            ZwClose(hDir);
            hDir = NULL;
        }
    }
    return STATUS_SUCCESS;
}

//=============================================================================
// 驱动卸载
//=============================================================================

VOID
XgsUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    KdPrint(("XGSRansomFilter: Unload\n"));

    if (g_XgsFilter != NULL)
    {
        FltUnregisterFilter(g_XgsFilter);
        g_XgsFilter = NULL;
    }

    XgsDeleteControlDevice();
}

//=============================================================================
// DriverEntry
//=============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("XGSRansomFilter: DriverEntry\n"));

    g_DriverObject = DriverObject;
    KeInitializeSpinLock(&g_Xgs.Lock);

    DriverObject->DriverUnload = XgsUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = XgsDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = XgsDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XgsDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XgsDispatchDeviceControl;

    st = XgsCreateControlDevice();
    if (!NT_SUCCESS(st))
    {
        return st;
    }

    //
    // 备份目录创建失败不致命 (写入时会重试)
    //
    XgsCreateBackupDirectory();

    st = FltRegisterFilter(DriverObject, &XgsReg, &g_XgsFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSRansomFilter: FltRegisterFilter failed 0x%08X\n", st));
        XgsDeleteControlDevice();
        return st;
    }

    st = FltStartFiltering(g_XgsFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGSRansomFilter: FltStartFiltering failed 0x%08X\n", st));
        FltUnregisterFilter(g_XgsFilter);
        g_XgsFilter = NULL;
        XgsDeleteControlDevice();
        return st;
    }

    KdPrint(("XGSRansomFilter: DriverEntry completed\n"));
    return STATUS_SUCCESS;
}
