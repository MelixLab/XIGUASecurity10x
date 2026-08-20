//=============================================================================
// XGSRansomFilter.c - XIGUASecurity 勒索防护过滤驱动 (多维行为检测引擎)
//
// 核心改进 (相比旧版):
//   1. 进程级跟踪: 每个进程独立计分, 消除多进程合法操作累积导致的误报
//   2. 多维评分系统: 8 种行为信号加权评分, 单一信号不足以触发阻断
//   3. 熵分析: 采样写入缓冲区, 检测高熵数据 (疑似加密)
//   4. 文件重命名监控: 检测扩展名变更 (勒索软件强特征, +35 分/次)
//   5. 滑动窗口: 60 秒窗口内行为计数, 旧数据自动过期
//   6. 进程级阻断: 仅阻断触发进程, 不影响其他进程正常工作
//
// 评分规则 (每进程, 60 秒滑动窗口):
//   - 扩展名变更:     +35/次 (极强信号)
//   - 高熵写入:       +15/次 (上限 60, 疑似加密)
//   - 大量修改:       +20 基础 + 2/文件 (>10 文件/30 秒)
//   - 大量删除:       +15 基础 + 2/文件 (>8 文件/30 秒)
//   - 大量重命名:     +25 基础 + 3/文件 (>5 文件/30 秒)
//   - 文件类型多样性: +15 (>5 种类型/30 秒)
//   - 目录多样性:     +10 (>8 个目录/30 秒)
//   - 快速连续写入:   +10 (>30 次/60 秒)
//   阈值: 100 分 → 阻断 + 通知用户态
//
// 文件系统微过滤器 + 传统控制设备 (IoCreateDeviceSecure)
// IOCTL 采用 METHOD_BUFFERED, Challenge-Response + HMAC-SHA256 双向鉴权
//=============================================================================

#include "XIGUAFileProtect.h"
#include "../AVCommon/AVPoolCompat.h"

//=============================================================================
// 全局状态
//=============================================================================
static PDRIVER_OBJECT g_DriverObject = NULL;
static PFLT_FILTER g_XgsFilter = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;

typedef struct _XGS_DEVICE_EXTENSION
{
    BOOLEAN Dummy;
} XGS_DEVICE_EXTENSION;

static XGS_GLOBAL_STATE g_Xgs = { 0 };

//=============================================================================
// 操作事件编码 (存入 OpTimes 环, 低 3 位为操作类型)
//=============================================================================
#define XGS_OP_WRITE      1
#define XGS_OP_DELETE     2
#define XGS_OP_RENAME     3
#define XGS_OP_EXT_CHG    4
#define XGS_OP_ENTROPY    5

#define XGS_ENCODE_OP(ts, op)  (((ts) << 3) | ((ULONGLONG)(op) & 0x7))
#define XGS_OP_TIME(enc)       ((enc) >> 3)
#define XGS_OP_TYPE(enc)       ((UINT32)((enc) & 0x7))

//=============================================================================
// 文档扩展名表 (小写, 含点)
// 包含媒体文件 (.jpg, .png, .mp4 等), 排除数据库文件
//=============================================================================
static const WCHAR* const g_DocExts[] =
{
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".pdf",
    L".txt", L".rtf",
    L".odt", L".ods", L".odp",
    L".csv", L".md",
    L".wps", L".et", L".dps",
    L".eml", L".msg", L".one",
    L".vsd", L".vsdx",
    L".zip", L".rar", L".7z",
    L".jpg", L".jpeg", L".png", L".bmp", L".gif", L".tiff",
    L".mp3", L".mp4", L".avi", L".mkv",
    L".pst"
};

//
// 数据库文件排除表 (不监控, 不备份)
//
static const WCHAR* const g_DbExts[] =
{
    L".sql", L".db", L".dbf", L".mdb", L".accdb"
};

//
// 已压缩/二进制文件类型 (熵分析跳过, 避免对已压缩文件误报)
// 这些格式保存时内容熵值天然高 (内部压缩流/OLE 复合文档),
// 若参与熵评分会导致正常保存操作误报。
//
static const WCHAR* const g_CompressedExts[] =
{
    L".docx", L".xlsx", L".pptx",
    L".doc", L".xls", L".ppt",
    L".pdf",
    L".zip", L".rar", L".7z",
    L".jpg", L".jpeg", L".png", L".gif",
    L".mp3", L".mp4", L".avi", L".mkv",
    L".odt", L".ods", L".odp",
    L".wps", L".et", L".dps",
    L".pst", L".eml", L".msg"
};

//=============================================================================
// 小型工具函数
//=============================================================================

static ULONGLONG XgsNow(VOID)
{
    return KeQueryUnbiasedInterruptTime();
}

static SIZE_T XgsStrLenW(_In_ PCWSTR s)
{
    SIZE_T n = 0;
    while (s[n] != L'\0') n++;
    return n;
}

static VOID XgsStrNCpyW(_Out_writes_(maxChars) PWCHAR dst, _In_ PCWSTR src, _In_ SIZE_T maxChars)
{
    SIZE_T i;
    if (maxChars == 0) return;
    for (i = 0; i + 1 < maxChars && src[i] != L'\0'; i++)
        dst[i] = src[i];
    dst[i] = L'\0';
}

static BOOLEAN XgsWcsCaseCmp(_In_ PCWSTR a, _In_ PCWSTR b, _In_ SIZE_T n)
{
    SIZE_T i;
    for (i = 0; i < n; i++)
    {
        WCHAR ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return FALSE;
    }
    return TRUE;
}

static ULONGLONG XgsHashPath(_In_ PCWSTR path)
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

static ULONGLONG XgsHashShort(_In_ PCWSTR s, _In_ SIZE_T len)
{
    ULONGLONG h = 1469598103934665603ULL;
    SIZE_T i;
    for (i = 0; i < len; i++)
    {
        WCHAR c = s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        h ^= (ULONGLONG)c;
        h *= 1099511628211ULL;
    }
    return h;
}

//
// 从路径中提取扩展名 (含点, 如 ".docx")
//
static PCWSTR XgsGetExtension(_In_ PCWSTR path, _In_ SIZE_T len)
{
    SIZE_T i;
    if (len < 2) return NULL;
    for (i = len; i > 0; i--)
    {
        WCHAR c = path[i - 1];
        if (c == L'.') return &path[i - 1];
        if (c == L'\\' || c == L'/') break;
    }
    return NULL;
}

//
// 从可能相对路径的名称中提取扩展名
//
static PCWSTR XgsGetExtFromName(_In_ PCWSTR name, _In_ ULONG nameChars)
{
    LONG i;
    if (nameChars == 0) return NULL;
    for (i = (LONG)nameChars - 1; i >= 0; i--)
    {
        WCHAR c = name[i];
        if (c == L'.') return &name[i];
        if (c == L'\\' || c == L'/') break;
    }
    return NULL;
}

static VOID XgsAnsiToWide(_Out_writes_(maxChars) PWCHAR dst, _In_ PCCHAR src, _In_ SIZE_T maxChars)
{
    SIZE_T i;
    if (maxChars == 0) return;
    for (i = 0; i + 1 < maxChars && src[i] != '\0'; i++)
        dst[i] = (WCHAR)(UCHAR)src[i];
    dst[i] = L'\0';
}

static BOOLEAN XgsMatchExtList(_In_ PCWSTR path, _In_ const WCHAR* const exts[], _In_ ULONG count)
{
    SIZE_T len = XgsStrLenW(path);
    ULONG i;
    if (len < 2 || path[len - 1] == L'\\') return FALSE;
    for (i = 0; i < count; i++)
    {
        SIZE_T el = XgsStrLenW(exts[i]);
        if (len >= el && XgsWcsCaseCmp(path + len - el, exts[i], el))
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN XgsIsDocExtension(_In_ PCWSTR path)
{
    return XgsMatchExtList(path, g_DocExts, ARRAYSIZE(g_DocExts));
}

static BOOLEAN XgsIsDatabaseFile(_In_ PCWSTR path)
{
    return XgsMatchExtList(path, g_DbExts, ARRAYSIZE(g_DbExts));
}

static BOOLEAN XgsIsCompressedType(_In_ PCWSTR path)
{
    return XgsMatchExtList(path, g_CompressedExts, ARRAYSIZE(g_CompressedExts));
}

static BOOLEAN XgsIsBackupDirPath(_In_ PCWSTR path)
{
    SIZE_T prefixLen = XgsStrLenW(XGS_BACKUP_DIR_NT);
    if (XgsStrLenW(path) >= prefixLen && XgsWcsCaseCmp(path, XGS_BACKUP_DIR_NT, prefixLen))
        return TRUE;
    return FALSE;
}

//=============================================================================
// XgsIsSystemProcessName - 是否为系统组件进程 (不参与勒索评分)
//
// 系统组件 (OneDrive 同步、搜索索引、后台服务等) 写文档属正常行为,
// 参与评分会产生大量误报。勒索软件不是系统进程, 排除不影响检测。
// 仅匹配进程名 (不区分路径), 但系统组件进程名被滥用时由行为规则兜底。
//=============================================================================
static BOOLEAN XgsIsSystemProcessName(_In_ PCWSTR name)
{
    static const WCHAR* const sysNames[] =
    {
        L"svchost.exe", L"System", L"explorer.exe", L"SearchIndexer.exe",
        L"SearchProtocolHost.exe", L"SearchFilterHost.exe", L"RuntimeBroker.exe",
        L"OneDrive.exe", L"dllhost.exe", L"MsMpEng.exe", L"WmiPrvSE.exe",
        L"smartscreen.exe", L"dwm.exe", L"csrss.exe", L"wininit.exe",
        L"services.exe", L"lsass.exe", L"taskhostw.exe", L"WUDFHost.exe",
        L"ShellExperienceHost.exe", L"StartMenuExperienceHost.exe",
        L"conhost.exe", L"winlogon.exe"
    };
    ULONG i;
    if (name == NULL || name[0] == L'\0')
        return FALSE;
    for (i = 0; i < ARRAYSIZE(sysNames); i++)
    {
        if (XgsWcsCaseCmp(name, sysNames[i], XgsStrLenW(sysNames[i])) == 0 &&
            XgsStrLenW(name) == XgsStrLenW(sysNames[i]))
            return TRUE;
    }
    return FALSE;
}

static VOID XgsBuildBackupPath(_In_ ULONGLONG hash, _Out_writes_(buflen) PWCHAR buf, _In_ ULONG buflen)
{
    static const WCHAR hexDigits[] = L"0123456789ABCDEF";
    static const WCHAR suffix[] = L".bak";
    PCWSTR prefix = XGS_BACKUP_DIR_NT;
    ULONG p = 0, i;

    if (buflen == 0) return;
    while (prefix[p] != L'\0' && p + 1 < buflen) { buf[p] = prefix[p]; p++; }
    for (i = 0; i < 16 && p + 1 < buflen; i++)
    {
        ULONG shift = (ULONG)(60 - i * 4);
        buf[p++] = hexDigits[(hash >> shift) & 0xF];
    }
    for (i = 0; suffix[i] != L'\0' && p + 1 < buflen; i++)
        buf[p++] = suffix[i];
    buf[p] = L'\0';
}

//=============================================================================
// 随机性/熵分析 (纯整数运算, 无浮点, 适合内核)
//
// 返回 0-255 的随机性分数:
//   - 唯一字节数 (0-128): 256 种字节值中出现多少种
//   - 均匀度 (0-127): 最大字节频率与期望频率的比值
//   加密数据 ~250+, 压缩数据 ~235+, 文本数据 ~50-100
//=============================================================================

static UINT32
XgsCalculateRandomness(_In_reads_bytes_(length) PUCHAR data, _In_ ULONG length)
{
    ULONG freq[256];
    ULONG i;
    UINT32 uniqueValues = 0;
    UINT32 maxFreq = 0;
    UINT32 expectedFreq;
    UINT32 score;

    RtlZeroMemory(freq, sizeof(freq));

    for (i = 0; i < length; i++)
        freq[data[i]]++;

    for (i = 0; i < 256; i++)
    {
        if (freq[i] > 0) uniqueValues++;
        if (freq[i] > maxFreq) maxFreq = freq[i];
    }

    score = (uniqueValues * 128) / 256;

    expectedFreq = length / 256;
    if (expectedFreq == 0) expectedFreq = 1;

    if (maxFreq <= expectedFreq * 2)
        score += 127;
    else if (maxFreq <= expectedFreq * 4)
        score += 80;
    else if (maxFreq <= expectedFreq * 8)
        score += 40;

    return score;
}

//
// 检查写入缓冲区的随机性
// 返回 TRUE 如果检测到高熵写入 (疑似加密)
//
static BOOLEAN
XgsCheckWriteEntropy(_In_ PFLT_CALLBACK_DATA Data)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    ULONG writeLength = iopb->Parameters.Write.Length;
    PUCHAR buffer = NULL;
    ULONG sampleLen;
    UINT32 randomness;

    if (writeLength < XGS_ENTROPY_SAMPLE_MIN)
        return FALSE;

    if (iopb->Parameters.Write.MdlAddress != NULL)
    {
        buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(
            iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    }
    else if (iopb->Parameters.Write.WriteBuffer != NULL)
    {
        buffer = (PUCHAR)iopb->Parameters.Write.WriteBuffer;
    }

    if (buffer == NULL)
        return FALSE;

    sampleLen = writeLength;
    if (sampleLen > XGS_ENTROPY_SAMPLE_MAX)
        sampleLen = XGS_ENTROPY_SAMPLE_MAX;

    randomness = XgsCalculateRandomness(buffer, sampleLen);

    if (randomness >= XGS_ENTROPY_THRESHOLD)
    {
        KdPrint(("XGS: Entropy alert! randomness=%u (threshold=%u) len=%lu\n",
                 randomness, XGS_ENTROPY_THRESHOLD, writeLength));
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// 进程跟踪 (调用者持锁)
//=============================================================================

static XGS_PROCESS_ENTRY*
XgsFindProcessLocked(_In_ HANDLE pid)
{
    ULONG i;
    for (i = 0; i < XGS_PROCESS_TABLE_SIZE; i++)
    {
        if (g_Xgs.Processes[i].IsActive && g_Xgs.Processes[i].ProcessId == pid)
            return &g_Xgs.Processes[i];
    }
    return NULL;
}

static XGS_PROCESS_ENTRY*
XgsAddProcessLocked(_In_ HANDLE pid, _In_ ULONGLONG now)
{
    ULONG i;
    ULONG oldestIdx = 0;
    ULONGLONG oldestTime = MAXULONG64;

    // 优先使用空闲槽
    for (i = 0; i < XGS_PROCESS_TABLE_SIZE; i++)
    {
        if (!g_Xgs.Processes[i].IsActive)
        {
            RtlZeroMemory(&g_Xgs.Processes[i], sizeof(XGS_PROCESS_ENTRY));
            g_Xgs.Processes[i].IsActive = TRUE;
            g_Xgs.Processes[i].ProcessId = pid;
            g_Xgs.Processes[i].FirstOpTime = now;
            g_Xgs.Processes[i].LastOpTime = now;
            g_Xgs.ActiveProcessCount++;
            KdPrint(("XGS: New process tracked PID=%p (slot %lu, total %lu)\n",
                     pid, i, g_Xgs.ActiveProcessCount));
            return &g_Xgs.Processes[i];
        }
    }

    // 表满, 替换最久未活动的条目
    for (i = 0; i < XGS_PROCESS_TABLE_SIZE; i++)
    {
        if (g_Xgs.Processes[i].LastOpTime < oldestTime)
        {
            oldestTime = g_Xgs.Processes[i].LastOpTime;
            oldestIdx = i;
        }
    }

    if (g_Xgs.Processes[oldestIdx].IsBlocked)
        g_Xgs.BlockedProcessCount--;

    RtlZeroMemory(&g_Xgs.Processes[oldestIdx], sizeof(XGS_PROCESS_ENTRY));
    g_Xgs.Processes[oldestIdx].IsActive = TRUE;
    g_Xgs.Processes[oldestIdx].ProcessId = pid;
    g_Xgs.Processes[oldestIdx].FirstOpTime = now;
    g_Xgs.Processes[oldestIdx].LastOpTime = now;

    KdPrint(("XGS: Process table full, replaced slot %lu with PID=%p\n",
             oldestIdx, pid));
    return &g_Xgs.Processes[oldestIdx];
}

//
// 添加操作事件到时间戳环
//
static VOID
XgsAddOpEventLocked(_In_ XGS_PROCESS_ENTRY* entry, _In_ ULONGLONG now, _In_ UINT32 opType)
{
    entry->OpTimes[entry->OpTimeHead] = XGS_ENCODE_OP(now, opType);
    entry->OpTimeHead = (entry->OpTimeHead + 1) % XGS_OP_TIMES_MAX;
    if (entry->OpTimeCount < XGS_OP_TIMES_MAX)
        entry->OpTimeCount++;
    entry->LastOpTime = now;
}

//
// 更新目录/扩展名多样性
//
static VOID
XgsUpdateDiversityLocked(
    _In_ XGS_PROCESS_ENTRY* entry,
    _In_ ULONGLONG dirHash,
    _In_ ULONGLONG extHash
    )
{
    ULONG i;
    BOOLEAN dirFound = FALSE;
    BOOLEAN extFound = FALSE;

    for (i = 0; i < XGS_DIVERSITY_SLOTS; i++)
    {
        if (entry->DirHashes[i] == dirHash && dirHash != 0)
            dirFound = TRUE;
        if (entry->ExtHashes[i] == extHash && extHash != 0)
            extFound = TRUE;
    }

    if (!dirFound && dirHash != 0)
    {
        for (i = 0; i < XGS_DIVERSITY_SLOTS; i++)
        {
            if (entry->DirHashes[i] == 0)
            {
                entry->DirHashes[i] = dirHash;
                entry->DirCount++;
                break;
            }
        }
    }

    if (!extFound && extHash != 0)
    {
        for (i = 0; i < XGS_DIVERSITY_SLOTS; i++)
        {
            if (entry->ExtHashes[i] == 0)
            {
                entry->ExtHashes[i] = extHash;
                entry->ExtTypeCount++;
                break;
            }
        }
    }
}

//
// 提取目录路径哈希 (去掉文件名, 保留目录部分)
//
static ULONGLONG
XgsHashDirectory(_In_ PCWSTR path, _In_ SIZE_T len)
{
    SIZE_T i;
    SIZE_T dirEnd = 0;
    for (i = len; i > 0; i--)
    {
        if (path[i - 1] == L'\\' || path[i - 1] == L'/')
        {
            dirEnd = i - 1;
            break;
        }
    }
    if (dirEnd == 0) return 0;
    return XgsHashShort(path, dirEnd);
}

//=============================================================================
// 评分引擎 (调用者持锁)
//
// 扫描操作时间戳环, 统计窗口内各类操作次数, 应用评分规则
// 返回 TRUE 如果威胁评分达到阈值
//=============================================================================

static BOOLEAN
XgsEvaluateThreatLocked(_In_ XGS_PROCESS_ENTRY* entry, _In_ ULONGLONG now)
{
    ULONG i;
    UINT32 writeCount = 0, deleteCount = 0, renameCount = 0;
    UINT32 extChangeCount = 0, entropyCount = 0;
    UINT32 totalOps = 0;
    UINT32 score = 0;
    UINT32 flags = 0;

    // 统计滑动窗口内各类操作次数
    for (i = 0; i < entry->OpTimeCount; i++)
    {
        ULONG idx = (entry->OpTimeHead + XGS_OP_TIMES_MAX - entry->OpTimeCount + i) %
                    XGS_OP_TIMES_MAX;
        ULONGLONG enc = entry->OpTimes[idx];
        ULONGLONG ts = XGS_OP_TIME(enc);

        if ((now - ts) <= XGS_WINDOW_100NS)
        {
            UINT32 opType = XGS_OP_TYPE(enc);
            totalOps++;
            switch (opType)
            {
            case XGS_OP_WRITE:   writeCount++; break;
            case XGS_OP_DELETE:  deleteCount++; break;
            case XGS_OP_RENAME:  renameCount++; break;
            case XGS_OP_EXT_CHG: extChangeCount++; break;
            case XGS_OP_ENTROPY: entropyCount++; break;
            }
        }
    }

    // 规则 1: 大量文件修改 (>10 文件/60 秒)
    if (writeCount > XGS_MASS_MODIFY_THRESHOLD)
    {
        score += XGS_SCORE_MASS_MODIFY_BASE +
                 (writeCount - XGS_MASS_MODIFY_THRESHOLD) * XGS_SCORE_MASS_MODIFY_PER;
        flags |= XGS_DETECT_MASS_MODIFY;
    }

    // 规则 2: 大量文件删除 (>8 文件/60 秒)
    if (deleteCount > XGS_MASS_DELETE_THRESHOLD)
    {
        score += XGS_SCORE_MASS_DELETE_BASE +
                 (deleteCount - XGS_MASS_DELETE_THRESHOLD) * XGS_SCORE_MASS_DELETE_PER;
        flags |= XGS_DETECT_MASS_DELETE;
    }

    // 规则 3: 大量文件重命名 (>5 文件/60 秒)
    if (renameCount > XGS_MASS_RENAME_THRESHOLD)
    {
        score += XGS_SCORE_MASS_RENAME_BASE +
                 (renameCount - XGS_MASS_RENAME_THRESHOLD) * XGS_SCORE_MASS_RENAME_PER;
        flags |= XGS_DETECT_MASS_RENAME;
    }

    // 规则 4: 扩展名变更 (极强信号, +35/次)
    if (extChangeCount > 0)
    {
        score += extChangeCount * XGS_SCORE_EXT_CHANGE;
        flags |= XGS_DETECT_EXT_CHANGE;
    }

    // 规则 5: 高熵写入 (疑似加密, 上限 60 分)
    if (entropyCount > 0)
    {
        UINT32 entropyScore = entropyCount * XGS_SCORE_ENTROPY_PER;
        if (entropyScore > XGS_SCORE_ENTROPY_MAX)
            entropyScore = XGS_SCORE_ENTROPY_MAX;
        score += entropyScore;
        flags |= XGS_DETECT_ENTROPY;
    }

    // 规则 6: 文件类型多样性 (>5 种/60 秒)
    if (entry->ExtTypeCount > XGS_TYPE_DIVERSITY_THRESHOLD)
    {
        score += XGS_SCORE_TYPE_DIVERSITY;
        flags |= XGS_DETECT_TYPE_DIVERSITY;
    }

    // 规则 7: 目录多样性 (>8 个/60 秒)
    if (entry->DirCount > XGS_DIR_DIVERSITY_THRESHOLD)
    {
        score += XGS_SCORE_DIR_DIVERSITY;
        flags |= XGS_DETECT_DIR_DIVERSITY;
    }

    // 规则 8: 快速连续写入 (>30 次/60 秒)
    if (totalOps > XGS_RAPID_WRITE_THRESHOLD)
    {
        score += XGS_SCORE_RAPID_WRITES;
        flags |= XGS_DETECT_RAPID_WRITES;
    }

    entry->ThreatScore = score;
    entry->DetectionFlags = flags;

    if (score >= XGS_RANSOM_SCORE_THRESHOLD)
    {
        KdPrint(("XGS: THREAT DETECTED! PID=%p score=%u flags=0x%02X "
                 "(W=%u D=%u R=%u E=%u N=%u dirs=%u types=%u total=%u)\n",
                 entry->ProcessId, score, flags,
                 writeCount, deleteCount, renameCount, extChangeCount,
                 entropyCount, entry->DirCount, entry->ExtTypeCount, totalOps));
        return TRUE;
    }

    return FALSE;
}

//=============================================================================
// 阻断超时检查 (调用者持锁)
//=============================================================================

static BOOLEAN
XgsCheckBlockTimeoutLocked(_In_ XGS_PROCESS_ENTRY* entry, _In_ ULONGLONG now)
{
    if (entry->IsBlocked && (now - entry->BlockTime) > XGS_TIMEOUT_100NS)
    {
        KdPrint(("XGS: Block timeout for PID=%p, auto-releasing\n", entry->ProcessId));
        entry->IsBlocked = FALSE;
        entry->ThreatScore = 0;
        entry->DetectionFlags = 0;
        entry->OpTimeCount = 0;
        entry->OpTimeHead = 0;
        if (g_Xgs.BlockedProcessCount > 0)
            g_Xgs.BlockedProcessCount--;
        return TRUE;
    }
    return FALSE;
}

//=============================================================================
// 已备份文件管理
//=============================================================================

static BOOLEAN XgsIsBackedUp(_In_ ULONGLONG hash)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    for (i = 0; i < g_Xgs.BackedUpCount; i++)
    {
        if (g_Xgs.BackedUpHashes[i] == hash) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return found;
}

static VOID XgsMarkBackedUp(_In_ ULONGLONG hash)
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
        g_Xgs.BackedUpHashes[g_Xgs.BackedUpCount++] = hash;
    else
    {
        g_Xgs.BackedUpHashes[g_Xgs.BackedUpHead] = hash;
        g_Xgs.BackedUpHead = (g_Xgs.BackedUpHead + 1) % XGS_BACKEDUP_MAX;
    }
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
}

//=============================================================================
// 记录受影响文件 (调用者持锁)
//=============================================================================

static VOID
XgsRecordModifiedLocked(
    _In_ PCWSTR originalPath,
    _In_ PCWSTR backupOrNewPath,
    _In_ ULONG op,
    _In_ UINT32 pid
    )
{
    ULONG idx;

    if (g_Xgs.ModifiedCount < XGS_MODIFIED_MAX)
        g_Xgs.ModifiedCount++;

    idx = g_Xgs.ModifiedHead;
    g_Xgs.Modified[idx].Operation = op;
    g_Xgs.Modified[idx].ProcessId = pid;
    XgsStrNCpyW(g_Xgs.Modified[idx].OriginalPath, originalPath, XGS_MAX_FILE_PATH_LEN);

    if (backupOrNewPath != NULL && backupOrNewPath[0] != L'\0')
        XgsStrNCpyW(g_Xgs.Modified[idx].BackupPath, backupOrNewPath, XGS_MAX_FILE_PATH_LEN);
    else
        g_Xgs.Modified[idx].BackupPath[0] = L'\0';

    g_Xgs.ModifiedHead = (g_Xgs.ModifiedHead + 1) % XGS_MODIFIED_MAX;
}

//=============================================================================
// 填充通知 (调用者持锁)
//=============================================================================

static VOID
XgsFillNotificationLocked(_In_ XGS_PROCESS_ENTRY* entry)
{
    ULONG n = 0;
    ULONG i;

    // 从 Modified 环中提取该进程的文件 (最新在前)
    for (i = 0; i < g_Xgs.ModifiedCount && n < XGS_RANSOM_LIST_MAX; i++)
    {
        ULONG idx = (g_Xgs.ModifiedHead + XGS_MODIFIED_MAX - 1 - i) % XGS_MODIFIED_MAX;
        if (g_Xgs.Modified[idx].ProcessId == (UINT32)(ULONG_PTR)entry->ProcessId)
        {
            g_Xgs.Notification.Files[n] = g_Xgs.Modified[idx];
            n++;
        }
    }

    g_Xgs.Notification.HasPending = TRUE;
    g_Xgs.Notification.NotificationId = g_Xgs.NotificationId;
    g_Xgs.Notification.ProcessId = (UINT32)(ULONG_PTR)entry->ProcessId;
    g_Xgs.Notification.ThreatScore = entry->ThreatScore;
    g_Xgs.Notification.DetectionFlags = entry->DetectionFlags;
    g_Xgs.Notification.FileCount = n;

    // 填充进程名 (从 entry 中没有存储, 使用 0 初始化)
    // 进程名在回调中获取并临时存储, 此处用 PID 标识
    RtlZeroMemory(g_Xgs.Notification.ProcessName, sizeof(g_Xgs.Notification.ProcessName));
}

//
// 在触发阻断时调用, 存储进程名到通知
//
static VOID
XgsSetNotificationProcessNameLocked(_In_ PCWSTR processName)
{
    if (processName != NULL)
        XgsStrNCpyW(g_Xgs.Notification.ProcessName, processName, 32);
}

//=============================================================================
// 文件复制 (备份/恢复共用)
//=============================================================================

static NTSTATUS
XgsCopyFile(_In_ PCWSTR src, _In_ PCWSTR dst, _In_ ULONG dstDisposition)
{
    UNICODE_STRING su, du;
    OBJECT_ATTRIBUTES soa, doa;
    IO_STATUS_BLOCK iosb;
    HANDLE hSrc = NULL, hDst = NULL;
    PVOID rawBuf = NULL;
    PUCHAR alignedBuf = NULL;
    LARGE_INTEGER offset;
    NTSTATUS st;

    RtlInitUnicodeString(&su, src);
    RtlInitUnicodeString(&du, dst);
    InitializeObjectAttributes(&soa, &su, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&doa, &du, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = ZwCreateFile(&hSrc, GENERIC_READ | SYNCHRONIZE, &soa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
                      NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = ZwCreateFile(&hDst, GENERIC_WRITE | SYNCHRONIZE, &doa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, 0, dstDisposition,
                      FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) { ZwClose(hSrc); return st; }

    rawBuf = AV_ALLOC_NON_PAGED(XGS_CHUNK_SIZE + 512, XGS_POOL_TAG);
    if (rawBuf == NULL) { ZwClose(hSrc); ZwClose(hDst); return STATUS_INSUFFICIENT_RESOURCES; }
    alignedBuf = (PUCHAR)ALIGN_UP((ULONG_PTR)rawBuf, 4096);

    offset.QuadPart = 0;
    for (;;)
    {
        ULONG readLen;

        st = ZwReadFile(hSrc, NULL, NULL, NULL, &iosb, alignedBuf,
                        XGS_CHUNK_SIZE, &offset, NULL);
        if (st == STATUS_END_OF_FILE) { st = STATUS_SUCCESS; break; }
        if (!NT_SUCCESS(st)) break;

        readLen = (ULONG)iosb.Information;
        if (readLen == 0) { st = STATUS_SUCCESS; break; }

        st = ZwWriteFile(hDst, NULL, NULL, NULL, &iosb, alignedBuf,
                         readLen, &offset, NULL);
        if (!NT_SUCCESS(st)) break;

        offset.QuadPart += readLen;
        if (readLen < XGS_CHUNK_SIZE) { st = STATUS_SUCCESS; break; }
    }

    ExFreePoolWithTag(rawBuf, XGS_POOL_TAG);
    ZwClose(hSrc);
    ZwClose(hDst);
    return st;
}

//=============================================================================
// 获取文件路径
//=============================================================================

static BOOLEAN
XgsGetFilePath(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
               _Out_writes_(buflen) PWCHAR out, _In_ ULONG buflen)
{
    NTSTATUS st;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG charCount;

    UNREFERENCED_PARAMETER(FltObjects);

    st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL)
        return FALSE;

    charCount = nameInfo->Name.Length / sizeof(WCHAR);
    if (charCount >= buflen)
        charCount = buflen - 1;

    RtlCopyMemory(out, nameInfo->Name.Buffer, charCount * sizeof(WCHAR));
    out[charCount] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return TRUE;
}

//=============================================================================
// 拒绝操作
//=============================================================================

static FLT_PREOP_CALLBACK_STATUS XgsDeny(_In_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

//=============================================================================
// 获取请求进程信息
//=============================================================================

static BOOLEAN
XgsGetProcessInfo(_In_ PFLT_CALLBACK_DATA Data,
                  _Out_ PHANDLE pPid,
                  _Out_writes_(nameLen) PWCHAR nameBuf,
                  _In_ ULONG nameLen)
{
    PEPROCESS process;

    process = FltGetRequestorProcess(Data);
    if (process == NULL)
        return FALSE;

    *pPid = PsGetProcessId(process);

    if (nameBuf != NULL && nameLen > 0)
    {
        PUCHAR imageName = PsGetProcessImageFileName(process);
        if (imageName != NULL)
            XgsAnsiToWide(nameBuf, (PCCHAR)imageName, nameLen);
        else
            nameBuf[0] = L'\0';
    }

    return TRUE;
}

//=============================================================================
// 前向声明
//=============================================================================
static BOOLEAN XgsIsClientConnected(VOID);

//=============================================================================
// 预操作回调: 创建 (文档以写/删能力打开时首次备份)
//=============================================================================

static FLT_PREOP_CALLBACK_STATUS
XgsPreCreate(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
             _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
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
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    disposition = (options >> 24) & 0xFF;
    if (disposition == FILE_CREATE)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (secCtx == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    desired = secCtx->DesiredAccess;
    if (!(desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!XgsGetFilePath(Data, FltObjects, path, XGS_MAX_PATH_BUFFER))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (XgsIsBackupDirPath(path) || !XgsIsDocExtension(path) || XgsIsDatabaseFile(path))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    hash = XgsHashPath(path);

    // 检查是否已备份
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

    // 执行备份
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

static FLT_PREOP_CALLBACK_STATUS
XgsPreWrite(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
            _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    KIRQL irql;
    BOOLEAN restoring;
    WCHAR path[XGS_MAX_PATH_BUFFER];
    HANDLE pid = NULL;
    WCHAR procName[32];
    ULONGLONG now;
    XGS_PROCESS_ENTRY* entry;
    BOOLEAN entropyAlert = FALSE;
    SIZE_T pathLen;
    ULONGLONG dirHash, extHash;
    PCWSTR extPtr;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (iopb->Parameters.Write.Length == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL || (iopb->IrpFlags & IRP_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!XgsGetFilePath(Data, FltObjects, path, XGS_MAX_PATH_BUFFER))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (XgsIsBackupDirPath(path) || !XgsIsDocExtension(path) || XgsIsDatabaseFile(path))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!XgsGetProcessInfo(Data, &pid, procName, 32))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 系统组件进程不参与勒索评分 (同步/索引/后台服务写文档属正常行为)
    if (XgsIsSystemProcessName(procName))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 熵分析 (在锁外执行, 避免长时间持锁)
    // 仅对非压缩文件类型且按间隔采样
    if (!XgsIsCompressedType(path))
    {
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        entry = XgsFindProcessLocked(pid);
        if (entry != NULL && (entry->WriteCount % XGS_ENTROPY_CHECK_INTERVAL) == 0)
        {
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            entropyAlert = XgsCheckWriteEntropy(Data);
            KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        }
        else if (entry == NULL)
        {
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            // 新进程, 直接检查一次
            entropyAlert = XgsCheckWriteEntropy(Data);
            KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        }
        else
        {
            // 不需要检查熵, 但需要重新获取锁
        }
    }
    else
    {
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    }

    // 重新查找/添加进程条目 (可能在上面的锁释放期间发生变化)
    now = XgsNow();
    entry = XgsFindProcessLocked(pid);
    if (entry == NULL)
        entry = XgsAddProcessLocked(pid, now);

    if (entry == NULL)
    {
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 检查是否已被阻断 (含超时自动恢复)
    // 注意: 客户端未连接时不执行阻断 (用户态程序断开后保护应停止)
    if (entry->IsBlocked)
    {
        if (!XgsIsClientConnected())
        {
            // 客户端已断开, 释放阻断
            entry->IsBlocked = FALSE;
            entry->ThreatScore = 0;
            entry->DetectionFlags = 0;
            entry->OpTimeCount = 0;
            entry->OpTimeHead = 0;
            if (g_Xgs.BlockedProcessCount > 0)
                g_Xgs.BlockedProcessCount--;
            KdPrint(("XGS: Releasing block for PID=%p (client disconnected)\n", pid));
        }
        else if (XgsCheckBlockTimeoutLocked(entry, now))
        {
            // 超时已恢复, 继续正常处理
        }
        else
        {
            // 仍然阻断
            g_Xgs.BlockedOps++;
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            return XgsDeny(Data);
        }
    }

    // 更新计数
    entry->FileWrites++;
    entry->WriteCount++;
    g_Xgs.DocWrites++;

    // 添加操作事件
    XgsAddOpEventLocked(entry, now, XGS_OP_WRITE);

    // 熵告警
    if (entropyAlert)
    {
        entry->EntropyAlerts++;
        XgsAddOpEventLocked(entry, now, XGS_OP_ENTROPY);
        KdPrint(("XGS: Entropy alert for PID=%p (total=%u)\n", pid, entry->EntropyAlerts));
    }

    // 更新多样性
    pathLen = XgsStrLenW(path);
    dirHash = XgsHashDirectory(path, pathLen);
    extPtr = XgsGetExtension(path, pathLen);
    extHash = extPtr ? XgsHashShort(extPtr, XgsStrLenW(extPtr)) : 0;
    XgsUpdateDiversityLocked(entry, dirHash, extHash);

    // 评分
    // 客户端未连接时不触发阻断 (无人处理通知, 阻断无意义)
    if (XgsIsClientConnected() && XgsEvaluateThreatLocked(entry, now))
    {
        // 触发阻断
        entry->IsBlocked = TRUE;
        entry->BlockTime = now;
        g_Xgs.BlockedProcessCount++;
        g_Xgs.TotalDetections++;
        g_Xgs.NotificationPending = TRUE;
        g_Xgs.NotificationId++;
        g_Xgs.BlockedOps++;

        XgsSetNotificationProcessNameLocked(procName);
        XgsFillNotificationLocked(entry);

        XgsRecordModifiedLocked(path, L"", XGS_OP_MODIFY, (UINT32)(ULONG_PTR)pid);

        KeReleaseSpinLock(&g_Xgs.Lock, irql);

        KdPrint(("XGS: WRITE BLOCKED - PID=%p score=%u\n", pid, entry->ThreatScore));
        return XgsDeny(Data);
    }

    // 记录修改
    XgsRecordModifiedLocked(path, L"", XGS_OP_MODIFY, (UINT32)(ULONG_PTR)pid);

    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//=============================================================================
// 预操作回调: 设置文件信息 (删除 + 重命名)
//=============================================================================

static FLT_PREOP_CALLBACK_STATUS
XgsPreSetInformation(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    KIRQL irql;
    BOOLEAN restoring;
    FILE_INFORMATION_CLASS infoClass;
    WCHAR path[XGS_MAX_PATH_BUFFER];
    HANDLE pid = NULL;
    WCHAR procName[32];
    ULONGLONG now;
    XGS_PROCESS_ENTRY* entry;
    SIZE_T pathLen;
    ULONGLONG dirHash, extHash;
    PCWSTR extPtr;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    infoClass = iopb->Parameters.SetFileInformation.FileInformationClass;

    // 只处理删除和重命名
    if (infoClass != FileDispositionInformation &&
        infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    restoring = g_Xgs.Restoring;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    if (restoring)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!XgsGetFilePath(Data, FltObjects, path, XGS_MAX_PATH_BUFFER))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (XgsIsBackupDirPath(path) || !XgsIsDocExtension(path) || XgsIsDatabaseFile(path))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!XgsGetProcessInfo(Data, &pid, procName, 32))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 系统组件进程不参与勒索评分 (同步/索引/后台服务删改文档属正常行为)
    if (XgsIsSystemProcessName(procName))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // ======== 删除处理 ========
    if (infoClass == FileDispositionInformation)
    {
        PFILE_DISPOSITION_INFORMATION dispInfo;
        dispInfo = (PFILE_DISPOSITION_INFORMATION)
            iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispInfo == NULL || !dispInfo->DeleteFile)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // ======== 重命名处理: 提取新文件名并检查扩展名变更 ========
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx)
    {
        PFILE_RENAME_INFORMATION renameInfo;
        renameInfo = (PFILE_RENAME_INFORMATION)
            iopb->Parameters.SetFileInformation.InfoBuffer;
        if (renameInfo == NULL || renameInfo->FileNameLength == 0)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // 比较新旧扩展名
        pathLen = XgsStrLenW(path);
        {
            PCWSTR oldExt = XgsGetExtension(path, pathLen);
            ULONG newChars = renameInfo->FileNameLength / sizeof(WCHAR);
            PCWSTR newExt = XgsGetExtFromName(renameInfo->FileName, newChars);
            BOOLEAN extChanged = FALSE;

            if (oldExt == NULL && newExt != NULL)
                extChanged = TRUE;
            else if (oldExt != NULL && newExt == NULL)
                extChanged = TRUE;
            else if (oldExt != NULL && newExt != NULL)
            {
                SIZE_T oldLen = XgsStrLenW(oldExt);
                SIZE_T newLen = XgsStrLenW(newExt);
                if (oldLen != newLen || !XgsWcsCaseCmp(oldExt, newExt, oldLen))
                    extChanged = TRUE;
            }

            if (extChanged)
            {
                KdPrint(("XGS: Extension change detected! PID=%p old=%ws new=%ws\n",
                         pid, oldExt ? oldExt : L"(none)", newExt ? newExt : L"(none)"));
            }
        }
    }

    // ======== 统一处理: 更新进程跟踪 + 评分 ========
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);

    now = XgsNow();
    entry = XgsFindProcessLocked(pid);
    if (entry == NULL)
        entry = XgsAddProcessLocked(pid, now);

    if (entry == NULL)
    {
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 检查是否已被阻断
    // 客户端未连接时不执行阻断
    if (entry->IsBlocked)
    {
        if (!XgsIsClientConnected())
        {
            entry->IsBlocked = FALSE;
            entry->ThreatScore = 0;
            entry->DetectionFlags = 0;
            entry->OpTimeCount = 0;
            entry->OpTimeHead = 0;
            if (g_Xgs.BlockedProcessCount > 0)
                g_Xgs.BlockedProcessCount--;
            KdPrint(("XGS: Releasing block for PID=%p (client disconnected)\n", pid));
        }
        else if (XgsCheckBlockTimeoutLocked(entry, now))
        {
            // 超时已恢复
        }
        else
        {
            g_Xgs.BlockedOps++;
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
            return XgsDeny(Data);
        }
    }

    // 根据操作类型更新计数
    if (infoClass == FileDispositionInformation)
    {
        entry->FileDeletes++;
        g_Xgs.DocDeletes++;
        XgsAddOpEventLocked(entry, now, XGS_OP_DELETE);
    }
    else // Rename
    {
        entry->FileRenames++;
        g_Xgs.DocRenames++;

        // 检查扩展名变更
        {
            PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)
                iopb->Parameters.SetFileInformation.InfoBuffer;
            if (renameInfo != NULL && renameInfo->FileNameLength > 0)
            {
                pathLen = XgsStrLenW(path);
                {
                    PCWSTR oldExt = XgsGetExtension(path, pathLen);
                    ULONG newChars = renameInfo->FileNameLength / sizeof(WCHAR);
                    PCWSTR newExt = XgsGetExtFromName(renameInfo->FileName, newChars);
                    BOOLEAN extChanged = FALSE;

                    if (oldExt == NULL && newExt != NULL)
                        extChanged = TRUE;
                    else if (oldExt != NULL && newExt == NULL)
                        extChanged = TRUE;
                    else if (oldExt != NULL && newExt != NULL)
                    {
                        SIZE_T oldLen = XgsStrLenW(oldExt);
                        SIZE_T newLen = XgsStrLenW(newExt);
                        if (oldLen != newLen || !XgsWcsCaseCmp(oldExt, newExt, oldLen))
                            extChanged = TRUE;
                    }

                    if (extChanged)
                    {
                        entry->ExtChanges++;
                        //
                        // 扩展名变更是更强信号, 只记 EXT_CHG 事件 (权重更高),
                        // 不再同时记录 RENAME, 避免一次操作双计分 (原 35+25 分)。
                        //
                        XgsAddOpEventLocked(entry, now, XGS_OP_EXT_CHG);
                    }
                    else
                    {
                        XgsAddOpEventLocked(entry, now, XGS_OP_RENAME);
                    }
                }
            }
            else
            {
                XgsAddOpEventLocked(entry, now, XGS_OP_RENAME);
            }
        }
    }

    // 更新多样性
    pathLen = XgsStrLenW(path);
    dirHash = XgsHashDirectory(path, pathLen);
    extPtr = XgsGetExtension(path, pathLen);
    extHash = extPtr ? XgsHashShort(extPtr, XgsStrLenW(extPtr)) : 0;
    XgsUpdateDiversityLocked(entry, dirHash, extHash);

    // 评分
    // 客户端未连接时不触发阻断
    if (XgsIsClientConnected() && XgsEvaluateThreatLocked(entry, now))
    {
        ULONG opType = (infoClass == FileDispositionInformation) ?
                        XGS_OP_DELETE : XGS_OP_RENAME;

        entry->IsBlocked = TRUE;
        entry->BlockTime = now;
        g_Xgs.BlockedProcessCount++;
        g_Xgs.TotalDetections++;
        g_Xgs.NotificationPending = TRUE;
        g_Xgs.NotificationId++;
        g_Xgs.BlockedOps++;

        XgsSetNotificationProcessNameLocked(procName);
        XgsFillNotificationLocked(entry);
        XgsRecordModifiedLocked(path, L"", opType, (UINT32)(ULONG_PTR)pid);

        KeReleaseSpinLock(&g_Xgs.Lock, irql);

        KdPrint(("XGS: SET_INFO BLOCKED - PID=%p score=%u\n", pid, entry->ThreatScore));
        return XgsDeny(Data);
    }

    // 记录修改
    {
        ULONG opType = (infoClass == FileDispositionInformation) ?
                        XGS_OP_DELETE : XGS_OP_RENAME;
        XgsRecordModifiedLocked(path, L"", opType, (UINT32)(ULONG_PTR)pid);
    }

    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//=============================================================================
// 过滤操作注册表
//=============================================================================

static const FLT_OPERATION_REGISTRATION XgsCallbacks[] =
{
    { IRP_MJ_CREATE, 0, XgsPreCreate, NULL, NULL },
    { IRP_MJ_WRITE, 0, XgsPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, XgsPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION XgsReg =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                        // Flags
    NULL,                     // ContextRegistration
    XgsCallbacks,             // OperationRegistration
    NULL,                     // FilterUnloadCallback
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

static NTSTATUS
XgsHmac(_In_reads_bytes_(dataLen) const UCHAR* data, _In_ ULONG dataLen,
        _Out_writes_bytes_(AV_HASH_SIZE) UCHAR* out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) return st;

    st = BCryptCreateHash(alg, &hash, NULL, 0,
                          (PUCHAR)AV_SHARED_KEY, AV_SHARED_KEY_SIZE, 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(alg, 0); return st; }

    st = BCryptHashData(hash, (PUCHAR)data, dataLen, 0);
    if (!NT_SUCCESS(st)) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return st; }

    st = BCryptFinishHash(hash, out, AV_HASH_SIZE, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st;
}

//=============================================================================
// 鉴权
//=============================================================================

static BOOLEAN XgsIsAuthed(VOID)
{
    KIRQL irql;
    BOOLEAN authed;
    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    authed = g_Xgs.Authed;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    return authed;
}

//
// 检查用户态代理是否在线 (有客户端句柄打开)
//
static BOOLEAN XgsIsClientConnected(VOID)
{
    return (g_Xgs.ClientRefCount > 0);
}

//
// 客户端断开时重置全部保护状态:
//   - 清除鉴权
//   - 释放所有被阻断的进程
//   - 清除待处理通知
//   - 清空进程跟踪表 (保留备份和统计)
//
static VOID XgsResetProtectionState(VOID)
{
    KIRQL irql;
    ULONG i;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);

    // 清除鉴权
    g_Xgs.Authed = FALSE;
    g_Xgs.ChallengeValid = FALSE;

    // 清除通知
    g_Xgs.NotificationPending = FALSE;
    g_Xgs.Restoring = FALSE;
    RtlZeroMemory(&g_Xgs.Notification, sizeof(g_Xgs.Notification));

    // 释放所有被阻断的进程
    for (i = 0; i < XGS_PROCESS_TABLE_SIZE; i++)
    {
        XGS_PROCESS_ENTRY* entry = &g_Xgs.Processes[i];
        if (entry->IsActive)
        {
            entry->IsBlocked = FALSE;
            entry->ThreatScore = 0;
            entry->DetectionFlags = 0;
            entry->EntropyScoreAccum = 0;
            entry->OpTimeCount = 0;
            entry->OpTimeHead = 0;
        }
    }
    g_Xgs.BlockedProcessCount = 0;

    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    KdPrint(("XGS: Protection state reset - client disconnected, all blocks released\n"));
}

static NTSTATUS
XgsIoctlAuthInit(_In_ PVOID systemBuffer, _In_ ULONG outLen, _Out_ PULONG info)
{
    AV_AUTH_CHALLENGE* out = (AV_AUTH_CHALLENGE*)systemBuffer;
    NTSTATUS st;
    KIRQL irql;
    BCRYPT_ALG_HANDLE hRng = NULL;

    KdPrint(("XGS: AuthInit ENTER, outLen=%lu\n", outLen));
    *info = 0;

    if (outLen < sizeof(AV_AUTH_CHALLENGE))
        return STATUS_BUFFER_TOO_SMALL;

    st = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) { KdPrint(("XGS: RNG open failed 0x%08lX\n", st)); return st; }

    st = BCryptGenRandom(hRng, g_Xgs.Challenge, AV_CHALLENGE_SIZE, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);
    if (!NT_SUCCESS(st)) { KdPrint(("XGS: GenRandom failed 0x%08lX\n", st)); return st; }

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    g_Xgs.ChallengeSeq++;
    g_Xgs.ChallengeValid = TRUE;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    out->SequenceId = g_Xgs.ChallengeSeq;
    RtlCopyMemory(out->Challenge, g_Xgs.Challenge, AV_CHALLENGE_SIZE);
    *info = sizeof(AV_AUTH_CHALLENGE);
    KdPrint(("XGS: AuthInit OK, seq=%llu\n", g_Xgs.ChallengeSeq));
    return STATUS_SUCCESS;
}

static NTSTATUS
XgsIoctlAuthVerify(_In_ PVOID systemBuffer, _In_ ULONG inLen, _In_ ULONG outLen,
                   _Out_ PULONG info)
{
    AV_AUTH_RESPONSE resp;
    AV_AUTH_RESULT* out;
    UCHAR hmacInput[AV_CHALLENGE_SIZE + sizeof(UINT64)];
    UCHAR hmac[AV_HASH_SIZE];
    NTSTATUS st = STATUS_SUCCESS;
    BOOLEAN valid = FALSE;
    KIRQL irql;

    *info = 0;
    if (inLen < sizeof(AV_AUTH_RESPONSE) || outLen < sizeof(AV_AUTH_RESULT))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&resp, systemBuffer, sizeof(AV_AUTH_RESPONSE));

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    if (g_Xgs.ChallengeValid && resp.SequenceId == g_Xgs.ChallengeSeq)
        valid = TRUE;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    if (valid)
    {
        RtlCopyMemory(hmacInput, g_Xgs.Challenge, AV_CHALLENGE_SIZE);
        RtlCopyMemory(hmacInput + AV_CHALLENGE_SIZE, &resp.SequenceId, sizeof(UINT64));
        st = XgsHmac(hmacInput, sizeof(hmacInput), hmac);
        if (NT_SUCCESS(st) && RtlEqualMemory(hmac, resp.Hmac, AV_HASH_SIZE))
        {
            KeAcquireSpinLock(&g_Xgs.Lock, &irql);
            g_Xgs.Authed = TRUE;
            KeReleaseSpinLock(&g_Xgs.Lock, irql);
        }
        else
        {
            st = STATUS_SUCCESS;
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

//=============================================================================
// IOCTL: 获取通知
//=============================================================================

static NTSTATUS
XgsIoctlGetNotification(_In_ PVOID systemBuffer, _In_ ULONG outLen, _Out_ PULONG info)
{
    XGS_RANSOM_NOTIFICATION* out = (XGS_RANSOM_NOTIFICATION*)systemBuffer;
    KIRQL irql;

    *info = 0;
    if (outLen < sizeof(XGS_RANSOM_NOTIFICATION))
        return STATUS_BUFFER_TOO_SMALL;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    RtlCopyMemory(out, &g_Xgs.Notification, sizeof(XGS_RANSOM_NOTIFICATION));
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    *info = sizeof(XGS_RANSOM_NOTIFICATION);
    return STATUS_SUCCESS;
}

// 前向声明 (XgsRestoreFiles 在 XgsIoctlSendDecision 之后定义)
static VOID XgsRestoreFiles(_In_opt_ UINT32 targetPid);

//=============================================================================
// IOCTL: 发送决策
//=============================================================================

static NTSTATUS
XgsIoctlSendDecision(_In_ PVOID systemBuffer, _In_ ULONG inLen, _Out_ PULONG info)
{
    XGS_RANSOM_DECISION decision;
    KIRQL irql;
    BOOLEAN doRestore = FALSE;
    NTSTATUS st = STATUS_SUCCESS;
    XGS_PROCESS_ENTRY* entry;
    ULONG i;

    *info = 0;
    if (inLen < sizeof(XGS_RANSOM_DECISION))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&decision, systemBuffer, sizeof(XGS_RANSOM_DECISION));

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);

    if (g_Xgs.NotificationPending &&
        decision.NotificationId == g_Xgs.Notification.NotificationId)
    {
        // 查找目标进程
        entry = XgsFindProcessLocked((HANDLE)(ULONG_PTR)decision.ProcessId);
        if (entry == NULL)
        {
            // 回退: 使用通知中的进程 ID
            entry = XgsFindProcessLocked((HANDLE)(ULONG_PTR)g_Xgs.Notification.ProcessId);
        }

        switch (decision.Decision)
        {
        case XGS_DECISION_ALLOW:
            if (entry != NULL)
            {
                entry->IsBlocked = FALSE;
                entry->ThreatScore = 0;
                entry->DetectionFlags = 0;
                entry->OpTimeCount = 0;
                entry->OpTimeHead = 0;
                if (g_Xgs.BlockedProcessCount > 0)
                    g_Xgs.BlockedProcessCount--;
            }
            g_Xgs.NotificationPending = FALSE;
            break;

        case XGS_DECISION_STAY_BLOCK:
            g_Xgs.NotificationPending = FALSE;
            break;

        case XGS_DECISION_RESTORE:
            if (entry != NULL)
            {
                entry->IsBlocked = FALSE;
                entry->ThreatScore = 0;
                entry->DetectionFlags = 0;
                entry->OpTimeCount = 0;
                entry->OpTimeHead = 0;
                if (g_Xgs.BlockedProcessCount > 0)
                    g_Xgs.BlockedProcessCount--;
            }
            g_Xgs.NotificationPending = FALSE;
            g_Xgs.Restoring = TRUE;
            doRestore = TRUE;
            break;

        default:
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        // 清理过期进程条目
        {
            ULONGLONG now = XgsNow();
            for (i = 0; i < XGS_PROCESS_TABLE_SIZE; i++)
            {
                if (g_Xgs.Processes[i].IsActive &&
                    !g_Xgs.Processes[i].IsBlocked &&
                    (now - g_Xgs.Processes[i].LastOpTime) >
                    (ULONGLONG)XGS_PROCESS_EXPIRE_SEC * 10000000ULL)
                {
                    RtlZeroMemory(&g_Xgs.Processes[i], sizeof(XGS_PROCESS_ENTRY));
                    if (g_Xgs.ActiveProcessCount > 0)
                        g_Xgs.ActiveProcessCount--;
                }
            }
        }
    }
    else
    {
        st = STATUS_NOT_FOUND;
    }

    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    if (doRestore)
    {
        XgsRestoreFiles(0);
        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        g_Xgs.Restoring = FALSE;
        KeReleaseSpinLock(&g_Xgs.Lock, irql);
    }

    return st;
}

//=============================================================================
// 恢复文件 (从备份复制回原路径)
//=============================================================================

static VOID
XgsRestoreFiles(_In_opt_ UINT32 targetPid)
{
    KIRQL irql;
    UINT32 count;
    UINT32 i;
    WCHAR original[XGS_MAX_PATH_BUFFER];
    WCHAR backup[XGS_MAX_PATH_BUFFER];
    NTSTATUS st;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    count = g_Xgs.ModifiedCount;
    if (count > XGS_MODIFIED_MAX) count = XGS_MODIFIED_MAX;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);

    for (i = 0; i < count; i++)
    {
        BOOLEAN canRestore = FALSE;

        KeAcquireSpinLock(&g_Xgs.Lock, &irql);
        if (g_Xgs.Modified[i].Operation == XGS_OP_MODIFY &&
            g_Xgs.Modified[i].BackupPath[0] != L'\0')
        {
            if (targetPid == 0 || g_Xgs.Modified[i].ProcessId == targetPid)
            {
                XgsStrNCpyW(original, g_Xgs.Modified[i].OriginalPath, XGS_MAX_PATH_BUFFER);
                XgsStrNCpyW(backup, g_Xgs.Modified[i].BackupPath, XGS_MAX_PATH_BUFFER);
                canRestore = TRUE;
            }
        }
        KeReleaseSpinLock(&g_Xgs.Lock, irql);

        if (canRestore)
        {
            st = XgsCopyFile(backup, original, FILE_OVERWRITE_IF);
            if (!NT_SUCCESS(st))
                KdPrint(("XGS: restore %ws failed 0x%08X\n", original, st));
        }
    }
}

//=============================================================================
// IOCTL: 获取单条受影响文件
//=============================================================================

static NTSTATUS
XgsIoctlGetModifiedFile(_In_ PVOID systemBuffer, _In_ ULONG inLen, _In_ ULONG outLen,
                        _Out_ PULONG info)
{
    UINT32 index;
    XGS_MODIFIED_FILE* out;
    KIRQL irql;

    *info = 0;
    if (inLen < sizeof(UINT32) || outLen < sizeof(XGS_MODIFIED_FILE))
        return STATUS_BUFFER_TOO_SMALL;

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

//=============================================================================
// IOCTL: 获取状态
//=============================================================================

static NTSTATUS
XgsIoctlGetStatus(_In_ PVOID systemBuffer, _In_ ULONG outLen, _Out_ PULONG info)
{
    XGS_STATUS* out = (XGS_STATUS*)systemBuffer;
    KIRQL irql;

    *info = 0;
    if (outLen < sizeof(XGS_STATUS))
        return STATUS_BUFFER_TOO_SMALL;

    KeAcquireSpinLock(&g_Xgs.Lock, &irql);
    out->Version = 2;
    out->RansomSuspected = g_Xgs.BlockedProcessCount;
    out->DocWrites = g_Xgs.DocWrites;
    out->DocDeletes = g_Xgs.DocDeletes;
    out->DocRenames = g_Xgs.DocRenames;
    out->BackupsCreated = g_Xgs.BackupsCreated;
    out->PendingNotification = g_Xgs.NotificationPending ? 1 : 0;
    out->ModifiedCount = g_Xgs.ModifiedCount;
    out->ActiveProcesses = g_Xgs.ActiveProcessCount;
    out->BlockedProcesses = g_Xgs.BlockedProcessCount;
    out->TotalDetections = g_Xgs.TotalDetections;
    KeReleaseSpinLock(&g_Xgs.Lock, irql);
    *info = sizeof(XGS_STATUS);
    return STATUS_SUCCESS;
}

//=============================================================================
// 传统控制设备
//=============================================================================

//=============================================================================
// 传统控制设备 - Create / Cleanup / Close
//
// Create:  客户端打开设备句柄时递增引用计数
// Cleanup: 客户端关闭句柄时递减引用计数, 若归零则重置保护状态
// Close:   文件对象最后一个引用释放 (无需额外操作)
//=============================================================================

static NTSTATUS
XgsDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    InterlockedIncrement(&g_Xgs.ClientRefCount);
    KdPrint(("XGS: Client connected (ref=%ld)\n", g_Xgs.ClientRefCount));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
XgsDispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    LONG ref = InterlockedDecrement(&g_Xgs.ClientRefCount);
    KdPrint(("XGS: Client handle closing (ref=%ld)\n", ref));

    if (ref <= 0)
    {
        // 最后一个客户端断开, 重置全部保护状态
        g_Xgs.ClientRefCount = 0;
        XgsResetProtectionState();
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
XgsDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
XgsDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
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
                st = STATUS_ACCESS_DENIED;
            else
                st = XgsIoctlGetNotification(systemBuffer, outLen, &info);
            break;

        case IOCTL_XGS_SEND_DECISION:
            if (!XgsIsAuthed())
                st = STATUS_ACCESS_DENIED;
            else
                st = XgsIoctlSendDecision(systemBuffer, inLen, &info);
            break;

        case IOCTL_XGS_GET_MODIFIED_FILE:
            if (!XgsIsAuthed())
                st = STATUS_ACCESS_DENIED;
            else
                st = XgsIoctlGetModifiedFile(systemBuffer, inLen, outLen, &info);
            break;

        case IOCTL_XGS_GET_STATUS:
            if (!XgsIsAuthed())
                st = STATUS_ACCESS_DENIED;
            else
                st = XgsIoctlGetStatus(systemBuffer, outLen, &info);
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

//=============================================================================
// 控制设备管理
//=============================================================================

static VOID XgsDeleteControlDevice(VOID)
{
    UNICODE_STRING symlinkName;
    if (g_ControlDevice == NULL) return;
    RtlInitUnicodeString(&symlinkName, XGS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    IoDeleteDevice(g_ControlDevice);
    g_ControlDevice = NULL;
}

static NTSTATUS XgsCreateControlDevice(VOID)
{
    UNICODE_STRING deviceName, symlinkName, sddl;
    PDEVICE_OBJECT device = NULL;
    NTSTATUS st;

    RtlInitUnicodeString(&deviceName, XGS_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, XGS_SYMLINK_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    st = IoCreateDeviceSecure(g_DriverObject, sizeof(XGS_DEVICE_EXTENSION),
                              &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
                              &sddl, NULL, &device);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGS: IoCreateDeviceSecure failed 0x%08X\n", st));
        return st;
    }

    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    st = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(st))
    {
        IoDeleteDevice(device);
        KdPrint(("XGS: IoCreateSymbolicLink failed 0x%08X\n", st));
        return st;
    }

    g_ControlDevice = device;
    return STATUS_SUCCESS;
}

//=============================================================================
// 备份目录创建
//=============================================================================

NTSTATUS XgsCreateBackupDirectory(VOID)
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
                          FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,
                          NULL, 0);
        if (!NT_SUCCESS(st) && st != STATUS_OBJECT_NAME_COLLISION)
            return st;
        if (hDir != NULL) { ZwClose(hDir); hDir = NULL; }
    }
    return STATUS_SUCCESS;
}

//=============================================================================
// 驱动卸载
//=============================================================================

VOID XgsUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    KdPrint(("XGS: Unload\n"));

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
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("XGS: DriverEntry (Multi-Dimensional Detection Engine v2.0)\n"));

    //
    // 初始化 ExAllocatePool2 兼容层 (Win10 < 2004 回退到 ExAllocatePoolWithTag)
    //
    AVPoolCompatInit();

    g_DriverObject = DriverObject;
    KeInitializeSpinLock(&g_Xgs.Lock);

    DriverObject->DriverUnload = XgsUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = XgsDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = XgsDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XgsDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XgsDispatchDeviceControl;

    st = XgsCreateControlDevice();
    if (!NT_SUCCESS(st)) return st;

    XgsCreateBackupDirectory();

    st = FltRegisterFilter(DriverObject, &XgsReg, &g_XgsFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGS: FltRegisterFilter failed 0x%08X\n", st));
        XgsDeleteControlDevice();
        return st;
    }

    st = FltStartFiltering(g_XgsFilter);
    if (!NT_SUCCESS(st))
    {
        KdPrint(("XGS: FltStartFiltering failed 0x%08X\n", st));
        FltUnregisterFilter(g_XgsFilter);
        g_XgsFilter = NULL;
        XgsDeleteControlDevice();
        return st;
    }

    KdPrint(("XGS: DriverEntry completed - Per-process tracking, entropy analysis, "
             "rename monitoring, multi-dimensional scoring (threshold=%u)\n",
             XGS_RANSOM_SCORE_THRESHOLD));
    return STATUS_SUCCESS;
}
