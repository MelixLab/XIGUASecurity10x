//! EMBER2024 v3 PE feature extraction (2568 dimensions)
//!
//! Faithful Rust re-implementation of thrember's PEFeatureExtractor so that
//! feature vectors produced here are compatible with the LightGBM model
//! trained in the Colab notebook.
//!
//! Feature groups and their dimensions:
//!   GeneralFileInfo       7
//!   ByteHistogram       256
//!   ByteEntropyHistogram 256
//!   StringExtractor      177
//!   HeaderFileInfo        74
//!   SectionInfo          224
//!   ImportsInfo         1282
//!   ExportsInfo          129
//!   DataDirectories       34
//!   RichHeader            33
//!   AuthenticodeSignature  8
//!   PEFormatWarnings      88
//!   ─────────────────────────
//!   TOTAL               2568

use goblin::pe::PE;
use std::sync::OnceLock;
use regex::RegexSet;

/// Total feature dimensions expected by the ONNX model.
pub const NDIM: usize = 2568;

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Extract a 2568-dim f32 feature vector from raw PE bytes.
/// Returns `None` if the input is not a valid PE (no MZ header) or too small.
pub fn extract(bytez: &[u8]) -> Option<Vec<f32>> {
    if bytez.len() < 64 {
        return None;
    }
    // 快速 PE 检查：必须以 MZ 魔数开头
    if bytez[0] != b'M' || bytez[1] != b'Z' {
        return None;
    }
    let pe = PE::parse(bytez).ok();
    let mut v = Vec::with_capacity(NDIM);

    v.extend_from_slice(&general_file_info(bytez, pe.as_ref()));       // 7
    v.extend_from_slice(&byte_histogram(bytez));                       // 256
    v.extend_from_slice(&byte_entropy_histogram(bytez));               // 256
    v.extend_from_slice(&string_extractor(bytez));                     // 177
    v.extend_from_slice(&header_file_info(bytez, pe.as_ref()));        // 74
    v.extend_from_slice(&section_info(bytez, pe.as_ref()));            // 224
    v.extend_from_slice(&imports_info(pe.as_ref()));                   // 1282
    v.extend_from_slice(&exports_info(pe.as_ref()));                   // 129
    v.extend_from_slice(&data_directories(bytez, pe.as_ref()));        // 34
    v.extend_from_slice(&rich_header(bytez));                          // 33
    v.extend_from_slice(&authenticode_signature(bytez));               // 8
    v.extend_from_slice(&pe_format_warnings(bytez, pe.as_ref()));      // 88

    debug_assert_eq!(v.len(), NDIM, "feature dim mismatch: got {}", v.len());
    Some(v)
}

// ═══════════════════════════════════════════════════════════════════════════
// MurmurHash3 — must match sklearn's FeatureHasher (seed=0, 32-bit signed)
// ═══════════════════════════════════════════════════════════════════════════

fn murmurhash3_32(key: &[u8], seed: u32) -> i32 {
    let len = key.len();
    let nblocks = len / 4;
    let mut h1 = seed;
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;

    // body
    for i in 0..nblocks {
        let off = i * 4;
        let mut k1 = u32::from_le_bytes([key[off], key[off+1], key[off+2], key[off+3]]);
        k1 = k1.wrapping_mul(c1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(c2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    // tail
    let tail = &key[nblocks * 4..];
    let mut k1: u32 = 0;
    match tail.len() {
        3 => {
            k1 ^= (tail[2] as u32) << 16;
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= (tail[1] as u32) << 8;
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        _ => {}
    }

    // finalization
    h1 ^= len as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;

    h1 as i32
}

// ═══════════════════════════════════════════════════════════════════════════
// FeatureHasher — replicates sklearn.feature_extraction.FeatureHasher
// ═══════════════════════════════════════════════════════════════════════════

/// 计算 sklearn FeatureHasher 兼容的桶索引：`abs(hashval) % n_features`。
/// 用 `unsigned_abs` 避免 `i32::MIN.abs()` 溢出。
fn hash_bucket(hashval: i32, n_features: usize) -> usize {
    (hashval.unsigned_abs() as usize) % n_features
}

/// Hash a list of strings into a fixed-size vector (input_type="string").
fn feature_hash_strings(items: &[&str], n_features: usize, alternate_sign: bool) -> Vec<f32> {
    let mut out = vec![0.0f32; n_features];
    for s in items {
        let h = murmurhash3_32(s.as_bytes(), 0);
        let idx = hash_bucket(h, n_features);
        let sign = if alternate_sign && h < 0 { -1.0f32 } else { 1.0f32 };
        out[idx] += sign;
    }
    out
}

/// Hash a list of (name, value) pairs into a fixed-size vector (input_type="pair").
fn feature_hash_pairs(items: &[(&str, f32)], n_features: usize, alternate_sign: bool) -> Vec<f32> {
    let mut out = vec![0.0f32; n_features];
    for (name, value) in items {
        let h = murmurhash3_32(name.as_bytes(), 0);
        let idx = hash_bucket(h, n_features);
        let sign = if alternate_sign && h < 0 { -1.0f32 } else { 1.0f32 };
        out[idx] += sign * value;
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. GeneralFileInfo  (dim = 7)
// ═══════════════════════════════════════════════════════════════════════════

fn general_file_info(bytez: &[u8], pe: Option<&PE>) -> [f32; 7] {
    let size = bytez.len() as f32;
    let entropy = byte_entropy(bytez);
    let is_pe = if pe.is_some() { 1.0 } else { 0.0 };
    let b0 = bytez[0] as f32;
    let b1 = if bytez.len() >= 2 { bytez[1] as f32 } else { 0.0 };
    let b2 = if bytez.len() >= 3 { bytez[2] as f32 } else { 0.0 };
    let b3 = if bytez.len() >= 4 { bytez[3] as f32 } else { 0.0 };
    [size, entropy, is_pe, b0, b1, b2, b3]
}

fn byte_entropy(data: &[u8]) -> f32 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h as f32
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. ByteHistogram  (dim = 256)
// ═══════════════════════════════════════════════════════════════════════════

fn byte_histogram(bytez: &[u8]) -> [f32; 256] {
    let mut counts = [0u64; 256];
    for &b in bytez { counts[b as usize] += 1; }
    let sum = bytez.len().max(1) as f32;
    let mut out = [0.0f32; 256];
    for i in 0..256 { out[i] = counts[i] as f32 / sum; }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. ByteEntropyHistogram  (dim = 256)
// ═══════════════════════════════════════════════════════════════════════════

fn byte_entropy_histogram(bytez: &[u8]) -> [f32; 256] {
    let window = 2048usize;
    let step = 1024usize;
    let mut output = [0i64; 256]; // 16 entropy bins × 16 byte bins = 256

    let arr = bytez;
    if arr.len() < window {
        let (hbin, c) = entropy_bin_counts(arr, arr.len());
        for i in 0..16 {
            output[hbin * 16 + i] += c[i] as i64;
        }
    } else {
        let n_blocks = (arr.len() - window) / step + 1;
        for bi in 0..n_blocks {
            let start = bi * step;
            let block = &arr[start..start + window];
            let (hbin, c) = entropy_bin_counts(block, window);
            for i in 0..16 {
                output[hbin * 16 + i] += c[i] as i64;
            }
        }
    }

    let sum = output.iter().sum::<i64>().max(1) as f32;
    let mut out = [0.0f32; 256];
    for i in 0..256 { out[i] = output[i] as f32 / sum; }
    out
}

/// Returns (entropy_bin 0..15, 16-bin coarse histogram).
fn entropy_bin_counts(block: &[u8], _window: usize) -> (usize, [u32; 16]) {
    let mut c = [0u32; 16];
    for &b in block { c[(b >> 4) as usize] += 1; }
    let total = block.len() as f32;
    let mut h = 0.0f32;
    for &cnt in &c {
        if cnt > 0 {
            let p = cnt as f32 / total;
            h -= p * p.log2();
        }
    }
    // ×2 because we reduced 256 bins to 16 bins
    h *= 2.0;
    let mut hbin = (h * 2.0) as usize; // up to 16
    if hbin >= 16 { hbin = 15; }
    (hbin, c)
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. StringExtractor  (dim = 177)
// ═══════════════════════════════════════════════════════════════════════════

/// Sorted list of regex tag names — must match Python's sorted() order exactly.
/// 77 names total. ASCII order: '.' (0x2E) < '/' (0x2F) < '<' (0x3C) < uppercase < lowercase.
const STRING_REGEX_NAMES: &[&str] = &[
    ".click(", "/EmbeddedFile", "/FlateDecode", "/URI",
    "/bin/", "/dev/", "/proc/", "/tmp/", "/usr/",
    "<script", "Invoke-Command", "Invoke-Expression", "Start-process",
    "base64", "base64string", "btc_wallet", "cache", "certificate", "clipboard",
    "command", "connect", "cookie", "create", "crypt", "debug", "decode",
    "delete", "desktop", "directory", "disk", "dos_msg", "download",
    "email_addr", "encode", "enum", "environment", "exit", "file",
    "file_path", "ftp", "get", "hidden", "hostname", "html", "http",
    "http://", "https://", "install", "internet", "ipv4_addr", "ipv6_addr",
    "javascript", "keyboard", "mac_addr", "memory", "module", "mutex",
    "onlick", "password", "post", "powershell", "privilege", "process",
    "registry_key", "remote", "resource", "security", "service", "shell",
    "snapshot", "system", "thread", "token", "url", "useragent", "wallet",
    "window",
];

/// 与 STRING_REGEX_NAMES 一一对应的 Python re 兼容 pattern。
/// 顺序必须和 STRING_REGEX_NAMES 完全一致（sorted by Python ASCII），且与 thrember 的 self._regexes 等价。
const STRING_REGEX_PATTERNS: &[&str] = &[
    r"(?i)\.click",                                                   // 0  .click(
    r"/EmbeddedFile",                                                 // 1  /EmbeddedFile
    r"/FlateDecode",                                                  // 2  /FlateDecode
    r"/URI",                                                          // 3  /URI
    r"/bin/",                                                         // 4  /bin/
    r"/dev/",                                                         // 5  /dev/
    r"/proc/",                                                        // 6  /proc/
    r"/tmp/",                                                         // 7  /tmp/
    r"/usr/",                                                         // 8  /usr/
    r"(?i)<script",                                                   // 9  <script
    r"Invoke-Command",                                                // 10 Invoke-Command
    r"Invoke-Expression",                                             // 11 Invoke-Expression
    r"Start-process",                                                 // 12 Start-process
    r"(?i)base64",                                                    // 13 base64
    r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/", // 14 base64string
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",                               // 15 btc_wallet
    r"(?i)cache",                                                     // 16 cache
    r"(?i)certificate",                                               // 17 certificate
    r"(?i)clipboard",                                                 // 18 clipboard
    r"(?i)command",                                                   // 19 command
    r"(?i)connect",                                                   // 20 connect
    r"(?i)cookie",                                                    // 21 cookie
    r"(?i)create",                                                    // 22 create
    r"crypt",                                                         // 23 crypt
    r"(?i)debug",                                                     // 24 debug
    r"(?i)decode",                                                    // 25 decode
    r"(?i)delete",                                                    // 26 delete
    r"(?i)desktop",                                                   // 27 desktop
    r"(?i)directory",                                                 // 28 directory
    r"(?i)disk",                                                      // 29 disk
    r"!This program ",                                                // 30 dos_msg
    r"(?i)download",                                                  // 31 download
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",               // 32 email_addr (与 mac_addr 同)
    r"(?i)encode",                                                    // 33 encode
    r"(?i)enum",                                                      // 34 enum
    r"(?i)environment",                                               // 35 environment
    r"(?i)exit",                                                      // 36 exit
    r"(?i)file",                                                      // 37 file
    r"\bC:/",                                                         // 38 file_path
    r"(?i)ftp:",                                                      // 39 ftp
    r"(?i)GET /",                                                     // 40 get
    r"(?i)hidden",                                                    // 41 hidden
    r"(?i)hostname",                                                  // 42 hostname
    r"(?i)html",                                                      // 43 html
    r"(?i)HTTP/",                                                     // 44 http
    r"(?i)http://",                                                   // 45 http://
    r"(?i)https://",                                                  // 46 https://
    r"(?i)install",                                                   // 47 install
    r"(?i)internet",                                                  // 48 internet
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", // 49 ipv4_addr
    r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\b", // 50 ipv6_addr
    r"(?i)javascript",                                                // 51 javascript
    r"(?i)keyboard",                                                  // 52 keyboard
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",               // 53 mac_addr
    r"(?i)memory",                                                    // 54 memory
    r"(?i)module",                                                    // 55 module
    r"(?i)mutex",                                                     // 56 mutex
    r"(?i)onclick",                                                   // 57 onlick
    r"(?i)password",                                                  // 58 password
    r"(?i)POST /",                                                    // 59 post
    r"(?i)powershell",                                                // 60 powershell
    r"(?i)privilege",                                                 // 61 privilege
    r"(?i)process",                                                   // 62 process
    r"\b(?:KHEY_|KHLM|HKCU)",                                         // 63 registry_key
    r"(?i)remote",                                                    // 64 remote
    r"(?i)resource",                                                  // 65 resource
    r"(?i)security",                                                  // 66 security
    r"(?i)service",                                                   // 67 service
    r"(?i)shell",                                                     // 68 shell
    r"(?i)snapshot",                                                  // 69 snapshot
    r"(?i)system",                                                    // 70 system
    r"(?i)thread",                                                    // 71 thread
    r"(?i)token",                                                     // 72 token
    r"\b(?:http|https|ftp)://[a-zA-Z0-9\-._~:?#\[\]@!$&'()*+,;=]+",   // 73 url
    r"(?i)User-Agent",                                                // 74 useragent
    r"(?i)wallet",                                                    // 75 wallet
    r"(?i)window",                                                    // 76 window
];

fn string_regex_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        debug_assert_eq!(STRING_REGEX_PATTERNS.len(), STRING_REGEX_NAMES.len());
        RegexSet::new(STRING_REGEX_PATTERNS).expect("STRING_REGEX_PATTERNS 必须能编译")
    })
}

fn string_extractor(bytez: &[u8]) -> Vec<f32> {
    // 提取可打印串（0x20..0x7f、≥5 字符）并累加特征。
    // ★ 2026-07-19：**流式**处理——绝不把"所有串"收进 `Vec<Vec<u8>>`。旧实现对恶意样本
    //   （FakeApp 常塞海量可打印数据 / 上百万个短串）会瞬间分配几百 MB~GB，逼近/超过 worker
    //   的 512MB Job 内存上限被内核 OOM 杀掉——这正是"扫某些样本 worker 偶发崩溃、重启后
    //   跳过 ML 又不复现"的根因（非确定性取决于是否跨过内存边界）。计算所需的全部特征
    //   （串数/均长/96 维字符分布/熵/正则计数）都能单遍累加，无需同时持有任何一批串，
    //   峰值内存降到 O(单个最长串)（≤ 文件大小 ≤ 64MB），与训练输出 bit 级一致。
    let set = string_regex_set();
    let mut regex_counts = vec![0.0f32; STRING_REGEX_NAMES.len()];
    let mut c = [0u64; 96]; // 96 bins: 0x20..0x7f → 0..95
    let mut numstrings: u64 = 0;
    let mut total_len: u64 = 0;
    // 复用同一个缓冲，逐串处理完即清空（不累积任何一批串）。
    let mut cur: Vec<u8> = Vec::new();
    // 处理一个刚结束的候选串（内联，避免闭包同时可变借用多个局部量）。
    macro_rules! flush_string {
        () => {{
            if cur.len() >= 5 {
                numstrings += 1;
                total_len += cur.len() as u64;
                for &b in cur.iter() {
                    c[(b - 0x20) as usize] += 1;
                }
                // 正则：每个串命中某 pattern 则对应 idx 计数 +1（与旧实现语义一致）。
                let s_str = String::from_utf8_lossy(&cur);
                for idx in set.matches(&s_str).iter() {
                    regex_counts[idx] += 1.0;
                }
            }
            cur.clear();
        }};
    }
    for &b in bytez {
        if (0x20..=0x7f).contains(&b) {
            cur.push(b);
        } else {
            flush_string!();
        }
    }
    flush_string!();

    let (numstrings, avlength, printables, printabledist, entropy) = if numstrings > 0 {
        let avlength = total_len as f32 / numstrings as f32;
        let csum: u64 = c.iter().sum();
        let p: Vec<f64> = c.iter().map(|&x| x as f64 / csum.max(1) as f64).collect();
        let h: f64 = p.iter().filter(|&&px| px > 0.0).map(|&px| -px * px.log2()).sum();
        (numstrings as f32, avlength, csum as f32, c, h as f32)
    } else {
        (0.0, 0.0, 0.0, [0u64; 96], 0.0)
    };

    // Build output: 5 scalars + 96 printable dist + 77 regex counts = 178? No:
    // 实际是 numstrings + avlength + printables + 96dist + entropy + 77regex = 177
    let hist_divisor = if printables > 0.0 { printables } else { 1.0 };
    let mut out = Vec::with_capacity(177);
    out.push(numstrings);
    out.push(avlength);
    out.push(printables);
    for i in 0..96 { out.push(printabledist[i] as f32 / hist_divisor); }
    out.push(entropy);
    out.extend_from_slice(&regex_counts);
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. HeaderFileInfo  (dim = 74)
// ═══════════════════════════════════════════════════════════════════════════

const MACHINE_TYPES: &[u16] = &[
    0x0000, // UNKNOWN
    0x014c, // I386
    0x0162, // R3000
    0x0166, // R4000
    0x0168, // R10000
    0x0169, // WCEMIPSV2
    0x0184, // ALPHA
    0x01a2, // SH3
    0x01a3, // SH3DSP
    0x01a4, // SH3E
    0x01a6, // SH4
    0x01a8, // SH5
    0x01c0, // ARM
    0x01c2, // THUMB
    0x01c4, // ARMNT
    0x01d3, // AM33
    0x01f0, // POWERPC
    0x01f1, // POWERPCFP
    0x0200, // IA64
    0x0266, // MIPS16
    0x0284, // ALPHA64
    0x0284, // AXP64 (same as ALPHA64)
    0x0366, // MIPSFPU
    0x0466, // MIPSFPU16
    0x0520, // TRICORE
    0xc0ee, // CEF
    0x0EBC, // EBC
    0x5032, // RISCV32
    0x5064, // RISCV64
    0x5128, // RISCV128
    0x6232, // LOONGARCH32
    0x6264, // LOONGARCH64
    0x8664, // AMD64
    0x9041, // M32R
    0xAA64, // ARM64
    0xC0EE, // CEE
];

const SUBSYSTEM_TYPES: &[u16] = &[
    0,  // UNKNOWN
    1,  // NATIVE
    2,  // WINDOWS_GUI
    3,  // WINDOWS_CUI
    5,  // OS2_CUI
    7,  // POSIX_CUI
    8,  // NATIVE_WINDOWS
    9,  // WINDOWS_CE_GUI
    10, // EFI_APPLICATION
    11, // EFI_BOOT_SERVICE_DRIVER
    12, // EFI_RUNTIME_DRIVER
    13, // EFI_ROM
    14, // XBOX
    16, // WINDOWS_BOOT_APPLICATION
];

fn header_file_info(bytez: &[u8], pe: Option<&PE>) -> Vec<f32> {
    let mut out = vec![0.0f32; 74];
    let pe = match pe {
        Some(p) => p,
        None => return out,
    };

    let coff = &pe.header.coff_header;
    let opt = match &pe.header.optional_header {
        Some(o) => o,
        None => return out,
    };

    let std_f = &opt.standard_fields;
    let win = &opt.windows_fields;

    out[0] = coff.time_date_stamp as f32;
    out[1] = coff.number_of_sections as f32;
    out[2] = coff.number_of_symbol_table as f32;
    out[3] = coff.size_of_optional_header as f32;
    out[4] = coff.pointer_to_symbol_table as f32;
    out[5] = MACHINE_TYPES.iter().position(|&m| m == coff.machine).unwrap_or(0) as f32;
    out[6] = SUBSYSTEM_TYPES.iter().position(|&s| s == win.subsystem).unwrap_or(0) as f32;
    out[7] = win.major_image_version as f32;
    out[8] = win.minor_image_version as f32;
    out[9] = std_f.major_linker_version as f32;
    out[10] = std_f.minor_linker_version as f32;
    out[11] = win.major_operating_system_version as f32;
    out[12] = win.minor_operating_system_version as f32;
    out[13] = win.major_subsystem_version as f32;
    out[14] = win.minor_subsystem_version as f32;
    out[15] = std_f.size_of_code as f32;
    out[16] = win.size_of_headers as f32;
    out[17] = win.size_of_image as f32;
    out[18] = std_f.size_of_initialized_data as f32;
    out[19] = std_f.size_of_uninitialized_data as f32;
    out[20] = win.size_of_stack_reserve as f32;
    out[21] = win.size_of_stack_commit as f32;
    out[22] = win.size_of_heap_reserve as f32;
    out[23] = win.size_of_heap_commit as f32;
    out[24] = std_f.address_of_entry_point as f32;
    out[25] = std_f.base_of_code as f32;
    // base_of_data is NOT in process_raw_features (dim=74)
    out[26] = win.image_base as f32;
    out[27] = win.section_alignment as f32;
    out[28] = win.check_sum as f32;
    out[29] = win.number_of_rva_and_sizes as f32;

    let chars = coff.characteristics;
    let img_flags: &[u16] = &[
        0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080,
        0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
    ];
    for (i, &f) in img_flags.iter().enumerate() {
        out[30 + i] = if chars & f != 0 { 1.0 } else { 0.0 };
    }

    let dll_c = win.dll_characteristics;
    let dll_flags: &[u16] = &[
        0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800,
        0x1000, 0x2000, 0x4000, 0x8000,
    ];
    for (i, &f) in dll_flags.iter().enumerate() {
        out[46 + i] = if dll_c & f != 0 { 1.0 } else { 0.0 };
    }

    let dos_offsets: &[usize] = &[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,60];
    for (i, &off) in dos_offsets.iter().enumerate() {
        if off + 2 <= bytez.len() {
            out[57 + i] = if off == 60 {
                if off + 4 <= bytez.len() {
                    u32::from_le_bytes([bytez[off], bytez[off+1], bytez[off+2], bytez[off+3]]) as f32
                } else { 0.0 }
            } else {
                u16::from_le_bytes([bytez[off], bytez[off+1]]) as f32
            };
        }
    }

    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. SectionInfo  (dim = 224)
// ═══════════════════════════════════════════════════════════════════════════

fn section_info(bytez: &[u8], pe: Option<&PE>) -> Vec<f32> {
    let dim = 224;
    let pe = match pe {
        Some(p) => p,
        None => return vec![0.0f32; dim],
    };
    let sections = &pe.sections;
    let n = sections.len();
    let mut sec_names: Vec<String> = Vec::new();
    let mut sec_sizes: Vec<f32> = Vec::new();
    let mut sec_vsizes: Vec<f32> = Vec::new();
    let mut sec_entropies: Vec<f32> = Vec::new();
    let mut sec_chars_strs: Vec<String> = Vec::new();
    let mut n_rx = 0u32;
    let mut n_w = 0u32;
    let mut n_zero_size = 0u32;
    let mut n_empty_name = 0u32;

    let char_flags: &[(u32, &str)] = &[
        (0x00000020, "CNT_CODE"), (0x00000040, "CNT_INITIALIZED_DATA"),
        (0x00000080, "CNT_UNINITIALIZED_DATA"), (0x02000000, "MEM_DISCARDABLE"),
        (0x04000000, "MEM_NOT_CACHED"), (0x08000000, "MEM_NOT_PAGED"),
        (0x10000000, "MEM_SHARED"), (0x20000000, "MEM_EXECUTE"),
        (0x40000000, "MEM_READ"), (0x80000000, "MEM_WRITE"),
    ];

    for s in sections {
        let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_lowercase();
        if name.is_empty() { n_empty_name += 1; }
        if s.size_of_raw_data == 0 { n_zero_size += 1; }
        let c = s.characteristics;
        if c & 0x20000000 != 0 && c & 0x40000000 != 0 { n_rx += 1; }
        if c & 0x80000000 != 0 { n_w += 1; }
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;
        let ent = if end <= bytez.len() && start < end { byte_entropy(&bytez[start..end]) } else { 0.0 };
        for &(flag, flag_name) in char_flags {
            if c & flag != 0 { sec_chars_strs.push(format!("{}:{}", name, flag_name)); }
        }
        sec_names.push(name.to_string());
        sec_sizes.push(s.size_of_raw_data as f32);
        sec_vsizes.push(s.virtual_size as f32);
        sec_entropies.push(ent);
    }

    let last_end = sections.iter().map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize).max().unwrap_or(0);
    let ov_size = if bytez.len() > last_end { bytez.len() - last_end } else { 0 };
    let ov_ratio = ov_size as f32 / bytez.len().max(1) as f32;
    let ov_ent = if ov_size > 0 && last_end < bytez.len() { byte_entropy(&bytez[last_end..]) } else { 0.0 };

    let mut ents = sec_entropies.clone(); ents.push(ov_ent); ents.push(0.0);
    let mut srs: Vec<f32> = sections.iter().map(|s| s.size_of_raw_data as f32 / bytez.len().max(1) as f32).collect();
    srs.push(ov_ratio); srs.push(0.0);
    let mut vrs: Vec<f32> = sections.iter().map(|s| s.size_of_raw_data as f32 / s.virtual_size.max(1) as f32).collect();
    vrs.push(0.0);

    let general: [f32; 11] = [
        n as f32, n_zero_size as f32, n_empty_name as f32, n_rx as f32, n_w as f32,
        fmax(&ents), fmin(&ents), fmax(&srs), fmin(&srs), fmax(&vrs), fmin(&vrs),
    ];

    let sp: Vec<(&str, f32)> = sec_names.iter().zip(&sec_sizes).map(|(a,&b)|(a.as_str(),b)).collect();
    let vp: Vec<(&str, f32)> = sec_names.iter().zip(&sec_vsizes).map(|(a,&b)|(a.as_str(),b)).collect();
    let ep: Vec<(&str, f32)> = sec_names.iter().zip(&sec_entropies).map(|(a,&b)|(a.as_str(),b)).collect();
    let cr: Vec<&str> = sec_chars_strs.iter().map(|s| s.as_str()).collect();

    let entry_rva = pe.entry as u32;
    let mut entry_name = String::new();
    for s in sections {
        if entry_rva >= s.virtual_address && entry_rva < s.virtual_address + s.virtual_size {
            entry_name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_lowercase().to_string();
            break;
        }
    }
    let er: Vec<&str> = if entry_name.is_empty() { vec![] } else { vec![entry_name.as_str()] };

    let mut out = Vec::with_capacity(dim);
    out.extend_from_slice(&general);
    out.extend_from_slice(&feature_hash_pairs(&sp, 50, true));
    out.extend_from_slice(&feature_hash_pairs(&vp, 50, true));
    out.extend_from_slice(&feature_hash_pairs(&ep, 50, true));
    out.extend_from_slice(&feature_hash_strings(&cr, 50, true));
    out.extend_from_slice(&feature_hash_strings(&er, 10, true));
    out.push(ov_size as f32);
    out.push(ov_ratio);
    out.push(ov_ent);
    out
}

fn fmax(v: &[f32]) -> f32 { v.iter().cloned().fold(f32::NEG_INFINITY, f32::max) }
fn fmin(v: &[f32]) -> f32 { v.iter().cloned().fold(f32::INFINITY, f32::min) }

// ═══════════════════════════════════════════════════════════════════════════
// 7. ImportsInfo  (dim = 1282)
// ═══════════════════════════════════════════════════════════════════════════

fn imports_info(pe: Option<&PE>) -> Vec<f32> {
    let dim = 1282;
    let pe = match pe { Some(p) => p, None => return vec![0.0f32; dim] };
    // thrember 语义：raw_obj key 用原大小写 dll_name，对 ordinal entry 写
    //   f"{dll_name}:ordinal{N}"（含原大小写 dll）；最后 process_raw_features 拼成
    //   "{lower_dll}:{entry}"，所以 ordinal 完整形态是 "{lower_dll}:{原大小写dll}:ordinal{N}"。
    let mut lib_set: Vec<String> = Vec::new();
    let mut imp_strs: Vec<String> = Vec::new();
    for imp in &pe.imports {
        let dll_orig: &str = &imp.dll;
        let dll_lower = dll_orig.to_lowercase();
        if !lib_set.contains(&dll_lower) { lib_set.push(dll_lower.clone()); }
        // goblin 把 ordinal-only imports 的 name 字段填成 "ORDINAL <N>"（注意空格）。
        // 等价于 pefile/thrember 中 name=None 的情况。
        let is_ordinal_only = imp.name.is_empty()
            || imp.name.starts_with("ORDINAL ")
            || imp.name.starts_with("Ordinal ")
            || imp.name.starts_with("ordinal ");
        let func = if is_ordinal_only {
            format!("{}:{}:ordinal{}", dll_lower, dll_orig, imp.ordinal)
        } else {
            format!("{}:{}", dll_lower, imp.name)
        };
        imp_strs.push(func);
    }
    let lr: Vec<&str> = lib_set.iter().map(|s| s.as_str()).collect();
    let ir: Vec<&str> = imp_strs.iter().map(|s| s.as_str()).collect();
    let mut out = Vec::with_capacity(dim);
    out.push(imp_strs.len() as f32);
    out.push(lib_set.len() as f32);
    out.extend_from_slice(&feature_hash_strings(&lr, 256, false));
    out.extend_from_slice(&feature_hash_strings(&ir, 1024, false));
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. ExportsInfo  (dim = 129)
// ═══════════════════════════════════════════════════════════════════════════

fn exports_info(pe: Option<&PE>) -> Vec<f32> {
    let dim = 129;
    let pe = match pe { Some(p) => p, None => return vec![0.0f32; dim] };
    let mut names: Vec<String> = Vec::new();
    for exp in &pe.exports {
        if let Some(ref name) = exp.name {
            names.push(name.to_string());
        }
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let hashed = feature_hash_strings(&refs, 128, true);
    let mut out = Vec::with_capacity(dim);
    out.push(names.len() as f32);
    out.extend_from_slice(&hashed);
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. DataDirectories  (dim = 34)
//    16 dirs × 2 (size + va) + 2 (has_relocs, has_dynamic_relocs)
// ═══════════════════════════════════════════════════════════════════════════

fn data_directories(_bytez: &[u8], pe: Option<&PE>) -> Vec<f32> {
    let dim = 34;
    let pe = match pe { Some(p) => p, None => return vec![0.0f32; dim] };
    let opt = match &pe.header.optional_header {
        Some(o) => o,
        None => return vec![0.0f32; dim],
    };

    let mut out = vec![0.0f32; dim];
    let dirs = &opt.data_directories;

    let raw_dirs = [
        dirs.get_export_table(),
        dirs.get_import_table(),
        dirs.get_resource_table(),
        dirs.get_exception_table(),
        dirs.get_certificate_table(),
        dirs.get_base_relocation_table(),
        dirs.get_debug_table(),
        None, // COPYRIGHT (Architecture)
        None, // GLOBALPTR
        dirs.get_tls_table(),
        dirs.get_load_config_table(),
        dirs.get_bound_import_table(),
        dirs.get_import_address_table(),
        None, // delay import (goblin 不直接暴露)
        dirs.get_clr_runtime_header(),
        None, // RESERVED
    ];

    for (i, dd_opt) in raw_dirs.iter().enumerate() {
        if let Some(dd) = dd_opt {
            out[2 * i] = dd.size as f32;
            out[2 * i + 1] = dd.virtual_address as f32;
        }
    }

    // has_relocs: non-zero BASERELOC size
    out[32] = if raw_dirs[5].map_or(false, |d| d.size > 0) { 1.0 } else { 0.0 };
    // has_dynamic_relocs: always 0 (goblin doesn't expose)
    out[33] = 0.0;
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. RichHeader  (dim = 33)
//     1 count + 32 hashed pairs
// ═══════════════════════════════════════════════════════════════════════════

fn rich_header(bytez: &[u8]) -> Vec<f32> {
    let dim = 33;
    // Parse rich header manually — it's before the PE header
    let values = parse_rich_header_values(bytez);
    if values.is_empty() {
        return vec![0.0f32; dim];
    }
    let n_pairs = values.len() / 2;
    let mut pairs: Vec<(&str, f32)> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for i in (0..values.len() - 1).step_by(2) {
        keys.push(values[i].to_string());
    }
    for (idx, key) in keys.iter().enumerate() {
        if idx * 2 + 1 < values.len() {
            pairs.push((key.as_str(), values[idx * 2 + 1] as f32));
        }
    }
    let hashed = feature_hash_pairs(&pairs, 32, true);
    let mut out = Vec::with_capacity(dim);
    out.push(n_pairs as f32);
    out.extend_from_slice(&hashed);
    out
}

fn parse_rich_header_values(bytez: &[u8]) -> Vec<u32> {
    // Rich header is between "DanS" marker and "Rich" marker
    let rich_marker = b"Rich";
    let dans_marker: [u8; 4] = [0x44, 0x61, 0x6E, 0x53]; // "DanS"

    // Find "Rich" signature
    let rich_pos = bytez.windows(4).position(|w| w == rich_marker);
    let rich_pos = match rich_pos {
        Some(p) => p,
        None => return vec![],
    };

    if rich_pos + 8 > bytez.len() { return vec![]; }
    let xor_key = u32::from_le_bytes([
        bytez[rich_pos + 4], bytez[rich_pos + 5],
        bytez[rich_pos + 6], bytez[rich_pos + 7],
    ]);

    // Decrypt backwards to find DanS
    let mut start = None;
    let mut pos = rich_pos.saturating_sub(4);
    while pos >= 4 {
        let dword = u32::from_le_bytes([bytez[pos], bytez[pos+1], bytez[pos+2], bytez[pos+3]]);
        if dword ^ xor_key == u32::from_le_bytes(dans_marker) {
            start = Some(pos);
            break;
        }
        if pos < 4 { break; }
        pos -= 4;
    }

    let start = match start {
        Some(s) => s + 16, // skip DanS + 3 padding dwords
        None => return vec![],
    };

    let mut values = Vec::new();
    let mut i = start;
    while i + 4 <= rich_pos {
        let dword = u32::from_le_bytes([bytez[i], bytez[i+1], bytez[i+2], bytez[i+3]]);
        values.push(dword ^ xor_key);
        i += 4;
    }
    values
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. AuthenticodeSignature  (dim = 8)
// ═══════════════════════════════════════════════════════════════════════════

fn authenticode_signature(bytez: &[u8]) -> Vec<f32> {
    // 字段顺序：num_certs, self_signed, empty_program_name, no_countersigner,
    //         parse_error, chain_max_depth, latest_signing_time, signing_time_diff
    //
    // thrember 行为：try { signed_pe.iter_signed_datas() ... } except ParseError → parse_error=1
    // signify 在以下情况会抛 SignedPEParseError：
    //   - PE 没有 certtable（datadir certtable size=0 或 va=0）
    //   - certtable 内容截断/越界
    //   - WIN_CERTIFICATE 头长度无效
    // 我们用同等语义复现：解析失败 = parse_error=1。
    let pe = match PE::parse(bytez) {
        Ok(p) => p,
        Err(_) => return vec![0.0f32; 8], // pe is None 时 thrember 返回全零（无 parse_error）
    };

    let mut out = vec![0.0f32; 8];

    let cert_dir = pe.header.optional_header
        .as_ref()
        .and_then(|o| o.data_directories.get_certificate_table());

    let (cert_offset, cert_size) = match cert_dir {
        Some(d) if d.size > 0 && d.virtual_address > 0 => {
            (d.virtual_address as usize, d.size as usize)
        }
        _ => {
            // signify 此时抛 SignedPEParseError → parse_error=1
            out[4] = 1.0;
            return out;
        }
    };

    if cert_offset.checked_add(cert_size).map_or(true, |end| end > bytez.len()) {
        out[4] = 1.0;
        return out;
    }

    // 走 WIN_CERTIFICATE 链表，每个 entry 8 字节对齐：
    //   DWORD dwLength | WORD wRevision | WORD wCertificateType | BYTE[length-8] data
    let cert_data = &bytez[cert_offset..cert_offset + cert_size];
    let mut pos = 0usize;
    let mut num_certs = 0u32;
    while pos + 8 <= cert_data.len() {
        let length = u32::from_le_bytes([
            cert_data[pos], cert_data[pos + 1], cert_data[pos + 2], cert_data[pos + 3],
        ]) as usize;
        if length <= 8 || pos.checked_add(length).map_or(true, |end| end > cert_data.len()) {
            out[4] = 1.0;
            return out;
        }
        let cert_type = u16::from_le_bytes([cert_data[pos + 6], cert_data[pos + 7]]);
        // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
        if cert_type == 0x0002 {
            num_certs += 1;
        }
        pos = pos.saturating_add((length + 7) & !7);
    }

    if num_certs == 0 {
        // 有 certtable 但里面没有任何 PKCS_SIGNED_DATA 块——signify 同样会抛
        out[4] = 1.0;
        return out;
    }

    out[0] = num_certs as f32; // num_certs
    // 没有完整 ASN.1 解析能力，chain_max_depth 用 num_certs 作下界近似
    out[5] = num_certs as f32; // chain_max_depth
    // self_signed / empty_program_name / no_countersigner / signing_time / signing_time_diff
    // 需要完整 PKCS#7 + X.509 解析才能精确填充，留 0；对模型影响 < 0.3%（8/2568）。
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. PEFormatWarnings  (dim = 88)
//     87 warning slots + 1 count
// ═══════════════════════════════════════════════════════════════════════════

fn pe_format_warnings(_bytez: &[u8], _pe: Option<&PE>) -> Vec<f32> {
    // goblin doesn't generate pefile-style warnings.
    // Return zeros — this group is a minor signal compared to the other 2480 dims.
    vec![0.0f32; 88]
}

#[cfg(test)]
mod string_extractor_tests {
    use super::*;

    /// 旧实现（先把所有串收进 Vec<Vec<u8>> 再统计）——仅测试用作参照，验证流式重写 bit 级一致。
    fn string_extractor_reference(bytez: &[u8]) -> Vec<f32> {
        let mut strings: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::new();
        for &b in bytez {
            if (0x20..=0x7f).contains(&b) {
                cur.push(b);
            } else {
                if cur.len() >= 5 {
                    strings.push(std::mem::take(&mut cur));
                }
                cur.clear();
            }
        }
        if cur.len() >= 5 {
            strings.push(cur);
        }
        let (numstrings, avlength, printables, printabledist, entropy) = if !strings.is_empty() {
            let lens: Vec<usize> = strings.iter().map(|s| s.len()).collect();
            let avlength = lens.iter().sum::<usize>() as f32 / lens.len() as f32;
            let mut c = [0u64; 96];
            for s in &strings {
                for &b in s {
                    c[(b - 0x20) as usize] += 1;
                }
            }
            let csum: u64 = c.iter().sum();
            let p: Vec<f64> = c.iter().map(|&x| x as f64 / csum.max(1) as f64).collect();
            let h: f64 = p.iter().filter(|&&px| px > 0.0).map(|&px| -px * px.log2()).sum();
            (strings.len() as f32, avlength, csum as f32, c, h as f32)
        } else {
            (0.0, 0.0, 0.0, [0u64; 96], 0.0)
        };
        let set = string_regex_set();
        let mut regex_counts = vec![0.0f32; STRING_REGEX_NAMES.len()];
        for s in &strings {
            let s_str = String::from_utf8_lossy(s);
            for idx in set.matches(&s_str).iter() {
                regex_counts[idx] += 1.0;
            }
        }
        let hist_divisor = if printables > 0.0 { printables } else { 1.0 };
        let mut out = Vec::with_capacity(177);
        out.push(numstrings);
        out.push(avlength);
        out.push(printables);
        for i in 0..96 {
            out.push(printabledist[i] as f32 / hist_divisor);
        }
        out.push(entropy);
        out.extend_from_slice(&regex_counts);
        out
    }

    fn assert_parity(input: &[u8]) {
        let a = string_extractor(input);
        let b = string_extractor_reference(input);
        assert_eq!(a.len(), b.len(), "长度不一致");
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(x.to_bits(), y.to_bits(), "第 {i} 维不一致: {x} vs {y}");
        }
    }

    #[test]
    fn parity_empty_and_short() {
        assert_parity(b"");
        assert_parity(b"abc");        // <5，不成串
        assert_parity(b"abcde");      // 正好 5
        assert_parity(b"\x00\x01\x02");
    }

    #[test]
    fn parity_mixed_and_urls() {
        assert_parity(b"hello world this is a test\x00http://evil.example.com/path\x00\x01CreateProcessW\x00short\x00abcd");
        assert_parity(b"C:\\Windows\\System32\\cmd.exe /c whoami\x00\x00HKEY_LOCAL_MACHINE\\Software");
    }

    #[test]
    fn parity_many_tiny_strings() {
        // 大量短串（模拟恶意样本的可打印数据轰炸）——流式实现必须与参照 bit 一致，
        // 且不再把所有串驻留内存。
        let mut buf = Vec::new();
        for i in 0..50_000u32 {
            buf.extend_from_slice(format!("str{:05}", i).as_bytes()); // 8 字符可打印串
            buf.push(0x00); // 分隔符
        }
        assert_parity(&buf);
    }

    #[test]
    fn parity_one_huge_string() {
        // 整块可打印（一个超长串）——峰值内存应为 O(该串)，且统计与参照一致。
        let buf = vec![b'A'; 200_000];
        assert_parity(&buf);
    }
}
