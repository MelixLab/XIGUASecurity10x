//! Sandboxie Monitor API - Synchronous driver-level trace reader
//!
//! Uses Sandboxie's kernel driver (SbieDrv.sys) Monitor API to read
//! structured behavior trace entries in real-time, replacing the old
//! polling approach (file system snapshots + network polling + process tree scanning).
//!
//! Key APIs:
//! - API_MONITOR_CONTROL (0x1234001B) — enable/disable monitoring
//! - API_MONITOR_GET2 (0x12340048) — bulk read trace entries
//!
//! Trace entry buffer format (per entry):
//!   u32 entry_size | u64 timestamp | u32 type_code | u32 pid | u32 tid | strings...
//! Strings are null-terminated UTF-16LE, terminated by 0xFFFF marker.

#![allow(dead_code)]

use std::ffi::c_void;
use std::time::Instant;

use crate::sandbox_analysis::BehaviorEvent;

// ── IOCTL & API constants ─────────────────────────────────────────

/// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x801, METHOD_NEITHER=3, FILE_ANY_ACCESS=0)
const SBIE_IOCTL: u32 = (0x22u32 << 16) | (0x801u32 << 2) | 3;

const API_MONITOR_CONTROL: u64 = 0x1234_001B;
const API_MONITOR_GET2: u64 = 0x1234_0048;

const API_NUM_ARGS: usize = 8;
const TRACE_BUFFER_SIZE: usize = 256 * 4096; // 1 MiB

/// HRESULTs returned by DeviceIoControl
const HRESULT_NO_MORE_ITEMS: u32 = 0x8007_0103;
const HRESULT_NOT_READY: u32 = 0x8007_0015;

/// Max drain rounds per collection cycle (32 * 1MB = 32MB)
const MAX_DRAIN_PER_ROUND: u32 = 32;

// ── Monitor type constants (lower byte of type_code) ──────────────

const MONITOR_TYPE_MASK: u32 = 0x000000FF;
const MONITOR_PIPE: u32 = 0x02;
const MONITOR_IPC: u32 = 0x03;
const MONITOR_IMAGE: u32 = 0x09;
const MONITOR_FILE: u32 = 0x0A;
const MONITOR_KEY: u32 = 0x0B;
const MONITOR_NETFW: u32 = 0x0D;
const MONITOR_SCM: u32 = 0x0E;
const MONITOR_RPC: u32 = 0x10;
const MONITOR_DNS: u32 = 0x11;

/// Result flags (bits 20-23)
const MONITOR_ALLOWED: u32 = 0x00100000;
const MONITOR_DENIED: u32 = 0x00200000;
const MONITOR_SUCCESS: u32 = 0x00400000;
const MONITOR_FAILURE: u32 = 0x00800000;

// ── Win32 imports ──────────────────────────────────────────────────

#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::IO::DeviceIoControl,
    },
};

// ── TraceEntry ─────────────────────────────────────────────────────

/// A decoded Sandboxie trace entry.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub type_code: u32,
    pub pid: u32,
    pub tid: u32,
    pub strings: Vec<String>,
}

impl TraceEntry {
    /// Extract the monitor type (lower byte).
    pub fn mon_type(&self) -> u32 {
        self.type_code & MONITOR_TYPE_MASK
    }

    /// Whether the operation was allowed.
    pub fn is_allowed(&self) -> bool {
        (self.type_code & MONITOR_ALLOWED) != 0
    }

    /// Whether the operation was denied.
    pub fn is_denied(&self) -> bool {
        (self.type_code & MONITOR_DENIED) != 0
    }

    /// Whether the operation succeeded.
    pub fn is_success(&self) -> bool {
        (self.type_code & MONITOR_SUCCESS) != 0
    }

    /// First string (usually the path or resource name).
    pub fn primary(&self) -> &str {
        self.strings.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Second string (usually the access flags, e.g. "FA 00100002").
    pub fn access_flags(&self) -> &str {
        self.strings.get(1).map(|s| s.as_str()).unwrap_or("")
    }
}

// ── SbieMonitor ────────────────────────────────────────────────────

/// Manages a connection to the Sandboxie kernel driver for trace reading.
///
/// Create with [`SbieMonitor::open`], then call [`SbieMonitor::collect`]
/// in a loop to drain trace entries and convert them to `BehaviorEvent`s.
/// Drop or call [`SbieMonitor::close`] to disable monitoring.
pub struct SbieMonitor {
    #[cfg(windows)]
    device: Option<HANDLE>,
    #[cfg(not(windows))]
    device: Option<()>,
    buf: Vec<u8>,
    start: Instant,
    /// PIDs belonging to the sample process tree (for filtering).
    sample_pids: std::collections::HashSet<u32>,
    /// Already-seen events (dedup key → ()),
    /// Key = (type, path_hash)
    seen: std::collections::HashSet<(u32, u64)>,
}

impl SbieMonitor {
    /// Open the Sandboxie driver and enable monitoring.
    ///
    /// `sample_pids` — PIDs of the target process and its children; only
    /// trace entries from these PIDs will be collected.
    #[cfg(windows)]
    pub fn open(sample_pids: Vec<u32>) -> Result<Self, String> {
        let device = open_sandboxie_driver().ok_or("无法打开 Sandboxie 驱动设备")?;

        if !set_monitor_state(device, true) {
            unsafe { let _ = CloseHandle(device); }
            return Err("无法启用 Sandboxie 监控 (API_MONITOR_CONTROL)".into());
        }

        println!("[SbieMonitor] 驱动已打开，监控已启用，目标 PIDs: {:?}", sample_pids);

        Ok(Self {
            device: Some(device),
            buf: vec![0u8; TRACE_BUFFER_SIZE],
            start: Instant::now(),
            sample_pids: sample_pids.into_iter().collect(),
            seen: std::collections::HashSet::new(),
        })
    }

    #[cfg(not(windows))]
    pub fn open(_sample_pids: Vec<u32>) -> Result<Self, String> {
        Err("Sandboxie Monitor API 仅支持 Windows".into())
    }

    /// Drain all pending trace entries and convert them to `BehaviorEvent`s.
    ///
    /// Call this in a loop (e.g. every 500 ms) until the analysis timeout.
    pub fn collect(&mut self) -> Vec<BehaviorEvent> {
        let mut events = Vec::new();

        #[cfg(windows)]
        {
            let device = match self.device {
                Some(h) => h,
                None => return events,
            };

            for _ in 0..MAX_DRAIN_PER_ROUND {
                match get_monitor_data(device, &mut self.buf) {
                    GetMonitorResult::Empty | GetMonitorResult::NotReady | GetMonitorResult::SessionMissing => break,
                    GetMonitorResult::Failed(_) => break,
                    GetMonitorResult::Entries(entries, _) => {
                        for entry in entries {
                            // Only collect entries from sample PIDs
                            if !self.sample_pids.is_empty() && !self.sample_pids.contains(&entry.pid) {
                                continue;
                            }

                            // Filter noise
                            if is_noise_event(&entry) {
                                continue;
                            }

                            // Map to BehaviorEvent
                            if let Some(event) = map_trace_to_behavior(&entry, self.start) {
                                // Dedup
                                let key = (event_type_key(&event), path_hash(&event));
                                if self.seen.insert(key) {
                                    events.push(event);
                                }
                            }
                        }
                    }
                }
            }
        }

        events
    }

    /// Disable monitoring and close the driver handle.
    pub fn close(&mut self) {
        #[cfg(windows)]
        {
            if let Some(device) = self.device.take() {
                let _ = set_monitor_state(device, false);
                unsafe { let _ = CloseHandle(device); }
                println!("[SbieMonitor] 监控已关闭");
            }
        }
    }
}

impl Drop for SbieMonitor {
    fn drop(&mut self) {
        self.close();
    }
}

// ── Win32 driver communication ─────────────────────────────────────

#[cfg(windows)]
fn open_sandboxie_driver() -> Option<HANDLE> {
    const CANDIDATES: &[&str] = &[
        "\\\\.\\GLOBALROOT\\Device\\SandboxieDriverApi",
        "\\\\.\\SandboxieDriverApi",
    ];

    for candidate in CANDIDATES {
        let path: Vec<u16> = candidate
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            match CreateFileW(
                PCWSTR(path.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                Ok(h) if h != INVALID_HANDLE_VALUE => return Some(h),
                _ => {}
            }
        }
    }
    None
}

#[cfg(windows)]
fn set_monitor_state(device: HANDLE, on: bool) -> bool {
    let mut new_state: u32 = if on { 1 } else { 0 };
    let mut parms: [u64; API_NUM_ARGS] = [0; API_NUM_ARGS];
    parms[0] = API_MONITOR_CONTROL;
    parms[1] = (&mut new_state) as *mut u32 as u64;

    unsafe {
        let mut bytes: u32 = 0;
        DeviceIoControl(
            device,
            SBIE_IOCTL,
            Some(parms.as_ptr() as *const c_void),
            (API_NUM_ARGS * 8) as u32,
            None,
            0,
            Some(&mut bytes),
            None,
        )
        .is_ok()
    }
}

#[cfg(windows)]
enum GetMonitorResult {
    Entries(Vec<TraceEntry>, u32),
    Empty,
    NotReady,
    SessionMissing,
    Failed(u32),
}

#[cfg(windows)]
fn get_monitor_data(device: HANDLE, buf: &mut [u8]) -> GetMonitorResult {
    let mut buf_len: u32 = buf.len() as u32;
    let mut parms: [u64; API_NUM_ARGS] = [0; API_NUM_ARGS];
    parms[0] = API_MONITOR_GET2;
    parms[1] = buf.as_mut_ptr() as u64;
    parms[2] = (&mut buf_len) as *mut u32 as u64;

    unsafe {
        let mut bytes: u32 = 0;
        match DeviceIoControl(
            device,
            SBIE_IOCTL,
            Some(parms.as_ptr() as *const c_void),
            (API_NUM_ARGS * 8) as u32,
            None,
            0,
            Some(&mut bytes),
            None,
        ) {
            Ok(()) => {
                let returned_len = buf_len as usize;
                if returned_len <= 4 {
                    return GetMonitorResult::Empty;
                }
                GetMonitorResult::Entries(decode_buffer(&buf[..returned_len]), returned_len as u32)
            }
            Err(e) => {
                let code = e.code().0 as u32;
                match code {
                    HRESULT_NO_MORE_ITEMS => GetMonitorResult::Empty,
                    HRESULT_NOT_READY => GetMonitorResult::NotReady,
                    _ => GetMonitorResult::Failed(code),
                }
            }
        }
    }
}

// ── Buffer decoding ────────────────────────────────────────────────

fn decode_buffer(buf: &[u8]) -> Vec<TraceEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos + 4 <= buf.len() {
        let size = read_u32(buf, pos);
        pos += 4;
        if size == 0 {
            break;
        }
        let entry_end = pos + size as usize;
        if entry_end > buf.len() {
            break;
        }
        if (size as usize) < 20 {
            pos = entry_end;
            continue;
        }

        pos += 8; // skip timestamp (8 bytes)
        let type_code = read_u32(buf, pos); pos += 4;
        let pid = read_u32(buf, pos); pos += 4;
        let tid = read_u32(buf, pos); pos += 4;

        let mut strings = Vec::new();
        loop {
            if pos + 2 > entry_end {
                break;
            }
            let w = read_u16(buf, pos);
            if w == 0xFFFF {
                break;
            }
            let str_start = pos;
            while pos + 2 <= entry_end && read_u16(buf, pos) != 0 {
                pos += 2;
            }
            let wchars: Vec<u16> = buf[str_start..pos]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            strings.push(String::from_utf16_lossy(&wchars));
            if pos + 2 <= entry_end {
                pos += 2; // skip null terminator
            }
        }

        entries.push(TraceEntry { type_code, pid, tid, strings });
        pos = entry_end;
    }
    entries
}

fn read_u32(buf: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
}

fn read_u16(buf: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([buf[pos], buf[pos + 1]])
}

// ── Noise filtering ────────────────────────────────────────────────

/// Filter out uninteresting system-level events that would flood the engine.
fn is_noise_event(entry: &TraceEntry) -> bool {
    if entry.strings.is_empty() {
        return true;
    }

    let res = entry.primary().to_lowercase();

    // Filter system DLL reads (normal dependency loading)
    if entry.mon_type() == MONITOR_FILE {
        let is_system_read = res.contains("\\windows\\system32\\")
            || res.contains("\\windows\\syswow64\\")
            || res.contains("\\windows\\winsxs\\")
            || res.contains("\\program files\\")
            || res.contains("\\program files (x86)\\")
            || res.contains("\\device\\harddiskvolume");

        // Only filter if it's a read operation (no write flags)
        let access = entry.access_flags().to_lowercase();
        let is_write = access.contains("00100000")
            || access.contains("00000002")
            || access.contains("00000004")
            || access.contains("00010000");

        if is_system_read && !is_write {
            return true;
        }

        // Filter sandbox-internal paths
        if res.contains("\\sandbox\\") && !is_write {
            return true;
        }
    }

    // Filter system registry queries (CLSID, Interface, TypeLib)
    if entry.mon_type() == MONITOR_KEY {
        let is_system_query = res.contains("\\clsid\\")
            || res.contains("\\interface\\")
            || res.contains("\\typelib\\")
            || res.contains("\\microsoft\\windows\\currentversion\\explorer")
            || res.contains("\\microsoft\\windows nt\\currentversion\\font");

        let is_important = res.contains("\\run")
            || res.contains("\\runonce")
            || res.contains("\\startup")
            || res.contains("\\shell\\open\\command")
            || res.contains("\\winlogon")
            || res.contains("\\services\\")
            || res.contains("\\drivers\\")
            || res.contains("\\image file execution")
            || res.contains("\\appinit_dlls");

        if is_system_query && !is_important {
            return true;
        }
    }

    // Filter common noise API calls
    let noise_patterns = [
        "alpcsendwaitreceiveport",
        "ntwaitformultipleobjects",
        "ntwaitforsingleobject",
        "ntdelayexecution",
        "ntqueryvirtualmemory",
        "ntqueryinformationprocess",
        "ntqueryinformationthread",
        "ntqueryobject",
        "ntquerysysteminformation",
        "ntqueryperformancecounter",
        "ntgettickcount",
        "ntgetsystemtime",
        "ntgetcurrentprocessorid",
        "ntgetcurrentthreadid",
        "ntgetcurrentprocessid",
        "rtlqueryperformancecounter",
        "rtlqueryperformancefrequency",
        "ntsetevent",
        "ntcreateevent",
        "ntopenevent",
        "ntresetevent",
        "ntclearevent",
        "ntclose",
        "baseNamedObjects",
    ];
    for p in &noise_patterns {
        if res.contains(p) {
            return true;
        }
    }

    false
}

// ── Trace → BehaviorEvent mapping ─────────────────────────────────

/// Convert a Sandboxie trace entry into a `BehaviorEvent`.
///
/// Returns `None` for entries that don't map to a meaningful behavior.
fn map_trace_to_behavior(entry: &TraceEntry, _start: Instant) -> Option<BehaviorEvent> {
    let mon_type = entry.mon_type();
    let path = entry.primary();
    let access = entry.access_flags();

    match mon_type {
        MONITOR_FILE => map_file_event(path, access),
        MONITOR_KEY => map_registry_event(entry, path, access),
        MONITOR_NETFW => map_network_event(path),
        MONITOR_DNS => map_dns_event(path),
        MONITOR_SCM => map_service_event(path),
        MONITOR_IPC | MONITOR_PIPE | MONITOR_RPC => map_ipc_event(path),
        MONITOR_IMAGE => map_image_event(path),
        _ => None,
    }
}

fn map_file_event(path: &str, access: &str) -> Option<BehaviorEvent> {
    let lower = path.to_lowercase();
    let is_write = access.contains("00100000")
        || access.contains("00000002")
        || access.contains("00000004");
    let is_delete = access.contains("00010000");

    if !is_write && !is_delete {
        return None; // Only care about writes/deletes
    }

    let is_executable = lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".sys")
        || lower.ends_with(".bat")
        || lower.ends_with(".ps1")
        || lower.ends_with(".vbs")
        || lower.ends_with(".js")
        || lower.ends_with(".scr");

    let is_system_dir = lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.contains("\\program files\\");

    let is_suspicious_dir = lower.contains("\\appdata\\roaming\\")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("\\windows\\temp\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("$recycle.bin\\");

    let filename = path.rsplit('\\').next().unwrap_or(path);
    let is_random_name = is_random_filename(filename);

    if is_delete {
        Some(BehaviorEvent::FileDelete {
            path: path.to_string(),
            count: 1,
        })
    } else {
        Some(BehaviorEvent::FileCreate {
            path: path.to_string(),
            is_system_dir,
            is_executable,
            is_suspicious_dir,
            is_random_name,
        })
    }
}

fn map_registry_event(entry: &TraceEntry, path: &str, access: &str) -> Option<BehaviorEvent> {
    let lower = path.to_lowercase();

    let is_run_key = lower.contains("\\run")
        || lower.contains("\\runonce")
        || lower.contains("\\startupapproved\\run");
    let is_security_key = lower.contains("\\security\\")
        || lower.contains("\\policies\\")
        || lower.contains("\\firewall");
    let is_proxy_key = lower.contains("\\proxysettings")
        || lower.contains("\\internet settings\\proxy");

    // Only report important registry keys
    let is_important = is_run_key
        || is_security_key
        || is_proxy_key
        || lower.contains("\\winlogon")
        || lower.contains("\\services\\")
        || lower.contains("\\drivers\\")
        || lower.contains("\\image file execution")
        || lower.contains("\\appinit_dlls")
        || lower.contains("\\shell\\open\\command")
        || lower.contains("\\userinit")
        || lower.contains("\\cmdprocedure");

    if !is_important {
        return None;
    }

    // Determine if create or modify
    let is_create = access.contains("00020000") || entry.is_success();

    if is_create && !entry.is_denied() {
        Some(BehaviorEvent::RegCreate {
            key: path.to_string(),
        })
    } else {
        Some(BehaviorEvent::RegModify {
            key: path.to_string(),
            is_run_key,
            is_security_key,
            is_proxy_key,
        })
    }
}

fn map_network_event(path: &str) -> Option<BehaviorEvent> {
    // NetFw trace entries contain the IP:port in the string
    // Try to parse IP and port from the trace string
    let (ip, port) = parse_ip_port(path);
    let is_suspicious = is_suspicious_port(port);

    Some(BehaviorEvent::NetworkConnect {
        ip,
        port,
        is_suspicious,
    })
}

fn map_dns_event(path: &str) -> Option<BehaviorEvent> {
    // DNS trace: the domain name is in the string
    let domain = path.to_string();
    let is_suspicious = is_suspicious_domain(&domain);

    Some(BehaviorEvent::NetworkDNS {
        domain,
        is_suspicious,
    })
}

fn map_service_event(path: &str) -> Option<BehaviorEvent> {
    // SCM trace: service control manager operations
    let name = path.rsplit('\\').next().unwrap_or(path).to_string();

    Some(BehaviorEvent::ServiceCreate { name })
}

fn map_ipc_event(path: &str) -> Option<BehaviorEvent> {
    let lower = path.to_lowercase();

    // Detect process injection via IPC
    if lower.contains("\\basenamedobjects\\")
        || lower.contains("\\rpc control\\")
        || lower.contains("\\windows\\")
    {
        return None; // Too noisy
    }

    // IPC to services.exe or lsass.exe can indicate injection
    if lower.contains("lsass") || lower.contains("sam_s") {
        return Some(BehaviorEvent::LsassAccess);
    }

    None
}

fn map_image_event(path: &str) -> Option<BehaviorEvent> {
    let lower = path.to_lowercase();

    // Detect driver loading
    if lower.ends_with(".sys") {
        let name = path.rsplit('\\').next().unwrap_or(path).to_string();
        return Some(BehaviorEvent::DriverLoad { name });
    }

    // Detect DLL injection (loading DLLs into other processes)
    if lower.ends_with(".dll") {
        let name = path.rsplit('\\').next().unwrap_or(path).to_string();
        let is_suspicious = is_suspicious_dll(&name);
        if is_suspicious {
            return Some(BehaviorEvent::DllInjection {
                target: name,
            });
        }
    }

    None
}

// ── Helpers ────────────────────────────────────────────────────────

fn is_random_filename(filename: &str) -> bool {
    let stem = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if stem.is_empty() {
        return false;
    }
    if stem.starts_with('~') {
        return true;
    }
    if stem.starts_with('{') && stem.ends_with('}') && stem.len() >= 36 {
        return true;
    }
    let is_hex = stem.len() >= 6 && stem.chars().all(|c| c.is_ascii_hexdigit());
    let is_hash_len = matches!(stem.len(), 32 | 40 | 64)
        && stem.chars().all(|c| c.is_ascii_hexdigit());
    let is_pure_digits = stem.len() >= 6 && stem.chars().all(|c| c.is_ascii_digit());
    is_hex || is_hash_len || is_pure_digits
}

fn parse_ip_port(s: &str) -> (String, u16) {
    // Try to extract IP:port from the NetFw trace string
    // Format varies; attempt common patterns
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() >= 2 {
        let ip = parts[parts.len() - 2].to_string();
        let port = parts[parts.len() - 1]
            .parse::<u16>()
            .unwrap_or(0);
        return (ip, port);
    }
    (s.to_string(), 0)
}

fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 4444 | 4445 | 6666 | 6667 | 9999 | 1234 | 31337 | 3389 | 22 | 23 | 445 | 139 | 8080 | 8443)
}

fn is_suspicious_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    // DGA-like domains (random-looking, long, many consonants)
    if lower.len() > 20 && lower.chars().filter(|c| c.is_alphabetic()).count() > 15 {
        return true;
    }
    // Known C2 patterns
    lower.ends_with(".xyz")
        || lower.ends_with(".top")
        || lower.ends_with(".click")
        || lower.ends_with(".ddns.net")
}

fn is_suspicious_dll(name: &str) -> bool {
    let lower = name.to_lowercase();
    // DLLs with random names or dropped to unusual locations
    is_random_filename(&lower) || lower.starts_with("ntdll") == false && lower.contains("hook")
}

/// Generate a type discriminator key for deduplication.
fn event_type_key(event: &BehaviorEvent) -> u32 {
    match event {
        BehaviorEvent::FileCreate { .. } => 1,
        BehaviorEvent::FileModify { .. } => 2,
        BehaviorEvent::FileDelete { .. } => 3,
        BehaviorEvent::RegModify { .. } => 4,
        BehaviorEvent::RegCreate { .. } => 5,
        BehaviorEvent::NetworkConnect { .. } => 6,
        BehaviorEvent::NetworkDNS { .. } => 7,
        BehaviorEvent::ServiceCreate { .. } => 8,
        BehaviorEvent::DriverLoad { .. } => 9,
        BehaviorEvent::DllInjection { .. } => 10,
        BehaviorEvent::LsassAccess => 11,
        _ => 99,
    }
}

/// Hash the path/domain/IP from an event for deduplication.
fn path_hash(event: &BehaviorEvent) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match event {
        BehaviorEvent::FileCreate { path, .. } |
        BehaviorEvent::FileModify { path, .. } |
        BehaviorEvent::FileDelete { path, .. } => { path.hash(&mut hasher); }
        BehaviorEvent::RegModify { key, .. } |
        BehaviorEvent::RegCreate { key, .. } => { key.hash(&mut hasher); }
        BehaviorEvent::NetworkConnect { ip, port, .. } => { ip.hash(&mut hasher); port.hash(&mut hasher); }
        BehaviorEvent::NetworkDNS { domain, .. } => { domain.hash(&mut hasher); }
        BehaviorEvent::ServiceCreate { name } => { name.hash(&mut hasher); }
        BehaviorEvent::DriverLoad { name } => { name.hash(&mut hasher); }
        BehaviorEvent::DllInjection { target, .. } => { target.hash(&mut hasher); }
        _ => {}
    }
    hasher.finish()
}
