use crate::models::OsForensics;
use chrono::DateTime;
use std::ffi::CStr;
use std::fs;
use std::mem::size_of;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use winreg::enums::*;
use winreg::RegKey;

/// Known injector and cheat tool process names
const KNOWN_INJECTOR_PROCESSES: &[(&str, &str)] = &[
    ("xenos.exe", "Xenos Injector (Inyector DLL avanzado)"),
    ("xenos64.exe", "Xenos Injector x64"),
    ("extreme injector.exe", "Extreme Injector (Inyector de DLLs con Manual Map)"),
    ("extreme injector v3.exe", "Extreme Injector v3"),
    ("gh injector.exe", "GH Injector (Guided Hacking Injector)"),
    ("cheatengine-x86_64.exe", "Cheat Engine x64"),
    ("cheatengine-i386.exe", "Cheat Engine x86"),
    ("cheatengine.exe", "Cheat Engine"),
    ("processhacker.exe", "Process Hacker"),
    ("aimware.exe", "Aimware Client / Loader"),
    ("fuzion.exe", "Fuzion Loader"),
    ("bhop.exe", "Bunnyhop Macro / Tool"),
];

/// Checks if the current process is running with elevated Administrator privileges
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let success = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token);
            if success.is_ok() {
                return elevation.TokenIsElevated != 0;
            }
        }
    }
    false
}

/// Checks the Windows InstallDate in the registry and checks for major updates
pub fn get_windows_install_info() -> (Option<u64>, Option<String>, bool) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut raw_ts: Option<u64> = None;
    let mut ts_str: Option<String> = None;
    let mut has_feature_updates = false;

    if let Ok(cur_ver) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
        if let Ok(install_date) = cur_ver.get_value::<u32, _>("InstallDate") {
            raw_ts = Some(install_date as u64);
            if let Some(dt) = DateTime::from_timestamp(install_date as i64, 0) {
                ts_str = Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
            }
        }
    }

    // Check if Source OS updates exist in HKLM\SYSTEM\Setup
    if let Ok(setup_key) = hklm.open_subkey("SYSTEM\\Setup") {
        for subkey_name in setup_key.enum_keys().filter_map(|r| r.ok()) {
            if subkey_name.starts_with("Source OS") {
                has_feature_updates = true;
                break;
            }
        }
    }

    (raw_ts, ts_str, has_feature_updates)
}

/// Scans running Windows processes for active injectors or cheat tools
pub fn find_active_injectors() -> Vec<String> {
    let mut found = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snap) = snapshot {
            let mut entry: PROCESSENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snap, &mut entry).is_ok() {
                loop {
                    let name = CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                        .to_string_lossy()
                        .to_lowercase();

                    for (proc_name, label) in KNOWN_INJECTOR_PROCESSES {
                        if name == *proc_name || name.contains(proc_name) {
                            let item = format!("{} (PID: {})", label, entry.th32ProcessID);
                            if !found.contains(&item) {
                                found.push(item);
                            }
                        }
                    }

                    if Process32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }
    found
}

/// Audits Windows Prefetch directory for suspicious executables or signs of wiping
pub fn audit_prefetch() -> (bool, usize, bool, Vec<String>) {
    let prefetch_dir = Path::new("C:\\Windows\\Prefetch");
    if !prefetch_dir.exists() {
        return (false, 0, false, Vec::new());
    }

    let mut total_files = 0usize;
    let mut suspicious_entries = Vec::new();

    if let Ok(entries) = fs::read_dir(prefetch_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().eq_ignore_ascii_case("pf") {
                    total_files += 1;
                    let filename = path.file_name().unwrap_or_default().to_string_lossy().to_uppercase();

                    // Check and identify specific tools in Prefetch
                    if filename.contains("XENOS") {
                        suspicious_entries.push(format!("Xenos Injector (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("EXTREMEINJECT") {
                        suspicious_entries.push(format!("Extreme Injector (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("CHEATENGINE") {
                        suspicious_entries.push(format!("Cheat Engine (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("GH_INJECTOR") || filename.contains("GHINJECTOR") {
                        suspicious_entries.push(format!("GH Injector (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("AIMWARE") {
                        suspicious_entries.push(format!("Aimware Loader (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("FUZION") {
                        suspicious_entries.push(format!("Fuzion Loader (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("AUTOHOTKEY") {
                        suspicious_entries.push(format!("AutoHotkey (Residuo en Prefetch: {})", filename));
                    } else if filename.contains("INJECTOR") {
                        suspicious_entries.push(format!("Inyector generico (Residuo en Prefetch: {})", filename));
                    }
                }
            }
        }
    }

    let wiped = total_files > 0 && total_files < 10;
    (true, total_files, wiped, suspicious_entries)
}

/// Collects all OS forensics metrics
pub fn collect_os_forensics() -> OsForensics {
    let admin = is_elevated();
    let (raw_ts, ts_str, has_updates) = get_windows_install_info();
    let (prefetch_on, total_pf, pf_wiped, suspicious_pf) = audit_prefetch();
    let active_injectors = find_active_injectors();

    OsForensics {
        is_admin: admin,
        windows_install_date_raw: raw_ts,
        windows_install_date_str: ts_str,
        has_feature_updates: has_updates,
        prefetch_enabled: prefetch_on,
        prefetch_total_files: total_pf,
        prefetch_wiped_recently: pf_wiped,
        suspicious_prefetch_entries: suspicious_pf,
        active_injector_processes: active_injectors,
        suspicious_game_files: Vec::new(),
    }
}
