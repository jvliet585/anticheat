use crate::models::{MemoryRegionDetail, ProcessAudit};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HMODULE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExA, LIST_MODULES_ALL};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// Finds the PID of left4dead2.exe if it is currently running
pub fn find_l4d2_pid() -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy();

                if name.eq_ignore_ascii_case("left4dead2.exe") {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

/// Known cheats, menus, and signature keywords to identify specifically
const KNOWN_CHEAT_SIGNATURES: &[(&str, &str)] = &[
    ("AIMWARE", "Aimware (Menu / Multihack comercial)"),
    ("INTERWEBZ", "Interwebz (Menu / Cheat para Source Engine)"),
    ("FUZION", "Fuzion (Menu / Cheat de L4D2)"),
    ("L4D2HOOK", "L4D2Hook (Internal Cheat / Menu para L4D2)"),
    ("NEONHACK", "NeonHack (Menu / ESP para L4D2)"),
    ("PROJECT INFINITY", "Project Infinity (Cheat de L4D2)"),
    ("ZOMBSMENU", "ZombsMenu (Menu de modificacion / VScript exploit)"),
    ("ADMIN SYSTEM", "Admin System (Menu de ejecucion no autorizada de VScript)"),
    ("MINHOOK", "MinHook (Libreria de enganche de funciones utilizada por inyectores)"),
    ("AIMBOT", "Aimbot generico (Firma de auto-apuntado en memoria)"),
    ("TRIGGERBOT", "Triggerbot (Firma de auto-disparo)"),
    ("GLOW_ESP", "Glow ESP / Wallhack (Firma de contornos en memoria)"),
    ("AUTOHOP", "Auto-Bunnyhop (Firma de salto automatico en memoria)"),
    ("BUNNYHOP", "Bunnyhop Script (Macro / Asistente de movimiento)"),
    ("SPEEDHACK", "Speedhack (Manipulacion de tickrate / velocidad)"),
    ("NORECOIL", "No-Recoil (Compensacion de retroceso)"),
    ("NOSPREAD", "No-Spread (Eliminacion de dispersion de armas)"),
];

/// Known legitimate overlays to avoid false accusations
const KNOWN_LEGIT_OVERLAYS: &[(&str, &str)] = &[
    ("DISCORDHOOK", "Discord In-Game Overlay"),
    ("GAMEOVERLAYRENDERER", "Steam Community Overlay"),
    ("RIVATUNER", "RivaTuner Statistics Server (RTSS)"),
    ("RTSS", "RivaTuner Statistics Server"),
    ("OBS-GAME-CAPTURE", "OBS Studio Game Capture"),
    ("NVSPCAP", "NVIDIA GeForce Experience ShadowPlay"),
];

/// Helper to extract printable ASCII strings from raw memory bytes
fn extract_printable_strings(buf: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut cur = Vec::new();

    for &b in buf {
        if (0x20..=0x7E).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 4 {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) && !strings.contains(&trimmed) {
                        strings.push(trimmed);
                    }
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        if let Ok(s) = String::from_utf8(cur) {
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() && trimmed.chars().any(|c| c.is_alphabetic()) && !strings.contains(&trimmed) {
                strings.push(trimmed);
            }
        }
    }
    strings
}

/// Performs memory and module audit of left4dead2.exe
pub fn audit_game_process() -> ProcessAudit {
    let pid_opt = find_l4d2_pid();
    if pid_opt.is_none() {
        return ProcessAudit {
            l4d2_running: false,
            pid: None,
            unbacked_memory_regions: 0,
            unbacked_rwx_regions: 0,
            unbacked_large_regions: 0,
            total_unbacked_bytes: 0,
            detected_cheat_names: Vec::new(),
            memory_diagnostics: Vec::new(),
            suspicious_modules: Vec::new(),
            total_modules_scanned: 0,
            memory_scan_completed: false,
            notes: vec!["left4dead2.exe no estaba en ejecucion durante la auditoria.".to_string()],
        };
    }

    let pid = pid_opt.unwrap();
    let mut notes = Vec::new();
    let mut unbacked_count = 0usize;
    let mut unbacked_rwx = 0usize;
    let mut unbacked_large = 0usize;
    let mut total_unbacked_bytes = 0usize;
    let mut detected_cheats = Vec::new();
    let mut memory_diagnostics = Vec::new();
    let mut suspicious_mods = Vec::new();
    let mut total_mods = 0usize;
    let mut memory_scan_ok = false;

    unsafe {
        let handle_res = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if let Ok(handle) = handle_res {
            // 1. Scan memory pages for unbacked executable memory and inspect memory content
            let mut addr: usize = 0x10000; // Start after null-page
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            loop {
                if addr >= 0x7FFF0000 {
                    // Reached typical 32-bit user-space limit
                    memory_scan_ok = true;
                    break;
                }

                let query_bytes = VirtualQueryEx(
                    handle,
                    Some(addr as *const c_void),
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if query_bytes == 0 {
                    break;
                }

                // Look for committed executable memory in private pages (not backed by file image)
                if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE {
                    let is_exec = mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ;
                    if is_exec {
                        unbacked_count += 1;
                        total_unbacked_bytes += mbi.RegionSize;

                        let is_rwx = mbi.Protect == PAGE_EXECUTE_READWRITE;
                        if is_rwx {
                            unbacked_rwx += 1;
                        }
                        if mbi.RegionSize >= 65536 {
                            unbacked_large += 1;
                        }

                        // Read up to 65536 bytes from this unbacked memory region to diagnose exact origin
                        let read_size = mbi.RegionSize.min(65536);
                        let mut buf = vec![0u8; read_size];
                        let mut bytes_read = 0usize;
                        let read_ok = ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buf.as_mut_ptr() as *mut c_void,
                            buf.len(),
                            Some(&mut bytes_read),
                        );

                        let mut region_strings = Vec::new();
                        let mut identified_origin: Option<String> = None;
                        let is_pe = bytes_read >= 2 && &buf[0..2] == b"MZ";

                        if read_ok.is_ok() && bytes_read > 0 {
                            let text = String::from_utf8_lossy(&buf[..bytes_read]).to_uppercase();
                            let raw_strings = extract_printable_strings(&buf[..bytes_read]);

                            // Check against known cheat signatures
                            for (sig, label) in KNOWN_CHEAT_SIGNATURES {
                                if text.contains(sig) {
                                    let found_str = format!("{} (Firma en memoria: {})", label, sig);
                                    if !detected_cheats.contains(&found_str) {
                                        detected_cheats.push(found_str);
                                    }
                                    identified_origin = Some(format!("Cheat / Menu detectado: {}", label));
                                }
                            }

                            // Check if it's an identified legitimate overlay
                            for (sig, label) in KNOWN_LEGIT_OVERLAYS {
                                if text.contains(sig) {
                                    notes.push(format!("Region de memoria respaldada por overlay legitimo: {}", label));
                                    identified_origin = Some(format!("Overlay legitimo: {}", label));
                                }
                            }

                            // Check graphics/driver indicators
                            if identified_origin.is_none() {
                                if text.contains("D3D") || text.contains("DIRECTX") || text.contains("NVIDIA") || text.contains("SHADER") || text.contains("RENDER") {
                                    identified_origin = Some("Renderizado Grafico / Shader JIT".to_string());
                                } else if is_pe {
                                    identified_origin = Some("DLL inyectada sin respaldo (Manual Map PE)".to_string());
                                } else if is_rwx {
                                    identified_origin = Some("Memoria RWX privada (posible hook/trampolin)".to_string());
                                }
                            }

                            // Keep top 8 informative strings for diagnostics
                            region_strings = raw_strings.into_iter().take(8).collect();
                        }

                        memory_diagnostics.push(MemoryRegionDetail {
                            base_address: format!("0x{:X}", mbi.BaseAddress as usize),
                            size_kb: mbi.RegionSize / 1024,
                            protection: if is_rwx { "RWX".to_string() } else { "RX".to_string() },
                            is_pe_image: is_pe,
                            identified_origin,
                            extracted_strings: region_strings,
                        });
                    }
                }

                let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if next_addr <= addr {
                    break;
                }
                addr = next_addr;
            }

            // 2. Scan loaded modules for injected DLLs and proxy DLL hijacking
            let mut modules = [HMODULE::default(); 1024];
            let mut cb_needed = 0u32;
            if EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * size_of::<HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_ok()
            {
                total_mods = (cb_needed as usize) / size_of::<HMODULE>();
                let limit = total_mods.min(modules.len());

                for i in 0..limit {
                    let hmod = modules[i];
                    let mut path_buf = [0u8; 512];
                    let len = GetModuleFileNameExA(handle, hmod, &mut path_buf);
                    if len > 0 {
                        let path_str = String::from_utf8_lossy(&path_buf[..len as usize]).to_string();
                        let lower = path_str.to_lowercase();

                        // Detect known cheat/injector naming signatures in loaded modules
                        if lower.contains("xenos")
                            || lower.contains("injector")
                            || lower.contains("aimware")
                            || lower.contains("fuzion")
                            || lower.contains("l4d2hook")
                            || lower.contains("neonhack")
                            || lower.contains("interwebz")
                            || lower.contains("cheat")
                            || lower.contains("hack")
                            || lower.contains("aimbot")
                        {
                            suspicious_mods.push(path_str.clone());
                            let detected_label = format!("Modulo DLL malicioso cargado: {}", path_str);
                            if !detected_cheats.contains(&detected_label) {
                                detected_cheats.push(detected_label);
                            }
                        }

                        // Detect proxy DLL hijacking in L4D2 folder (e.g. d3d9.dll, dxgi.dll, version.dll loaded from game folder)
                        if (lower.ends_with("d3d9.dll") || lower.ends_with("dxgi.dll") || lower.ends_with("version.dll"))
                            && !lower.contains("windows\\system32")
                            && !lower.contains("windows\\syswow64")
                        {
                            let proxy_msg = format!("Proxy DLL sospechosa en carpeta del juego: {}", path_str);
                            suspicious_mods.push(proxy_msg.clone());
                            detected_cheats.push(proxy_msg);
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
            notes.push(format!("Proceso escaneado exitosamente (PID: {}).", pid));
        } else {
            notes.push("No se pudo abrir left4dead2.exe. Ejecute la auditoria como Administrador.".to_string());
        }
    }

    ProcessAudit {
        l4d2_running: true,
        pid: Some(pid),
        unbacked_memory_regions: unbacked_count,
        unbacked_rwx_regions: unbacked_rwx,
        unbacked_large_regions: unbacked_large,
        total_unbacked_bytes,
        detected_cheat_names: detected_cheats,
        memory_diagnostics,
        suspicious_modules: suspicious_mods,
        total_modules_scanned: total_mods,
        memory_scan_completed: memory_scan_ok,
        notes,
    }
}
