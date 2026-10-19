use crate::models::SteamAccount;
use chrono::DateTime;
use std::fs;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

/// Detects the installation path of Steam from the Windows Registry
pub fn get_steam_install_path() -> Option<PathBuf> {
    // 1. Check HKCU\Software\Valve\Steam -> SteamPath
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(steam_key) = hkcu.open_subkey("Software\\Valve\\Steam") {
        if let Ok(steam_path) = steam_key.get_value::<String, _>("SteamPath") {
            let path = PathBuf::from(steam_path);
            if path.exists() {
                return Some(path);
            }
        }
    }

    // 2. Fallback to HKLM\SOFTWARE\WOW6432Node\Valve\Steam -> InstallPath
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(steam_key) = hklm.open_subkey("SOFTWARE\\WOW6432Node\\Valve\\Steam") {
        if let Ok(install_path) = steam_key.get_value::<String, _>("InstallPath") {
            let path = PathBuf::from(install_path);
            if path.exists() {
                return Some(path);
            }
        }
    }

    // 3. Fallback to standard default path
    let default_path = PathBuf::from("C:\\Program Files (x86)\\Steam");
    if default_path.exists() {
        return Some(default_path);
    }

    None
}

/// Converts SteamID64 to SteamID32 (AccountID used in userdata folders)
pub fn steam64_to_steam32(steam64: u64) -> Option<u32> {
    const STEAM_BASE_ID: u64 = 76561197960265728;
    if steam64 > STEAM_BASE_ID {
        Some((steam64 - STEAM_BASE_ID) as u32)
    } else {
        None
    }
}

/// Audits all Steam accounts that have logged into this PC
pub fn audit_steam_accounts() -> Result<Vec<SteamAccount>, String> {
    let steam_dir = get_steam_install_path().ok_or_else(|| "No se encontró la instalación de Steam en el Registro de Windows.".to_string())?;

    let loginusers_path = steam_dir.join("config").join("loginusers.vdf");
    if !loginusers_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&loginusers_path)
        .map_err(|e| format!("Error leyendo loginusers.vdf: {}", e))?;

    let parsed_accounts = parse_loginusers_vdf(&content);

    let mut accounts = Vec::new();
    for mut acc in parsed_accounts {
        // Check if this account has played L4D2 (AppID: 550)
        if let Ok(steam64) = acc.steam_id_64.parse::<u64>() {
            if let Some(steam32) = steam64_to_steam32(steam64) {
                let user_l4d2_dir = steam_dir.join("userdata").join(steam32.to_string()).join("550");
                if user_l4d2_dir.exists() {
                    acc.played_l4d2 = true;
                }

                // Check localconfig.vdf for last played time
                let localconfig_path = steam_dir
                    .join("userdata")
                    .join(steam32.to_string())
                    .join("config")
                    .join("localconfig.vdf");

                if localconfig_path.exists() {
                    if let Ok(lcfg_content) = fs::read_to_string(&localconfig_path) {
                        if let Some(last_played) = parse_l4d2_last_played(&lcfg_content) {
                            acc.played_l4d2 = true;
                            acc.l4d2_last_played_unix = Some(last_played);
                            if let Some(dt) = DateTime::from_timestamp(last_played as i64, 0) {
                                acc.l4d2_last_played_str = Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                            }
                        }
                    }
                }
            }
        }
        accounts.push(acc);
    }

    // Sort accounts by most recent first
    accounts.sort_by(|a, b| b.last_login_unix.cmp(&a.last_login_unix));

    Ok(accounts)
}

/// Simple line-based parser for loginusers.vdf
fn parse_loginusers_vdf(content: &str) -> Vec<SteamAccount> {
    let mut accounts = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut current_steamid: Option<String> = None;
    let mut account_name = String::new();
    let mut persona_name = String::new();
    let mut most_recent = false;
    let mut timestamp_unix = 0u64;

    for line in lines {
        let trimmed = line.trim();

        // Detect SteamID block start: e.g. "76561198..."
        if trimmed.starts_with('"') && trimmed.ends_with('"') && !trimmed.contains("users") {
            let inner = trimmed.trim_matches('"');
            if inner.starts_with("7656119") && inner.len() == 17 {
                // If we were already tracking one, save it
                if let Some(prev_id) = current_steamid.take() {
                    let dt_str = DateTime::from_timestamp(timestamp_unix as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Desconocido".to_string());

                    accounts.push(SteamAccount {
                        steam_id_64: prev_id,
                        account_name: account_name.clone(),
                        persona_name: persona_name.clone(),
                        most_recent,
                        last_login_unix: timestamp_unix,
                        last_login_str: dt_str,
                        played_l4d2: false,
                        l4d2_last_played_unix: None,
                        l4d2_last_played_str: None,
                    });
                }

                current_steamid = Some(inner.to_string());
                account_name.clear();
                persona_name.clear();
                most_recent = false;
                timestamp_unix = 0;
                continue;
            }
        }

        if current_steamid.is_none() {
            continue;
        }

        // Parse key-value pairs
        if let Some((k, v)) = extract_kv(trimmed) {
            match k.to_lowercase().as_str() {
                "accountname" => account_name = v,
                "personaname" => persona_name = v,
                "mostrecent" => most_recent = v == "1",
                "timestamp" => {
                    if let Ok(ts) = v.parse::<u64>() {
                        timestamp_unix = ts;
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(id) = current_steamid {
        let dt_str = DateTime::from_timestamp(timestamp_unix as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Desconocido".to_string());

        accounts.push(SteamAccount {
            steam_id_64: id,
            account_name,
            persona_name,
            most_recent,
            last_login_unix: timestamp_unix,
            last_login_str: dt_str,
            played_l4d2: false,
            l4d2_last_played_unix: None,
            l4d2_last_played_str: None,
        });
    }

    accounts
}

/// Helper to parse key-value lines like: "AccountName" "Player1"
fn extract_kv(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.split('"').filter(|s| !s.trim().is_empty()).collect();
    if parts.len() >= 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Parses localconfig.vdf looking for "550" -> "LastPlayed"
fn parse_l4d2_last_played(content: &str) -> Option<u64> {
    let mut in_l4d2_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "\"550\"" {
            in_l4d2_block = true;
            continue;
        }
        if in_l4d2_block {
            if let Some((k, v)) = extract_kv(trimmed) {
                if k.eq_ignore_ascii_case("lastplayed") {
                    return v.parse::<u64>().ok();
                }
            }
            if trimmed == "}" {
                in_l4d2_block = false;
            }
        }
    }
    None
}
