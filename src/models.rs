use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Clean,          // 0 - 19 pts
    Inconclusive,   // 20 - 49 pts
    Suspicious,     // 50 - 74 pts
    HighSuspicion,  // 75 - 89 pts
    StrongEvidence, // 90+ pts
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Clean => "LIMPIO",
            RiskLevel::Inconclusive => "INCONCLUSO",
            RiskLevel::Suspicious => "SOSPECHOSO",
            RiskLevel::HighSuspicion => "ALTA SOSPECHA",
            RiskLevel::StrongEvidence => "EVIDENCIA FUERTE",
        }
    }

    #[allow(dead_code)]
    pub fn color_hex(&self) -> u32 {
        match self {
            RiskLevel::Clean => 0x2ECC71,          // Green
            RiskLevel::Inconclusive => 0x95A5A6,   // Grey
            RiskLevel::Suspicious => 0xF1C40F,     // Yellow
            RiskLevel::HighSuspicion => 0xE67E22,  // Orange
            RiskLevel::StrongEvidence => 0xE74C3C, // Red
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamAccount {
    pub steam_id_64: String,
    pub account_name: String,
    pub persona_name: String,
    pub most_recent: bool,
    pub last_login_unix: u64,
    pub last_login_str: String,
    pub played_l4d2: bool,
    pub l4d2_last_played_unix: Option<u64>,
    pub l4d2_last_played_str: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionDetail {
    pub base_address: String,
    pub size_kb: usize,
    pub protection: String,
    pub is_pe_image: bool,
    pub identified_origin: Option<String>,
    pub extracted_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAudit {
    pub l4d2_running: bool,
    pub pid: Option<u32>,
    pub unbacked_memory_regions: usize,
    pub unbacked_rwx_regions: usize,
    pub unbacked_large_regions: usize,
    pub total_unbacked_bytes: usize,
    pub detected_cheat_names: Vec<String>,
    pub memory_diagnostics: Vec<MemoryRegionDetail>,
    pub suspicious_modules: Vec<String>,
    pub total_modules_scanned: usize,
    pub memory_scan_completed: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsForensics {
    pub is_admin: bool,
    pub windows_install_date_raw: Option<u64>,
    pub windows_install_date_str: Option<String>,
    pub has_feature_updates: bool,
    pub prefetch_enabled: bool,
    pub prefetch_total_files: usize,
    pub prefetch_wiped_recently: bool,
    pub suspicious_prefetch_entries: Vec<String>,
    pub active_injector_processes: Vec<String>,
    pub suspicious_game_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub category: String,
    pub detection_type: String,
    pub description: String,
    pub points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total_points: u32,
    pub level: RiskLevel,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub report_id: String,
    pub timestamp_utc: String,
    pub machine_name: String,
    pub user_consent: bool,
    pub player_note: String,
    pub steam_accounts: Vec<SteamAccount>,
    pub process_audit: ProcessAudit,
    pub os_forensics: OsForensics,
    pub risk_score: RiskScore,
}
