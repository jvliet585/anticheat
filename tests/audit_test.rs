use l4d2_audit_tool::forensics::collect_os_forensics;
use l4d2_audit_tool::game::audit_game_process;
use l4d2_audit_tool::scoring::evaluate_risk;
use l4d2_audit_tool::steam::audit_steam_accounts;

#[test]
fn test_steam_audit() {
    let accounts = audit_steam_accounts();
    assert!(accounts.is_ok(), "Steam audit should not crash");
}

#[test]
fn test_os_forensics() {
    let forensics = collect_os_forensics();
    println!("Windows InstallDate: {:?}", forensics.windows_install_date_str);
    println!("Prefetch files: {}", forensics.prefetch_total_files);
}

#[test]
fn test_game_audit() {
    let proc_audit = audit_game_process();
    println!("L4D2 running: {}", proc_audit.l4d2_running);
    println!("Unbacked regions: {}", proc_audit.memory_diagnostics.len());
    for (i, reg) in proc_audit.memory_diagnostics.iter().enumerate() {
        println!(" [Region #{}] Addr: {}, Size: {} KB, Prot: {}, Origin: {:?}, PE: {}",
            i + 1, reg.base_address, reg.size_kb, reg.protection, reg.identified_origin, reg.is_pe_image);
    }
    println!("Total modules scanned: {}", proc_audit.total_modules_scanned);
    println!("Suspicious modules: {:?}", proc_audit.suspicious_modules);
    println!("Detected cheat names: {:?}", proc_audit.detected_cheat_names);
}

#[test]
fn test_scoring_system() {
    let accounts = audit_steam_accounts().unwrap_or_default();
    let proc_audit = audit_game_process();
    let forensics = collect_os_forensics();
    let score = evaluate_risk(&accounts, &proc_audit, &forensics);
    println!("Calculated Risk Score: {} ({})", score.total_points, score.level.as_str());
    for a in &score.anomalies {
        println!(" - [+{} pts] [{}]: {}", a.points, a.detection_type, a.description);
    }
}

