use crate::models::{Anomaly, OsForensics, ProcessAudit, RiskLevel, RiskScore, SteamAccount};

pub fn evaluate_risk(
    steam_accounts: &[SteamAccount],
    process_audit: &ProcessAudit,
    os_forensics: &OsForensics,
) -> RiskScore {
    let mut anomalies = Vec::new();
    let mut total_points = 0u32;

    // 1. Specific Cheat / Menu Identified in Game Memory
    if process_audit.l4d2_running {
        if !process_audit.detected_cheat_names.is_empty() {
            let pts = 95;
            total_points += pts;
            anomalies.push(Anomaly {
                category: "Cheat / Menu Identificado en Memoria".to_string(),
                detection_type: "ACTIVO EN MEMORIA: Menu o Modulo Malicioso Detectado".to_string(),
                description: format!(
                    "Se identificaron firmas/modulos especificos de cheat en el juego: {:?}",
                    process_audit.detected_cheat_names
                ),
                points: pts,
            });
        } else {
            let pe_injected = process_audit.memory_diagnostics.iter().any(|d| d.is_pe_image);
            if pe_injected {
                let pts = 90;
                total_points += pts;
                anomalies.push(Anomaly {
                    category: "Inyeccion Oculta en Memoria".to_string(),
                    detection_type: "ACTIVO EN MEMORIA: Inyeccion Reflectiva / DLL Oculta (Manual Map PE)".to_string(),
                    description: "Se detecto una cabecera PE ejecutable en memoria privada sin archivo en disco (DLL inyectada oculta).".to_string(),
                    points: pts,
                });
            } else if process_audit.unbacked_large_regions > 0 {
                let pts = 15;
                total_points += pts;
                anomalies.push(Anomaly {
                    category: "Memoria Dinamica del Motor/Driver".to_string(),
                    detection_type: "CONTEXTUAL: Buffer de Shaders / JIT Grafico (Sin firmas de cheat)".to_string(),
                    description: format!(
                        "Region de ejecucion dinamica (>64KB, total: {} KB). No contiene firmas de cheat ni cabeceras PE; tipico de buffers de shaders DirectX o drivers graficos.",
                        process_audit.total_unbacked_bytes / 1024
                    ),
                    points: pts,
                });
            } else if process_audit.unbacked_rwx_regions > 0 {
                let pts = 10;
                total_points += pts;
                anomalies.push(Anomaly {
                    category: "Paginas RWX en Memoria".to_string(),
                    detection_type: "CONTEXTUAL: Trampolines de enganche (Overlays/DirectX)".to_string(),
                    description: format!(
                        "Se detectaron {} paginas con permisos RWX, consistentes con trampolines de renderizado u overlays de captura.",
                        process_audit.unbacked_rwx_regions
                    ),
                    points: pts,
                });
            }
        }
    }

    // 2. Active Injectors or Cheat Loaders running on Windows
    if !os_forensics.active_injector_processes.is_empty() {
        let pts = 90;
        total_points += pts;
        anomalies.push(Anomaly {
            category: "Inyector Activo en Windows".to_string(),
            detection_type: "PROCESO ACTIVO EN WINDOWS: Inyector o Loader en Ejecucion".to_string(),
            description: format!(
                "Se detectaron herramientas de inyeccion activas en segundo plano: {:?}",
                os_forensics.active_injector_processes
            ),
            points: pts,
        });
    }

    // 3. Historical Residues in Prefetch (Executed and closed/deleted)
    if !os_forensics.suspicious_prefetch_entries.is_empty() {
        let pts = 65;
        total_points += pts;
        anomalies.push(Anomaly {
            category: "Residuo de Ejecucion en Disco".to_string(),
            detection_type: "RESIDUO FORENSE EN DISCO: Cheat / Inyector Utilizado Previamente".to_string(),
            description: format!(
                "Se encontraron registros de ejecucion en Prefetch de herramientas cerradas o borradas: {:?}",
                os_forensics.suspicious_prefetch_entries
            ),
            points: pts,
        });
    }

    // 4. Anti-Forensic Tampering
    if os_forensics.prefetch_wiped_recently {
        let pts = 40;
        total_points += pts;
        anomalies.push(Anomaly {
            category: "Anti-Forense".to_string(),
            detection_type: "ENCUBRIMIENTO / MANIPULACION: Vaciado deliberado de Prefetch".to_string(),
            description: "La carpeta Prefetch parece haber sido vaciada o reiniciada deliberadamente hace poco tiempo para ocultar ejecuciones.".to_string(),
            points: pts,
        });
    }

    // 5. Audit Permissions
    if !os_forensics.is_admin {
        let pts = 10;
        total_points += pts;
        anomalies.push(Anomaly {
            category: "Permisos de Auditoria".to_string(),
            detection_type: "ADVERTENCIA DE EJECUCION: Falta Elevacion UAC".to_string(),
            description: "La auditoria se ejecuto sin privilegios de Administrador; ciertas lecturas de memoria y prefetch pueden estar limitadas.".to_string(),
            points: pts,
        });
    }

    // 6. Multi-accounting
    let l4d2_accounts_count = steam_accounts.iter().filter(|a| a.played_l4d2).count();
    if l4d2_accounts_count > 3 {
        let pts = 15;
        total_points += pts;
        anomalies.push(Anomaly {
            category: "Cuentas de Steam".to_string(),
            detection_type: "CONTEXTUAL: Multicuenta / Deteccion de Smurfs en la PC".to_string(),
            description: format!(
                "Multiples cuentas ({}) han jugado Left 4 Dead 2 en esta maquina.",
                l4d2_accounts_count
            ),
            points: pts,
        });
    }

    let level = match total_points {
        0..=19 => RiskLevel::Clean,
        20..=49 => RiskLevel::Inconclusive,
        50..=74 => RiskLevel::Suspicious,
        75..=89 => RiskLevel::HighSuspicion,
        _ => RiskLevel::StrongEvidence,
    };

    RiskScore {
        total_points,
        level,
        anomalies,
    }
}
