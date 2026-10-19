use crate::forensics::collect_os_forensics;
use crate::game::audit_game_process;
use crate::models::{AuditReport, RiskLevel};
use crate::scoring::evaluate_risk;
use crate::sender::send_report_to_worker;
use crate::steam::audit_steam_accounts;
use chrono::Utc;
use eframe::egui;
use std::sync::mpsc::{channel, Receiver, Sender};

#[derive(PartialEq)]
enum Tab {
    Verdict,
    Game,
    Steam,
    Forensics,
    JsonPreview,
    Settings,
}

pub struct AuditApp {
    current_tab: Tab,
    player_tag: String,
    worker_url: String,
    secret_token: String,
    report: Option<AuditReport>,
    is_scanning: bool,
    send_status: Option<Result<String, String>>,
    is_sending: bool,
    sender_rx: Option<Receiver<Result<String, String>>>,
}

impl Default for AuditApp {
    fn default() -> Self {
        Self {
            current_tab: Tab::Verdict,
            player_tag: String::new(),
            worker_url: "https://l4d2-audit-proxy.workers.dev/report".to_string(),
            secret_token: "CAMBIAR_ESTE_TOKEN_SECRETO".to_string(),
            report: None,
            is_scanning: false,
            send_status: None,
            is_sending: false,
            sender_rx: None,
        }
    }
}

impl AuditApp {
    fn run_audit(&mut self) {
        self.is_scanning = true;

        let accounts = audit_steam_accounts().unwrap_or_default();
        let process_audit = audit_game_process();
        let os_forensics = collect_os_forensics();
        let risk_score = evaluate_risk(&accounts, &process_audit, &os_forensics);

        let machine_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Desconocido".to_string());
        let report_id = format!("{:x}", rand_u64());

        self.report = Some(AuditReport {
            report_id,
            timestamp_utc: Utc::now().to_rfc3339(),
            machine_name,
            user_consent: true,
            player_note: self.player_tag.clone(),
            steam_accounts: accounts,
            process_audit,
            os_forensics,
            risk_score,
        });

        self.is_scanning = false;
        self.send_status = None;
    }

    fn dispatch_send(&mut self) {
        if let Some(rep) = self.report.clone() {
            self.is_sending = true;
            self.send_status = None;

            let (tx, rx): (Sender<Result<String, String>>, Receiver<Result<String, String>>) =
                channel();
            self.sender_rx = Some(rx);

            let url = self.worker_url.clone();
            let token = self.secret_token.clone();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();

                if let Ok(rt) = rt {
                    let res = rt.block_on(async {
                        send_report_to_worker(&url, &token, &rep).await
                    });
                    let _ = tx.send(res);
                } else {
                    let _ = tx.send(Err("Fallo al inicializar runtime asíncrono".to_string()));
                }
            });
        }
    }
}

impl eframe::App for AuditApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check async send result
        if let Some(ref rx) = self.sender_rx {
            if let Ok(res) = rx.try_recv() {
                self.send_status = Some(res);
                self.is_sending = false;
                self.sender_rx = None;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Header bar
            ui.horizontal(|ui| {
                ui.heading("Left 4 Dead 2 - Community Audit Tool");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if crate::forensics::is_elevated() {
                        ui.colored_label(egui::Color32::from_rgb(46, 204, 113), "[ADMIN]");
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(241, 196, 15), "[USUARIO ESTANDAR]");
                    }
                });
            });

            ui.separator();

            // Player identity & Action bar
            ui.horizontal(|ui| {
                ui.label("Tag de Discord / Jugador:");
                ui.text_edit_singleline(&mut self.player_tag);

                if ui
                    .add_sized([160.0, 24.0], egui::Button::new("Iniciar Auditoría"))
                    .clicked()
                {
                    self.run_audit();
                }
            });

            ui.add_space(8.0);

            // Tab bar
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Verdict, "Veredicto");
                ui.selectable_value(&mut self.current_tab, Tab::Game, "L4D2");
                ui.selectable_value(&mut self.current_tab, Tab::Steam, "Cuentas Steam");
                ui.selectable_value(&mut self.current_tab, Tab::Forensics, "Forense OS");
                ui.selectable_value(&mut self.current_tab, Tab::JsonPreview, "Vista Previa");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "Servidor / Worker");
            });

            ui.separator();

            // Content Area
            egui::ScrollArea::vertical().show(ui, |ui| {
                if let Some(ref report) = self.report {
                    match self.current_tab {
                        Tab::Verdict => render_verdict_tab(ui, report),
                        Tab::Game => render_game_tab(ui, report),
                        Tab::Steam => render_steam_tab(ui, report),
                        Tab::Forensics => render_forensics_tab(ui, report),
                        Tab::JsonPreview => render_json_tab(ui, report),
                        Tab::Settings => self.render_settings_tab(ui),
                    }
                } else if self.current_tab == Tab::Settings {
                    self.render_settings_tab(ui);
                } else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.label("Haz clic en 'Iniciar Auditoría' para comenzar el escaneo.");
                        ui.label("Esta herramienta solo inspecciona L4D2, Steam y rastros forenses legítimos.");
                    });
                }
            });

            // Bottom bar: Send to Discord
            if self.report.is_some() {
                ui.separator();
                ui.horizontal(|ui| {
                    let send_btn = egui::Button::new("Enviar Reporte a Discord");
                    let enabled = !self.is_sending;

                    if ui.add_enabled(enabled, send_btn).clicked() {
                        self.dispatch_send();
                    }

                    if self.is_sending {
                        ui.spinner();
                        ui.label("Transmitiendo reporte al Cloudflare Worker...");
                    }

                    if let Some(ref status) = self.send_status {
                        match status {
                            Ok(msg) => {
                                ui.colored_label(egui::Color32::from_rgb(46, 204, 113), msg);
                            }
                            Err(err) => {
                                ui.colored_label(egui::Color32::from_rgb(231, 76, 60), err);
                            }
                        }
                    }
                });
            }
        });
    }
}

impl AuditApp {
    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Configuracion del Proxy de Discord (Cloudflare Worker)");
        ui.label("El cliente envia el reporte firmado al Worker, y el Worker lo despacha al Webhook de Discord sin exponerlo.");
        ui.add_space(8.0);

        ui.label("URL del Cloudflare Worker:");
        ui.text_edit_singleline(&mut self.worker_url);

        ui.add_space(4.0);
        ui.label("Token Secreto compartido (X-Audit-Token):");
        ui.text_edit_singleline(&mut self.secret_token);
    }
}

fn render_verdict_tab(ui: &mut egui::Ui, report: &AuditReport) {
    ui.heading("Resultado del Análisis de Riesgo");

    let level_color = match report.risk_score.level {
        RiskLevel::Clean => egui::Color32::from_rgb(46, 204, 113),
        RiskLevel::Inconclusive => egui::Color32::from_rgb(149, 165, 166),
        RiskLevel::Suspicious => egui::Color32::from_rgb(241, 196, 15),
        RiskLevel::HighSuspicion => egui::Color32::from_rgb(230, 126, 34),
        RiskLevel::StrongEvidence => egui::Color32::from_rgb(231, 76, 60),
    };

    ui.horizontal(|ui| {
        ui.label("Veredicto:");
        ui.colored_label(level_color, report.risk_score.level.as_str());
        ui.label(format!("(Puntos de Riesgo: {})", report.risk_score.total_points));
    });

    ui.add_space(10.0);
    ui.label("Anomalías e Indicadores Detectados:");

    if report.risk_score.anomalies.is_empty() {
        ui.colored_label(
            egui::Color32::from_rgb(46, 204, 113),
            "No se detectaron anomalías ni rastros de manipulación conocidos.",
        );
    } else {
        for a in &report.risk_score.anomalies {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(231, 76, 60), format!("[+{} pts]", a.points));
                    ui.strong(&a.detection_type);
                });
                ui.label(format!("Detalle técnico: {}", a.description));
            });
        }
    }
}

fn render_game_tab(ui: &mut egui::Ui, report: &AuditReport) {
    ui.heading("Estado del Proceso Left 4 Dead 2");
    ui.horizontal(|ui| {
        ui.label("left4dead2.exe:");
        if report.process_audit.l4d2_running {
            ui.colored_label(egui::Color32::from_rgb(46, 204, 113), "EN EJECUCION");
            if let Some(pid) = report.process_audit.pid {
                ui.label(format!("(PID: {})", pid));
            }
        } else {
            ui.colored_label(egui::Color32::GRAY, "NO ACTIVO");
        }
    });

    if report.process_audit.l4d2_running {
        ui.label(format!(
            "Regiones de memoria ejecutable privada: {} (RWX: {}, Grandes >64KB: {}, Total: {} KB)",
            report.process_audit.unbacked_memory_regions,
            report.process_audit.unbacked_rwx_regions,
            report.process_audit.unbacked_large_regions,
            report.process_audit.total_unbacked_bytes / 1024
        ));
        ui.label(format!(
            "Total de módulos DLL escaneados: {}",
            report.process_audit.total_modules_scanned
        ));

        if !report.process_audit.detected_cheat_names.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(231, 76, 60),
                "ALERTAS: Menus / Cheats identificados en el juego:",
            );
            for c in &report.process_audit.detected_cheat_names {
                ui.label(format!(" * {}", c));
            }
        }

        if !report.process_audit.suspicious_modules.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(231, 76, 60),
                "Modulos sospechosos encontrados:",
            );
            for m in &report.process_audit.suspicious_modules {
                ui.label(format!(" - {}", m));
            }
        }

        if !report.process_audit.memory_diagnostics.is_empty() {
            ui.separator();
            ui.strong("Diagnóstico de Regiones de Memoria Privada (Origen y Cadenas Extraidas):");
            for (idx, reg) in report.process_audit.memory_diagnostics.iter().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}: Direccion: {}", idx + 1, reg.base_address));
                        ui.label(format!("Tamaño: {} KB", reg.size_kb));
                        ui.label(format!("Permisos: {}", reg.protection));
                        if reg.is_pe_image {
                            ui.colored_label(egui::Color32::from_rgb(231, 76, 60), "[CABECERA PE (DLL) DETECTADA]");
                        }
                    });
                    if let Some(ref origin) = reg.identified_origin {
                        ui.label(format!("Diagnóstico de origen: {}", origin));
                    }
                    if !reg.extracted_strings.is_empty() {
                        ui.label(format!("Cadenas de texto encontradas en la memoria: {}", reg.extracted_strings.join(" | ")));
                    }
                });
            }
        }
    }

    for n in &report.process_audit.notes {
        ui.label(format!("Nota: {}", n));
    }
}

fn render_steam_tab(ui: &mut egui::Ui, report: &AuditReport) {
    ui.heading(format!(
        "Cuentas de Steam Detectadas ({})",
        report.steam_accounts.len()
    ));

    for acc in &report.steam_accounts {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(&acc.persona_name);
                ui.label(format!("({})", acc.account_name));
                if acc.most_recent {
                    ui.colored_label(egui::Color32::from_rgb(52, 152, 219), "[ACTUAL/MAS RECIENTE]");
                }
            });
            ui.label(format!("SteamID64: {}", acc.steam_id_64));
            ui.label(format!("Ultimo inicio de sesion: {}", acc.last_login_str));

            if acc.played_l4d2 {
                let l4d2_str = acc
                    .l4d2_last_played_str
                    .as_deref()
                    .unwrap_or("Fecha local no registrada");
                ui.colored_label(
                    egui::Color32::from_rgb(46, 204, 113),
                    format!("Ha jugado L4D2 en esta PC (Ultima vez: {})", l4d2_str),
                );
            } else {
                ui.label("Sin registro local de partidas en L4D2.");
            }
        });
    }
}

fn render_forensics_tab(ui: &mut egui::Ui, report: &AuditReport) {
    ui.heading("Forense del Sistema Operativo");

    ui.label(format!(
        "Fecha de Instalacion de Windows (Registro): {}",
        report
            .os_forensics
            .windows_install_date_str
            .as_deref()
            .unwrap_or("No disponible")
    ));

    if report.os_forensics.has_feature_updates {
        ui.label("Actualizaciones de caracteristicas (Feature Updates) detectadas: SI (El InstallDate refleja la ultima actualizacion, no necesariamente un formateo limpio).");
    }

    ui.separator();
    ui.label(format!(
        "Archivos en Prefetch: {}",
        report.os_forensics.prefetch_total_files
    ));

    if report.os_forensics.prefetch_wiped_recently {
        ui.colored_label(
            egui::Color32::from_rgb(231, 76, 60),
            "Advertencia: Cantidad de archivos Prefetch inusualmente baja (posible vaciado manual).",
        );
    }

    if !report.os_forensics.active_injector_processes.is_empty() {
        ui.separator();
        ui.colored_label(
            egui::Color32::from_rgb(231, 76, 60),
            "ALERTAS: Inyectores / Loaders ejecutandose activamente en Windows:",
        );
        for inj in &report.os_forensics.active_injector_processes {
            ui.label(format!(" * {}", inj));
        }
    }

    if !report.os_forensics.suspicious_prefetch_entries.is_empty() {
        ui.separator();
        ui.colored_label(
            egui::Color32::from_rgb(231, 76, 60),
            "Residuos historicos en Prefetch (Herramientas ejecutadas previamente):",
        );
        for e in &report.os_forensics.suspicious_prefetch_entries {
            ui.label(format!(" - {}", e));
        }
    }
}

fn render_json_tab(ui: &mut egui::Ui, report: &AuditReport) {
    ui.heading("Vista Previa del Reporte (Transparencia de Datos)");
    ui.label("Estos son los datos exactos que seran transmitidos a los administradores de la comunidad:");

    if let Ok(json_str) = serde_json::to_string_pretty(report) {
        ui.text_edit_multiline(&mut json_str.as_str());
    }
}

fn rand_u64() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
