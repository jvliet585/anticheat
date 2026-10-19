use crate::forensics::collect_os_forensics;
use crate::game::audit_game_process;
use crate::models::{AuditReport, RiskLevel};
use crate::scoring::evaluate_risk;
use crate::sender::send_report_to_worker;
use crate::steam::audit_steam_accounts;
use chrono::Utc;
use eframe::egui::{self, Color32, Frame, Margin, RichText, Rounding, Stroke};
use std::sync::mpsc::{channel, Receiver, Sender};

#[derive(PartialEq, Clone, Copy)]
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
    pub fn new(cc: &eframe::CreationContext) -> Self {
        configure_visuals(&cc.egui_ctx);
        Self::default()
    }

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

            let (tx, rx): (Sender<Result<String, String>>, Receiver<Result<String, String>>) = channel();
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
                    let _ = tx.send(Err("Fallo al inicializar runtime asincrono".to_string()));
                }
            });
        }
    }
}

fn configure_visuals(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(Color32::from_rgb(241, 245, 249));
    visuals.panel_fill = Color32::from_rgb(11, 15, 25);
    visuals.window_fill = Color32::from_rgb(15, 21, 34);
    visuals.faint_bg_color = Color32::from_rgb(20, 27, 43);
    visuals.extreme_bg_color = Color32::from_rgb(8, 11, 18);

    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(19, 26, 42);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(33, 44, 68));
    visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(23, 31, 50);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(41, 55, 84));
    visuals.widgets.inactive.rounding = Rounding::same(6.0);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(32, 45, 72);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(59, 130, 246));
    visuals.widgets.hovered.rounding = Rounding::same(6.0);

    visuals.widgets.active.bg_fill = Color32::from_rgb(2, 132, 199);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248));
    visuals.widgets.active.rounding = Rounding::same(6.0);

    visuals.selection.bg_fill = Color32::from_rgb(2, 132, 199);
    visuals.selection.stroke = Stroke::new(1.0_f32, Color32::from_rgb(125, 211, 252));
    visuals.window_rounding = Rounding::same(8.0);

    ctx.set_visuals(visuals);
}

// Styling helper frames
fn card_frame() -> Frame {
    Frame::none()
        .fill(Color32::from_rgb(18, 25, 41))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(34, 46, 73)))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
}

fn header_panel_frame() -> Frame {
    Frame::none()
        .fill(Color32::from_rgb(14, 19, 32))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(28, 39, 63)))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
}

impl eframe::App for AuditApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(ref rx) = self.sender_rx {
            if let Ok(res) = rx.try_recv() {
                self.send_status = Some(res);
                self.is_sending = false;
                self.sender_rx = None;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Top App Bar
            header_panel_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("LEFT 4 DEAD 2  |  SUITE DE AUDITORIA FORENSE")
                                .size(16.0)
                                .strong()
                                .color(Color32::from_rgb(56, 189, 248)),
                        );
                        ui.label(
                            RichText::new("HERRAMIENTA EXTERNA DE INTEGRIDAD, MEMORIA Y SISTEMA OPERATIVO")
                                .size(10.5)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Admin status pill
                        let (admin_text, admin_color, admin_bg) = if crate::forensics::is_elevated() {
                            ("[PRIVILEGIOS: ADMINISTRADOR]", Color32::from_rgb(52, 211, 153), Color32::from_rgb(16, 46, 36))
                        } else {
                            ("[PRIVILEGIOS: USUARIO ESTANDAR]", Color32::from_rgb(251, 191, 36), Color32::from_rgb(50, 40, 18))
                        };

                        Frame::none()
                            .fill(admin_bg)
                            .stroke(Stroke::new(1.0_f32, admin_color))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(Margin::symmetric(8.0, 4.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(admin_text).size(10.5).strong().color(admin_color));
                            });

                        // L4D2 status indicator pill
                        let l4d2_active = crate::game::find_l4d2_pid().is_some();
                        let (l4d2_text, l4d2_color, l4d2_bg) = if l4d2_active {
                            ("[L4D2: EN EJECUCION]", Color32::from_rgb(56, 189, 248), Color32::from_rgb(14, 38, 58))
                        } else {
                            ("[L4D2: NO DETECTADO]", Color32::from_rgb(156, 163, 175), Color32::from_rgb(31, 41, 55))
                        };

                        Frame::none()
                            .fill(l4d2_bg)
                            .stroke(Stroke::new(1.0_f32, l4d2_color))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(Margin::symmetric(8.0, 4.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(l4d2_text).size(10.5).strong().color(l4d2_color));
                            });
                    });
                });
            });

            ui.add_space(8.0);

            // Action & Identity Card
            card_frame().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("IDENTIFICADOR DEL JUGADOR:")
                            .size(11.5)
                            .strong()
                            .color(Color32::from_rgb(203, 213, 225)),
                    );

                    let text_edit = egui::TextEdit::singleline(&mut self.player_tag)
                        .hint_text("Ingresa tu Nick / Tag de Discord...")
                        .desired_width(260.0);
                    ui.add(text_edit);

                    ui.add_space(10.0);

                    let scan_btn = egui::Button::new(
                        RichText::new("  EJECUTAR AUDITORIA COMPLETA  ")
                            .size(12.5)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(2, 132, 199))
                    .rounding(Rounding::same(6.0));

                    if ui.add_sized([220.0, 26.0], scan_btn).clicked() {
                        self.run_audit();
                    }

                    if self.is_scanning {
                        ui.spinner();
                        ui.label(
                            RichText::new("Analizando entorno...")
                                .size(11.0)
                                .color(Color32::from_rgb(56, 189, 248)),
                        );
                    } else if let Some(ref rep) = self.report {
                        ui.label(
                            RichText::new(format!("Auditoria lista ({})", &rep.report_id[..6]))
                                .size(11.0)
                                .color(Color32::from_rgb(52, 211, 153)),
                        );
                    }
                });
            });

            ui.add_space(8.0);

            // Modern Pill Navigation Bar
            ui.horizontal(|ui| {
                tab_pill(ui, &mut self.current_tab, Tab::Verdict, "Veredicto y Riesgo");
                tab_pill(ui, &mut self.current_tab, Tab::Game, "L4D2 Memoria Virtual");
                tab_pill(ui, &mut self.current_tab, Tab::Steam, "Cuentas Steam");
                tab_pill(ui, &mut self.current_tab, Tab::Forensics, "Forense Windows");
                tab_pill(ui, &mut self.current_tab, Tab::JsonPreview, "Vista Previa JSON");
                tab_pill(ui, &mut self.current_tab, Tab::Settings, "Servidor / Worker");
            });

            ui.add_space(6.0);

            // Tab Content Body
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
                    render_hero_welcome(ui);
                }
            });

            // Bottom Dispatch Bar
            if self.report.is_some() {
                ui.add_space(6.0);
                Frame::none()
                    .fill(Color32::from_rgb(14, 19, 32))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(28, 39, 63)))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let send_btn = egui::Button::new(
                                RichText::new("  TRANSMITIR REPORTE A DISCORD (VIA WORKER)  ")
                                    .size(12.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(Color32::from_rgb(16, 185, 129))
                            .rounding(Rounding::same(6.0));

                            let enabled = !self.is_sending;
                            if ui.add_enabled(enabled, send_btn).clicked() {
                                self.dispatch_send();
                            }

                            if self.is_sending {
                                ui.spinner();
                                ui.label(
                                    RichText::new("Firmando y transmitiendo informe al Cloudflare Worker...")
                                        .size(11.5)
                                        .color(Color32::from_rgb(56, 189, 248)),
                                );
                            }

                            if let Some(ref status) = self.send_status {
                                match status {
                                    Ok(msg) => {
                                        ui.label(
                                            RichText::new(format!("[CONFIRMADO] {}", msg))
                                                .size(11.5)
                                                .strong()
                                                .color(Color32::from_rgb(52, 211, 153)),
                                        );
                                    }
                                    Err(err) => {
                                        ui.label(
                                            RichText::new(format!("[ERROR] {}", err))
                                                .size(11.5)
                                                .strong()
                                                .color(Color32::from_rgb(248, 113, 113)),
                                        );
                                    }
                                }
                            }
                        });
                    });
            }
        });
    }
}

fn tab_pill(ui: &mut egui::Ui, current: &mut Tab, target: Tab, label: &str) {
    let is_active = *current == target;
    let (bg, text_color, stroke) = if is_active {
        (
            Color32::from_rgb(2, 132, 199),
            Color32::WHITE,
            Stroke::new(1.0_f32, Color32::from_rgb(56, 189, 248)),
        )
    } else {
        (
            Color32::from_rgb(20, 27, 43),
            Color32::from_rgb(148, 163, 184),
            Stroke::new(1.0_f32, Color32::from_rgb(33, 44, 68)),
        )
    };

    let btn = egui::Button::new(
        RichText::new(format!("  {}  ", label))
            .size(11.5)
            .strong()
            .color(text_color),
    )
    .fill(bg)
    .stroke(stroke)
    .rounding(Rounding::same(6.0));

    if ui.add(btn).clicked() {
        *current = target;
    }
}

fn render_hero_welcome(ui: &mut egui::Ui) {
    card_frame().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(
                RichText::new("SISTEMA DE AUDITORIA LISTO")
                    .size(18.0)
                    .strong()
                    .color(Color32::from_rgb(56, 189, 248)),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Herramienta oficial de verificacion forense para torneos y comunidades competitivas de Left 4 Dead 2.")
                    .size(12.0)
                    .color(Color32::from_rgb(203, 213, 225)),
            );
            ui.add_space(16.0);
        });

        ui.horizontal(|ui| {
            ui.columns(3, |cols| {
                cols[0].group(|ui| {
                    ui.label(RichText::new("1. JUEGO EN VIVO").size(12.0).strong().color(Color32::from_rgb(56, 189, 248)));
                    ui.label(RichText::new("Abre Left 4 Dead 2 para inspeccionar modulos inyectados y memoria virtual.").size(11.0).color(Color32::from_rgb(148, 163, 184)));
                });
                cols[1].group(|ui| {
                    ui.label(RichText::new("2. ELEVACION ADMIN").size(12.0).strong().color(Color32::from_rgb(52, 211, 153)));
                    ui.label(RichText::new("Ejecuta como Administrador para leer artefactos de Prefetch y memoria de procesos.").size(11.0).color(Color32::from_rgb(148, 163, 184)));
                });
                cols[2].group(|ui| {
                    ui.label(RichText::new("3. TRANSPARENCIA").size(12.0).strong().color(Color32::from_rgb(251, 191, 36)));
                    ui.label(RichText::new("Revisa el JSON antes de enviarlo. No se inspeccionan archivos personales ni claves.").size(11.0).color(Color32::from_rgb(148, 163, 184)));
                });
            });
        });

        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(
                RichText::new("Presiona 'EJECUTAR AUDITORIA COMPLETA' en la barra superior para iniciar.")
                    .size(13.0)
                    .strong()
                    .color(Color32::from_rgb(241, 245, 249)),
            );
            ui.add_space(15.0);
        });
    });
}

fn render_verdict_tab(ui: &mut egui::Ui, report: &AuditReport) {
    let (level_color, level_bg, banner_desc) = match report.risk_score.level {
        RiskLevel::Clean => (
            Color32::from_rgb(52, 211, 153),
            Color32::from_rgb(14, 46, 34),
            "ENTORNO VERIFICADO: No se encontraron rastros de inyectores, memorias no respaldadas ni firmas conocidas.",
        ),
        RiskLevel::Inconclusive => (
            Color32::from_rgb(148, 163, 184),
            Color32::from_rgb(30, 41, 59),
            "EVIDENCIA INCONCLUSIVA: Se registraron pequenas anomalias contextuales sin confirmacion concluyente.",
        ),
        RiskLevel::Suspicious => (
            Color32::from_rgb(251, 191, 36),
            Color32::from_rgb(52, 40, 16),
            "EVIDENCIA SOSPECHOSA: Se detectaron parametros inusuales o residuos que ameritan revision detallada.",
        ),
        RiskLevel::HighSuspicion => (
            Color32::from_rgb(249, 115, 22),
            Color32::from_rgb(55, 28, 14),
            "ALTA PROBABILIDAD DE TRAMPA: Inyectores ejecutados recientemente o trampolines de memoria sospechosos.",
        ),
        RiskLevel::StrongEvidence => (
            Color32::from_rgb(248, 113, 113),
            Color32::from_rgb(60, 20, 26),
            "EVIDENCIA CRITICA CONFIRMADA: Inyector activo en Windows, modulos inyectados o firmas de cheats detectadas.",
        ),
    };

    // Hero Score Card
    Frame::none()
        .fill(level_bg)
        .stroke(Stroke::new(1.5_f32, level_color))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("VEREDICTO GLOBAL DE AUDITORIA")
                            .size(11.0)
                            .strong()
                            .color(Color32::from_rgb(203, 213, 225)),
                    );
                    ui.label(
                        RichText::new(report.risk_score.level.as_str())
                            .size(22.0)
                            .strong()
                            .color(level_color),
                    );
                    ui.label(RichText::new(banner_desc).size(11.5).color(Color32::from_rgb(226, 232, 240)));
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!("{}/100", report.risk_score.total_points))
                                .size(28.0)
                                .strong()
                                .color(level_color),
                        );
                        ui.label(
                            RichText::new("PUNTOS DE RIESGO")
                                .size(10.0)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );
                    });
                });
            });

            ui.add_space(8.0);
            let progress = (report.risk_score.total_points as f32 / 100.0).clamp(0.0, 1.0);
            let progress_bar = egui::ProgressBar::new(progress)
                .fill(level_color)
                .animate(false);
            ui.add(progress_bar);
        });

    ui.add_space(10.0);

    // Diagnostics Quick Summary Bar
    ui.horizontal(|ui| {
        let active_inj_count = report.os_forensics.active_injector_processes.len();
        let prefetch_res_count = report.os_forensics.suspicious_prefetch_entries.len();
        let unbacked_mem_count = report.process_audit.unbacked_memory_regions;
        let steam_accs_count = report.steam_accounts.len();

        kpi_metric_card(ui, "INYECTORES ACTIVOS", &active_inj_count.to_string(), active_inj_count > 0);
        kpi_metric_card(ui, "RESIDUOS PREFETCH", &prefetch_res_count.to_string(), prefetch_res_count > 0);
        kpi_metric_card(ui, "MEMORIA NO RESPALDADA", &unbacked_mem_count.to_string(), unbacked_mem_count > 0);
        kpi_metric_card(ui, "CUENTAS STEAM", &steam_accs_count.to_string(), false);
    });

    ui.add_space(10.0);

    // Anomalies & Findings
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("DESGLOSE DE ANOMALIAS E INDICADORES DETECTADOS")
                .size(13.0)
                .strong()
                .color(Color32::from_rgb(56, 189, 248)),
        );
        ui.separator();

        if report.risk_score.anomalies.is_empty() {
            Frame::none()
                .fill(Color32::from_rgb(16, 42, 32))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(52, 211, 153)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(12.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("[OK] No se detectaron anomalias en la sesion ni en el historial del sistema.")
                            .size(12.5)
                            .strong()
                            .color(Color32::from_rgb(52, 211, 153)),
                    );
                });
        } else {
            for a in &report.risk_score.anomalies {
                let badge_color = if a.points >= 60 {
                    Color32::from_rgb(248, 113, 113)
                } else if a.points >= 30 {
                    Color32::from_rgb(251, 191, 36)
                } else {
                    Color32::from_rgb(56, 189, 248)
                };

                Frame::none()
                    .fill(Color32::from_rgb(22, 30, 48))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 52, 82)))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("[+{} PTS]", a.points))
                                    .size(12.0)
                                    .strong()
                                    .color(badge_color),
                            );
                            ui.label(
                                RichText::new(&a.detection_type)
                                    .size(12.5)
                                    .strong()
                                    .color(Color32::from_rgb(241, 245, 249)),
                            );
                        });
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(&a.description)
                                .size(11.5)
                                .color(Color32::from_rgb(203, 213, 225)),
                        );
                    });
                ui.add_space(4.0);
            }
        }
    });
}

fn kpi_metric_card(ui: &mut egui::Ui, title: &str, value: &str, alert: bool) {
    let (border, text_color) = if alert {
        (Color32::from_rgb(239, 68, 68), Color32::from_rgb(248, 113, 113))
    } else {
        (Color32::from_rgb(38, 50, 78), Color32::from_rgb(56, 189, 248))
    };

    Frame::none()
        .fill(Color32::from_rgb(18, 25, 41))
        .stroke(Stroke::new(1.0_f32, border))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(14.0, 8.0))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(9.5).color(Color32::from_rgb(148, 163, 184)));
                ui.label(RichText::new(value).size(16.0).strong().color(text_color));
            });
        });
}

fn render_game_tab(ui: &mut egui::Ui, report: &AuditReport) {
    card_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("ESTADO DEL PROCESO LEFT 4 DEAD 2 (left4dead2.exe)")
                    .size(13.0)
                    .strong()
                    .color(Color32::from_rgb(56, 189, 248)),
            );
            if report.process_audit.l4d2_running {
                ui.label(
                    RichText::new("[EN EJECUCION]")
                        .size(11.5)
                        .strong()
                        .color(Color32::from_rgb(52, 211, 153)),
                );
                if let Some(pid) = report.process_audit.pid {
                    ui.label(RichText::new(format!("(PID: {})", pid)).size(11.0).color(Color32::from_rgb(148, 163, 184)));
                }
            } else {
                ui.label(
                    RichText::new("[NO DETECTADO / CERRADO]")
                        .size(11.5)
                        .color(Color32::from_rgb(156, 163, 175)),
                );
            }
        });

        ui.separator();

        if report.process_audit.l4d2_running {
            ui.horizontal(|ui| {
                kpi_metric_card(ui, "PAGINAS PRIVADAS", &report.process_audit.unbacked_memory_regions.to_string(), report.process_audit.unbacked_memory_regions > 0);
                kpi_metric_card(ui, "PAGINAS RWX", &report.process_audit.unbacked_rwx_regions.to_string(), report.process_audit.unbacked_rwx_regions > 0);
                kpi_metric_card(ui, "PAGINAS GRANDES (>64KB)", &report.process_audit.unbacked_large_regions.to_string(), false);
                kpi_metric_card(ui, "TOTAL KB NO RESPALDADOS", &(report.process_audit.total_unbacked_bytes / 1024).to_string(), false);
                kpi_metric_card(ui, "DLLS ESCANEADAS", &report.process_audit.total_modules_scanned.to_string(), false);
            });

            if !report.process_audit.detected_cheat_names.is_empty() {
                ui.add_space(8.0);
                Frame::none()
                    .fill(Color32::from_rgb(60, 20, 26))
                    .stroke(Stroke::new(1.5_f32, Color32::from_rgb(239, 68, 68)))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("[ALERTA CRITICA] Menus o firmas de trampas identificados en memoria:")
                                .size(12.5)
                                .strong()
                                .color(Color32::from_rgb(248, 113, 113)),
                        );
                        for c in &report.process_audit.detected_cheat_names {
                            ui.label(RichText::new(format!(" * {}", c)).size(12.0).strong().color(Color32::WHITE));
                        }
                    });
            }

            if !report.process_audit.suspicious_modules.is_empty() {
                ui.add_space(8.0);
                Frame::none()
                    .fill(Color32::from_rgb(52, 38, 16))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(251, 191, 36)))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("[ADVERTENCIA] Modulos DLL sospechosos cargados en el proceso:")
                                .size(12.0)
                                .strong()
                                .color(Color32::from_rgb(251, 191, 36)),
                        );
                        for m in &report.process_audit.suspicious_modules {
                            ui.label(RichText::new(format!(" - {}", m)).size(11.5).color(Color32::WHITE));
                        }
                    });
            }

            if !report.process_audit.memory_diagnostics.is_empty() {
                ui.add_space(10.0);
                ui.label(
                    RichText::new("DIAGNOSTICO DE REGIONES DE MEMORIA PRIVADA Y CADENAS EXTRAIDAS:")
                        .size(12.0)
                        .strong()
                        .color(Color32::from_rgb(56, 189, 248)),
                );

                for (idx, reg) in report.process_audit.memory_diagnostics.iter().enumerate() {
                    Frame::none()
                        .fill(Color32::from_rgb(22, 30, 48))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 52, 82)))
                        .rounding(Rounding::same(6.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("#{}: Direccion: {}", idx + 1, reg.base_address)).size(11.5).strong().color(Color32::WHITE));
                                ui.label(RichText::new(format!("Tamano: {} KB", reg.size_kb)).size(11.0).color(Color32::from_rgb(148, 163, 184)));
                                ui.label(RichText::new(format!("Permisos: {}", reg.protection)).size(11.0).color(Color32::from_rgb(148, 163, 184)));

                                if reg.is_pe_image {
                                    ui.label(RichText::new("[CABECERA PE DETECTADA]").size(11.0).strong().color(Color32::from_rgb(248, 113, 113)));
                                }
                            });

                            if let Some(ref origin) = reg.identified_origin {
                                ui.label(RichText::new(format!("Origen identificado: {}", origin)).size(11.0).color(Color32::from_rgb(56, 189, 248)));
                            }

                            if !reg.extracted_strings.is_empty() {
                                ui.label(RichText::new(format!("Cadenas halladas: {}", reg.extracted_strings.join(" | "))).size(10.5).color(Color32::from_rgb(203, 213, 225)));
                            }
                        });
                    ui.add_space(4.0);
                }
            }
        } else {
            ui.label(
                RichText::new("Left 4 Dead 2 no esta en ejecucion en esta computadora. Abre el juego si el administrador solicita peritaje de memoria.")
                    .size(11.5)
                    .color(Color32::from_rgb(148, 163, 184)),
            );
        }

        if !report.process_audit.notes.is_empty() {
            ui.add_space(8.0);
            for n in &report.process_audit.notes {
                ui.label(RichText::new(format!("Nota: {}", n)).size(10.5).color(Color32::from_rgb(148, 163, 184)));
            }
        }
    });
}

fn render_steam_tab(ui: &mut egui::Ui, report: &AuditReport) {
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new(format!("CUENTAS DE STEAM DETECTADAS EN ESTA PC ({})", report.steam_accounts.len()))
                .size(13.0)
                .strong()
                .color(Color32::from_rgb(56, 189, 248)),
        );
        ui.label(
            RichText::new("Historial de usuarios registrados en loginusers.vdf y actividad en app 550 (L4D2).")
                .size(11.0)
                .color(Color32::from_rgb(148, 163, 184)),
        );
        ui.separator();

        if report.steam_accounts.is_empty() {
            ui.label("No se encontraron cuentas de Steam registradas en la instalacion local.");
        } else {
            for acc in &report.steam_accounts {
                Frame::none()
                    .fill(Color32::from_rgb(22, 30, 48))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 52, 82)))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&acc.persona_name).size(13.0).strong().color(Color32::WHITE));
                            ui.label(RichText::new(format!("(Cuenta: {})", acc.account_name)).size(11.5).color(Color32::from_rgb(148, 163, 184)));

                            if acc.most_recent {
                                ui.label(
                                    RichText::new("[SESION MAS RECIENTE]")
                                        .size(10.5)
                                        .strong()
                                        .color(Color32::from_rgb(56, 189, 248)),
                                );
                            }
                        });

                        ui.add_space(3.0);
                        ui.label(RichText::new(format!("SteamID64: {}", acc.steam_id_64)).size(11.0).color(Color32::from_rgb(203, 213, 225)));
                        ui.label(RichText::new(format!("Ultimo inicio de sesion: {}", acc.last_login_str)).size(11.0).color(Color32::from_rgb(148, 163, 184)));

                        if acc.played_l4d2 {
                            let l4d2_str = acc
                                .l4d2_last_played_str
                                .as_deref()
                                .unwrap_or("Fecha local no registrada");
                            ui.label(
                                RichText::new(format!("[L4D2] Ha jugado en esta PC (Ultima sesion: {})", l4d2_str))
                                    .size(11.5)
                                    .strong()
                                    .color(Color32::from_rgb(52, 211, 153)),
                            );
                        } else {
                            ui.label(
                                RichText::new("[L4D2] Sin historial de partidas de L4D2 en este equipo.")
                                    .size(11.0)
                                    .color(Color32::from_rgb(148, 163, 184)),
                            );
                        }
                    });
                ui.add_space(4.0);
            }
        }
    });
}

fn render_forensics_tab(ui: &mut egui::Ui, report: &AuditReport) {
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("FORENSE DEL SISTEMA OPERATIVO Y ARTEFACTOS DE WINDOWS")
                .size(13.0)
                .strong()
                .color(Color32::from_rgb(56, 189, 248)),
        );
        ui.separator();

        ui.horizontal(|ui| {
            // OS Dates Card
            Frame::none()
                .fill(Color32::from_rgb(22, 30, 48))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 52, 82)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("INSTALACION DE WINDOWS").size(11.0).strong().color(Color32::from_rgb(56, 189, 248)));
                        let install_date = report.os_forensics.windows_install_date_str.as_deref().unwrap_or("No disponible");
                        ui.label(RichText::new(format!("Fecha registrada: {}", install_date)).size(11.5).color(Color32::WHITE));

                        if report.os_forensics.has_feature_updates {
                            ui.label(RichText::new("Actualizaciones de compilacion (Feature Updates): Detectadas").size(10.5).color(Color32::from_rgb(148, 163, 184)));
                        }
                    });
                });

            // Prefetch Status Card
            Frame::none()
                .fill(Color32::from_rgb(22, 30, 48))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 52, 82)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("ESTADO DE PREFETCH").size(11.0).strong().color(Color32::from_rgb(56, 189, 248)));
                        ui.label(RichText::new(format!("Total de archivos: {}", report.os_forensics.prefetch_total_files)).size(11.5).color(Color32::WHITE));

                        if report.os_forensics.prefetch_wiped_recently {
                            ui.label(
                                RichText::new("[ALERTA] Cantidad baja de archivos (posible vaciado manual)").size(11.0).strong().color(Color32::from_rgb(248, 113, 113)),
                            );
                        } else {
                            ui.label(RichText::new("[OK] Historial de ejecucion integro").size(11.0).color(Color32::from_rgb(52, 211, 153)));
                        }
                    });
                });
        });

        // Active Injectors Alert
        if !report.os_forensics.active_injector_processes.is_empty() {
            ui.add_space(8.0);
            Frame::none()
                .fill(Color32::from_rgb(60, 20, 26))
                .stroke(Stroke::new(1.5_f32, Color32::from_rgb(239, 68, 68)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("[ALERTA CRITICA] Inyectores / Loaders ejecutandose activamente en Windows:")
                            .size(12.5)
                            .strong()
                            .color(Color32::from_rgb(248, 113, 113)),
                    );
                    for inj in &report.os_forensics.active_injector_processes {
                        ui.label(RichText::new(format!(" * {}", inj)).size(12.0).strong().color(Color32::WHITE));
                    }
                });
        }

        // Historic Prefetch Residues
        if !report.os_forensics.suspicious_prefetch_entries.is_empty() {
            ui.add_space(8.0);
            Frame::none()
                .fill(Color32::from_rgb(52, 38, 16))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(251, 191, 36)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("[ADVERTENCIA] Residuos historicos en Prefetch (Herramientas ejecutadas en el equipo):")
                            .size(12.0)
                            .strong()
                            .color(Color32::from_rgb(251, 191, 36)),
                    );
                    for e in &report.os_forensics.suspicious_prefetch_entries {
                        ui.label(RichText::new(format!(" - {}", e)).size(11.5).color(Color32::WHITE));
                    }
                });
        }
    });
}

fn render_json_tab(ui: &mut egui::Ui, report: &AuditReport) {
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("VISTA PREVIA DEL REPORTE (TRANSPARENCIA DE DATOS)")
                .size(13.0)
                .strong()
                .color(Color32::from_rgb(56, 189, 248)),
        );
        ui.label(
            RichText::new("Este es el documento JSON completo que sera transmitido al Worker de Discord:")
                .size(11.0)
                .color(Color32::from_rgb(148, 163, 184)),
        );
        ui.separator();

        if let Ok(json_str) = serde_json::to_string_pretty(report) {
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut json_str.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(18)
                            .desired_width(f32::INFINITY),
                    );
                });
        }
    });
}

impl AuditApp {
    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            ui.label(
                RichText::new("CONFIGURACION DEL PROXY DE DISCORD (CLOUDFLARE WORKER)")
                    .size(13.0)
                    .strong()
                    .color(Color32::from_rgb(56, 189, 248)),
            );
            ui.label(
                RichText::new("El cliente envia el reporte firmado al Worker y este lo despacha al Webhook de Discord sin exponerlo.")
                    .size(11.0)
                    .color(Color32::from_rgb(148, 163, 184)),
            );
            ui.separator();

            ui.label(
                RichText::new("URL DEL CLOUDFLARE WORKER:")
                    .size(11.5)
                    .strong()
                    .color(Color32::from_rgb(203, 213, 225)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.worker_url)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(10.0);

            ui.label(
                RichText::new("TOKEN SECRETO COMPARTIDO (X-Audit-Token):")
                    .size(11.5)
                    .strong()
                    .color(Color32::from_rgb(203, 213, 225)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.secret_token)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(12.0);
            Frame::none()
                .fill(Color32::from_rgb(14, 20, 32))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(28, 40, 64)))
                .rounding(Rounding::same(6.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Nota de seguridad: Si utilizas el ejecutable distribuido por los administradores de tu torneo, estos parametros vendran preconfigurados de forma segura.")
                            .size(10.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });
        });
    }
}

fn rand_u64() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
