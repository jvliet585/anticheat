#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod forensics;
mod game;
mod models;
mod scoring;
mod sender;
mod steam;
mod ui;

use eframe::egui;
use ui::AuditApp;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([880.0, 660.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("Left 4 Dead 2 - Forensic Community Audit Suite"),
        ..Default::default()
    };

    eframe::run_native(
        "L4D2 Audit Tool",
        native_options,
        Box::new(|cc| Ok(Box::new(AuditApp::new(cc)))),
    )
}
