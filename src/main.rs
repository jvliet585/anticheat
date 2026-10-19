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
            .with_inner_size([780.0, 580.0])
            .with_min_inner_size([600.0, 450.0])
            .with_title("Left 4 Dead 2 - Audit Tool (Community Edition)"),
        ..Default::default()
    };

    eframe::run_native(
        "L4D2 Audit Tool",
        native_options,
        Box::new(|_cc| Ok(Box::new(AuditApp::default()))),
    )
}
