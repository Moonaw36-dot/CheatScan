use imgui::Ui;
use std::sync::mpsc::{channel, Receiver};
use crate::Structs::{Settings, ScanResult};
use crate::checker::find_suspicious_dlls;

pub struct Tab1 {
    pub receiver: std::sync::Arc<std::sync::Mutex<Option<Receiver<Vec<ScanResult>>>>>,
    // Persistent progress tracker
    pub progress: std::sync::Arc<std::sync::Mutex<f32>>,
    pub is_scanning: std::sync::Arc<std::sync::Mutex<bool>>,
}

impl Tab1 {
    pub fn new() -> Self {
        Self {
            receiver: std::sync::Arc::new(std::sync::Mutex::new(None)),
            progress: std::sync::Arc::new(std::sync::Mutex::new(0.0)),
            is_scanning: std::sync::Arc::new(std::sync::Mutex::new(false)),
        }
    }

    pub fn build(&self, ui: &Ui, settings: &mut Settings) {
        ui.text("Welcome to CheatScan made by Moonaw!");

        // Poll for results
        if let Ok(mut rx_guard) = self.receiver.lock() {
            if let Some(ref rx) = *rx_guard {
                if let Ok(results) = rx.try_recv() {
                    settings.scan_results = results;
                    *rx_guard = None; // Reset
                    if let Ok(mut s) = self.is_scanning.lock() { *s = false; }
                }
            }
        }

        if ui.button("Begin scanning") {
            let bepinex_path = settings.bepinex_path.clone();
            let full_disk = settings.full_disk_scan;
            let (tx, rx) = channel();
            let progress = self.progress.clone();

            if let Ok(mut rx_guard) = self.receiver.lock() {
                *rx_guard = Some(rx);
            }
            if let Ok(mut s) = self.is_scanning.lock() { 
                *s = true; 
                if let Ok(mut p) = self.progress.lock() { *p = 0.0; }
            }

            std::thread::spawn(move || {
                let results = find_suspicious_dlls(&bepinex_path.to_string_lossy(), full_disk, progress);
                let _ = tx.send(results);
            });
        }

        if let Ok(s) = self.is_scanning.lock() {
            if *s {
                if let Ok(p) = self.progress.lock() {
                    imgui::ProgressBar::new(*p).size([200.0, 10.0]).build(ui);
                }
            }
        }

        ui.separator();
        if settings.scan_results.is_empty() {
            ui.text("No suspicious files found.")
        } else {
            for result in &settings.scan_results {
                ui.text(format!("{}: {}", result.file_name, result.importance));
            }
        }
    }
}
