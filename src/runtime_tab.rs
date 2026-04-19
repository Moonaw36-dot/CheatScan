use crate::Structs::{RuntimeScanReport, Settings};
use crate::runtime_scanner::scan_for_apphost;
use imgui::Ui;
use std::sync::mpsc::{Receiver, channel};

pub struct Tab3 {
    receiver: std::sync::Arc<std::sync::Mutex<Option<Receiver<RuntimeScanReport>>>>,
    is_scanning: std::sync::Arc<std::sync::Mutex<bool>>,
}

impl Tab3 {
    pub fn new() -> Self {
        Self {
            receiver: std::sync::Arc::new(std::sync::Mutex::new(None)),
            is_scanning: std::sync::Arc::new(std::sync::Mutex::new(false)),
        }
    }

    pub fn build(&mut self, ui: &Ui, settings: &mut Settings) {
        if let Ok(mut rx_guard) = self.receiver.lock() {
            if let Some(ref rx) = *rx_guard {
                if let Ok(report) = rx.try_recv() {
                    settings.runtime_scan_report = Some(report);
                    *rx_guard = None;
                    if let Ok(mut scanning) = self.is_scanning.lock() {
                        *scanning = false;
                    }
                }
            }
        }

        ui.text("Runtime scanner for apphost.exe.");
        ui.text("It cross-checks the normal process list with multiple PID side channels.");

        if ui.button("Scan for apphost") {
            let (tx, rx) = channel();

            if let Ok(mut rx_guard) = self.receiver.lock() {
                *rx_guard = Some(rx);
            }

            if let Ok(mut scanning) = self.is_scanning.lock() {
                *scanning = true;
            }

            std::thread::spawn(move || {
                let _ = tx.send(scan_for_apphost());
            });
        }

        if let Ok(scanning) = self.is_scanning.lock() {
            if *scanning {
                ui.text("Runtime scan in progress...");
            }
        }

        if let Some(report) = &settings.runtime_scan_report {
            ui.separator();
            if report.detected {
                ui.text_colored(
                    [1.0, 0.2, 0.2, 1.0],
                    format!("Detected {}", report.target_process),
                );
            } else {
                ui.text_colored(
                    [0.2, 1.0, 0.4, 1.0],
                    format!("{} was not detected", report.target_process),
                );
            }

            for note in &report.notes {
                ui.text_wrapped(note);
            }

            if !report.findings.is_empty() {
                ui.separator();
                for finding in &report.findings {
                    let pid_label = finding
                        .pid
                        .map(|pid| format!("PID {}", pid))
                        .unwrap_or_else(|| "PID unavailable".to_string());
                    let visibility = if finding.visible_in_process_list {
                        "visible in process list"
                    } else {
                        "missing from process list"
                    };

                    ui.text(format!(
                        "{} | {} | {}",
                        finding.method, pid_label, visibility
                    ));
                    ui.text_wrapped(&finding.details);
                }
            }
        }
    }
}
