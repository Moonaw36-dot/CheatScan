use imgui::Ui;
use crate::Structs::Settings;
use crate::checker::find_suspicious_dlls;

pub struct Tab1 {
    pub settings: Settings,
}

impl Tab1 {
    pub fn build(&self, ui: &Ui, settings: &mut Settings) {
        ui.text("Welcome to CheatScan made by Moonaw!");
        ui.text("It is made to detect cheaters on Gorilla Tag, including DLLs, Injectors, and more.");
        ui.text("WARNING! While scanning, it might slow down your pc, since it is scanning your whole drive for cheats.");

        if ui.button("Begin scanning") {
            settings.scan_results = find_suspicious_dlls(settings.bepinex_path.to_str().unwrap_or(""));
        }

        if settings.scan_results.is_empty() {
            ui.text("No suspicious DLL found.")
        } else {
            for result in &settings.scan_results {
                ui.text(format!("{}: {}", result.file_name, result.importance));
            }
        }
    }
}
