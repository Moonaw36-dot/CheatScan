use crate::Structs::Settings;
use crate::files::{exe_dialog, find_bepinex_path, find_gorilla_tag_path, folder_dialog};
use imgui::Ui;

pub struct Tab2;

impl Tab2 {
    pub fn build(&self, ui: &Ui, settings: &mut Settings) {
        ui.checkbox("Full disk scan", &mut settings.full_disk_scan);

        if settings.gorilla_tag_path.is_dir() {
            ui.text(format!(
                "Gorilla Tag path: {}",
                settings.gorilla_tag_path.display()
            ));
        } else {
            ui.text("Gorilla tag folder not set / found.")
        }

        ui.same_line();

        if ui.button("Find Gorilla Tag path") {
            if let Some(path) = find_gorilla_tag_path() {
                settings.gorilla_tag_path = path;
            }
        }

        ui.same_line();

        if ui.button("Set Gorilla Tag path") {
            if let Some(path) = exe_dialog() {
                settings.gorilla_tag_path = path;
            }
        }

        if settings.bepinex_path.exists() {
            ui.text(format!(
                "Plugins path: {}",
                &settings.bepinex_path.to_str().unwrap()
            ));
        } else {
            ui.text("Plugins folder is not set / found.");
        }

        ui.same_line();

        if ui.button("Find Plugins path") {
            if let Some(path) = find_bepinex_path(settings) {
                settings.bepinex_path = path;
            }
        }

        ui.same_line();

        if ui.button("Set Plugins path") {
            if let Some(path) = folder_dialog() {
                settings.bepinex_path = path;
            }
        }
    }
}
