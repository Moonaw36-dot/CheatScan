use crate::Structs::Settings;
use imgui::Ui;
use crate::checker::{check_intellect};

pub struct Tab3 {}

impl Tab3 {
    pub fn new() -> Self {
        Tab3 {}
    }
    pub fn build(&mut self, ui: &Ui, settings: &mut Settings) {
        ui.text("This check is REALLY basic and only checks the process name.");
        ui.text("It will not detect it if the user has hide process enabled.");
        if ui.button("Check for Intellect") {
            if check_intellect() {
                settings.is_intellect_running = Some(true);
            } else {
                settings.is_intellect_running = Some(false);
            }
        }

        if settings.is_intellect_running.is_some() && settings.is_intellect_running.unwrap() {
            ui.text("Intellect is running.");
        } else {
            ui.text("Intellect wasn't found during the scan.");
        }
    }
}
