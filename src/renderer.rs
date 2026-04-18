use glow::HasContext;
use imgui::{Ui};
use imgui_glow_renderer::AutoRenderer;
use std::cell::RefCell;
use crate::Main::Tab1;
use crate::Settings::Tab2;
use crate::Structs::Settings;

pub struct Renderer {
    glow_renderer: AutoRenderer,
    tab1: Tab1,
    tab2: Tab2,
    settings: RefCell<Settings>,
}

impl Renderer {
    pub fn new(gl: glow::Context, imgui: &mut imgui::Context) -> Self {
        Self {
            glow_renderer: AutoRenderer::new(gl, imgui).unwrap(),
            tab1: Tab1 { settings: Settings {  full_disk_scan: true, gorilla_tag_path: Default::default(), bepinex_path: Default::default(), scan_results: Vec::new() } },
            tab2: Tab2,
            settings: RefCell::new(Settings { full_disk_scan: true ,gorilla_tag_path: Default::default(), bepinex_path: Default::default(), scan_results: Vec::new() }),
        }
    }

    pub fn build_ui(&self, ui: &Ui) {
        let mut settings = self.settings.borrow_mut();
        ui.window("CheatScan")
            .size([400.0, 300.0], imgui::Condition::FirstUseEver)
            .build(|| {
                if let Some(tab_bar) = ui.tab_bar("MainTabBar") {
                    if let Some(tab) = ui.tab_item("Main") {
                        self.tab1.build(ui, &mut settings);
                        tab.end();
                    }
                    if let Some(tab) = ui.tab_item("Settings") {
                        self.tab2.build(ui, &mut settings);
                        tab.end();
                    }
                    tab_bar.end();
                }
            });
    }


    pub fn render(&mut self, draw_data: &imgui::DrawData, width: u32, height: u32) {
        let gl = self.glow_renderer.gl_context();
        unsafe {
            gl.viewport(0, 0, width as i32, height as i32);
            gl.clear_color(0.1, 0.1, 0.1, 1.0);
            gl.clear(glow::COLOR_BUFFER_BIT);
        }
        self.glow_renderer.render(draw_data).expect("Glow renderer failed");
    }
}

