mod ImportanceEnum;
mod Main;
mod Settings;
mod Structs;
mod checker;
mod files;
mod renderer;
mod runtime_tab;

use crate::renderer::Renderer;
use glutin::config::{ConfigTemplateBuilder, GlConfig};
use glutin::context::{ContextAttributesBuilder, NotCurrentGlContext};
use glutin::display::{GetGlDisplay, GlDisplay};
use glutin::surface::{GlSurface, SurfaceAttributesBuilder, WindowSurface};
use glutin_winit::DisplayBuilder;
use imgui::Context;
use imgui_winit_support::{HiDpiMode, WinitPlatform};
use std::num::NonZeroU32;
use std::time::Instant;
use winit::application::ApplicationHandler;
use winit::event::{Event, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::raw_window_handle::HasWindowHandle;
use winit::window::{Window, WindowAttributes};

struct App {
    window: Option<Window>,
    gl_context: Option<glutin::context::PossiblyCurrentContext>,
    gl_surface: Option<glutin::surface::Surface<glutin::surface::WindowSurface>>,
    imgui: Context,
    platform: WinitPlatform,
    renderer: Option<Renderer>,
    last_frame: Instant,
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        let window_attributes = WindowAttributes::default().with_title("Cheat Scan");
        let template = ConfigTemplateBuilder::new();
        let display_builder = DisplayBuilder::new().with_window_attributes(Some(window_attributes));

        let (window, gl_config) = display_builder
            .build(event_loop, template, |configs| {
                configs
                    .reduce(|accum, config| {
                        if config.num_samples() > accum.num_samples() {
                            config
                        } else {
                            accum
                        }
                    })
                    .unwrap()
            })
            .unwrap();

        let window = window.unwrap();
        let gl_display = gl_config.display();
        let raw_window_handle = window.window_handle().unwrap().as_raw();

        let context_attributes = ContextAttributesBuilder::new().build(Some(raw_window_handle));
        let not_current_gl_context = unsafe {
            gl_display
                .create_context(&gl_config, &context_attributes)
                .unwrap()
        };

        let attrs = SurfaceAttributesBuilder::<WindowSurface>::new().build(
            raw_window_handle,
            NonZeroU32::new(window.inner_size().width).unwrap(),
            NonZeroU32::new(window.inner_size().height).unwrap(),
        );
        let gl_surface = unsafe {
            gl_display
                .create_window_surface(&gl_config, &attrs)
                .unwrap()
        };
        let gl_context = not_current_gl_context.make_current(&gl_surface).unwrap();

        let gl = unsafe {
            glow::Context::from_loader_function(|s| {
                let c_str = std::ffi::CString::new(s).unwrap();
                gl_display.get_proc_address(c_str.as_c_str())
            })
        };

        self.platform
            .attach_window(self.imgui.io_mut(), &window, HiDpiMode::Default);
        let renderer = Renderer::new(gl, &mut self.imgui);

        self.window = Some(window);
        self.gl_context = Some(gl_context);
        self.gl_surface = Some(gl_surface);
        self.renderer = Some(renderer);
        self.last_frame = Instant::now();
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _id: winit::window::WindowId,
        event: WindowEvent,
    ) {
        let window = self.window.as_ref().unwrap();

        match event {
            WindowEvent::Resized(_) => {
                window.request_redraw();
            }
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => {
                let now = Instant::now();
                self.imgui.io_mut().update_delta_time(now - self.last_frame);
                self.last_frame = now;

                let draw_data = {
                    let ui = self.imgui.frame();
                    self.renderer.as_mut().unwrap().build_ui(ui);
                    self.platform.prepare_render(ui, window);
                    self.imgui.render()
                };

                let size = window.inner_size();
                if size.width > 0
                    && size.height > 0
                    && draw_data.total_vtx_count > 0
                    && draw_data.total_idx_count > 0
                {
                    self.renderer
                        .as_mut()
                        .unwrap()
                        .render(draw_data, size.width, size.height);
                    self.gl_surface
                        .as_ref()
                        .unwrap()
                        .swap_buffers(self.gl_context.as_ref().unwrap())
                        .unwrap();
                }
                window.request_redraw();
            }
            _ => {
                self.platform.handle_event::<()>(
                    self.imgui.io_mut(),
                    window,
                    &Event::WindowEvent {
                        window_id: _id,
                        event,
                    },
                );
            }
        }
    }
}

fn main() {
    let _settings = Structs::Settings {
        full_disk_scan: true,
        gorilla_tag_path: Default::default(),
        bepinex_path: Default::default(),
        scan_results: Vec::new(),
    };

    let event_loop = EventLoop::new().unwrap();
    let mut imgui = Context::create();
    let platform = WinitPlatform::new(&mut imgui);

    let mut app = App {
        window: None,
        gl_context: None,
        gl_surface: None,
        imgui,
        platform,
        renderer: None,
        last_frame: Instant::now(),
    };

    event_loop.run_app(&mut app).unwrap();
}
