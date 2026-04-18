use std::path::PathBuf;
use walkdir::WalkDir;
use crate::Structs::Settings;

pub fn exe_dialog() -> Option<PathBuf> {
    let path = rfd::FileDialog::new()
        .add_filter("EXE", &["exe"])
        .set_directory(".")
        .pick_file()?;

    Some(path)
}

pub fn folder_dialog() -> Option<PathBuf> {
    let path = rfd::FileDialog::new()
        .pick_folder();

    Some(path?)
}

pub fn find_gorilla_tag_path() -> Option<PathBuf> {
    let target = "Gorilla Tag.exe";

    #[cfg(target_os = "windows")]
    let start_dir = "C:\\";

    #[cfg(target_os = "linux")]
    let start_dir = "/home";

    for entry in WalkDir::new(start_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_name() == target {
            return entry.path().parent().map(|p| p.to_path_buf());
        }
    }
    None
}


pub fn find_bepinex_path(settings: &mut Settings) -> Option<PathBuf> {
    if settings.gorilla_tag_path.is_dir() {
        for entry in WalkDir::new(&settings.gorilla_tag_path)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_name().to_string_lossy().to_lowercase() == "bepinex" && entry.file_type().is_dir() {
                return Some(entry.path().to_path_buf());
            }
        }
    }
    None
}
