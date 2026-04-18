use walkdir::WalkDir;
use rayon::prelude::*;
use pelite::FileMap;
use pelite::pe32::{Pe as Pe32};
use pelite::pe64::{Pe as Pe64};
use crate::ImportanceEnum::ImportanceEnum;
use crate::Structs::ScanResult;

fn get_original_filename(path: &std::path::Path) -> Option<String> {
    let map = FileMap::open(path).ok()?;
    let bytes = map.as_ref();

    let resources = if let Ok(file) = pelite::pe64::PeFile::from_bytes(bytes) {
        file.resources().ok()
    } else if let Ok(file) = pelite::pe32::PeFile::from_bytes(bytes) {
        file.resources().ok()
    } else {
        None
    }?;

    let version_info = resources.version_info().ok()?;
    
    let mut original_filename = None;
    
    for &lang in version_info.translation() {
        version_info.strings(lang, |key: &str, value: &str| {
            if key == "OriginalFilename" {
                original_filename = Some(value.to_string());
            }
        });
        if original_filename.is_some() { break; }
    }
    
    original_filename
}

pub fn find_suspicious_dlls(plugins_path: &str) -> Vec<ScanResult> {
    let suspicious_names = [
        "ii's Stupid Menu.dll", "ColossalCheatMenu", "CCM", "Slider", "Preds", "WallWalk",
        "ModMenu", "CheatMenu", "Skid", "Pull", "PSA", "Malachis", "Mod Menu",
        "Cheat Menu", "Comp Gui", "Comp Cheat", "arms", "Zybers", "Speed Boost",
        "Boost", "Quest Menu", "Fake Quest", "Pigeito", "LongArms", "Tag Reach",
        "Tag fix", "Ventern", "Goobas", "Mintys", "Velmax", "Velocity",
        "Seralyth", "Soduim", "Spoofer", "pull cap", "Comp ", "external", "Predictions",
    ];

    let mut paths_to_scan = vec![plugins_path.to_string()];

    #[cfg(target_os = "windows")]
    {
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            paths_to_scan.push(format!("{}\\Downloads", user_profile));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            paths_to_scan.push(format!("{}/Downloads", home));
        }
    }

    paths_to_scan.into_par_iter().flat_map(|path| {
        let mut found_files = Vec::new();
        let is_plugins_folder = path == plugins_path;

        if !path.is_empty() && std::path::Path::new(&path).exists() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                let file_name = entry.file_name().to_string_lossy();
                let is_dll = file_name.ends_with(".dll");

                if is_plugins_folder && !is_dll && entry.file_type().is_file() {
                    found_files.push(ScanResult {
                        file_name: file_name.to_string(),
                        importance: ImportanceEnum::Suspicious,
                    });
                }
                
                if is_dll {
                    let mut is_suspicious = false;

                    // 1. Check filename
                    if suspicious_names.iter().any(|&name| file_name.contains(name)) {
                        is_suspicious = true;
                    }

                    // 2. Check metadata
                    if !is_suspicious {
                        if let Some(check_name) = get_original_filename(path) {
                            if suspicious_names.iter().any(|&name| check_name.contains(name)) {
                                is_suspicious = true;
                            }
                        }
                    }

                    if is_suspicious {
                        found_files.push(ScanResult {
                            file_name: file_name.to_string(),
                            importance: ImportanceEnum::CheatMenu,
                        });
                    }
                }
            }
        }
        found_files
    }).collect()
}
