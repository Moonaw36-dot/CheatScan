use walkdir::WalkDir;
use rayon::prelude::*;
use pelite::FileMap;
use pelite::pe32::{Pe as Pe32};
use pelite::pe64::{Pe as Pe64};
use crate::ImportanceEnum::ImportanceEnum;
use crate::Structs::ScanResult;
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, BufReader};

fn get_file_hash(path: &std::path::Path) -> String {
    let file = File::open(path).ok();
    if let Some(file) = file {
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        return hex::encode(hasher.finalize());
    }
    String::new()
}

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

pub fn find_suspicious_dlls(plugins_path: &str, full_disk: bool) -> Vec<ScanResult> {
    let all_suspicious = [
        "iis_Stupid_Menu", "ColossalCheatMenu", "CCM", "Slider", "Preds", "WallWalk",
        "ModMenu", "CheatMenu", "Skid", "Pull", "PSA", "Malachis", "Mod Menu",
        "Cheat Menu", "Comp Gui", "Comp Cheat", "arms", "Zybers", "Speed Boost",
        "Boost", "Quest Menu", "Fake Quest", "Pigeito", "LongArms", "Tag Reach",
        "Tag fix", "Ventern", "Goobas", "Mintys", "Velmax", "Velocity",
        "Seralyth", "Soduim", "Spoofer", "pull cap", "Comp ", "external", "Predictions",
        "wyvldr", "5cintill4", "inject", "cheat", "hack", "sharpmono", "bypass", "smi",
        "trainer", "loader", "injector", "parallex", "extremeinjector", "scintilla",
        "intellect"
    ];

    let safe_hashes: HashSet<String> = HashSet::new();

    let mut paths_to_scan = vec![plugins_path.to_string()];
    
    if full_disk {
        #[cfg(target_os = "windows")]
        paths_to_scan.push("C:\\".to_string());
        #[cfg(not(target_os = "windows"))]
        paths_to_scan.push("/".to_string());
    }

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
                let is_exe = file_name.ends_with(".exe");

                if is_plugins_folder && !is_dll && !is_exe && entry.file_type().is_file() {
                    found_files.push(ScanResult {
                        file_name: file_name.to_string(),
                        importance: ImportanceEnum::Suspicious,
                    });
                }

                if is_dll || is_exe {
                    let mut is_suspicious = false;

                    // 1. Check filename
                    if all_suspicious.iter().any(|&name| file_name.contains(name)) {
                        is_suspicious = true;
                    }

                    // 2. Check metadata
                    if !is_suspicious {
                        if let Some(check_name) = get_original_filename(path) {
                            if all_suspicious.iter().any(|&name| check_name.contains(name)) {
                                is_suspicious = true;
                            }
                        }
                    }

                    // 3. Only hash if suspicious to check against allowlist
                    if is_suspicious {
                        let file_hash = get_file_hash(path);
                        if safe_hashes.contains(&file_hash) {
                            is_suspicious = false;
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
