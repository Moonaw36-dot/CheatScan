use walkdir::WalkDir;
use crate::ImportanceEnum::ImportanceEnum;
use crate::Structs::ScanResult;

pub fn find_suspicious_dlls(plugins_path: &str) -> Vec<ScanResult> {
    let suspicious_names = [
        "iis_Stupid_Menu", "ColossalCheatMenu", "CCM", "Slider", "Preds", "WallWalk",
        "ModMenu", "CheatMenu", "Skid", "Pull", "PSA", "Malachis", "Mod Menu",
        "Cheat Menu", "Comp Gui", "Comp Cheat", "arms", "Zybers", "Speed Boost",
        "Boost", "Quest Menu", "Fake Quest", "Pigeito", "LongArms", "Tag Reach",
        "Tag fix", "Ventern", "Goobas", "Mintys", "Velmax", "Velocity",
        "Seralyth", "Soduim", "Spoofer", "pull cap", "Comp ", "external", "Predictions",
    ];

    let mut found_files: Vec<ScanResult> = Vec::new();

    for entry in WalkDir::new(plugins_path).into_iter().skip(1).filter_map(|e| e.ok()) {
        let file_name = entry.file_name().to_string_lossy();
        if suspicious_names.iter().any(|&name| file_name.contains(name)) {
            found_files.push(ScanResult {
                file_name: file_name.to_string(),
                importance: ImportanceEnum::CheatMenu,
            });
        }
    }
    found_files
}
