use std::path::PathBuf;
use crate::ImportanceEnum::ImportanceEnum;

pub struct ScanResult {
    pub file_name: String,
    pub importance: ImportanceEnum,
}

pub struct Settings {
    pub full_disk_scan: bool,
    pub gorilla_tag_path: PathBuf,
    pub bepinex_path: PathBuf,
    pub scan_results: Vec<ScanResult>,
}