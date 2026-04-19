use crate::ImportanceEnum::ImportanceEnum;
use std::path::PathBuf;

pub struct ScanResult {
    pub file_name: String,
    pub importance: ImportanceEnum,
}

pub struct RuntimeFinding {
    pub method: String,
    pub details: String,
    pub pid: Option<u32>,
    pub visible_in_process_list: bool,
}

pub struct RuntimeScanReport {
    pub target_process: String,
    pub detected: bool,
    pub findings: Vec<RuntimeFinding>,
    pub notes: Vec<String>,
}

pub struct Settings {
    pub full_disk_scan: bool,
    pub gorilla_tag_path: PathBuf,
    pub bepinex_path: PathBuf,
    pub scan_results: Vec<ScanResult>,
    pub runtime_scan_report: Option<RuntimeScanReport>,
}
