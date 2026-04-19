use crate::ImportanceEnum::ImportanceEnum;
use crate::Structs::ScanResult;
use jwalk::WalkDir;
use pelite::FileMap;
use pelite::pe32::Pe as Pe32;
use pelite::pe64::Pe as Pe64;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::{Arc, Mutex};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

fn get_file_hash(path: &std::path::Path) -> String {
    let file = File::open(path).ok();
    if let Some(file) = file {
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
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
        if original_filename.is_some() {
            break;
        }
    }

    original_filename
}

pub fn find_suspicious_dlls(
    plugins_path: &str,
    full_disk: bool,
    progress: Arc<Mutex<f32>>,
) -> Vec<ScanResult> {
    let all_suspicious = [
        "apphost",
        "iis_Stupid_Menu",
        "ColossalCheatMenu",
        "CCM",
        "Slider",
        "Preds",
        "WallWalk",
        "ModMenu",
        "CheatMenu",
        "Skid",
        "Pull",
        "PSA",
        "Malachis",
        "Mod Menu",
        "Cheat Menu",
        "Comp Gui",
        "Comp Cheat",
        "arms",
        "Zybers",
        "Speed Boost",
        "Boost",
        "Quest Menu",
        "Fake Quest",
        "Pigeito",
        "LongArms",
        "Tag Reach",
        "Tag fix",
        "Ventern",
        "Goobas",
        "Mintys",
        "Velmax",
        "Velocity",
        "Seralyth",
        "Soduim",
        "Spoofer",
        "pull cap",
        "Comp ",
        "external",
        "Predictions",
        "wyvldr",
        "5cintill4",
        "inject",
        "cheat",
        "hack",
        "sharpmono",
        "bypass",
        "smi",
        "trainer",
        "loader",
        "injector",
        "parallex",
        "extremeinjector",
        "scintilla",
        "intellect",
        "IntellectFree",
    ];

    let safe_hashes: HashSet<String> = [
        "c755a5ab2712915a32f9a850d580a8c1b70ff1653bc76600f2767aa8ffccc663",
        "00c8f2ac48593e4d45ce4eb26ce4e68b18113c5c489b38b8bf0850f65830d601",
        "55d3895351a9d16b63b6f35f1c01b44ac650979e853d0bd3a442b92a082af64f",
        "8255b28902886085c578b9e427d3073c97002db85176d2090cdeda90ef14ce70",
        "7ce1342d3afa0334b59a3e38c0aed15e162b9abe9d46f95f34be44af47f3b493",
        "1a21cc03424fc82c3dd1346905d16494536b9595ae4162228d99fb7c285c1031",
        "7ae470288fff4a402899c254d0a76cefef55877f5c54f96e83c797cc5bb6e2f6",
        "5896d1898f616701fff18f3b2c71e6b844d2390ef9f41e1c5fccce8cb27c698e",
        "174db44a067f58561510af746f3caeb032037762c57a31c8d9ee32db25174984",
        "54ac539fb5ddc8b44c0e9acd0fcb7324f89d1a072edf8ebc1b06dd691e3d3927",
        "40e49bb314391cd7bddc2644f8553eeba92c194b940836b103df16955c464e0c",
        "9d1495f147ac93c4f81f84538c1a326e8f8a6aefc78d6289d798f3ce1162c5e9",
        "7ba2266061b9f8a9f146218a312bfdd0d7f2b53a99a7e66c957215c6b66ca0d7",
        "0577b362023a3432d6e8d7934c5eddc3e08fdbb19e191af083e341562c5ede38",
        "a04fedf08f7c81f5d01aba6f2840a7ffce50b79bbd24587d8dbe69ab73971d29",
        "d1f02fc3ada3a13da307de421225bfe56ebe24064370980979391c4be021672f",
        "33275b2783b7b99495a02c098ee86d6a9a2783e884a5c9369021f20c94cf99e7",
        "54887808960d156550b37d602d08847607aa9e908d039f2765fb0b5e79394aa4",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let malicious_hashes: HashSet<String> = [
        "ea0df233a20070c7aeec60bfb8b9ce0c42ac809640b5da68ccf7619656a35e9e", // original intellect loader
        "7a7261eae09358decff8653ebda60fa87bb98d6672d2bff422d1c2143cc34b8c", // Intellect lite
        "1b8021fdd9ead2bee2bb706793bbd47cc7a74816b8b533ca5d78b6d69ffbaf2f" // apphost.exe
    ]
    .into_iter()
    .map(String::from)
    .collect();

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
            paths_to_scan.push(format!(r"{}\Downloads", user_profile));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            paths_to_scan.push(format!("{}/Downloads", home));
        }
    }

    let results = paths_to_scan
        .into_par_iter()
        .flat_map(|path| {
            let mut found_files = Vec::new();
            let _is_plugins_folder = path == plugins_path;

            if !path.is_empty() && std::path::Path::new(&path).exists() {
                let entries: Vec<_> = WalkDir::new(path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .collect();
                let total_entries = entries.len();

                for (i, entry) in entries.into_iter().enumerate() {
                    if i % 100 == 0 {
                        if let Ok(mut p) = progress.lock() {
                            *p = (i as f32 / total_entries as f32).min(0.95);
                        }
                    }

                    let path = entry.path();
                    let file_name = entry.file_name.to_string_lossy();
                    let is_dll = file_name.ends_with(".dll");
                    let is_exe = file_name.ends_with(".exe");

                    if is_dll || is_exe {
                        let file_hash = get_file_hash(&path);

                        // 1. Known safe hash
                        if safe_hashes.contains(&file_hash) {
                            continue;
                        }

                        let mut is_suspicious = false;

                        // 2. Known malicious hash
                        if malicious_hashes.contains(&file_hash) {
                            is_suspicious = true;
                        }

                        // 3. Check filename
                        if !is_suspicious
                            && all_suspicious.iter().any(|&name| file_name.contains(name))
                        {
                            is_suspicious = true;
                        }

                        // 4. Check metadata
                        if !is_suspicious {
                            if let Some(check_name) = get_original_filename(&path) {
                                if all_suspicious.iter().any(|&name| check_name.contains(name)) {
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
        })
        .collect();

    if let Ok(mut p) = progress.lock() {
        *p = 1.0;
    }

    results
}

pub fn check_intellect() -> bool {

    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything())
    );


    sys.refresh_processes(ProcessesToUpdate::All, true);

    let intellect_process = "apphost";


    sys.processes().values().any(|val| {
        val.name()
            .to_str()
            .map(|s| s.to_lowercase().contains(intellect_process))
            .unwrap_or(false)
    })
}