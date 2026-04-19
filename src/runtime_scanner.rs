#[cfg(any(target_os = "windows", target_os = "linux"))]
use crate::Structs::RuntimeFinding;
use crate::Structs::RuntimeScanReport;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::path::Path;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

const TARGET_PROCESS: &str = "apphost";

pub fn scan_for_apphost() -> RuntimeScanReport {
    #[cfg(target_os = "windows")]
    {
        return scan_windows_target(TARGET_PROCESS);
    }

    #[cfg(target_os = "linux")]
    {
        return scan_linux_target(TARGET_PROCESS);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        RuntimeScanReport {
            target_process: TARGET_PROCESS.to_string(),
            detected: false,
            findings: Vec::new(),
            notes: vec![
                "Runtime apphost scanning is currently implemented for Windows and Linux."
                    .to_string(),
            ],
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn target_name_matches(name: &str, target: &str) -> bool {
    let lowered_target = target.to_ascii_lowercase();
    let lowered_name = name.to_ascii_lowercase();
    let basename = Path::new(&lowered_name)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or(lowered_name);

    basename == lowered_target || basename == format!("{lowered_target}.exe")
}

fn push_finding(
    report: &mut RuntimeScanReport,
    seen_findings: &mut std::collections::HashSet<(String, u32)>,
    method: &str,
    pid: u32,
    visible_in_process_list: bool,
    details: String,
) {
    if seen_findings.insert((method.to_string(), pid)) {
        report.findings.push(RuntimeFinding {
            method: method.to_string(),
            details,
            pid: Some(pid),
            visible_in_process_list,
        });
    }
}

#[cfg(target_os = "windows")]
fn scan_windows_target(target: &str) -> RuntimeScanReport {
    use std::collections::{BTreeSet, HashSet};

    let mut report = RuntimeScanReport {
        target_process: format!("{target}.exe"),
        detected: false,
        findings: Vec::new(),
        notes: vec![
            "Methods run: visible process list, direct PID sweep, top-level window owners, and thread owners."
                .to_string(),
        ],
    };
    let mut seen_findings = HashSet::new();
    let mut visible_pids = BTreeSet::new();
    let mut highest_visible_pid = 0u32;

    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes(ProcessesToUpdate::All, true);

    for process in system.processes().values() {
        let pid = process.pid().as_u32();
        highest_visible_pid = highest_visible_pid.max(pid);

        if target_name_matches(&process.name().to_string_lossy(), target) {
            visible_pids.insert(pid);
            push_finding(
                &mut report,
                &mut seen_findings,
                "Visible process list",
                pid,
                true,
                format!(
                    "The standard process snapshot reported {} for PID {}.",
                    process.name().to_string_lossy(),
                    pid
                ),
            );
        }
    }

    let sweep_upper_bound = highest_visible_pid
        .saturating_add(16384)
        .max(65536)
        .min(262144);
    report.notes.push(format!(
        "Direct PID sweep checked PID values from 4 to {}.",
        sweep_upper_bound
    ));

    for pid in (4..=sweep_upper_bound).step_by(4) {
        if let Some(name) = process_name_from_pid(pid) {
            if target_name_matches(&name, target) {
                let visible = visible_pids.contains(&pid);
                push_finding(
                    &mut report,
                    &mut seen_findings,
                    "Direct PID sweep",
                    pid,
                    visible,
                    if visible {
                        format!(
                            "PID {} resolved to {} through direct handle queries and also appears in the normal process list.",
                            pid, name
                        )
                    } else {
                        format!(
                            "PID {} resolved to {} through direct handle queries even though it was absent from the normal process list.",
                            pid, name
                        )
                    },
                );
            }
        }
    }

    for pid in collect_window_owner_pids() {
        if let Some(name) = process_name_from_pid(pid) {
            if target_name_matches(&name, target) {
                let visible = visible_pids.contains(&pid);
                push_finding(
                    &mut report,
                    &mut seen_findings,
                    "Window owner scan",
                    pid,
                    visible,
                    if visible {
                        format!(
                            "A top-level window belongs to PID {} and that PID resolves to {}.",
                            pid, name
                        )
                    } else {
                        format!(
                            "A top-level window belongs to PID {} and that PID resolves to {} even though it was missing from the normal process list.",
                            pid, name
                        )
                    },
                );
            }
        }
    }

    for pid in collect_thread_owner_pids() {
        if let Some(name) = process_name_from_pid(pid) {
            if target_name_matches(&name, target) {
                let visible = visible_pids.contains(&pid);
                push_finding(
                    &mut report,
                    &mut seen_findings,
                    "Thread owner scan",
                    pid,
                    visible,
                    if visible {
                        format!(
                            "Thread enumeration found an owner PID {} that resolves to {}.",
                            pid, name
                        )
                    } else {
                        format!(
                            "Thread enumeration found an owner PID {} that resolves to {} even though it was missing from the normal process list.",
                            pid, name
                        )
                    },
                );
            }
        }
    }

    report.detected = !report.findings.is_empty();

    let hidden_hits = report
        .findings
        .iter()
        .filter(|finding| !finding.visible_in_process_list)
        .count();

    if hidden_hits > 0 {
        report.notes.push(format!(
            "{} detection path(s) found apphost without a matching visible process entry.",
            hidden_hits
        ));
    }

    if !report.detected {
        report
            .notes
            .push("No apphost process was confirmed by any runtime method.".to_string());
    }

    report
}

#[cfg(target_os = "windows")]
fn process_name_from_pid(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        let success = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        let _ = CloseHandle(handle);

        if success == 0 || size == 0 {
            return None;
        }

        let full_path = String::from_utf16_lossy(&buffer[..size as usize]);
        Path::new(&full_path)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
    }
}

#[cfg(target_os = "windows")]
fn collect_window_owner_pids() -> Vec<u32> {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId};
    use windows_sys::core::BOOL;

    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let pids = &mut *(lparam as *mut std::collections::BTreeSet<u32>);
        let mut pid = 0u32;
        let _ = GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != 0 {
            pids.insert(pid);
        }
        1
    }

    let mut pids = std::collections::BTreeSet::new();
    unsafe {
        let _ = EnumWindows(Some(callback), &mut pids as *mut _ as isize);
    }
    pids.into_iter().collect()
}

#[cfg(target_os = "windows")]
fn collect_thread_owner_pids() -> Vec<u32> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }

        let mut pids = std::collections::BTreeSet::new();
        let mut entry: THREADENTRY32 = zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID != 0 {
                    pids.insert(entry.th32OwnerProcessID);
                }

                entry.dwSize = size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        pids.into_iter().collect()
    }
}

#[cfg(target_os = "linux")]
fn scan_linux_target(target: &str) -> RuntimeScanReport {
    use std::collections::{BTreeSet, HashSet};

    let mut report = RuntimeScanReport {
        target_process: format!("{target}.exe"),
        detected: false,
        findings: Vec::new(),
        notes: vec![
            "Methods run: visible process list, direct /proc PID probe, signal(0) PID probe, and cgroup.procs PID harvesting."
                .to_string(),
        ],
    };
    let mut seen_findings = HashSet::new();
    let mut visible_pids = BTreeSet::new();
    let mut highest_visible_pid = 0u32;

    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes(ProcessesToUpdate::All, true);

    for process in system.processes().values() {
        let pid = process.pid().as_u32();
        highest_visible_pid = highest_visible_pid.max(pid);

        if target_name_matches(&process.name().to_string_lossy(), target) {
            visible_pids.insert(pid);
            push_finding(
                &mut report,
                &mut seen_findings,
                "Visible process list",
                pid,
                true,
                format!(
                    "The standard process snapshot reported {} for PID {}.",
                    process.name().to_string_lossy(),
                    pid
                ),
            );
        }
    }

    let kernel_pid_max = read_kernel_pid_max().unwrap_or(262_144);
    let sweep_upper_bound = highest_visible_pid
        .saturating_add(16_384)
        .max(65_536)
        .min(kernel_pid_max)
        .min(262_144);

    report.notes.push(format!(
        "PID probes checked PID values from 1 to {}.",
        sweep_upper_bound
    ));

    for pid in 1..=sweep_upper_bound {
        if let Some(name) = process_name_from_proc(pid) {
            if target_name_matches(&name, target) {
                let visible = visible_pids.contains(&pid);
                push_finding(
                    &mut report,
                    &mut seen_findings,
                    "Direct /proc PID probe",
                    pid,
                    visible,
                    if visible {
                        format!(
                            "PID {} resolved to {} through direct /proc access and also appears in the normal process list.",
                            pid, name
                        )
                    } else {
                        format!(
                            "PID {} resolved to {} through direct /proc access even though it was absent from the normal process list.",
                            pid, name
                        )
                    },
                );
            }
        }
    }

    let mut hidden_unresolved_pid_count = 0usize;
    for pid in 1..=sweep_upper_bound {
        if process_exists_via_signal(pid) {
            let visible = visible_pids.contains(&pid);
            match process_name_from_proc(pid) {
                Some(name) if target_name_matches(&name, target) => {
                    push_finding(
                        &mut report,
                        &mut seen_findings,
                        "Signal(0) PID probe",
                        pid,
                        visible,
                        if visible {
                            format!(
                                "PID {} responded to signal(0) and resolved to {}.",
                                pid, name
                            )
                        } else {
                            format!(
                                "PID {} responded to signal(0) and resolved to {} even though it was missing from the normal process list.",
                                pid, name
                            )
                        },
                    );
                }
                None if !visible => {
                    hidden_unresolved_pid_count += 1;
                }
                _ => {}
            }
        }
    }

    if hidden_unresolved_pid_count > 0 {
        report.notes.push(format!(
            "Signal(0) probe found {} PID(s) that exist but could not be resolved through /proc paths.",
            hidden_unresolved_pid_count
        ));
    }

    for pid in collect_cgroup_pids() {
        if let Some(name) = process_name_from_proc(pid) {
            if target_name_matches(&name, target) {
                let visible = visible_pids.contains(&pid);
                push_finding(
                    &mut report,
                    &mut seen_findings,
                    "cgroup.procs scan",
                    pid,
                    visible,
                    if visible {
                        format!(
                            "PID {} was found in cgroup.procs and resolved to {}.",
                            pid, name
                        )
                    } else {
                        format!(
                            "PID {} was found in cgroup.procs and resolved to {} even though it was missing from the normal process list.",
                            pid, name
                        )
                    },
                );
            }
        }
    }

    report.detected = !report.findings.is_empty();

    let hidden_hits = report
        .findings
        .iter()
        .filter(|finding| !finding.visible_in_process_list)
        .count();

    if hidden_hits > 0 {
        report.notes.push(format!(
            "{} detection path(s) found apphost without a matching visible process entry.",
            hidden_hits
        ));
    }

    if !report.detected {
        report
            .notes
            .push("No apphost process was confirmed by any runtime method.".to_string());
    }

    report
}

#[cfg(target_os = "linux")]
fn process_name_from_proc(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{pid}/comm");
    if let Ok(comm) = std::fs::read_to_string(comm_path) {
        let name = comm.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    let exe_path = format!("/proc/{pid}/exe");
    if let Ok(link) = std::fs::read_link(exe_path) {
        if let Some(name) = link.file_name() {
            let value = name.to_string_lossy().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(raw) = std::fs::read(cmdline_path) {
        if let Some(first_token) = raw.split(|byte| *byte == 0).next() {
            if !first_token.is_empty() {
                let as_text = String::from_utf8_lossy(first_token);
                if let Some(name) = Path::new(&*as_text).file_name() {
                    let value = name.to_string_lossy().to_string();
                    if !value.is_empty() {
                        return Some(value);
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn read_kernel_pid_max() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
}

#[cfg(target_os = "linux")]
fn process_exists_via_signal(pid: u32) -> bool {
    let kill_result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if kill_result == 0 {
        return true;
    }

    if let Some(errno) = std::io::Error::last_os_error().raw_os_error() {
        errno == libc::EPERM
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn collect_cgroup_pids() -> Vec<u32> {
    use std::collections::BTreeSet;
    use walkdir::WalkDir;

    let mut pids = BTreeSet::new();
    let root = Path::new("/sys/fs/cgroup");
    if !root.exists() {
        return Vec::new();
    }

    for entry in WalkDir::new(root)
        .max_depth(16)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if entry.file_name() != "cgroup.procs" {
            continue;
        }

        if let Ok(contents) = std::fs::read_to_string(entry.path()) {
            for line in contents.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    if pid > 0 {
                        pids.insert(pid);
                    }
                }
            }
        }
    }

    pids.into_iter().collect()
}
