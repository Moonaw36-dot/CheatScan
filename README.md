# CheatScan

CheatScan is a security-focused utility designed to scan your system for suspicious DLLs and executables. Originally developed with a focus on modding frameworks like BepInEx, it helps identify potentially malicious files while reducing false positives through known safe-hash verification.

## Features

- **Automated Scanning:** Scans selected directories or your entire disk for suspicious DLL/EXE files.
- **Safe-Hash Verification:** Automatically ignores files with known, verified safe hashes, reducing false positives.
- **Configurable Paths:** Easily set your BepInEx or modding framework paths for targeted scanning.
- **Cross-Platform:** Built with Rust, providing high performance and cross-platform compatibility.

## How it Works

CheatScan performs several checks on detected executables:
1. **Hash Verification:** Checks against a built-in list of known safe file hashes.
2. **Malicious Detection:** Flags files matching known malicious file hashes.
3. **Keyword Matching:** Analyzes filenames and metadata (OriginalFilename) for suspicious keywords associated with common cheats or injectors.

## Usage

1. Configure your BepInEx or Gorilla Tag installation path in the **Settings** tab.
2. Enable "Full Disk Scan" if you wish to scan beyond your specified directory.
3. Click "Begin scanning" to start the analysis.
4. If the scanner detects a suspicious file, it will be listed in the interface.

## Contributing

Contributions are welcome! If you have found a false positive or want to improve the scanner's efficiency, feel free to open a pull request.

---

*This project is built using Rust and imgui-rs.*
