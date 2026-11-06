# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-06

### Added
- Multi-drive volume management engine (`VolumeManager`) querying fixed drives and tracking storage deltas.
- Per-volume fast quarantine architecture: targets on secondary drives (e.g. `D:`) are moved via instantaneous atomic intra-volume MFT rename into `<drive>\$obliterator_quarantine\<id>\`, avoiding slow cross-volume physical file copying and preventing system drive storage exhaustion.
- Custom quarantine destination option (`--quarantine-dir <path>`) with cross-volume discovery in session listings and restore commands.
- Multi-volume storage delta reporting: exact physical bytes freed per volume (`C:`, `D:`, etc.) tracked before and after execution via `GetDiskFreeSpaceExW` and reported in console output and `--json`.
- Multi-drive remnant scanner: searches secondary fixed disks for orphaned program folders in standard paths (`D:\Program Files`, `D:\Games`, `D:\Apps`, `D:\SteamLibrary`, `D:\Epic Games`, `D:\GOG Games`).
- Headless JSON-RPC / NDJSON streaming daemon (`--rpc`): provides a streaming control protocol over standard I/O for automation tools, PowerShell, Python, Ansible, and external GUIs with real-time progress events.
- Batch uninstallation pipeline (`--batch <file>`): non-interactive sequential removal supporting plaintext and JSON input lists with consolidated summary reporting for Golden Image preparation and Sysprep.

## [0.2.0] - 2026-11-04

### Added
- System diagnostics inspector (`--diagnose`) collecting OS build, token privileges, real-time protection state, and protected processes with automated personal data sanitization.
- Fullscreen Terminal User Interface (TUI) using pure Win32 Virtual Terminal processing and double-buffer rendering.
- Background preview plan calculation with real-time artifact counts and spinner indicator.
- Artifact plan details view with confidence score visualization and individual item exclusion.
- Exact program name typing requirement in deletion confirmation modal.
- Multi-architecture support for x64 and ARM64 Windows platforms.
- Embedded VERSIONINFO binary resource for antivirus transparency and identification.
- Statically linked C++ runtime (/MT) eliminating external Visual C++ redistributable dependencies.
- Machine-readable CycloneDX v1.5 Software Bill of Materials (SBOM) generator script.
- Package manager manifests for Windows Package Manager (WinGet) and Scoop with autoupdate.
- Documentation for code signing, package publishing, screencast demonstrations, architecture specification, and build reproducibility.
- Security policy, contributing guidelines, code of conduct, and issue/PR templates.

### Changed
- Enforced compiler and linker security hardening: Control Flow Guard (/guard:cf, /GUARD:CF), CET Shadow Stack compatibility (/CETCOMPAT), /GS, /DYNAMICBASE, /HIGHENTROPYVA, and /Qspectre.
- Unified the 9-phase obliteration execution pipeline across both CLI and TUI modes.
- Added deterministic build linker flag (/Brepro).

### Fixed
- Out-of-bounds front element access on empty normalized service image paths discovered during libFuzzer validation.

### Security
- Hardened PE binaries against ROP attacks and stack buffer overflows.
- Added CI step verifying deterministic build reproduction.

## [0.1.0] - 2026-11-03

### Added
- Core forced removal engine for files, directories, processes, services, scheduled tasks, and registry keys.
- Recovery defusing for service failure actions and watchdog restart configurations.
- Process tree freeze and termination via NtSuspendProcess.
- File lock inspection and handle closure via Restart Manager and DuplicateHandle.
- System Restore Point creation via dynamic srclient.dll invocation.
- File and registry quarantine engine with manifest, hash checks, and full rollback support.
- Multi-profile offline registry hive mounting and cleanup.
- Residual artifact discovery with weighted confidence scoring engine.
- Windows Explorer directory context menu integration.
