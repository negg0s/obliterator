# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-04

### Added
- Fullscreen Terminal User Interface (TUI) using pure Win32 Virtual Terminal processing and double-buffer rendering.
- Background preview plan calculation with real-time artifact counts and spinner indicator.
- Artifact plan details view with confidence score visualization and individual item exclusion.
- Exact program name typing requirement in deletion confirmation modal.
- Multi-architecture support for x64 and ARM64 Windows platforms.
- Embedded VERSIONINFO binary resource for antivirus transparency and identification.
- Statically linked C++ runtime (/MT) eliminating external Visual C++ redistributable dependencies.
- Machine-readable CycloneDX v1.5 Software Bill of Materials (SBOM) generator script.
- Package manager manifests for Windows Package Manager (WinGet) and Scoop with autoupdate.
- Documentation for code signing, package publishing, and build reproducibility.

### Changed
- Enforced compiler and linker security hardening: Control Flow Guard (/guard:cf, /GUARD:CF), CET Shadow Stack compatibility (/CETCOMPAT), /GS, /DYNAMICBASE, /HIGHENTROPYVA, and /Qspectre.
- Unified the 9-phase obliteration execution pipeline across both CLI and TUI modes.
- Added deterministic build linker flag (/Brepro).

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
