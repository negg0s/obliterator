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
- Direct NTFS USN Journal rapid remnant discovery (`UsnJournalScanner`): queries Master File Table change journals directly via `FSCTL_ENUM_USN_DATA` on secondary volumes (`D:`, `E:`) to instantly discover residual directories matching targets without slow recursive directory traversal.
- COM Shell Extension & Explorer cleaner (`ShellCleaner`): discovers orphaned `InprocServer32` CLSIDs, `ContextMenuHandlers`, and `ShellIconOverlayIdentifiers` pointing to removed DLLs, purges registry hooks, and broadcasts `SHChangeNotify(SHCNE_ASSOCCHANGED, ...)` to prevent Windows Explorer lockups and stutter.
- Native PowerShell module (`scripts/Obliterator.psd1`, `scripts/Obliterator.psm1`): exposes `Get-ObliteratorApp`, `Invoke-Obliteration`, `Get-ObliteratorSession`, and `Restore-ObliteratorSession` with native pipeline support and tab-completion.
- Headless JSON-RPC / NDJSON streaming daemon (`--rpc`): provides a streaming control protocol over standard I/O for automation tools, PowerShell, Python, Ansible, and external GUIs with real-time progress events.
- Batch uninstallation pipeline (`--batch <file>`): non-interactive sequential removal supporting plaintext and JSON input lists with consolidated summary reporting for Golden Image preparation and Sysprep.
- Windows Installer package cache cleaner (`MsiCacheCleaner`): resolves product codes using packed GUID transposition algorithms, unlinks cached `.msi` installers from `%SystemRoot%\Installer`, and deregisters entries in `UserData\S-1-5-18\Products` and `HKCR\Installer`.
- OEM DriverStore package uninstaller (`DriverCleaner`): inspects `%SystemRoot%\INF\oem*.inf` metadata for matched service binaries, catalog hashes, and vendor names, triggering forced driver deregistration via `SetupUninstallOEMInfW` (`SUOI_FORCEDELETE`) with protected hardware vendor guards.
- NTFS Alternate Data Stream purger (`AdsHelper`): discovers and unlinks secondary data streams (`:Zone.Identifier`, `:favicon`, hidden metadata streams) via `FindFirstStreamW` during directory wipes.
- Windows Filtering Platform network cleaner (`WfpCleaner`): queries and removes orphaned WFP callout filters and providers registered by VPNs, ad-blockers, and firewalls via dynamic loading of `fwpuclnt.dll` (`FwpmEngineOpen0`, `FwpmFilterDeleteById0`, `FwpmProviderDeleteByKey0`) with protected system filter filtering.
- Windows Cryptographic Certificate & Root Store cleaner (`CertificateCleaner`): enumerates and removes custom Root CAs, intermediate authorities, and publisher certificates from LocalMachine and CurrentUser certificate stores (`ROOT`, `CA`, `TrustedPublisher`, `MY`) using `crypt32.dll`, protecting trusted public root certificates.
- URL protocol, App Paths, and FileExts association cleaner (`AssociationCleaner`): deregisters custom URL protocol schemes (`<scheme>://`), `App Paths` execution keys, and Explorer `FileExts\OpenWithList` entries pointing to obliterated binaries, broadcasting `SHChangeNotify(SHCNE_ASSOCCHANGED)` to prevent broken browser links and invalid shell associations.
- Windows Event Log and ETW publisher cleaner (`EventLogCleaner`): scans and unregisters orphaned classic Event Log sources (`SYSTEM\CurrentControlSet\Services\EventLog\Application` and `System`) with `EventMessageFile` / `CategoryMessageFile` pointers into uninstalled program folders, and deregisters orphaned ETW publishers (`WINEVT\Publishers`) to prevent Event Viewer Error 15016 and 1000 warnings.
- Windows Error Reporting (WER) and crash dump cleaner (`WerCleaner`): removes orphaned `LocalDumps` registry keys from `HKLM` and `HKCU`, purges lingering `.dmp` files from `%LOCALAPPDATA%\CrashDumps`, and wipes crash archives in `%ProgramData%\Microsoft\Windows\WER\ReportArchive` and `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive` left behind by unstable target applications.
- Application Compatibility layer cleaner (`AppCompatCleaner`): scans and removes orphaned compatibility mode layer flags (`AppCompatFlags\Layers` in `HKLM` and `HKCU`), Program Compatibility Assistant records (`AppCompatFlags\Compatibility Assistant\Store`), and custom SDB flags pointing to uninstalled applications.
- Windows Notification and Task Manager Startup cleaner (`NotificationCleaner`): purges phantom AppUserModelID notification configurations (`Notifications\Settings`) in Windows Settings and removes ghost startup entries in `StartupApproved\Run`, `Run32`, and `StartupFolder` across `HKLM` and `HKCU` to prevent blank entries in Task Manager's Startup apps tab.
- Background Intelligent Transfer Service cleaner (`BitsCleaner`): enumerates persistent background download jobs via BITS COM interfaces (`IBackgroundCopyManager`, `IBackgroundCopyJob`, `IBackgroundCopyFile`), cancelling orphaned download jobs targeting removed application trees and reclaiming network bandwidth and temp space.
- Image File Execution Options cleaner (`IfeoCleaner`): removes target executable keys in `Image File Execution Options` (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`) and scans all IFEO keys to remove lingering `Debugger` interception hooks pointing into uninstalled program directories.
- Windows Power Request Overrides cleaner (`PowerCleaner`): removes orphaned power execution overrides in `PowerRequestOverrides\PROCESS` (`HKLM\SYSTEM\CurrentControlSet\Control\Power`) to restore normal system sleep, display timeouts, and Modern Standby states.
- Windows Search RecentApps cleaner (`RecentAppsCleaner`): cleans orphaned `{GUID}` records in `HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` referencing uninstalled binaries, clearing phantom entries from the Start Menu and Search history.

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
