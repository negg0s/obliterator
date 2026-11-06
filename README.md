# obliterator

Windows uninstallers frequently leave behind locked background services, auto-start registry run keys, scheduled watchdog tasks, and gigabytes of orphaned data in hidden profile directories. Most third-party uninstaller utilities hide behind bloated Electron or .NET interfaces that take seconds just to render a list, prompting for wizard confirmations while failing when a process refuses to terminate.

obliterator is a single native C++20 console binary designed to inspect, disarm, and remove stubborn Windows applications and their residual files in milliseconds.

[Download Latest Release (v0.3.0)](https://github.com/negg0s/obliterator/releases/latest)

## Quick Start

```cmd
:: 1. Interactive terminal UI (browse, sort, filter, and preview targets)
obliterator

:: 2. Remove by registered application name (non-interactive, automated confirmation)
obliterator "Discord" -y

:: 3. Clean an unregistered directory tree with full remnant discovery
obliterator "C:\Program Files\StubbornApp" --force
```

## Command-Line Options

| Flag | Description |
| :--- | :--- |
| `[target]` | Application display name, bundle ID, or filesystem path |
| `-y, --yes` | Skip manual confirmation prompts and proceed automatically |
| `-f, --force` | Kill blocking processes immediately without graceful shutdown signals |
| `-n, --dry-run` | Build and display the execution plan without writing changes |
| `-s, --silent` | Suppress non-error console output |
| `--json` | Output structured JSON plan and execution logs to standard output |
| `--tui` | Launch the full-screen terminal interface |
| `--native-first` | Attempt silent native vendor uninstaller before remnant cleanup |
| `--native-timeout <sec>` | Timeout for vendor uninstaller before terminating it (default: 120s) |
| `--all-profiles` | Scan and clean remnants across all user profiles on the host |
| `--quarantine` | Move files to quarantine instead of deleting |
| `--quarantine-dir <dir>` | Custom base directory for quarantine storage |
| `--rpc` | Start headless JSON-RPC automation server on stdin/stdout |
| `--batch <file>` | Obliterate targets listed sequentially in a batch file |
| `--no-restore-point` | Skip System Restore point generation |
| `--require-restore-point` | Abort execution if System Restore point generation fails |
| `--confidence <score>` | Minimum confidence threshold (0-100) for deleting remnants (default: 50) |
| `--diagnose [file]` | Dump sanitized system and security diagnostics for troubleshooting |
| `--version` | Display program version and build details |
| `--help` | Display help and usage summary |

## Execution Pipeline

When obliterator targets an application, it executes sequentially through seven distinct phases:

1. **Target Identification & Discovery**: Locates installed entries across 32-bit and 64-bit Registry hives (`Uninstall`, `App Paths`, `Run`, `RunOnce`), MSI databases, Shell Folders, and running processes. Remnants are assigned a confidence score based on explicit path matches, digital signature publishers, CLSIDs, and service binaries.
2. **System Restore Point**: Calls `SRSetRestorePointW` via dynamic linking to create an `APPLICATION_UNINSTALL` restore checkpoint unless explicitly disabled with `--no-restore-point`.
3. **Vendor Uninstaller Handling (Optional)**: If `--native-first` is specified, identifies the uninstaller type (MSI, Inno Setup, NSIS, Wise, InstallShield) and launches it with vendor-specific quiet arguments under a job object. If the process hangs past the timeout, obliterator kills the tree and continues.
4. **Disarm Persistence**: Disables auto-recovery mechanisms before touching active processes. It strips service failure recovery actions via `ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)`, suspends scheduled watchdog tasks, unhooks WMI event consumers, and removes startup registry triggers.
5. **Freeze & Terminate**: Freezes process threads using `NtSuspendProcess`, revokes file lock handles via Restart Manager and NT handle enumeration, and terminates the tree using `TerminateProcess`.
6. **Filesystem Removal / Quarantine**: Strips read-only attributes and ACL restrictions using backup semantics (`SE_RESTORE_NAME`, `SE_BACKUP_NAME`). Discovers and unlinks NTFS Alternate Data Streams (`:Zone.Identifier`, hidden streams) via `FindFirstStreamW`. Deletes files across multi-threaded folder batches using POSIX unlink semantics (`FILE_DISPOSITION_FLAG_POSIX_SEMANTICS`), bypassing NTFS directory metadata serialization. If `--quarantine` is active, files are relocated to quarantine storage with an encrypted or SDDL-preserved manifest.
7. **Registry, Drivers & Artifact Cleanup**: Removes associated keys across loaded user hives and offline profiles (`NTUSER.DAT` / `UsrClass.dat` via temporary `RegLoadKeyW` mounts), unlinks cached `.msi` installers from `C:\Windows\Installer` via packed GUID resolution, uninstalls OEM driver packages from DriverStore via `SetupUninstallOEMInfW`, purges Windows Filtering Platform (WFP) network filters/providers to prevent broken internet routing, cleans custom Root and Intermediate CA certificates from Windows Certificate Stores, removes orphaned URL protocol handlers (`<scheme>://`), stale `App Paths` execution registrations, and Explorer `FileExts` open-with associations, purges classic Event Log sources and ETW publishers to eliminate Event ID 15016 errors, cleans Windows Error Reporting (WER) `LocalDumps` keys and lingering crash dumps, purges Application Compatibility (AppCompat) Layers and PCA store records, removes phantom Action Center notification settings and ghost Task Manager StartupApproved entries, cancels orphaned BITS background download jobs, purges Image File Execution Options (IFEO) target keys and debugger hooks, removes PowerRequestOverrides preventing system sleep, cleans Windows Search RecentApps entries, purges DirectX/Direct3D per-app GPU preferences, clears Explorer UserAssist ROT-13 execution history, cleans orphaned Volume Mixer audio sessions, purges firewall rules, removes service registrations via Service Control Manager, and clears shell icon caches via `SHChangeNotify`.

## Multi-Drive & Per-Volume Fast Quarantine

Windows installations often place large applications, games, and runtime stores on secondary fixed drives (e.g. `D:\Games`, `D:\Program Files`, `D:\Software`).

- **Atomic Intra-Volume Move**: When `--quarantine` is enabled for an application residing on a secondary disk like `D:`, obliterator stores quarantine sessions directly on the target volume under `D:\$obliterator_quarantine\<id>\`. Files are relocated using intra-volume NTFS index renames without cross-volume data copying. This completes in milliseconds and prevents filling system drive `C:`.
- **Custom Quarantine Path**: Pass `--quarantine-dir <path>` to store all quarantine archives on a dedicated volume or backup drive.
- **Cross-Volume Session Discovery**: Commands such as `--list-sessions`, `--restore <id>`, and `--purge-quarantine <id>` automatically detect sessions across all fixed disk volumes and custom paths.
- **Volume Freed Delta Tracking**: Queries physical volume clusters via `GetDiskFreeSpaceExW` before and after execution, displaying exact storage freed per volume (`C:`, `D:`) in text summaries and JSON reports.
- **Multi-Drive Remnant Scan**: Scans standard directories across all attached fixed drives (`D:\Program Files`, `D:\Games`, `D:\Apps`, `D:\SteamLibrary`, `D:\Epic Games`, `D:\GOG Games`) for orphaned application trees.

## Automation & DevOps Administration

obliterator includes first-class headless protocols and tooling for orchestration via PowerShell, Python, Ansible, and Golden Image pipelines:

- **PowerShell Automation Module (`scripts/Obliterator.psd1`)**: Pure PowerShell module integrating obliterator into automated management workflows.
  ```powershell
  Import-Module .\scripts\Obliterator.psd1
  
  # Search installed apps and inspect metadata
  Get-ObliteratorApp -Filter "Node.js"
  
  # Execute silent obliteration with pipeline support and WhatIf safety checks
  Get-ObliteratorApp -Filter "Zoom" | Invoke-Obliteration -Quarantine -Force
  
  # Inspect quarantine sessions across all volumes and restore
  Get-ObliteratorSession
  Restore-ObliteratorSession -SessionId "20261106_Zoom"
  ```
  Includes native dynamic tab-completion for installed applications and session identifiers.

- **Headless JSON-RPC / NDJSON Daemon (`--rpc`)**: Runs obliterator as a persistent child process communicating via single-line JSON requests and responses over standard I/O. Supports `ping`, `list_installed`, `scan`, `execute`, `restore`, `list_sessions`, and `diagnose`, streaming real-time event updates (`phase`, `log`) as operations proceed.
- **Batch Processing (`--batch <file>`)**: Sequentially obliterates a list of applications specified in a plaintext or JSON array file with zero interactive prompts, emitting consolidated batch reports for Sysprep and desktop provisioning.
- **Direct NTFS USN Journal Scanner**: Rapidly discovers leftover program folders on secondary fixed drives (`D:`, `E:`) by querying the volume Master File Table change journal directly (`FSCTL_ENUM_USN_DATA`), eliminating slow recursive folder tree walks.
- **COM Shell Extension & Explorer Cleaner**: Discovers and deregisters orphaned inproc COM servers (`InprocServer32`), Shell Context Menu Handlers, and Shell Icon Overlay Identifiers pointing into uninstalled target directories, broadcasting `SHChangeNotify(SHCNE_ASSOCCHANGED, ...)` to prevent Windows Explorer hangs and context menu stutter.
- **Windows Filtering Platform (WFP) Cleaner**: Queries and removes orphaned WFP callout filters and providers registered by uninstalled VPNs, firewalls, and proxies via dynamic loading of `fwpuclnt.dll` (`FwpmFilterDeleteById0`, `FwpmProviderDeleteByKey0`), preventing broken TCP/IP networking, dropped packets, and DNS lookup failures while protecting core Windows filtering providers.
- **Windows Cryptographic Certificate & Root Store Cleaner**: Discovers and removes self-signed Root CAs, intermediate authorities, and publisher certificates associated with uninstalled applications from `CERT_SYSTEM_STORE_LOCAL_MACHINE` and `CERT_SYSTEM_STORE_CURRENT_USER` (`ROOT`, `CA`, `TrustedPublisher`, `MY`) via `crypt32.dll`, protecting trusted public root certificates.
- **URL Protocol, App Paths & File Association Cleaner**: Discovers and deregisters orphaned custom URL protocol handlers (`HKCR\<protocol>`, `HKCU\Software\Classes\<protocol>`), stale `App Paths` execution keys, and Explorer `FileExts\OpenWithList` entries, broadcasting `SHChangeNotify(SHCNE_ASSOCCHANGED, ...)` so browsers and File Explorer release uninstalled application associations.
- **Windows Event Log & ETW Publisher Cleaner**: Purges orphaned classic Event Log sources (`SYSTEM\CurrentControlSet\Services\EventLog`) whose `EventMessageFile` or `CategoryMessageFile` point to uninstalled software, and deregisters lingering ETW publishers under `WINEVT\Publishers`, preventing Event Viewer from logging Event ID 15016 and 1000 errors.
- **Windows Error Reporting (WER) & Crash Dump Cleaner**: Purges orphaned `LocalDumps` registry keys, unlinks lingering crash dump files (`.dmp`) from `%LOCALAPPDATA%\CrashDumps`, and wipes crash report packages in `ReportArchive` left behind by crashed target applications, reclaiming disk space.
- **Application Compatibility (AppCompat) Cleaner**: Scans and removes orphaned compatibility mode layer flags (`HKLM` and `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`) and Program Compatibility Assistant records (`Compatibility Assistant\Store`) pointing to uninstalled executables.
- **Windows Notification & Task Manager Startup Cleaner**: Purges phantom AppUserModelID notification settings (`Notifications\Settings`) from Windows Settings and cleans ghost `StartupApproved` records (`Run`, `Run32`, `StartupFolder`) across `HKLM` and `HKCU`, eliminating blank ghost rows in Task Manager's Startup apps tab.
- **Background Intelligent Transfer Service (BITS) Cleaner**: Inspects queued and active background download tasks via BITS COM interfaces (`IBackgroundCopyManager`), cancelling orphaned background downloads targeting removed application folders to prevent recurring network and disk thrashing.
- **Image File Execution Options (IFEO) Cleaner**: Removes per-app IFEO keys (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`) and unhooks lingering `Debugger` interception values pointing into uninstalled directories to prevent broken application launching.
- **Windows Power Request Overrides Cleaner**: Purges orphaned power execution overrides (`PowerRequestOverrides\PROCESS`) to restore normal system sleep, display timeouts, and Modern Standby states.
- **Windows Search RecentApps Cleaner**: Cleans orphaned `{GUID}` records in `HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`, removing ghost items from the Start Menu and Search history.
- **DirectX & Direct3D GPU Preference Cleaner**: Purges orphaned per-application GPU preference entries in `DirectX\UserGpuPreferences` (`HKCU` and `HKLM`), clearing uninstalled apps and games from Windows Graphics Settings.
- **Windows Explorer UserAssist History Cleaner**: Decodes ROT-13 values in `Explorer\UserAssist\{GUID}\Count` to remove lingering execution telemetry, run counts, and launch records for obliterated binaries.
- **Windows Volume Mixer Audio Session Cleaner**: Cleans orphaned per-app audio session records in `LowRegistry\Audio\PolicyConfig\PropertyStore` and `AppVolume`, removing phantom volume sliders from Windows Volume Mixer.
- **Windows Defender & Exploit Guard Exclusion Cleaner**: Scans and removes orphaned path exclusions, process exclusions, and Controlled Folder Access allowed application entries in `HKLM` and `HKCU` pointing to uninstalled programs, preventing security holes from lingering exclusions.
- **Windows Common Dialog (ComDlg32) MRU Cleaner**: Inspects binary records in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` by extracting wide null-terminated executable names, and purges dialog window geometry cache in `CIDSizeMRU` for uninstalled binaries.
- **Windows Console Host Settings Cleaner**: Scans per-application console host configurations in `HKCU\Console` using normalized path and executable name matching, purging lingering terminal settings and font customizations for removed binaries.
- **WinINet Proxy & PAC Cleaner**: Scans and resets orphaned proxy configurations, `ProxyEnable` flags, `ProxyServer` pointers, and `AutoConfigURL` PAC files left behind by uninstalled VPNs, debugging proxies, and network tools, broadcasting `INTERNET_OPTION_SETTINGS_CHANGED` and `INTERNET_OPTION_REFRESH` via `wininet.dll` so web browsers immediately retain direct internet access.
- **Print Spooler Monitor & Virtual Printer Cleaner**: Scans and cleans orphaned Print Monitors (`Control\Print\Monitors`), Print Processors, and virtual printer registrations (`Control\Print\Printers`) left behind by PDF creators and virtual printer drivers, preventing `spoolsv.exe` spooler startup crashes.
- **Cryptographic Service Provider (CSP) Cleaner**: Scans and removes orphaned custom Cryptographic Service Providers (CSPs) in `SOFTWARE\Microsoft\Cryptography\Defaults\Provider` and `WOW6432Node` and cleans references in `Provider Types` pointing to uninstalled security suites and smart card token software, preventing CryptoAPI and Schannel TLS authentication failures.

## What obliterator Does NOT Do

- **Kernel Driver / EDR Bypass**: obliterator operates in Win32 user mode with administrative privileges (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`). It does not install kernel rootkits or bypass kernel-level Endpoint Detection and Response (EDR) agents or Windows Defender Tamper Protection.
- **Shared Library Guessing**: obliterator does not delete shared dynamic-link libraries located in `%SystemRoot%\System32` or Windows Side-by-Side (`WinSxS`) caches, even if a target program installer dropped them there.
- **Data Recovery Without Quarantine**: By default, file deletion uses POSIX unlink semantics for maximum throughput. Unless `--quarantine` is specified, deleted files are unlinked from the volume and cannot be recovered from the Recycle Bin.

## Performance Benchmarks

Measured on an Intel Core i5-10400F (6 cores, 12 threads), 16 GB DDR4, NVMe SSD, Windows 11 x64.
Dataset: 5,000 files across 200 directories (depth 8), 600 MB total (4,994 small files, 6 large files). Timer: `QueryPerformanceCounter`, median of 10 runs.

| Step | obliterator | Bulk Crap Uninstaller | Revo Uninstaller | Geek Uninstaller |
| :--- | :--- | :--- | :--- | :--- |
| **Installed Apps Scan (Warm)** | **23.1 ms** | ~5-15 s (GUI startup + .NET) | ~3-8 s (GUI + registry load) | ~1-2 s (Win32 native) |
| **Process Discovery** | 42.3 ms | Included in total run | Included in total run | Included in total run |
| **Directory Enumeration** | 16.9 ms | Not measured separately | Not measured separately | Not measured separately |
| **File Deletion** | 132.6 ms | Not measured separately | Not measured separately | Not measured separately |
| **Registry Cleanup** | 16.9 ms | Not measured separately | Not measured separately | Not measured separately |
| **Total Deletion Time** | **213.1 ms** | ~10-60 s (interactive wizard) | ~5-30 s (interactive wizard) | ~2-5 s (sequential Win32) |

*(Note: Third-party tool numbers reflect typical user-observed UI and scanning cycles under comparable workloads; they do not provide automated headless benchmark interfaces).*

## Safety Warning

Obliteration is permanent. When executed with `-y` or `-f`, target files and associated configuration keys are immediately unlinked from disk and registry without prompting.

For safety on untested applications:
1. Always run with `-n` (`--dry-run`) first to verify the generated deletion plan.
2. Use `--quarantine` if you might need to inspect or restore files later.
3. Keep Windows System Restore enabled.
