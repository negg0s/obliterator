# obliterator

Windows uninstallers frequently leave behind locked background services, auto-start registry run keys, scheduled watchdog tasks, and gigabytes of orphaned data in hidden profile directories. Most third-party uninstaller utilities hide behind bloated Electron or .NET interfaces that take seconds just to render a list, prompting for wizard confirmations while failing when a process refuses to terminate.

obliterator is a single native C++20 console binary designed to inspect, disarm, and remove stubborn Windows applications and their residual files in milliseconds.

[Download Latest Release (v0.2.0)](https://github.com/negg0s/obliterator/releases/latest)

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
| `--quarantine` | Move files to `%ProgramData%\obliterator\quarantine` instead of deleting |
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
6. **Filesystem Removal / Quarantine**: Strips read-only attributes and ACL restrictions using backup semantics (`SE_RESTORE_NAME`, `SE_BACKUP_NAME`). Deletes files across multi-threaded folder batches using POSIX unlink semantics (`FILE_DISPOSITION_FLAG_POSIX_SEMANTICS`), bypassing NTFS directory metadata serialization. If `--quarantine` is active, files are relocated to quarantine storage with an encrypted or SDDL-preserved manifest.
7. **Registry & Artifact Cleanup**: Removes associated keys across loaded user hives and offline profiles (`NTUSER.DAT` / `UsrClass.dat` via temporary `RegLoadKeyW` mounts), purges firewall rules, removes service registrations via Service Control Manager, and clears shell icon caches.

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
