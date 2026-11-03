# Community Launch Posts

---

## 1. Reddit (r/windows, r/software)

**Title:**
I wrote an uninstaller in C++ because existing tools took 10 seconds to scan and failed on locked services

**Post Body:**

Like many of you, I got tired of dealing with Windows software that leaves behind dozens of auto-start entries, background helper services, and gigabytes in AppData. The existing uninstaller utilities have their strengths, but most of them either run on heavy runtimes (.NET or Electron) that take 5 to 15 seconds just to load the list of installed software, or they lock up with "file is in use by another process" when an application has background watchdogs.

I decided to write `obliterator`. It is a single, static native C++20 executable with no external dependencies that runs from the command line or a VT-terminal interface.

A few things I learned the hard way while building it:

1. Killing processes sequentially is useless against watchdog pairs.
If an app has two processes monitoring each other, killing one causes the second to restart it before you can kill the second. The solution was using `NtSuspendProcess` to freeze all threads in every matching process across the target directory simultaneously before calling `TerminateProcess`.

2. Services that auto-restart must be disarmed first.
If a Windows service has failure recovery actions configured (`SERVICE_CONFIG_FAILURE_ACTIONS`), killing the process or stopping the service causes Windows Service Control Manager to revive it within a second. You have to strip the failure actions via `ChangeServiceConfig2W` before stopping or deleting the service.

3. Deleting files one-by-one is slow on NTFS due to directory metadata locks.
Deleting 5,000 files using standard `DeleteFileW` across multiple threads causes heavy lock contention on the NTFS directory index B-tree. Grouping files into per-folder batches and using `FileDispositionInfoEx` with `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` drops deletion time for 5,000 files to ~130 ms on an SSD.

4. Offline user hives will stay locked if you make a single error.
If you scan all profiles on a multi-user machine, you have to mount unloaded `NTUSER.DAT` and `UsrClass.dat` hives via `RegLoadKeyW`. If anything fails or throws before `RegUnLoadKeyW` is called, Windows keeps the hive locked and that user cannot log in. Wrapping hive mounting in strict RAII guards was mandatory.

Because deletion with POSIX semantics unlinks files directly without moving them to the Recycle Bin, I added a `--quarantine` flag that moves files into an isolated directory with an SDDL manifest instead of deleting them.

The binary and full source are on GitHub:
https://github.com/negg0s/obliterator

Happy to answer technical questions about how it works under the hood.

---

## 2. Hacker News (Show HN)

**Title:**
Show HN: Obliterator - Native C++20 Windows uninstaller using POSIX unlink and NT process suspension

**Post Body:**

Link: https://github.com/negg0s/obliterator

Obliterator is an open-source command-line and terminal-based uninstaller for Windows written in native C++20 with zero external library dependencies.

The tool addresses several limitations in how Windows uninstallation and leftover cleanup are typically handled:

1. Deletion Throughput and POSIX Semantics
Standard Win32 file deletion (`DeleteFileW`) incurs multiple round-trips: querying attributes, clearing read-only flags, and unlinking. In multithreaded workloads, parallel deletions inside the same folder cause thread contention on NTFS directory index B-trees.
Obliterator structures work into per-directory batches distributed across a lightweight thread pool, calling `SetFileInformationByHandle` with `FileDispositionInfoEx` and `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE`. This unlinks files immediately upon closing the handle, removing a 5,000-file (600 MB) tree in 132 ms on NVMe storage.

2. Process Tree Suspension Before Handle Revocation
Programs with watchdog processes or child monitor routines detect process termination and immediately spawn replacement workers. Rather than issuing sequential `TerminateProcess` calls, obliterator discovers all processes holding open handles in the target directory (via Restart Manager and `NtQuerySystemInformation`), calls `NtSuspendProcess` to halt execution across all threads at the NT kernel boundary, revokes file locks via handle duplication, and then terminates the tree.

3. Disarming Service Control Manager Recovery Actions
Stopping a service whose configuration specifies recovery actions (`SERVICE_CONFIG_FAILURE_ACTIONS`) triggers automatic restart by `services.exe`. The pipeline resets these failure actions to empty via `ChangeServiceConfig2W` prior to issuing `SERVICE_CONTROL_STOP` and `DeleteService`.

4. Cross-Profile Registry Hive Mounts
Uninstallers usually clean only the current user's `HKEY_CURRENT_USER`. Residual keys left in other user profiles remain indefinitely. Obliterator queries `ProfileList` in HKLM, mounts unloaded user profile hives (`NTUSER.DAT` and `UsrClass.dat`) under temporary registry keys via `RegLoadKeyW`, applies remnant cleaning rules, and deterministically unmounts them via RAII wrappers (`RegUnLoadKeyW`).

5. Remnant Scoring Engine
Leftover artifacts (files, keys, CLSIDs, type libraries, firewall rules, scheduled tasks) are scored using weighted heuristics (direct path match, publisher string identity, shell associations). A configurable confidence threshold (default 50/100) prevents aggressive false positives on shared paths.

The binary compiles with MSVC using static CRT (`/MT`), Control Flow Guard (`/guard:cf`), `/GS`, `/DYNAMICBASE`, `/HIGHENTROPYVA`, `/CETCOMPAT`, and `/Brepro` for bit-for-bit reproducible builds. A full test suite and libFuzzer targets are included in the repository.

Performance benchmarks and architecture documentation:
https://github.com/negg0s/obliterator/blob/main/docs/perf.md
https://github.com/negg0s/obliterator/blob/main/docs/architecture.md

Feedback and code reviews welcome.
