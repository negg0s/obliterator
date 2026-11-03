# obliterator Architecture Specification

This document details the pipeline design, module decomposition, Win32 API contracts, and guidelines for extending the obliterator codebase.

---

## 1. Pipeline Execution Sequence

The cleanup pipeline follows a strict dependency order to guarantee that running targets cannot revive themselves during deletion, lock handles are released cleanly, and destructive operations can be restored or dry-run inspected.

```
+-------------------------------------------------------------------------+
| Phase 0: CLI / TUI Argument Parsing & Target Resolution                |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 1: Safety Validation & Drive Protection Checks                   |
| - Verify target is not Windows, Program Files root, System32, or volume |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 2: Remnant Discovery & Confidence Scoring Engine                  |
| - Scan Registry, Services, Tasks, Firewall, Startup, and User Profiles  |
| - Score artifacts based on explicit paths, publisher, and CLSID rules  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 3: System Restore Point Creation                                  |
| - Call SRSetRestorePointW (APPLICATION_UNINSTALL)                       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 4: Native Vendor Uninstaller Execution (Optional)                |
| - If --native-first: Run silent vendor uninstaller inside Job Object    |
| - Enforce timeout; kill vendor process if hung                         |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 5: Neutralize Persistence Mechanisms                              |
| - Strip SCM failure recovery actions (SERVICE_CONFIG_FAILURE_ACTIONS)   |
| - Disable scheduled watchdog tasks in Task Scheduler                    |
| - Unregister autostart Registry Run / RunOnce keys                      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 6: Freeze & Terminate Running Processes                           |
| - Suspend all target threads via NtSuspendProcess                       |
| - Query and revoke file locks using Restart Manager & handle duplicate  |
| - Terminate frozen tree via TerminateProcess                            |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 7: Service and Task Removal                                       |
| - Stop active services via ControlService(SERVICE_CONTROL_STOP)         |
| - Delete service definitions via DeleteService                          |
| - Delete scheduled tasks via ITaskFolder::DeleteTask                    |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 8: Filesystem Removal or Quarantine                               |
| - Multi-threaded folder batching with POSIX unlink semantics           |
| - If --quarantine: Relocate files preserving SDDL security descriptors  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Phase 9: Registry & Multi-Profile Hive Purge                            |
| - Delete target keys in HKLM and HKCU                                   |
| - Mount offline user hives via RegLoadKeyW, clean, unmount via RAII     |
| - Remove Windows Firewall rules and clear shell icon caches             |
+-------------------------------------------------------------------------+
```

### Why This Order Is Required
1. **Safety First**: Validation occurs before any handle acquisition. Target directories located at critical system boundaries (such as `C:\`, `C:\Windows`, `C:\Users`) are rejected immediately.
2. **Restore Point Before Mutation**: Once state modification begins, changes cannot be rolled back without a restore snapshot or quarantine manifest.
3. **Neutralize Before Terminating**: If a service with `SERVICE_CONFIG_FAILURE_ACTIONS` or a scheduled task with an hourly trigger is active, terminating its process immediately triggers Windows to respawn the executable. Persistence mechanisms must be disabled before the processes are terminated.
4. **Freeze Before Unlinking**: Deleting an open binary on NTFS fails with sharing violations unless handles are revoked or the executable is unmapped. Freezing the threads first prevents the process from recreating child workers during handle revocation.
5. **Services Before Files**: A registered service points to a binary path on disk. Deleting the service definition first avoids orphan service entries pointing to deleted filesystem locations.
6. **Files Before Registry**: Registry cleanup cleans references and associations. Leaving file removal until after registry removal could leave files on disk if registry cleanup fails.

---

## 2. Module Dependency Graph

```
                               [ main.cpp ]
                                    |
                +-------------------+-------------------+
                |                                       |
          [ cli.hpp/cpp ]                         [ tui.hpp/cpp ]
                |                                       |
                +-------------------+-------------------+
                                    |
                             [ executor.hpp/cpp ]
                                    |
         +--------------------------+--------------------------+
         |                          |                          |
 [ scanner.hpp/cpp ]       [ remnants.hpp/cpp ]      [ safety.hpp/cpp ]
         |                          |                          |
         +-------------+------------+------------+-------------+
                       |                         |
          +------------+------------+            |
          |                         |            |
   [ process.hpp/cpp ]      [ service.hpp/cpp ]  |
   [ task.hpp/cpp ]         [ profile.hpp/cpp ]  |
   [ file.hpp/cpp ]         [ registry.hpp/cpp ] |
   [ quarantine.hpp/cpp ]   [ firewall.hpp/cpp ] |
          |                         |            |
          +------------+------------+            |
                       |                         |
                       +------------+------------+
                                    |
                       +------------+------------+
                       |                         |
              [ win32.hpp/cpp ]         [ thread_pool.hpp ]
              [ handle.hpp ]            [ logger.hpp ]
              [ result.hpp ]            [ app_type.hpp ]
```

---

## 3. Subsystem Descriptions and Win32 API Contracts

### Core Foundations
- `handle.hpp`: RAII wrappers (`UniqueHandle`, `UniqueHKey`, `UniqueScHandle`) enforcing deterministic handle release via `CloseHandle`, `RegCloseKey`, and `CloseServiceHandle`. Guarantees zero handle leaks during early returns or exception unwinding.
- `result.hpp`: `Result<T>` template representing either a successful value or a structured `Win32Error` containing Win32 error codes and descriptive message context.
- `win32.hpp`: Privilege escalation utilities (`EnablePrivilege` for `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, `SeBackupPrivilege`).
- `thread_pool.hpp`: Lightweight thread pool managing worker queues with condition variables for parallel directory dispatch.

### Target Analysis & Safety
- `safety.hpp`: Enforces path boundaries using normalized NT namespace comparisons. Rejects system root (`GetWindowsDirectoryW`), system drive roots (`GetSystemDirectoryW`), `ProgramData`, and top-level user directories.
- `scanner.hpp`: Fast multi-location application scanner. Queries 32-bit and 64-bit Registry hives (`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`), MSI installations via `MsiEnumProductsW`, and packaged apps. Completes warm scans in under 25 milliseconds.
- `remnants.hpp`: Confidence scoring engine. Discovers leftover artifacts (registry values, app paths, type libraries, temp directories, startup items, firewall rules). Computes confidence points (0-100) based on weighted heuristics defined in `include/obliterator/remnants.hpp`.

### Process & Handle Management
- `process.hpp`: Process inspection and termination.
  - Enumerates loaded modules using `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE)`.
  - Freezes process execution via `NtSuspendProcess` (loaded dynamically from `ntdll.dll`).
  - Identifies file locks using Restart Manager (`RmStartSession`, `RmRegisterResources`, `RmGetList`).
  - Terminates processes using `OpenProcess(PROCESS_TERMINATE)` and `TerminateProcess`.

### Service, Task, & Firewall Neutralization
- `service.hpp`: Interacts with the Service Control Manager (`OpenSCManagerW`, `OpenServiceW`).
  - Strips auto-restart failure actions using `ChangeServiceConfig2W` with `SERVICE_CONFIG_FAILURE_ACTIONS` set to empty actions.
  - Controls service execution state using `ControlService(SERVICE_CONTROL_STOP)`.
  - Deletes services using `DeleteService`.
- `task.hpp`: Connects to Windows Task Scheduler via COM interfaces (`ITaskService`, `ITaskFolder`, `IRegisteredTask`). Disables triggers and removes tasks associated with the target application path.
- `firewall.hpp`: Manages Windows Defender Firewall rules via COM `INetFwPolicy2` and `INetFwRules` interfaces to remove orphaned inbound and outbound firewall entries.

### Storage & Filesystem
- `file.hpp`: Fast filesystem enumeration and deletion.
  - Enumerates directories with 64 KB buffers using `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`.
  - Groups directory trees into per-directory batches for parallel thread pool consumption.
  - Unlinks files using `SetFileInformationByHandle(FileDispositionInfoEx)` with flags `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE`.
  - Resets file ownership and DACLs when access is denied using `SetNamedSecurityInfoW` under backup privileges.
- `quarantine.hpp`: Secure relocation. Moves target files into `%ProgramData%\obliterator\quarantine\<id>\` using `MoveFileExW` with `MOVEFILE_COPY_ALLOWED`. Preserves metadata and file security descriptors (SDDL) in a manifest file for auditing.

### Registry & Multi-Profile Support
- `registry.hpp`: Recursive registry key deletion using `RegDeleteTreeW` across 32-bit and 64-bit views (`KEY_WOW64_32KEY`, `KEY_WOW64_64KEY`).
- `profile.hpp`: Multi-profile inspection. Enumerates user profiles from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`. For unloaded profiles, mounts `NTUSER.DAT` and `UsrClass.dat` under temporary keys via `RegLoadKeyW`, performs targeted cleanup, and unmounts them deterministically via RAII guards calling `RegUnLoadKeyW`.

---

## 4. How to Add a New Pipeline Stage

Follow these steps to add a new stage (for example, clearing an application-specific cache or browser extension registration):

### Step 1: Implement the Subsystem Logic
Create the dedicated subsystem header and source file in `include/obliterator/<subsystem>.hpp` and `src/<subsystem>.cpp`.
Ensure that all Win32 handles are managed via RAII:

```cpp
#pragma once
#include <obliterator/result.hpp>
#include <string>

namespace obliterator {

class CustomStage {
public:
    static Result<void> Neutralize(const std::wstring& target_path, bool dry_run);
};

} // namespace obliterator
```

### Step 2: Integrate into the Remnant Scoring Engine (Optional)
If the stage discovers items that need confidence evaluation, add a new rule in `include/obliterator/remnants.hpp` and map the evidence in `src/remnants.cpp`:

```cpp
constexpr double WEIGHT_CUSTOM_ARTIFACT = 25.0;
```

### Step 3: Register in Execution Plan (`executor.hpp` / `executor.cpp`)
Add stage representation to `ExecutionPlan` and coordinate execution inside `Executor::Execute`:

```cpp
// In src/executor.cpp:
if (plan.custom_artifact_found) {
    if (plan.dry_run) {
        logger.Info(L"[DRY-RUN] Would neutralize custom artifact: " + target);
    } else {
        auto res = CustomStage::Neutralize(target, false);
        if (!res) {
            logger.Warn(L"Failed to neutralize custom artifact: " + res.error().message);
        }
    }
}
```

### Step 4: Add Unit and Integration Tests
Add test coverage in `tests/test_main.cpp` exercising standard operation, dry-run mode, and error recovery handling. Verify that no memory leaks or unreleased handles occur.
