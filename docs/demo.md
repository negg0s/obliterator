# Screencast Demonstration Scenarios

This document contains reproducible test benches and terminal interaction scripts for recording video demonstrations of obliterator.

All commands run in an elevated Administrator command prompt or PowerShell session.

---

## Scenario 1: Watchdog Process Pair (Self-Healing Loop)

### Problem
A target software consists of two mutual watchdogs (`watchdog_a.exe` and `watchdog_b.exe`). If one is terminated, the other immediately spawns a replacement instance. Normal `taskkill` fails because one process always survives and respawns the other.

### Step 1: Prepare the Test Environment
Run the following PowerShell command to create a mutual watchdog loop in `C:\DemoApp`:

```powershell
New-Item -ItemType Directory -Path "C:\DemoApp" -Force | Out-Null
Set-Content -Path "C:\DemoApp\watchdog.ps1" -Value @'
param([string]$peer)
$parentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($true) {
    Start-Sleep -Milliseconds 500
    $procs = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match $peer
    }
    if (-not $procs) {
        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File `"$parentDir\watchdog.ps1`" -peer $($MyInvocation.BoundParameters['peer'])"
    }
}
'@

# Launch mutual watchdogs
$p1 = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File C:\DemoApp\watchdog.ps1 -peer watchdog_b" -PassThru
$p2 = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File C:\DemoApp\watchdog.ps1 -peer watchdog_a" -PassThru
Write-Host "Watchdog processes running. PIDs: $($p1.Id), $($p2.Id)"
```

### Step 2: Execute obliterator
Run obliterator with process freezing enabled:

```cmd
obliterator "C:\DemoApp" --force
```

### Expected Terminal Output
```
[INFO] obliterator v0.2.0 (x64-windows)
[INFO] Resolving target: C:\DemoApp
[INFO] Target identified as Directory (Unregistered)
[PLAN] Phase 1: Disarm Persistence Mechanisms
[PLAN]   Found 0 registered services
[PLAN]   Found 0 scheduled tasks
[PLAN] Phase 2: Freeze and Terminate Active Processes
[PLAN]   Detected 2 locking processes holding handles to C:\DemoApp:
[PLAN]     PID 14820: powershell.exe (C:\DemoApp\watchdog.ps1)
[PLAN]     PID 17292: powershell.exe (C:\DemoApp\watchdog.ps1)
[PLAN] Phase 3: Filesystem Removal
[PLAN]   Target directory: C:\DemoApp (2 files, 4.12 KB)
[EXEC] Freezing process tree with NtSuspendProcess...
[EXEC]   Frozen PID 14820
[EXEC]   Frozen PID 17292
[EXEC] Revoking file locks via Restart Manager... OK
[EXEC] Terminating frozen processes...
[EXEC]   Terminated PID 14820 [ExitCode: 1]
[EXEC]   Terminated PID 17292 [ExitCode: 1]
[EXEC] Removing filesystem artifacts (1 directory, 2 files)...
[EXEC]   Batch unlinking using FILE_DISPOSITION_FLAG_POSIX_SEMANTICS... OK
[DONE] Successfully removed 2 processes and 2 files in 48.2 ms.
```

### Step 3: Verification
```powershell
Get-Process -Id 14820, 17292 -ErrorAction SilentlyContinue
Test-Path "C:\DemoApp"
```
Both return empty and `False`.

---

## Scenario 2: Active Windows Service with Auto-Recovery

### Problem
A service is running in `Automatic` mode. When stopped via `net stop` or killed, Windows Service Control Manager triggers configured failure actions (`SERVICE_CONFIG_FAILURE_ACTIONS`) to restart the service binary immediately.

### Step 1: Prepare the Test Environment
Register a dummy service with aggressive restart actions:

```cmd
mkdir C:\ServiceDemo
copy %SystemRoot%\System32\ping.exe C:\ServiceDemo\service_worker.exe

sc.exe create DemoWorker binPath= "C:\ServiceDemo\service_worker.exe 127.0.0.1 -t" start= auto DisplayName= "Demo Worker Service"
sc.exe failure DemoWorker reset= 0 actions= restart/1000/restart/1000/restart/1000
sc.exe start DemoWorker
```

Verify the service is running:
```cmd
sc.exe query DemoWorker
```

### Step 2: Execute obliterator
Run obliterator targeting the service directory:

```cmd
obliterator "C:\ServiceDemo" --yes
```

### Expected Terminal Output
```
[INFO] obliterator v0.2.0 (x64-windows)
[INFO] Target: C:\ServiceDemo
[PLAN] Remnant Analysis:
[PLAN]   Associated Service: DemoWorker [Display: Demo Worker Service]
[PLAN]   Service Binary: C:\ServiceDemo\service_worker.exe
[PLAN]   Service Status: RUNNING (PID: 8840)
[PLAN]   Failure Actions: Auto-Restart enabled (Delay: 1000 ms)
[EXEC] Step 1: Neutralizing service failure restart actions...
[EXEC]   ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS): Reset to None [OK]
[EXEC] Step 2: Stopping service DemoWorker...
[EXEC]   ControlService(SERVICE_CONTROL_STOP): STOP_PENDING -> STOPPED [OK]
[EXEC] Step 3: Deleting service registration from Service Control Manager...
[EXEC]   DeleteService(DemoWorker): SCM registration marked for deletion [OK]
[EXEC] Step 4: Checking for remaining process instances...
[EXEC]   Terminated PID 8840 [OK]
[EXEC] Step 5: Removing files in C:\ServiceDemo...
[EXEC]   Unlinked: C:\ServiceDemo\service_worker.exe
[EXEC]   Removed directory: C:\ServiceDemo
[DONE] Service unregistered and files purged in 86.4 ms.
```

### Step 3: Verification
```cmd
sc.exe query DemoWorker
dir C:\ServiceDemo
```
`sc query` returns `The specified service does not exist as an installed service.` and the directory is gone.

---

## Scenario 3: Exclusively Locked File (Handle Revocation)

### Problem
A running helper process holds an exclusive read/write lock (`dwShareMode = 0`) on an application database file (`data.db`). A standard `del` or GUI deletion fails with `The process cannot access the file because it is being used by another process`.

### Step 1: Prepare the Test Environment
Run the following PowerShell script to lock a file exclusively in background:

```powershell
New-Item -ItemType Directory -Path "C:\LockDemo" -Force | Out-Null
Set-Content -Path "C:\LockDemo\data.db" -Value "DEMO_DATABASE_PAYLOAD_TEST"

$code = @'
using System;
using System.IO;
using System.Threading;

public class Locker {
    public static void Main(string[] args) {
        using (FileStream fs = new FileStream(@"C:\LockDemo\data.db", FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
            Console.WriteLine("LOCKED");
            Thread.Sleep(300000);
        }
    }
}
'@

Add-Type -TypeDefinition $code -OutputAssembly "C:\LockDemo\Locker.exe"
$lockerProc = Start-Process "C:\LockDemo\Locker.exe" -PassThru
Start-Sleep -Seconds 1
Write-Host "File locked exclusively by PID $($lockerProc.Id)"
```

Confirm that standard deletion fails:
```cmd
del C:\LockDemo\data.db
```
*(Fails with "The process cannot access the file because it is being used by another process.")*

### Step 2: Execute obliterator
Run obliterator with `--force`:

```cmd
obliterator "C:\LockDemo" --force -y
```

### Expected Terminal Output
```
[INFO] obliterator v0.2.0 (x64-windows)
[INFO] Target: C:\LockDemo
[SCAN] Enumerating files and directory handles...
[SCAN] C:\LockDemo\data.db is locked with exclusive sharing flags.
[EXEC] Querying Restart Manager session for file: C:\LockDemo\data.db
[EXEC]   Identified locking process: Locker.exe (PID: 11048)
[EXEC] Freezing PID 11048 via NtSuspendProcess...
[EXEC] Revoking file handles for PID 11048 via DuplicateHandle/CLOSE...
[EXEC] Terminating locking process 11048... OK
[EXEC] Deleting filesystem entries...
[EXEC]   POSIX unlink: C:\LockDemo\data.db [OK]
[EXEC]   Remove directory: C:\LockDemo [OK]
[DONE] Successfully unlocked and removed target in 31.7 ms.
```

### Step 3: Verification
```cmd
Test-Path "C:\LockDemo"
```
Returns `False`.
