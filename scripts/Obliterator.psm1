# Obliterator PowerShell Automation Module
# Provides native cmdlets and dynamic argument auto-completion for obliterator.exe

function Get-ObliteratorBinary {
    [CmdletBinding()]
    param()

    # 1. Check path relative to module script
    $localBin = Join-Path $PSScriptRoot "..\build_rel\obliterator.exe"
    if (Test-Path $localBin) {
        return (Resolve-Path $localBin).Path
    }

    # 2. Check current working directory build outputs
    $candidates = @(
        ".\build_rel\obliterator.exe",
        ".\build\Release\obliterator.exe",
        ".\build\obliterator.exe",
        ".\obliterator.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            return (Resolve-Path $cand).Path
        }
    }

    # 3. Check system PATH
    $cmd = Get-Command "obliterator.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    throw "obliterator.exe binary not found. Build the project or add obliterator.exe to your PATH."
}

function Get-ObliteratorApp {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Filter
    )

    $bin = Get-ObliteratorBinary
    $req = '{"id":1,"method":"list_installed"}'
    $exitReq = '{"id":2,"method":"exit"}'

    $raw = & cmd.exe /c "(echo $req & echo $exitReq) | `"$bin`" --rpc"
    foreach ($line in $raw) {
        if ($line -match '^\{"id":1,"result":(\[.*\])\}') {
            $json = $matches[1] | ConvertFrom-Json
            if ($Filter) {
                return $json | Where-Object { $_.name -like "*$Filter*" -or $_.publisher -like "*$Filter*" }
            }
            return $json
        }
    }
}

function Get-ObliteratorSession {
    [CmdletBinding()]
    param()

    $bin = Get-ObliteratorBinary
    $req = '{"id":1,"method":"list_sessions"}'
    $exitReq = '{"id":2,"method":"exit"}'

    $raw = & cmd.exe /c "(echo $req & echo $exitReq) | `"$bin`" --rpc"
    foreach ($line in $raw) {
        if ($line -match '^\{"id":1,"result":(\[.*\])\}') {
            return $matches[1] | ConvertFrom-Json
        }
    }
}

function Restore-ObliteratorSession {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$SessionId
    )

    process {
        if ($PSCmdlet.ShouldProcess("Quarantine session $SessionId", "Restore files, permissions, and registry keys")) {
            $bin = Get-ObliteratorBinary
            & $bin --restore $SessionId
        }
    }
}

function Invoke-Obliteration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Name")]
        [string]$Target,

        [switch]$Quarantine,
        [string]$QuarantineDir,
        [switch]$DryRun,
        [switch]$Force,
        [switch]$Aggressive,
        [switch]$AllUsers,
        [switch]$NoBackup,
        [switch]$PassThru
    )

    process {
        $bin = Get-ObliteratorBinary

        $argsList = @()
        $argsList += $Target
        $argsList += "--yes"

        if ($Quarantine) { $argsList += "--quarantine" }
        if ($QuarantineDir) { $argsList += "--quarantine-dir"; $argsList += $QuarantineDir }
        if ($DryRun) { $argsList += "--dry-run" }
        if ($Force) { $argsList += "--force" }
        if ($Aggressive) { $argsList += "--aggressive" }
        if ($AllUsers) { $argsList += "--all-users" }
        if ($NoBackup) { $argsList += "--no-backup" }
        $argsList += "--json"

        if ($PSCmdlet.ShouldProcess("Target '$Target'", "Obliterate application and all residual artifacts")) {
            $output = & $bin @argsList
            $jsonText = ($output | Where-Object { $_ -match '^\s*[\{\[]' }) -join "`n"
            if ($jsonText) {
                try {
                    $res = $jsonText | ConvertFrom-Json
                    if ($PassThru) {
                        return $res
                    }
                    if ($res.success) {
                        Write-Host "Obliterated $Target successfully. Freed: $($res.filesystem.bytes_freed_formatted)" -ForegroundColor Green
                    } else {
                        Write-Warning "Obliteration finished with warnings or reboot requirement for $Target"
                    }
                } catch {
                    Write-Host $output
                }
            } else {
                Write-Host $output
            }
        }
    }
}

# Dynamic Tab Completion for obliterator and Invoke-Obliteration
$appCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    try {
        $apps = Get-ObliteratorApp
        $apps | Where-Object { $_.name -like "$wordToComplete*" } |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new(
                    "`"$($_.name)`"",
                    $_.name,
                    [System.Management.Automation.CompletionResultType]::ParameterValue,
                    "$($_.name) ($($_.publisher))"
                )
            }
    } catch {
        # Fallback to filesystem if binary cannot be reached
    }
}

Register-ArgumentCompleter -CommandName "Invoke-Obliteration" -ParameterName "Target" -ScriptBlock $appCompleter
Register-ArgumentCompleter -Native -CommandName "obliterator" -ScriptBlock $appCompleter
Register-ArgumentCompleter -Native -CommandName "obliterator.exe" -ScriptBlock $appCompleter

Export-ModuleMember -Function Get-ObliteratorBinary, Get-ObliteratorApp, Get-ObliteratorSession, Restore-ObliteratorSession, Invoke-Obliteration
