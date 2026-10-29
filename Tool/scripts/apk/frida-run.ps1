#requires -Version 5

[CmdletBinding()]
param(
    [string]$Package,

    [string]$Process,

    [string]$RemoteHost = '127.0.0.1:27042',

    [string]$ScriptPath,

    [switch]$Usb,

    [switch]$Spawn,

    [switch]$Pause,

    [switch]$ListDevices,

    [switch]$ListProcesses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Get-PythonScriptCandidates {
    param([Parameter(Mandatory = $true)][string]$ExecutableName)

    $roots = @(
        (Join-Path $env:APPDATA 'Python'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python')
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }

        $matches = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $matches) {
            $candidate = Join-Path $dir.FullName (Join-Path 'Scripts' $ExecutableName)
            if (Test-Path -LiteralPath $candidate) {
                $candidates.Add($candidate)
            }
        }
    }

    return $candidates
}

function Get-ToolPath {
    param([Parameter(Mandatory = $true)][string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    foreach ($candidate in Get-PythonScriptCandidates -ExecutableName ($Name + '.exe')) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $acquireScript = Join-Path $PSScriptRoot '..\tool-acquire.py'
    if (Test-Path -LiteralPath $acquireScript) {
        $output = @(& python $acquireScript --tool frida --install --json)
        if ($LASTEXITCODE -ne 0) { throw "Frida acquisition failed: $($output -join [Environment]::NewLine)" }
        $result = ($output -join [Environment]::NewLine) | ConvertFrom-Json
        if ($result.verdict -ne 'USABLE' -or $result.identity.ok -ne $true) {
            throw 'Frida acquisition did not verify the CLI identity.'
        }
        $cliSteps = @($result.steps | Where-Object {
            $_.PSObject.Properties['kind'] -and $_.kind -eq 'cli' -and
            $_.PSObject.Properties['ok'] -and $_.ok -and
            $_.PSObject.Properties['exe'] -and $_.exe
        })
        if ($cliSteps.Count -gt 0) {
            $executable = [string]$cliSteps[-1].exe
            if ($Name -eq 'frida' -and (Test-Path -LiteralPath $executable -PathType Leaf)) { return $executable }
            foreach ($extension in @('.exe', '.cmd', '.bat', '')) {
                $candidate = Join-Path (Split-Path -Parent $executable) ($Name + $extension)
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
            }
        }
    }

    throw "Missing required CLI tool: $Name — install with: pip install frida-tools"
}

if ($ListDevices) {
    $fridaLsDevices = Get-ToolPath -Name 'frida-ls-devices'
    & $fridaLsDevices
    exit $LASTEXITCODE
}

$target = if ($Package) { $Package } elseif ($Process) { $Process } else { '' }
if ([string]::IsNullOrWhiteSpace($target) -and -not $ListProcesses) {
    throw 'Provide -Package or -Process, or use -ListProcesses.'
}

$deviceFlag = if ($Usb) { '-U' } else { '-H' }

if ($ListProcesses) {
    $fridaPs = Get-ToolPath -Name 'frida-ps'
    $processArgs = @()
    if ($Usb) {
        $processArgs += '-U'
    }
    else {
        $processArgs += @('-H', $RemoteHost)
    }
    & $fridaPs @processArgs
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "Frida script not found: $ScriptPath"
}

$frida = Get-ToolPath -Name 'frida'

$fridaArgs = @($deviceFlag)
if (-not $Usb) {
    $fridaArgs += $RemoteHost
}
if ($Spawn) {
    $fridaArgs += '-f'
} else {
    $fridaArgs += '-n'
}
$fridaArgs += $target
$fridaArgs += '-l'
$fridaArgs += $ScriptPath
if ($Spawn -and $Pause) {
    $fridaArgs += '--pause'
}

& $frida @fridaArgs
exit $LASTEXITCODE
