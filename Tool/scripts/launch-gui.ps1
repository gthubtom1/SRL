#Requires -Version 5.1
<#
.SYNOPSIS
    Launch or observe a task-scoped executable without waiting for exit.
.DESCRIPTION
    shell (default) uses the Windows shell with an explicit working directory.
    attach only observes; user returns a manual handoff without polling.
    Parent names are facts, not proof of detection or human input.
    Process presence does not verify windows or application functionality.
    The caller must establish task scope and execution environment first.
.PARAMETER Arguments
    Raw Windows arguments. The caller owns application-specific quoting.
.PARAMETER InstancePid
    Select an existing instance by PID AND full executable path. Never kills it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [ValidateSet('user', 'shell', 'attach')][string]$Mode = 'shell',
    [ValidateRange(0, 300)][int]$WaitSeconds = 20,
    [switch]$ListWindows,
    [string]$Cwd,
    [string]$Arguments = '',
    [ValidateRange(0, 2147483647)][int]$InstancePid = 0,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8
$result = [ordered]@{
    target = $Target; imageName = ''; mode = $Mode; workingDir = ''
    launched = $false; launchRequested = $false; reusedExisting = $false
    status = 'INVALID'; instances = @(); windows = @(); instructions = @()
    verdict = 'UNKNOWN'; verdictReason = ''; diagnostics = @()
    observationComplete = $true; windowVerified = $false; functionalityVerified = $false
    creationFlags = $null
}
$exitCode = 2

function Observe-Instances {
    $rows = @()
    $name = $script:result.imageName.Replace("'", "''")
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction Stop)) {
        if ($InstancePid -and [int]$process.ProcessId -ne $InstancePid) { continue }
        if (-not $process.ExecutablePath) {
            $script:result.observationComplete = $false
            continue
        }
        if (-not [string]::Equals([IO.Path]::GetFullPath($process.ExecutablePath),
                                 $script:result.target, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $parentName = 'unknown'
        try {
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.ParentProcessId)" -ErrorAction Stop
            if ($parent) { $parentName = $parent.Name }
        } catch { }
        $rows += [ordered]@{
            pid = [int]$process.ProcessId; ppid = [int]$process.ParentProcessId
            executablePath = $process.ExecutablePath; created = "$($process.CreationDate)"
            parentName = $parentName
            risk = 'UNKNOWN'; riskReason = 'Parent identity alone does not establish detection.'
        }
    }
    return $rows
}

try {
    $baseDir = if ($Cwd) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Cwd) } else { (Get-Location).Path }
    if (-not [IO.Path]::IsPathRooted($Target)) { $Target = Join-Path $baseDir $Target }
    if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) { throw "Executable not found: $Target" }
    $result.target = (Resolve-Path -LiteralPath $Target).ProviderPath
    if ([IO.Path]::GetExtension($result.target) -notin @('.exe', '.com')) {
        throw 'Target must be an executable; resolve shortcuts and launchers explicitly.'
    }
    $result.imageName = [IO.Path]::GetFileName($result.target)
    $result.workingDir = if ($Cwd) { $baseDir } else { [IO.Path]::GetDirectoryName($result.target) }
    if (-not (Test-Path -LiteralPath $result.workingDir -PathType Container)) { throw 'Working directory does not exist.' }
    if ($Arguments -and ($Mode -ne 'shell' -or $InstancePid)) {
        throw 'Arguments apply only to a new shell launch, not attach/user/PID selection.'
    }
    if ($Mode -eq 'user') {
        $result.status = 'WAIT_USER'
        $result.instructions = @('Manual mode was explicitly selected. Open the target, then observe with -Mode attach.')
        $exitCode = 5
    } else {
        $before = @(Observe-Instances)
        if ($before.Count -gt 1) {
            $result.instances = $before
            $result.status = 'AMBIGUOUS'
            $result.verdictReason = 'Multiple matching instances; select the intended InstancePid before interacting.'
            $exitCode = 6
        } elseif ($before.Count -eq 1) {
            if ($Arguments) { throw 'Arguments would be ignored by an existing instance; observe it or explicitly arrange a fresh instance.' }
            $result.instances = $before
            $result.reusedExisting = $true
            $result.launched = $true
            $result.status = 'EXISTING'
            $exitCode = 0
        } elseif ($Mode -eq 'attach' -or $InstancePid) {
            $result.status = 'NOT_FOUND'
            $result.verdictReason = 'No instance matches full path and PID; no launch attempted.'
            $exitCode = 4
        } elseif (-not $result.observationComplete) {
            $result.status = 'OBSERVATION_UNAVAILABLE'
            $result.verdictReason = 'Executable identity unavailable; do not risk launching a duplicate.'
            $exitCode = 4
        } else {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $result.target
            $startInfo.WorkingDirectory = $result.workingDir
            $startInfo.Arguments = $Arguments
            $startInfo.UseShellExecute = $true
            $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
            $result.launchRequested = $true
            $startedAt = Get-Date
            $handle = [System.Diagnostics.Process]::Start($startInfo)
            $startedPid = if ($handle) { $handle.Id } else { 0 }
            try {
                $deadline = (Get-Date).AddSeconds($WaitSeconds)
                do {
                    $observed = @(Observe-Instances)
                    $matches = @($observed | Where-Object {
                        $_.pid -eq $startedPid -and [datetime]$_.created -ge $startedAt.AddSeconds(-2)
                    })
                    if ($matches.Count -eq 1 -or (Get-Date) -ge $deadline) { break }
                    Start-Sleep -Milliseconds 250
                } while ($true)
                if ($matches.Count -eq 1) {
                    $result.instances = $matches
                    $result.launched = $true
                    $result.status = 'STARTED'
                    $exitCode = 0
                } else {
                    $result.status = 'UNVERIFIED'
                    $result.verdictReason = 'Shell request returned but exact process was not observed; inspect state before retrying.'
                    $exitCode = 4
                }
            } finally {
                # Release our handle, never terminate the application or other instances.
                if ($handle) { $handle.Dispose() }
            }
        }
    }
    if ($ListWindows -and $result.instances.Count -gt 0) {
        if (-not ('SeepWindowObservation.Native' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
namespace SeepWindowObservation {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
        public delegate bool EnumProc(IntPtr hwnd, IntPtr data);
        [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr data);
        [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int count);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hwnd, StringBuilder text, int count);
        [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    }
}
'@
        }
        $selected = @($result.instances | ForEach-Object { $_.pid })
        $script:foundWindows = New-Object System.Collections.ArrayList
        $callback = [SeepWindowObservation.Native+EnumProc]{
            param($windowHandle, $data)
            [uint32]$windowPid = 0
            [void][SeepWindowObservation.Native]::GetWindowThreadProcessId($windowHandle, [ref]$windowPid)
            if ($selected -contains [int]$windowPid) {
                $title = New-Object System.Text.StringBuilder 512
                $class = New-Object System.Text.StringBuilder 256
                [void][SeepWindowObservation.Native]::GetWindowTextW($windowHandle, $title, 512)
                [void][SeepWindowObservation.Native]::GetClassNameW($windowHandle, $class, 256)
                $rect = New-Object SeepWindowObservation.Native+RECT
                [void][SeepWindowObservation.Native]::GetClientRect($windowHandle, [ref]$rect)
                [void]$script:foundWindows.Add([ordered]@{
                    pid = [int]$windowPid; hwnd = ('0x{0:X}' -f $windowHandle.ToInt64())
                    class = $class.ToString(); title = $title.ToString()
                    visible = [SeepWindowObservation.Native]::IsWindowVisible($windowHandle)
                    clientW = $rect.R - $rect.L; clientH = $rect.B - $rect.T
                })
            }
            return $true
        }
        [void][SeepWindowObservation.Native]::EnumWindows($callback, [IntPtr]::Zero)
        $result.windows = @($script:foundWindows.ToArray())
        $result.windowVerified = @($result.windows | Where-Object { $_.visible }).Count -gt 0
    }
} catch {
    $result.diagnostics += $_.Exception.Message
    if ($result.launchRequested -or $result.launched) {
        $result.status = 'OBSERVATION_FAILED'
        $exitCode = 4
    } else {
        $result.status = 'INVALID_OR_UNAVAILABLE'
        $exitCode = 2
    }
}
$result.verdict = $result.status
$result.windowMatchRule = 'Bind PID + executable path + creation time, then HWND and fresh observation; titles and sizes are not identity.'
if ($Json) { $result | ConvertTo-Json -Depth 6 } else { $result | Format-List | Out-String | Write-Output }
exit $exitCode
