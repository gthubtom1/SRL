<#
.SYNOPSIS
    launch-gui.ps1 — GUI 目标的唯一合法启动通道（启动纪律标准件）

.DESCRIPTION
    为什么需要它：
      用 bash / powershell / python / node 直接 CreateProcess 拉起目标，
      父进程链、创建标志、令牌来源全都和"真人双击"不同。
      目标里有完整性自检 / 反自动化的，一眼就能看出来：
        - 父进程 = bash.exe / powershell.exe / python.exe / node.exe   → 高检测风险
        - 用了 DETACHED_PROCESS / CREATE_SUSPENDED / DEBUG_PROCESS       → 极高风险
        - 命令行带参数（正常用户双击是零参数）                          → 中风险
      实测（explorer.exe 拉起）：parent=explorer.exe，命令行只有 exe 路径，无创建标志
      —— 这是"像真人一样点开"的等价实现。

    三种模式：
      -Mode user   （默认，推荐）不替你启动。打印一句人话让用户自己双击，然后只做观察。
      -Mode shell  必须由 Agent 启动时用。走 explorer.exe "<绝对路径>"，父进程 = explorer.exe。
      -Mode attach 目标已经在跑，只做观察（不动进程）。

    启动后一律给出「父进程画像 + 风险裁定」，并可用 -ListWindows 输出窗口状态机原料。

.PARAMETER Target
    目标 exe 绝对路径。相对路径会按 -WorkingDirectory 解析。

.PARAMETER Mode
    user | shell | attach   默认 user。

.PARAMETER WaitSeconds
    启动后轮询等待进程出现的秒数。默认 20。

.PARAMETER ListWindows
    列出该进程的所有顶层窗口：hwnd / class / title / 客户区尺寸。
    ★ 很多目标每次启动都换窗口标题（本次实测：SystemTuner_1757 / DisplayManager_1338 /
      PerformanceTuner_5040），所以**永远按 (pid, class, size) 匹配，不要按标题匹配**。

.PARAMETER Cwd
    指定工作目录。默认 = 目标 exe 所在目录（与双击行为一致）。

.PARAMETER Json
    输出 JSON（给 Agent 直接消费）。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Tool/scripts/launch-gui.ps1 `
        -Target "<SAMPLE_DIR>\目标.exe" -Mode user

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Tool/scripts/launch-gui.ps1 `
        -Target "<SAMPLE_DIR>\目标.exe" -Mode shell -ListWindows -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [ValidateSet('user', 'shell', 'attach')]
    [string]$Mode = 'user',
    [int]$WaitSeconds = 20,
    [switch]$ListWindows,
    [string]$Cwd,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8

# ───────────────────────── 0. 解析目标 ─────────────────────────
if (-not [System.IO.Path]::IsPathRooted($Target)) {
    $base = if ($Cwd) { $Cwd } else { (Get-Location).Path }
    $Target = Join-Path $base $Target
}
if (-not (Test-Path -LiteralPath $Target)) {
    Write-Error "目标不存在：$Target"
    exit 2
}
$Target = (Resolve-Path -LiteralPath $Target).Path
$imgName = [System.IO.Path]::GetFileName($Target)
$exeDir = [System.IO.Path]::GetDirectoryName($Target)
if (-not $Cwd) { $Cwd = $exeDir }

$result = [ordered]@{
    target        = $Target
    imageName     = $imgName
    mode          = $Mode
    workingDir    = $Cwd
    launched      = $false
    instances     = @()
    verdict       = ''
    verdictReason = ''
    instructions  = @()
    windows       = @()
}

# ───────────────────────── 1. 父进程画像 ─────────────────────────
function Get-ParentName([int]$parentPid) {
    if ($parentPid -le 0) { return 'none' }
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$parentPid" -ErrorAction Stop
        if ($p) { return $p.Name }
    } catch { }
    return 'unknown'
}

$SUSPECT_PARENTS = @('bash.exe', 'sh.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe',
    'python.exe', 'pythonw.exe', 'node.exe', 'wt.exe', 'conhost.exe')

function Get-Verdict([string]$parentName) {
    if ($parentName -eq 'explorer.exe') {
        return @('LOW', '父进程 = explorer.exe，等于真人双击；命令行零参数、无创建标志。')
    }
    if ($SUSPECT_PARENTS -contains $parentName.ToLower()) {
        return @('HIGH', "父进程 = $parentName —— 目标只要读一次父进程名就能判定是被 Agent 拉起，属典型反自动化检测面。改用 -Mode user 或 -Mode shell。")
    }
    return @('MEDIUM', "父进程 = $parentName（非 explorer，也未在常见 shell 名单里）。有反自动化检测的目标建议改 -Mode user。")
}

function Snapshot-Instances {
    $out = @()
    foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='$imgName'" -ErrorAction SilentlyContinue)) {
        $pn = Get-ParentName ([int]$p.ParentProcessId)
        $v = Get-Verdict $pn
        $out += [ordered]@{
            pid        = [int]$p.ProcessId
            ppid       = [int]$p.ParentProcessId
            parentName = $pn
            commandLine = $p.CommandLine
            created    = "$($p.CreationDate)"
            risk       = $v[0]
            riskReason = $v[1]
        }
    }
    return $out
}

# ───────────────────────── 2. 按模式动作 ─────────────────────────
switch ($Mode) {

    'attach' {
        $result.instructions += @("目标已在运行，本次只观察，不创建进程。")
    }

    'user' {
        $result.instructions += @(
            "【请你自己动手 · 不要用命令行/快捷方式】",
            "1. 打开文件夹：$exeDir",
            "2. 双击：$imgName",
            "3. 按需操作界面（例如点「激活授权」并输入卡密）",
            "4. 做完回一句话（例如「好了」），我这边只做观察，不动鼠标键盘。"
        )
    }

    'shell' {
        # ★ 唯一合法的 Agent 侧拉起方式：explorer.exe 作为父进程
        #   禁止：Start-Process / cmd /c start / subprocess.Popen / Win32_Process Create
        $result.instructions += @("通过 explorer.exe 拉起（父进程 = explorer.exe，等价双击）。")
        Push-Location -LiteralPath $Cwd
        try {
            Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$Target`"" -WindowStyle Hidden
        } finally {
            Pop-Location
        }
    }
}

# ───────────────────────── 3. 等待 + 观察 ─────────────────────────
if ($Mode -ne 'attach') {
    $deadline = (Get-Date).AddSeconds([Math]::Max(3, $WaitSeconds))
    do {
        Start-Sleep -Milliseconds 500
        $inst = @(Snapshot-Instances)
    } while ($inst.Count -eq 0 -and (Get-Date) -lt $deadline)

    if ($inst.Count -eq 0) {
        $result.verdict = 'NOT_STARTED'
        $result.verdictReason = "等待 ${WaitSeconds}s 仍未看到 $imgName 进程。若你还没双击，请先双击；若已双击却没起来，去看它自己的报错弹窗（完整性自检这类会直接弹框后退出）。"
    } else {
        $result.launched = $true
        $result.instances = $inst
        $rank = @{ 'LOW' = 0; 'MEDIUM' = 1; 'HIGH' = 2 }
        $worst = @($inst[0].risk, $inst[0].riskReason)
        foreach ($i in $inst) {
            if ($rank[$i.risk] -gt $rank[$worst[0]]) { $worst = @($i.risk, $i.riskReason) }
        }
        $result.verdict = $worst[0]
        $result.verdictReason = $worst[1]
    }
} else {
    $inst = @(Snapshot-Instances)
    $result.instances = $inst
    $result.launched = ($inst.Count -gt 0)
    if ($inst.Count -gt 0) {
        $result.verdict = $inst[0].risk
        $result.verdictReason = $inst[0].riskReason
    }
}

# ───────────────────────── 4. 窗口清单（状态机原料） ─────────────────────────
if ($ListWindows -and $result.instances.Count -gt 0) {
    if (-not ('W.U' -as [type])) {
        Add-Type -Namespace W -Name U -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
[StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, System.IntPtr p);
public delegate bool EnumProc(System.IntPtr h, System.IntPtr p);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr h, out uint pid);
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern int GetWindowTextW(System.IntPtr h, System.Text.StringBuilder s, int n);
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern int GetClassNameW(System.IntPtr h, System.Text.StringBuilder s, int n);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool IsWindowVisible(System.IntPtr h);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool GetClientRect(System.IntPtr h, out RECT r);
'@
    }
    $pids = @($result.instances | ForEach-Object { $_.pid })
    $script:found = New-Object System.Collections.ArrayList
    $cb = [W.U+EnumProc] {
        param($h, $l)
        $wpid = 0
        [void][W.U]::GetWindowThreadProcessId($h, [ref]$wpid)
        if ($pids -contains [int]$wpid) {
            $sb = New-Object System.Text.StringBuilder 512
            [void][W.U]::GetWindowTextW($h, $sb, 512); $title = $sb.ToString()
            $cb2 = New-Object System.Text.StringBuilder 256
            [void][W.U]::GetClassNameW($h, $cb2, 256); $cls = $cb2.ToString()
            $r = New-Object W.U+RECT
            [void][W.U]::GetClientRect($h, [ref]$r)
            [void]$script:found.Add([ordered]@{
                pid       = [int]$wpid
                hwnd      = ('0x{0:X}' -f $h.ToInt64())
                class     = $cls
                title     = $title
                visible   = [bool][W.U]::IsWindowVisible($h)
                clientW   = $r.R - $r.L
                clientH   = $r.B - $r.T
            })
        }
        return $true
    }
    [void][W.U]::EnumWindows($cb, [IntPtr]::Zero)
    $result.windows = @($script:found)
}

# 窗口匹配纪律提醒（写死在输出里，避免下次又按标题匹配）
$result.windowMatchRule = '按 (pid, class, clientW, clientH) 匹配窗口；标题每次启动可能随机，只作日志不作为键。'

# ───────────────────────── 5. 输出 ─────────────────────────
if ($Json) {
    $result | ConvertTo-Json -Depth 6
} else {
    Write-Output "target   : $($result.target)"
    Write-Output "mode     : $($result.mode)   workingDir: $($result.workingDir)"
    Write-Output "launched : $($result.launched)"
    if ($result.instructions.Count -gt 0) {
        Write-Output '--- 指令 ---'
        $result.instructions | ForEach-Object { Write-Output $_ }
    }
    if ($result.instances.Count -gt 0) {
        Write-Output '--- 实例 ---'
        foreach ($i in $result.instances) {
            Write-Output ("  pid={0} ppid={1} parent={2} risk={3}" -f $i.pid, $i.ppid, $i.parentName, $i.risk)
        }
    }
    if ($result.windows.Count -gt 0) {
        Write-Output '--- 窗口 ---'
        foreach ($w in $result.windows) {
            Write-Output ("  {0} pid={1} class={2} {3}x{4} visible={5} title={6}" -f $w.hwnd, $w.pid, $w.class, $w.clientW, $w.clientH, $w.visible, $w.title)
        }
    }
    Write-Output "verdict  : $($result.verdict)  $($result.verdictReason)"
    Write-Output "匹配纪律 : $($result.windowMatchRule)"
}

if ($result.verdict -eq 'HIGH') { exit 3 }
if ($result.verdict -eq 'NOT_STARTED') { exit 4 }
exit 0
