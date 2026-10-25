#Requires -Version 5.1
# Initialize work/<case>/ with scope, timeline, workitems (reverse-skill ops contract).
# Bare invocation keeps pending/offline defaults.
# Ready-to-act example:
#   powershell -File Tool/scripts/case-init.ps1 -Hint "apk 签名校验" -CaseName my-case `
#     -AuthGranted -TargetUrl "https://app.example/" -NetworkProfile authorized_target_only
# Offline sample ready-to-act example:
#   powershell -File Tool/scripts/case-init.ps1 -Hint "offline apk" -CaseName my-sample `
#     -Preset offline-sample -Sample ".\app.apk"
param(
    [string] $Hint = '',
    [string] $CaseName = '',
    [string] $PackageRoot = '',
    [AllowEmptyString()]
    [string] $ProjectRoot = '',
    [switch] $AuthGranted,
    [string] $AuthStatus = '',
    [string] $AuthBasis = 'own_system',
    [string] $EvidenceOfAuth = '',
    [string] $TargetUrl = '',
    [string] $Sample = '',
    [string] $Preset = '',
    [string[]] $InScopeAssets = @(),
    [string] $NetworkProfile = '',
    [switch] $ReadyForAct
)
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir
if (-not $PackageRoot) { $PackageRoot = Split-Path -Parent $skillsRoot }
. (Join-Path (Join-Path $scriptDir 'lib') 'WorkRoot.ps1')
. (Join-Path (Join-Path $scriptDir 'lib') 'HostRuntime.ps1')
$HostExe = Resolve-ReverseHostExe
$requestedProjectRoot = if (-not [string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot
} elseif ($PSBoundParameters.ContainsKey('PackageRoot')) {
    $PackageRoot
} else {
    ''
}
$projectRoot = Resolve-ReverseProjectRoot -RequestedRoot $requestedProjectRoot

if (-not [string]::IsNullOrWhiteSpace($Sample)) {
    try {
        $Sample = [System.IO.Path]::GetFullPath($Sample)
    } catch {
        throw "Invalid -Sample path '$Sample': $($_.Exception.Message)"
    }
    if (-not (Test-Path -LiteralPath $Sample -PathType Leaf)) {
        throw "Local -Sample file not found: $Sample"
    }
}

# Cross-platform case presets. Keep semantics aligned with case-init.sh.
$presetNormalized = $Preset.Trim().ToLowerInvariant()
if ($presetNormalized -in @('offline-sample', 'own-sample', 'local-sample')) {
    $AuthGranted = $true
    $AuthStatus = 'granted'
    $AuthBasis = 'own_system'
    if ([string]::IsNullOrWhiteSpace($NetworkProfile)) { $NetworkProfile = 'offline' }
    if ([string]::IsNullOrWhiteSpace($EvidenceOfAuth)) {
        $EvidenceOfAuth = 'preset:offline-sample (owner-operated local file)'
    }
} elseif ($presetNormalized -in @('ctf-public', 'ctf')) {
    $AuthGranted = $true
    $AuthStatus = 'granted'
    $AuthBasis = 'ctf_public'
    if ([string]::IsNullOrWhiteSpace($NetworkProfile)) { $NetworkProfile = 'authorized_target_only' }
    if ([string]::IsNullOrWhiteSpace($EvidenceOfAuth)) { $EvidenceOfAuth = 'preset:ctf-public' }
} elseif ($presetNormalized -in @('own-system', 'lab-only')) {
    $AuthGranted = $true
    $AuthStatus = 'granted'
    $AuthBasis = 'own_system'
    if ([string]::IsNullOrWhiteSpace($NetworkProfile)) { $NetworkProfile = 'lab_only' }
    if ([string]::IsNullOrWhiteSpace($EvidenceOfAuth)) { $EvidenceOfAuth = 'preset:own-system/lab' }
} elseif (-not [string]::IsNullOrWhiteSpace($Preset)) {
    throw ("Invalid -Preset '{0}'. Allowed: offline-sample|ctf-public|own-system" -f $Preset)
}

if (-not $CaseName) {
    $slug = if ($Hint) {
        ($Hint.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    } else { 'case' }
    if ($slug.Length -gt 32) { $slug = $slug.Substring(0, 32).TrimEnd('-') }
    $CaseName = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $slug
}

# CaseName is a directory name, not a path. Keep every case under projectRoot/work.
# The pattern allows localized names but excludes Windows path syntax and names that
# Windows would normalize into a dot segment (for example, '.. ' or 'case.').
if ([string]::IsNullOrWhiteSpace($CaseName) -or
    $CaseName -notmatch '^[\p{L}\p{N}][\p{L}\p{N}._ -]{0,79}$' -or
    $CaseName -match '[.\s]$') {
    throw "Invalid -CaseName '$CaseName'. Use a 1-80 character directory name beginning with a letter or number; path separators, dot segments, trailing dots/spaces, control characters, and wildcard characters are not allowed."
}
if (-not [string]::IsNullOrWhiteSpace($NetworkProfile) -and
    $NetworkProfile.Trim().ToLowerInvariant() -notin @('offline', 'lab_only', 'authorized_target_only', 'unrestricted_lab', 'lab', 'authorized', 'auth', 'offline_only')) {
    throw "Invalid -NetworkProfile '$NetworkProfile'. Allowed: offline, lab_only, authorized_target_only, unrestricted_lab (aliases: lab, authorized, auth, offline_only)."
}

$workRoot = Join-Path $projectRoot 'work'
$caseRoot = Join-Path $workRoot $CaseName
$dirs = @('evidence', 'notes', 'report')
New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $caseRoot $d) | Out-Null
}

# Resolve auth / network / assets
# Priority: explicit -AuthStatus (only if bound) > -AuthGranted > pending.
# Never let a stray positional string overwrite AuthGranted.
$authStatusResolved = 'pending'
if ($AuthGranted) { $authStatusResolved = 'granted' }
if ($PSBoundParameters.ContainsKey('AuthStatus') -and -not [string]::IsNullOrWhiteSpace($AuthStatus)) {
    $candidate = $AuthStatus.Trim().ToLowerInvariant()
    $allowedAuth = @('pending', 'granted', 'denied', 'unknown')
    if ($allowedAuth -contains $candidate) {
        $authStatusResolved = $candidate
    } else {
        Write-Host ("WARN: ignoring invalid -AuthStatus '{0}' (allowed: pending|granted|denied|unknown)" -f $AuthStatus) -ForegroundColor Yellow
        # if user also passed AuthGranted, keep granted; else stay pending
    }
}

$evidenceAuth = if (-not [string]::IsNullOrWhiteSpace($EvidenceOfAuth)) {
    $EvidenceOfAuth
} elseif ($AuthGranted -or $authStatusResolved -eq 'granted') {
    'cli-flag AuthGranted or AuthStatus=granted'
} else {
    'FILL_ME'
}

$assets = New-Object System.Collections.Generic.List[string]
if (-not [string]::IsNullOrWhiteSpace($TargetUrl)) { [void]$assets.Add($TargetUrl.Trim()) }
if (-not [string]::IsNullOrWhiteSpace($Sample) -and -not $assets.Contains($Sample.Trim())) {
    [void]$assets.Add($Sample.Trim())
}
foreach ($a in @($InScopeAssets)) {
    if (-not [string]::IsNullOrWhiteSpace($a) -and -not $assets.Contains($a.Trim())) {
        [void]$assets.Add($a.Trim())
    }
}
# Also accept host-only tokens that look like domains/IPs from TargetUrl leftovers
if ($assets.Count -eq 0 -and $Hint -match 'https?://([^\s/]+)') {
    [void]$assets.Add(('https://{0}/' -f $Matches[1]))
}

$networkMode = 'offline'
if (-not [string]::IsNullOrWhiteSpace($NetworkProfile)) {
    $networkMode = $NetworkProfile.Trim()
} elseif ($assets.Count -gt 0 -and $authStatusResolved -eq 'granted' -and [string]::IsNullOrWhiteSpace($Sample)) {
    # Authorized network targets default to target-only. Explicit local samples remain offline.
    $networkMode = 'authorized_target_only'
}
# normalize common aliases
$netAliases = @{
    'lab' = 'lab_only'
    'authorized' = 'authorized_target_only'
    'auth' = 'authorized_target_only'
    'offline_only' = 'offline'
}
if ($netAliases.ContainsKey($networkMode.ToLowerInvariant())) {
    $networkMode = $netAliases[$networkMode.ToLowerInvariant()]
}
$allowedNetworkModes = @('offline', 'lab_only', 'authorized_target_only', 'unrestricted_lab')
if ($networkMode -notin $allowedNetworkModes) {
    throw "Invalid -NetworkProfile '$NetworkProfile'. Allowed: offline, lab_only, authorized_target_only, unrestricted_lab (aliases: lab, authorized, auth, offline_only)."
}

# ready_for_act requires auth granted + assets. Network targets need a non-offline
# profile; an explicit local sample is valid in offline mode. -ReadyForAct never
# bypasses auth or scope.
$ready = $false
$netAllowsAct = ($networkMode -ne 'offline' -and -not [string]::IsNullOrWhiteSpace($networkMode))
$offlineSampleReady = ($networkMode -eq 'offline' -and -not [string]::IsNullOrWhiteSpace($Sample) -and $assets.Count -gt 0)
if ($authStatusResolved -eq 'granted' -and $assets.Count -gt 0 -and ($netAllowsAct -or $offlineSampleReady)) {
    $ready = $true
} elseif ($ReadyForAct) {
    if ($authStatusResolved -ne 'granted') {
        Write-Host 'WARN: -ReadyForAct ignored because auth.status is not granted' -ForegroundColor Yellow
    } elseif ($assets.Count -eq 0) {
        Write-Host 'WARN: -ReadyForAct ignored because in_scope.assets is empty' -ForegroundColor Yellow
    } elseif (-not $netAllowsAct -and -not $offlineSampleReady) {
        Write-Host 'WARN: -ReadyForAct ignored because offline mode requires an explicit -Sample' -ForegroundColor Yellow
    }
}

# 判型落到哪个包（S3：master-route.ps1 已删，唯一实现是 route.py --resolve）
# W5：不再静默兜底 —— 拿不到具体域就把 primary 留空并告警，由 seep-router 先问一句再定。
$primary = ''
$primaryId = ''
$routeScript = Join-Path $scriptDir 'route.py'
$routeWarn = 'WARN: 路由失败，判型待定（先过 seep-router）'
# route.py 是 Python 脚本：不能用 $HostExe（那是 PowerShell 宿主）去跑，否则永远拿不到 JSON。
$pyExe = $null
foreach ($cand in @('python', 'py')) {
    $c = Get-Command $cand -ErrorAction SilentlyContinue
    if ($c -and $c.Source) { $pyExe = $c.Source; break }
}
if (-not $Hint) {
    Write-Host ("{0}：没有 -Hint，未判型" -f $routeWarn) -ForegroundColor Yellow
} elseif (-not (Test-Path $routeScript)) {
    Write-Host ("{0}：找不到 {1}" -f $routeWarn, $routeScript) -ForegroundColor Yellow
} elseif (-not $pyExe) {
    Write-Host ("{0}：PATH 里没有 python，跑不了 route.py" -f $routeWarn) -ForegroundColor Yellow
} else {
    $prevOutEnc = [Console]::OutputEncoding
    try {
        # route.py 输出 UTF-8；不设 Console::OutputEncoding 的话 PS 5.1 会按 OEM 码页解码 → JSON 坏 → 静默掉兜底
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
        $json = & $pyExe $routeScript --resolve $Hint --json --strict 2>$null
        $routeRc = $LASTEXITCODE
        $routed = $null
        try { $routed = ($json | Out-String) | ConvertFrom-Json } catch { $routed = $null }
        $hits = @()
        if ($routed -and $routed.hits) {
            $hits = @($routed.hits | Where-Object { $_ -and -not $_.fallback })
        }
        if ($routeRc -eq 0 -and $hits.Count -gt 0) {
            $primary = "$($hits[0].pack)/SKILL.md"
            $primaryId = "P$($hits[0].priority)"
        } elseif ($routeRc -eq 2 -or ($routed -and $routed.unclassified)) {
            Write-Host ("{0}：UNCLASSIFIED" -f $routeWarn) -ForegroundColor Yellow
        } else {
            Write-Host ("{0}：route.py rc={1}" -f $routeWarn, $routeRc) -ForegroundColor Yellow
        }
    } catch {
        Write-Host ("{0}：{1}" -f $routeWarn, $_.Exception.Message) -ForegroundColor Yellow
    } finally {
        [Console]::OutputEncoding = $prevOutEnc
    }
}
$primaryLabel = if ($primary) { $primary } else { '(待定 — 先过 seep-router)' }

$created = Get-Date -Format 'o'
if ($assets.Count -gt 0) {
    $assetsBlock = ($assets | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
} else {
    $assetsBlock = '  []'
}

$checkAuth = if ($authStatusResolved -eq 'granted') { '[x]' } else { '[ ]' }
$checkScope = if ($assets.Count -gt 0) { '[x]' } else { '[ ]' }
$checkNet = if ($networkMode -and $networkMode -ne '') { '[x]' } else { '[ ]' }
$readyStr = if ($ready) { 'true' } else { 'false' }
$timelineNext = if ($ready) {
    'open PRIMARY SKILL.md and ACT within scope'
} else {
    'fill scope auth + in_scope; set ready_for_act'
}
$timelineSummary = if ($ready) {
    'case directory created; scope ready_for_act=true'
} else {
    'case directory created; scope pending auth'
}

$scope = @"
# Case Scope

## meta
- case_id: $CaseName
- created: $created
- operator: local
- project_root: $projectRoot
- primary_skill: $primaryLabel
- primary_id: $(if ($primaryId) { $primaryId } else { '(待定)' })
- lead_role: lead
- specialist_roles: []
- hint: $Hint
- preset: $(if ([string]::IsNullOrWhiteSpace($Preset)) { 'none' } else { $Preset })

## auth
- status: $authStatusResolved
- basis: $AuthBasis
- evidence_of_auth: $evidenceAuth
- MUST NOT proceed if status != granted

## in_scope
- assets:
$assetsBlock
- surfaces: []
- activities: []

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: $networkMode
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: $readyStr
- checklist:
  - $checkAuth auth.status = granted
  - $checkScope in_scope.assets non-empty OR offline sample path set
  - $checkNet network_profile.mode chosen
  - [ ] out_of_scope reviewed
  - [ ] roles assigned (see Tool/skill/softseep/SKILL.md)

## ops_refs
- MANUAL/POC-VALIDATION.md          (授权范围与 PoC 闭环验证 SOP)
- MANUAL/DEPLOYMENT-CHECKLIST.md    (资产与合规基准)
- Tool/skill/softseep/SKILL.md      (G-Auth 授权门 + 判型调度)
- Tool/scripts/route.py             (任务路由：--resolve/--check)
"@

$timeline = @"
# Timeline (append-only)

## $created | lead | init
- action: case-init
- command_or_ref: Tool/scripts/case-init.ps1
- result_summary: $timelineSummary
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- decision_delta: [case_initialized]
- carry_forward_refs: [scope.md]
- next: $timelineNext
"@

$workitems = @"
# Work Items

| ID | title | role | targets | surface | status | evidence | notes |
|----|-------|------|---------|---------|--------|----------|-------|
| WI-001 | Establish scope and auth | lead | case | process | in_progress | | |

## Coverage
- [ ] Recon/analysis complete for in_scope assets
- [ ] Critical/High candidates triaged (or N/A for pure RE)
- [ ] Validated findings have Evidence (E-*)
- [ ] Path documented (attack/call/solve)
- [ ] Timeline continuous across major phases
- [ ] Report via docs-generator
- [ ] field-journal anonymized

## Refs
- MANUAL/POC-VALIDATION.md
- Tool/skill/softseep/SKILL.md
"@

$utf8 = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText((Join-Path $caseRoot 'scope.md'), $scope, $utf8)
[System.IO.File]::WriteAllText((Join-Path $caseRoot 'timeline.md'), $timeline, $utf8)
[System.IO.File]::WriteAllText((Join-Path $caseRoot 'workitems.md'), $workitems, $utf8)

$readmeNext = if ($ready) {
    @"
1. Scope is ready_for_act=true (auth granted + in_scope set)
2. Open primary skill: Tool/skill/$primaryLabel
3. Append ``timeline.md``; update ``workitems.md``
4. Append Evidence: 把证据文件放入 ``evidence/`` 并登记到 ``workitems.md``
5. Promote findings with Evidence chain (MANUAL/POC-VALIDATION.md)
6. Report via docs-generator; journal via field-journal
"@
} else {
    @"
1. Edit ``scope.md`` — set auth.status=granted and in_scope
   - network target: re-run with ``-AuthGranted -TargetUrl <url>``
   - local sample: re-run with ``-Preset offline-sample -Sample <path>``
2. Set ready_for_act when checklist complete
3. Open primary skill: skills/$primaryLabel
4. Append ``timeline.md``; update ``workitems.md``
5. Promote findings with Evidence chain (skills/ops/evidence-finding-path.md)
6. Report via docs-generator; journal via field-journal
"@
}

$readme = @"
# Case $CaseName

$readmeNext
"@
[System.IO.File]::WriteAllText((Join-Path $caseRoot 'README.md'), $readme, $utf8)

Write-Host ("CASE -> {0}" -f $caseRoot) -ForegroundColor Green
Write-Host ("PROJECT -> {0}" -f $projectRoot)
Write-Host ("PRIMARY skill: Tool/skill/{0} ({1})" -f $primaryLabel, $(if ($primaryId) { $primaryId } else { '待定' }))
Write-Host ("auth.status={0} network_profile={1} ready_for_act={2}" -f $authStatusResolved, $networkMode, $readyStr)
if ($ready) {
    Write-Host 'NEXT: open PRIMARY SKILL.md and ACT within scope' -ForegroundColor Green
} else {
    Write-Host 'NEXT: fill scope.md auth + in_scope; then open PRIMARY SKILL.md'
}
