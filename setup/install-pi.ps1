#Requires -Version 5.1
<#
  Seep 工作台 —— 一键配置 Pi Agent 运行环境 (加强版)
  包含：
    1. 备份原 ~/.pi/agent 配置
    2. 同步当前启用的 Skill
    3. 同步提示词与安全放行扩展
    4. 增量合并 mcp.json（保护已有用户配置，UTF-8 No BOM，反斜杠安全转义）
    5. 配置 settings.json
#>
[CmdletBinding()]
param(
    [switch]$SkipPackages,
    [string]$AgentRoot = ''
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$NormalizedRoot = $Root.Replace('\', '/')
$ToolDir   = Join-Path $Root 'Tool'
$AgentDir  = $null
$SkillsDir = $null
$ExtDir    = $null
$InstallManifest = $null

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }

function Test-SkillRuntimeCache([string]$RelativePath, [bool]$IsDirectory) {
    $segments = @($RelativePath -split '[\\/]+')
    foreach ($segment in $segments) {
        if (@('__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache') -contains $segment) {
            return $true
        }
    }
    if (-not $IsDirectory) {
        $extension = [System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
        if (@('.pyc', '.pyo') -contains $extension) { return $true }
    }
    return $false
}

function Copy-SkillTree([string]$SourcePath, [string]$Destination) {
    $sourceRoot = [System.IO.Path]::GetFullPath($SourcePath).TrimEnd([char[]]@('\', '/'))
    $sourcePrefix = $sourceRoot + [System.IO.Path]::DirectorySeparatorChar
    New-Item -ItemType Directory -Path $Destination -Force -ErrorAction Stop | Out-Null

    foreach ($directory in (Get-ChildItem -LiteralPath $sourceRoot -Directory -Recurse -Force -ErrorAction Stop)) {
        $relative = $directory.FullName.Substring($sourcePrefix.Length)
        if (Test-SkillRuntimeCache $relative $true) { continue }
        New-Item -ItemType Directory -Path (Join-Path $Destination $relative) -Force -ErrorAction Stop | Out-Null
    }
    foreach ($file in (Get-ChildItem -LiteralPath $sourceRoot -File -Recurse -Force -ErrorAction Stop)) {
        $relative = $file.FullName.Substring($sourcePrefix.Length)
        if (Test-SkillRuntimeCache $relative $false) { continue }
        $target = Join-Path $Destination $relative
        $parent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force -ErrorAction Stop
    }
}

function Backup-ExistingSkill([string]$SourcePath, [string]$SkillName) {
    $script:LastSkillBackup = ''
    if (-not (Test-Path $SourcePath)) { return $true }
    $backupRoot = Join-Path $AgentDir ("backup-install-skills-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + "-" + [guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path $backupRoot $SkillName
    try {
        New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
        Copy-Item $SourcePath $backupPath -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path $backupPath)) { throw 'skill backup destination missing' }
        $script:LastSkillBackup = $backupPath
        Write-Info "已备份既有 skill: $SkillName -> $backupPath"
        return $true
    } catch {
        if (Test-Path $backupRoot) {
            Remove-Item -LiteralPath $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Warn "既有 skill 备份失败，保持旧树不动: $SkillName"
        return $false
    }
}

function Restore-SkillBackup([string]$Destination, [string]$BackupPath, [bool]$ExistedBefore) {
    try {
        if (-not [string]::IsNullOrWhiteSpace($BackupPath) -and (Test-Path $BackupPath)) {
            if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force -ErrorAction Stop }
            Copy-Item $BackupPath $Destination -Recurse -Force -ErrorAction Stop
            return (Test-Path $Destination)
        }
        if (-not $ExistedBefore -and (Test-Path $Destination)) {
            Remove-Item $Destination -Recurse -Force -ErrorAction Stop
        }
        if ($ExistedBefore) { return (Test-Path $Destination) }
        return (-not (Test-Path $Destination))
    } catch {
        return $false
    }
}

function Copy-ExtensionAsset([string]$SourcePath, [string]$Destination, [string]$TextContent = '',
    [ValidateSet('extensions', 'tasks', 'agents')][string]$BackupCategory = 'extensions') {
    $backupPath = ''
    $backupRoot = ''
    $backupCaptured = $false
    $temporary = Join-Path (Split-Path -Parent $Destination) ('.seep-extension-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        if (Test-Path $Destination) {
            $backupRoot = Join-Path $AgentDir ("backup-install-" + $BackupCategory + "-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + "-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
            $backupPath = Join-Path $backupRoot (Split-Path -Leaf $Destination)
            Copy-Item -LiteralPath $Destination -Destination $backupPath -Force -ErrorAction Stop
            $backupCaptured = $true
            Write-Info "已备份既有部署文件: $(Split-Path -Leaf $Destination)"
        }
        if ($PSBoundParameters.ContainsKey('TextContent')) {
            [System.IO.File]::WriteAllText($temporary, $TextContent, (New-Object System.Text.UTF8Encoding($false)))
        } else {
            Copy-Item -LiteralPath $SourcePath -Destination $temporary -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $temporary -Destination $Destination -Force -ErrorAction Stop
        if (-not (Test-Path $Destination)) { throw 'deployment destination missing' }
        return $true
    } catch {
        if (Test-Path $temporary) { Remove-Item $temporary -Force -ErrorAction SilentlyContinue }
        if (-not $backupCaptured -and -not [string]::IsNullOrWhiteSpace($backupRoot) -and
            (Test-Path $backupRoot)) {
            Remove-Item -LiteralPath $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ([string]::IsNullOrWhiteSpace($backupPath) -eq $false -and (Test-Path $backupPath)) {
            try {
                if (-not (Test-Path $Destination)) {
                    Copy-Item -LiteralPath $backupPath -Destination $Destination -Force -ErrorAction Stop
                }
            } catch {
                Write-Warn "部署文件旧版本回滚失败: $(Split-Path -Leaf $Destination)"
            }
        } elseif (-not (Test-Path $Destination)) {
            # No prior file and no published result: nothing must remain.
        }
        return $false
    }
}

function Test-OwnedDeploymentFile([string]$RelativePath, [string]$Destination) {
    if ($null -eq $script:InstallOwnership -or $null -eq $script:InstallOwnership.managed_files) { return $false }
    $record = $script:InstallOwnership.managed_files.PSObject.Properties[$RelativePath]
    if ($null -eq $record -or $record.Value -isnot [string] -or $record.Value -notmatch '^[0-9a-f]{64}$') { return $false }
    try {
        $item = Get-Item -LiteralPath $Destination -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $actual = [System.BitConverter]::ToString($hasher.ComputeHash([System.IO.File]::ReadAllBytes($Destination))).Replace('-', '')
            return ($actual -eq $record.Value)
        } finally {
            $hasher.Dispose()
        }
    } catch {
        return $false
    }
}

function Write-InstallManifest([string]$Status) {
    $manifestScript = @'
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
agent = Path(sys.argv[2]).resolve()
manifest_path = Path(sys.argv[3])
status = sys.argv[4]
allowed = ("skills/", "prompts/", "agents/", "extensions/")
cache_dirs = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def runtime_cache(rel):
    parts = Path(str(rel).replace("\\", "/")).parts
    return any(part in cache_dirs for part in parts) or Path(rel).suffix.lower() in (".pyc", ".pyo")

def safe_rel(rel):
    rel = str(rel).replace("\\", "/")
    parts = Path(rel).parts
    return (bool(rel) and not rel.startswith("/") and ".." not in parts
            and any(rel.startswith(prefix) for prefix in allowed))

def safe_target(base, rel):
    if not safe_rel(rel):
        return None
    target = base / Path(rel)
    try:
        target.resolve(strict=False).relative_to(base.resolve())
    except (OSError, ValueError):
        return None
    if any(part.is_symlink() for part in target.parents if part != base):
        return None
    return target

def record_deployed(rel, expected):
    if status == "installing" or runtime_cache(rel):
        return
    target = safe_target(agent, rel)
    if target is None:
        return
    try:
        if target.is_file() and not target.is_symlink():
            actual = sha(target.read_bytes())
            if actual == expected:
                managed[rel] = actual
    except OSError:
        pass

managed = {}
try:
    previous = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, ValueError):
    previous = {}
previous_ok = (isinstance(previous, dict)
               and previous.get("schema") == "seep-agent-install/1"
               and str(previous.get("source_root", "")) == str(root))
if previous_ok and isinstance(previous.get("managed_files"), dict):
    for rel, recorded in previous["managed_files"].items():
        if not safe_rel(rel) or runtime_cache(rel) or not isinstance(recorded, str):
            continue
        target = safe_target(agent, rel)
        if target is None:
            continue
        try:
            if target.is_file() and not target.is_symlink() and sha(target.read_bytes()) == recorded:
                managed[rel] = recorded
        except OSError:
            pass

preexisting = set()
if (previous_ok and previous.get("status") == "installing"
        and isinstance(previous.get("preexisting_files"), list)):
    preexisting.update(
        rel for rel in previous["preexisting_files"]
        if isinstance(rel, str) and safe_rel(rel)
    )
else:
    candidates = []
    tasks_root = root / "Tool" / "prompts" / "tasks"
    if tasks_root.is_dir():
        candidates.extend("prompts/" + path.name for path in tasks_root.glob("*.md")
                          if path.name != "README.md" and path.is_file() and not path.is_symlink())
    agents_root = root / "Tool" / "prompts" / "agents"
    if agents_root.is_dir():
        candidates.extend("agents/" + path.name for path in agents_root.glob("*.md")
                          if path.name != "README.md" and path.is_file() and not path.is_symlink())
    for rel in candidates:
        target = safe_target(agent, rel)
        if (rel not in managed and target is not None
                and target.exists() and not target.is_symlink()):
            preexisting.add(rel)

skill_root = root / "Tool" / "skill"
if skill_root.is_dir():
    for source in sorted(skill_root.iterdir(), key=lambda p: p.name):
        if not source.is_dir() or source.name.startswith("_") or source.name == "update":
            continue
        deployments = []
        if source.name == "safe-skills":
            for sub in sorted(source.iterdir(), key=lambda p: p.name):
                if sub.is_dir() and not (skill_root / sub.name).exists():
                    deployments.append(sub)
        else:
            deployments.append(source)
        for directory in deployments:
            for path in directory.rglob("*"):
                if not path.is_file() or path.is_symlink():
                    continue
                rel = "skills/" + directory.name + "/" + path.relative_to(directory).as_posix()
                record_deployed(rel, sha(path.read_bytes()))

tasks = root / "Tool" / "prompts" / "tasks"
if tasks.is_dir():
    root_posix = str(root).replace("\\", "/")
    for path in sorted(tasks.glob("*.md")):
        if path.name == "README.md" or not path.is_file() or path.is_symlink():
            continue
        text = path.read_text(encoding="utf-8-sig").replace("@SEEP_ROOT@", root_posix)
        rel = "prompts/" + path.name
        if rel not in preexisting or rel in managed:
            record_deployed(rel, sha(text.encode("utf-8")))

agents = root / "Tool" / "prompts" / "agents"
if agents.is_dir():
    for path in sorted(agents.glob("*.md")):
        if path.name == "README.md" or not path.is_file() or path.is_symlink():
            continue
        rel = "agents/" + path.name
        if rel not in preexisting or rel in managed:
            record_deployed(rel, sha(path.read_bytes()))

extensions = root / "Tool" / "prompts" / "extensions"
if extensions.is_dir():
    for path in sorted(extensions.iterdir(), key=lambda p: p.name):
        if (path.is_file() and not path.is_symlink()
                and path.suffix.lower() in (".ts", ".json", ".md")):
            rel = "extensions/" + path.name
            record_deployed(rel, sha(path.read_bytes()))

created = []
if isinstance(previous, dict) and isinstance(previous.get("created_paths"), list):
    created.extend(p for p in previous["created_paths"] if p == "agents/settings.json")
if not (agent / "agents" / "settings.json").exists():
    created.append("agents/settings.json")
created = sorted(set(created))

version_path = root / "VERSION"
version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else None
payload = {
    "schema": "seep-agent-install/1",
    "runtime_id": "seep-reverse-lab/softseep",
    "source_root": str(root),
    "version": version,
    "status": status,
    "managed_files": dict(sorted(managed.items())),
    "prompt_blocks": ["AGENTS.md", "SEEP.md"],
    "created_paths": created,
    "preexisting_files": sorted(preexisting),
}
agent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".seep-install-", dir=agent)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, manifest_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
'@
    $manifestScript | & python - $Root $AgentDir $InstallManifest $Status
    return ($LASTEXITCODE -eq 0)
}

$script:Failed = @()
$runtimeBridge = Join-Path $ToolDir 'scripts\runtime-root.py'
$resolveArgs = @($runtimeBridge, 'resolve')
if ($AgentRoot -ne '') { $resolveArgs += @('--agent-root', $AgentRoot) }
$resolveOutput = @(& python @resolveArgs 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Warn "AgentRoot 无效或 runtime helper 不可用: $($resolveOutput -join ' ')"
    exit 1
}
try {
    $resolvedAgent = (($resolveOutput -join "`n") | ConvertFrom-Json)
    if (-not $resolvedAgent.ok -or [string]::IsNullOrWhiteSpace([string]$resolvedAgent.agent_root)) { throw 'resolver returned no agent root' }
    $AgentDir = [System.IO.Path]::GetFullPath([string]$resolvedAgent.agent_root)
} catch {
    Write-Warn "AgentRoot 解析结果无效: $($_.Exception.Message)"
    exit 1
}
$SkillsDir = Join-Path $AgentDir 'skills'
$ExtDir    = Join-Path $AgentDir 'extensions'
$InstallManifest = Join-Path $AgentDir 'seep-install-manifest.json'
$env:PI_CODING_AGENT_DIR = $AgentDir
$script:SkillSyncOk = $true

# Reject malformed user configuration before copying or replacing anything.
& python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --validate-only
if ($LASTEXITCODE -ne 0) { Write-Warn '安装输入无效，原件保留；请修正后重试'; exit 1 }

# 真实失败清单：本脚本以前末尾恒 `exit 0`，于是 install.ps1 那边永远
# 看到 rc=0、把 'pi' 当成部署成功（说假话）。现在每个“确实没部署成”的分支
# 都往这里记一笔，退出码由它唯一决定。
$script:Failed = @()

Write-Host "`n  === Pi Agent 环境配置 ===" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 目录与备份
foreach ($d in @($AgentDir, $SkillsDir, $ExtDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
if (-not (Write-InstallManifest 'installing')) {
    Write-Warn '无法写入安装所有权清单；未部署任何工作台资产'
    exit 1
}
try {
    $script:InstallOwnership = Get-Content -LiteralPath $InstallManifest -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Warn '无法读取安装所有权清单；未部署任何工作台资产'
    exit 1
}

$backup = Join-Path $AgentDir ("backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
$needBackup = @('SEEP.md', 'AGENTS.md', 'mcp.json', 'settings.json')
$hasOld = $false
foreach ($f in $needBackup) {
    if (Test-Path (Join-Path $AgentDir $f)) { $hasOld = $true; break }
}
if ($hasOld) {
    try {
        New-Item -ItemType Directory -Path $backup -Force -ErrorAction Stop | Out-Null
        $n = 0
        foreach ($f in $needBackup) {
            $p = Join-Path $AgentDir $f
            if (Test-Path $p) { Copy-Item -LiteralPath $p -Destination $backup -Force -ErrorAction Stop; $n++ }
        }
        Write-Ok "已安全备份原有配置 ($n 个文件) -> $backup"
    } catch { Write-Warn '配置备份失败，停止安装并保留原件'; exit 1 }
}

# ---------------------------------------------------------------- 2. Skill 同步
$srcSkills = Join-Path $ToolDir 'skill'
if (Test-Path $srcSkills) {
    foreach ($s in (Get-ChildItem $srcSkills -Directory)) {
        # ★ S3「索引 32→9」：`_pending/` 是归档区（不索引、不路由、不部署）
        if ($s.Name.StartsWith('_')) { continue }
        if ($s.Name -eq 'safe-skills') {
            foreach ($sub in (Get-ChildItem $s.FullName -Directory)) {
                $dst = Join-Path $SkillsDir $sub.Name
                # ★ 冲突守卫：safe-skills 的子技能若与顶层技能同名，会静默覆盖顶层那份
                #   （历史事故：safe-skills/ida-reverse 覆盖了顶层 ida-reverse，
                #    导致带 13337 全自动唤醒规约的核心技能丢失）。
                $topLevel = Join-Path $srcSkills $sub.Name
                if ((Test-Path $topLevel) -and $sub.Name -ne 'safe-skills') {
                    Write-Warn "safeskills 子技能与顶层技能同名，已跳过以免覆盖: $($sub.Name)"
                    continue
                }
                $existedBefore = Test-Path $dst
                $script:LastSkillBackup = ''
                try {
                    if ($existedBefore -and -not (Backup-ExistingSkill $dst $sub.Name)) {
                        throw 'existing skill backup failed'
                    }
                    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction Stop }
                    if ($env:SEEP_INTERNAL_TEST_FAIL_SKILL_COPY -eq $sub.Name) {
                        throw 'injected skill copy failure'
                    }
                    Copy-SkillTree $sub.FullName $dst
                    if (-not (Test-Path $dst)) { throw 'copy destination missing' }
                } catch {
                    $script:SkillSyncOk = $false
                    $script:Failed += "skill:$($sub.Name)"
                    if (-not (Restore-SkillBackup $dst $script:LastSkillBackup $existedBefore)) {
                        $script:Failed += "skill-rollback:$($sub.Name)"
                        Write-Warn "技能复制失败且旧版本回滚失败: $($sub.Name)"
                    } else {
                        Write-Warn "技能复制失败，旧版本已回滚: $($sub.Name)"
                    }
                }
            }
            Write-Ok 'safe-skills 子技能 -> ~/.pi/agent/skills/'
        } elseif ($s.Name -ne 'update') {
            $dst = Join-Path $SkillsDir $s.Name
            $existedBefore = Test-Path $dst
            $script:LastSkillBackup = ''
            try {
                if ($existedBefore -and -not (Backup-ExistingSkill $dst $s.Name)) {
                    throw 'existing skill backup failed'
                }
                if (Test-Path $dst) { Remove-Item $dst -Recurse -Force -ErrorAction Stop }
                if ($env:SEEP_INTERNAL_TEST_FAIL_SKILL_COPY -eq $s.Name) {
                    throw 'injected skill copy failure'
                }
                Copy-SkillTree $s.FullName $dst
                if (-not (Test-Path $dst)) { throw 'copy destination missing' }
                Write-Ok "skill: $($s.Name)"
            } catch {
                $script:SkillSyncOk = $false
                $script:Failed += "skill:$($s.Name)"
                if (-not (Restore-SkillBackup $dst $script:LastSkillBackup $existedBefore)) {
                    $script:Failed += "skill-rollback:$($s.Name)"
                    Write-Warn "技能复制失败且旧版本回滚失败: $($s.Name)"
                } else {
                    Write-Warn "技能复制失败，旧版本已回滚: $($s.Name)"
                }
            }
        }
    }
} else { Write-Warn "未找到 $srcSkills"; $script:Failed += 'skills' }

# ---------------------------------------------------------------- 3. 提示词 + 扩展
$srcPrompt = Join-Path $ToolDir 'prompts'
# ★ 文件名是 SEEP.md，不是 SYSTEM.md：pi 内核把 <agent-dir>/SYSTEM.md 理解为「替换默认系统提示词」，
#   与扩展的 sections["seep-reverse-lab"] 叠加会让整份规则在提示词里出现两次，并顶掉 pi 自带的默认提示词。
& python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --prompts-only
if ($LASTEXITCODE -ne 0) { $script:Failed += 'prompts'; Write-Warn '规则同步失败，原件保留' }

# 任务卡（prompt templates）：Tool/prompts/tasks/*.md → ~/.pi/agent/prompts/<name>.md
#   pi 把每个文件当一条 /slash 命令；这是"用户说一句话就开工"的入口，不进系统提示词（不占每轮上下文）。
$srcTasks = Join-Path $srcPrompt 'tasks'
$dstTasks = Join-Path $AgentDir 'prompts'
if (Test-Path $srcTasks) {
    if (-not (Test-Path $dstTasks)) { New-Item -ItemType Directory -Path $dstTasks -Force | Out-Null }
    # @SEEP_ROOT@ 占位符在这里替换成实际仓库根（正斜杠），
    # 这样命令卡里能写"绝对可读"的技能路径，而仓库本身不含机器专属路径（可移植性判据会红）
    $sep = [char]92
    $rootFwd = "$Root".Replace($sep, '/')
    $taskEncoding = New-Object System.Text.UTF8Encoding($false)
    if ([string]::IsNullOrWhiteSpace($rootFwd)) {
        Write-Warn "@SEEP_ROOT@ 替换失败（仓库根为空）——命令卡保留占位符，请检查"
    }
    foreach ($f in (Get-ChildItem $srcTasks -Filter '*.md' -ErrorAction SilentlyContinue)) {
        # README.md 是说明，不是任务卡（部署成 /README 就是废命令）
        if ($f.Name -eq 'README.md') { continue }
        $raw = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
        if ($raw -match '@SEEP_ROOT@') {
            if ([string]::IsNullOrWhiteSpace($rootFwd)) {
                Write-Warn "任务卡缺根路径，保留占位符: $($f.Name)"
            } else {
                $raw = $raw.Replace('@SEEP_ROOT@', $rootFwd)
            }
        }
        $raw = $raw.Replace("`r`n", "`n").Replace("`r", "`n")
        $taskDest = Join-Path $dstTasks $f.Name
        if ((Test-Path $taskDest) -and -not (Test-OwnedDeploymentFile ('prompts/' + $f.Name) $taskDest)) {
            Write-Info "保留无法证明归工作台所有的 prompt task: $($f.Name)"
        } else {
            if (Copy-ExtensionAsset -SourcePath $f.FullName -Destination $taskDest -TextContent $raw -BackupCategory tasks) {
                Write-Ok "task card: /$([System.IO.Path]::GetFileNameWithoutExtension($f.Name))"
            } else {
                $script:Failed += "task:$($f.Name)"
                Write-Warn "任务卡同步失败，原件保留: $($f.Name)"
            }
        }
    }
}

# 未能证明属于本工作台的历史 prompt 保留原位，避免把用户自有条目 retire。

# 迁移：旧版把规则写成 ~/.pi/agent/SYSTEM.md，会被 pi 内核当“替换默认提示词”，必须退役
$legacySystem = Join-Path $AgentDir 'SYSTEM.md'
if (Test-Path $legacySystem) {
    $isOurs = Select-String -Path $legacySystem -Pattern 'Seep Reverse Lab' -Quiet
    if ($isOurs) {
        $retired = Join-Path $AgentDir 'backup-retired-prompts'
        if (-not (Test-Path $retired)) { New-Item -ItemType Directory -Path $retired -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        Move-Item -Path $legacySystem -Destination (Join-Path $retired "SYSTEM.md.$stamp") -Force
        Write-Ok "已退役旧版 SYSTEM.md（会被 pi 内核当替换提示词）-> backup-retired-prompts/SYSTEM.md.$stamp"
    } else {
        Write-Warn "检测到非本工作台的 ~/.pi/agent/SYSTEM.md，保持原样（未迁移）"
    }
}
$srcExt = Join-Path $srcPrompt 'extensions'
if (Test-Path $srcExt) {
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.ts')) {
        try {
            if (-not (Copy-ExtensionAsset $f.FullName (Join-Path $ExtDir $f.Name))) { throw 'extension copy failed' }
            Write-Ok "extension: $($f.Name)"
        } catch { $script:Failed += "extension:$($f.Name)"; Write-Warn "扩展同步失败: $($f.Name)" }
    }
    # 扩展的配套规则文件（如 cmd-guard.rules.json：cmd-guard 从 __dirname 读它）
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.json' -ErrorAction SilentlyContinue)) {
        try {
            if (-not (Copy-ExtensionAsset $f.FullName (Join-Path $ExtDir $f.Name))) { throw 'extension rules copy failed' }
            Write-Ok "extension rules: $($f.Name)"
        } catch { $script:Failed += "extension:$($f.Name)"; Write-Warn "扩展规则同步失败: $($f.Name)" }
    }
    # 扩展的文档型配置（TOOL-CHAIN.md：cmd-guard 的 GUI→CLI 派生源；缺它会降级并常年告警）
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.md' -ErrorAction SilentlyContinue)) {
        try {
            if (-not (Copy-ExtensionAsset $f.FullName (Join-Path $ExtDir $f.Name))) { throw 'extension doc copy failed' }
            Write-Ok "extension doc: $($f.Name)"
        } catch { $script:Failed += "extension:$($f.Name)"; Write-Warn "扩展说明同步失败: $($f.Name)" }
    }
    # 自动安全退役与归档已融合的旧版独立扩展（其人设卡/RULES/粘性保护已100%全量融入 load-system-prompt.ts）
    $legacyCompat = Join-Path $ExtDir 'prompt-compat.ts'
    if (Test-Path $legacyCompat) {
        $retiredDir = Join-Path $AgentDir 'backup-retired-extensions'
        if (-not (Test-Path $retiredDir)) { New-Item -ItemType Directory -Path $retiredDir -Force | Out-Null }
        Move-Item -Path $legacyCompat -Destination (Join-Path $retiredDir 'prompt-compat.ts') -Force
        Write-Ok "已安全归档旧版独立扩展 prompt-compat.ts -> backup-retired-extensions/ (消除双重注册冲突)"
    }
}

# ---------------------------------------------------------------- 3.5 子代理定义（agents/*.md）
# pi 从 <agent-dir>/agents/*.md 读子代理角色；仓库是唯一事实源（Tool/prompts/agents/）。
# 为什么要有这一段：这些角色原先只存在于某台机器的 ~/.pi/agent/agents/ 里、仓库里没有，
# 换机器就等于“并行分工能力消失”，而门禁全绿看不出来。
$srcAgents = Join-Path $srcPrompt 'agents'
$dstAgents = Join-Path $AgentDir 'agents'
if (Test-Path $srcAgents) {
    if (-not (Test-Path $dstAgents)) { New-Item -ItemType Directory -Path $dstAgents -Force | Out-Null }
    foreach ($f in (Get-ChildItem $srcAgents -Filter '*.md' -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'README.md') { continue }
        $agentDest = Join-Path $dstAgents $f.Name
        if ((Test-Path $agentDest) -and -not (Test-OwnedDeploymentFile ('agents/' + $f.Name) $agentDest)) {
            Write-Info "保留无法证明归工作台所有的 agent: $($f.Name)"
        } else {
            if (Copy-ExtensionAsset -SourcePath $f.FullName -Destination $agentDest -BackupCategory agents) {
                Write-Ok "agent: $([System.IO.Path]::GetFileNameWithoutExtension($f.Name))"
            } else {
                $script:Failed += "agent:$($f.Name)"
                Write-Warn "子代理定义同步失败，原件保留: $($f.Name)"
            }
        }
    }
    # 未能证明属于本工作台的历史 agent 保留原位，避免无依据 retire。
    # 这份文件由 pi-web 用 readFileSync(path,'utf8') + JSON.parse 直接读，不剥 BOM。
    # 血案：PowerShell 5.1 的 `Set-Content -Encoding UTF8` 会写 BOM → JSON.parse 抛
    #   "Unexpected token '\uFEFF'" → pi-web 的 getBuiltInEnabled() catch 兜底成 false
    #   → 设置页「启用 Pi Web 内置子代理」显示关闭（文件里明明写着 true）、并发数回落默认 10、
    #   Agent 工具根本不注册 → 只能 bash 里套娃跑 `pi -p` 当子代理用。
    # 所以必须走 .NET 的无 BOM 写法（与下面 mcp.json / settings.json 一致）。
    & python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --agents-only
    if ($LASTEXITCODE -ne 0) {
        $script:Failed += 'agents-settings'
        Write-Warn '子代理设置文件无效或不可写，原件保留'
    }
} else { Write-Warn "未找到子代理定义目录 $srcAgents"; $script:Failed += 'agents' }

# ---------------------------------------------------------------- 4–5. 跨平台配置合并
# MCP 与 settings 复用 Shell 安装器的原子合并实现，保留深层用户数据。
& python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir
if ($LASTEXITCODE -ne 0) {
    $script:Failed += 'agent-config'
    Write-Warn 'MCP/settings 合并未完成，请按上方具体错误修复'
}

# ---------------------------------------------------------------- 6. 安装扩展包
if (-not $SkipPackages) {
    $pi = Get-Command pi -ErrorAction SilentlyContinue
    if ($pi) {
        Write-Info 'pi update --extensions ...'
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & pi update --extensions 2>&1 | ForEach-Object { Write-Info  $_ }
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'pi 扩展包已更新' }
        else { Write-Warn 'pi update 失败，可稍后手动执行：pi update --extensions'; $script:Failed += 'pi-packages' }
    } else {
        Write-Warn '未找到 Pi，请从 https://pi.dev 安装宿主后重跑；当前仅准备了配置'
        $script:Failed += 'pi-host-missing'
    }
}

# ---------------------------------------------------------------- 6.5 真实 runtime 注册（仅在 skill 拷贝成功后）
$entrySource = Join-Path $ToolDir 'skill\softseep\scripts\version-migrate.py'
$entryDest = Join-Path $SkillsDir 'softseep\scripts\version-migrate.py'
if (-not $script:SkillSyncOk) {
    Write-Warn '技能复制未完整成功，拒绝生成 runtime 注册'
    $script:Failed += 'runtime-registration-copy'
} elseif (-not (Test-Path $runtimeBridge)) {
    Write-Warn '缺少 runtime-root.py，拒绝生成 runtime 注册'
    $script:Failed += 'runtime-registration-helper'
} else {
    $registerArgs = @($runtimeBridge, 'register', '--agent-root', $AgentDir,
                      '--runtime-root', $Root, '--entry-source', $entrySource,
                      '--entry-dest', $entryDest)
    $registerOutput = @(& python @registerArgs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "runtime 注册失败，未登记 success: $($registerOutput -join ' ')"
        $script:Failed += 'runtime-registration'
    } else {
        Write-Ok 'runtime 已验证、部署 entry hash 一致并完成原子注册'
    }
}

# ---------------------------------------------------------------- 7. 扩展命名冲突自检（pi 的 replaceable 内置）
# 背景：pi 把部分内置标记为 replaceable（内置 MCP 即其一）。第三方扩展只要注册了同名
# 工具/命令/旗标（如 /mcp），内置就会被静默顶掉并在启动时打 [Extension issues]。
# 本步在**装完就报**，而不是等用户看启动横幅。
$conflictScript = Join-Path $ToolDir 'scripts\check-extension-conflicts.py'
if (Test-Path $conflictScript) {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        Write-Info '检查已装扩展是否与 pi 内置抢名（replaceable）...'
        & python $conflictScript --agent-dir $AgentDir 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-Warn '存在扩展与 pi 内置同名冲突：该扩展会顶掉内置，启动会出现 [Extension issues]。按上面提示处置。'
            $script:Failed += 'extension-conflict'
        } else {
            Write-Ok '扩展命名无冲突（pi 内置 MCP 等保持生效）'
        }
    }
}

# 退出码 = 真实失败（以前恒 exit 0，上游 install.ps1 永远以为成功）
if ($script:Failed.Count -gt 0) {
    if (-not (Write-InstallManifest 'incomplete')) { Write-Warn '安装所有权清单也未能更新为 incomplete' }
    Write-Warn "Pi 环境配置未完成，失败项: $($script:Failed -join ', ')"
    exit 1
}
if (-not (Write-InstallManifest 'complete')) {
    Write-Warn '安装内容已同步，但安装所有权清单无法更新为 complete'
    exit 1
}
exit 0
