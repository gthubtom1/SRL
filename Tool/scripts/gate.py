#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gate.py —— 按包判定（S3）：一份判据、可复现、unknown 永不计 pass。

判据（红 = 失败，不接受 skipped/unknown 记 pass）：
  G2 pack-schema      pack.json `.strict()`：多一个字段即红；l1 ≤140 字；limitations/invalidation/witness/cases 非空
  G3 route-parity     route.py 的解析空间与包里声明一致；0 条死路由 / 0 个重复 priority
  G4 pack-witness     真跑 witness.cmd（预算 budget_s）；exit≠0、expect 子句不满足 → 红
  G5 evidence-ledger  claim 必须带 confidence ∈ 四态 + authority；proven 必须有非空 evidence；
                      并**逐条执行**本包 evidence_contract.required_fields（claim/confidence/
                      authority 必须是非空字符串，evidence 必须是非空字符串数组；其余声明字段
                      按“存在且非空”检查，不静默跳过）；整包 0 条 observed/derived 证据 → 红
                      （hypothesis/refuted 是历史，不为 pass 背书，也不因缺字段把整包判红）
  G6 verification-receipt / G4b target-asset（回执可核、真输入资产）

摘要的读法（第 4 轮评审 P1-2，别把两件事读成一件）：
  `[GATE] N 个包：结构 pass/fail`  = 每个包的**判据**都跑通了（这条不放宽）。
  `[GATE] 见证证据：real x / public y / self-built z / fixture w` =
      这些包的 witness 案例里，多少是**真实产物**（real=客户真实目标，public=公开可分发的
      真实产物：教学靶场/CTF/公开 crackme/MIT 示例）；self-built 与 fixture 只证明
      **流程可跑**，**不得**读成「该域可用」。
  可用性三档口径：real 或 public → 计入「有真实产物见证」；self-built / fixture /
      unknown → 不计入。某包既无 real 也无 public 仍判 NOT PROVEN 并点名。

用法：
    python Tool/scripts/gate.py --all [--json] [--no-witness] [--require-usable]
    python Tool/scripts/gate.py --pack apkseep [--json]
    python Tool/scripts/gate.py --list
退出码：0 结构全绿且可用性 proven / 1 有红（结构 fail 优先）或 --require-usable 下未证明
        / 3 结构全绿但可用性 NOT PROVEN / 2 用法错误
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import route as route_mod  # noqa: E402  同一目录；路由判据与索引共用一套实现
sys.path.insert(0, os.path.join(HERE, "lib"))
import domain_registry as registry_mod  # noqa: E402  单向：registry 不 import gate/route
from typed_assets import TypedAssetError, _project_path, file_identity  # noqa: E402

CASES_DIR = os.path.join(ROOT, "Tool", "cases")
SERVER = os.path.join(ROOT, "Tool", "mcp", "seep_mcp_server.py")

PACK_KEYS = route_mod.PACK_KEYS
# Adapter contracts were added without changing the pack schema version.  Keep the
# legacy pack field set valid, but validate every declared adapter contract rather
# than treating it as an arbitrary extension point.
ADAPTER_FIELDS = {
    # 逐域静态深度要求（2026-10-27 从 lib/domain_spec 的硬编码九域表搬进各 pack）。
    # 严格校验：字段集合、类型、区间都在 lib/domain_registry.validate_depth_contract 里
    # 单点实现（本文件只消费它的 errors，不复制第二份阈值表）。
    "depth_contract": ("skill", "board", "matrix", "case_globs"),
    "project_lifecycle": ("entry", "manager", "handoff", "resume", "version", "run", "migration"),
    "input_contract": ("types", "sample_completeness", "environment"),
    "failure_contract": ("criteria", "block", "reroute"),
    "version_contract": ("version", "run", "migration", "variant", "incremental"),
    "extension_contract": ("entry", "docs", "pack", "parent_skill"),
}
PACK_SCHEMA_KEYS = PACK_KEYS | {"case_roles"} | set(ADAPTER_FIELDS) | set(route_mod.OPTIONAL_KEYS)
CONFIDENCE = ("observed", "derived", "inferred", "unknown")
AUTHORITY = ("shipped-artifact", "controlled-replay", "external-service", "reported", "none")
STRONG = ("observed", "derived")
MAX_L1 = 140


def _local_path(root, relative, within=None):
    if not isinstance(relative, str) or not relative.strip() or "\0" in relative:
        raise ValueError("本地引用必须是非空字符串")
    path = _project_path(Path(root), relative)
    if within is not None:
        boundary = _project_path(Path(root), within)
        try:
            path.relative_to(boundary)
        except ValueError as exc:
            raise ValueError("本地引用越出允许目录：%s" % relative[:64]) from exc
    return path


def _case_dir(name):
    if not isinstance(name, str) or name in (".", "..") or any(c in name for c in "/\\:"):
        raise ValueError("案例名必须是 cases/ 下的单个目录名")
    directory = _local_path(CASES_DIR, name)
    if not directory.is_dir():
        raise ValueError("案例目录不存在：%s" % name)
    return directory


def _command_argv(command):
    """Parse argv without a shell; Windows backslashes remain path characters."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("命令必须是非空字符串")
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    if os.name == "nt":
        lexer.escape = ""
    argv = list(lexer)
    if not argv or not argv[0]:
        raise ValueError("命令为空")
    if argv[0].lower() in ("python", "python3"):
        argv[0] = sys.executable
    elif argv[0].lower().endswith(".py"):
        argv.insert(0, sys.executable)
    return argv


def _witness_ref(pack):
    witness = pack.get("witness")
    if not isinstance(witness, dict):
        raise ValueError("witness 必须是对象")
    argv = _command_argv(witness.get("cmd"))
    refs = []
    for index, arg in enumerate(argv):
        if arg == "--case":
            if index + 1 >= len(argv):
                raise ValueError("--case 缺路径")
            refs.append(argv[index + 1])
        elif arg.startswith("--case="):
            refs.append(arg[len("--case="):])
    if len(refs) != 1:
        raise ValueError("witness 必须明确指定一个 --case")
    ref = refs[0].replace("\\", "/")
    if Path(ref).is_absolute():
        candidate = Path(os.path.abspath(ref))
    else:
        candidate = _local_path(ROOT, ref)
    directory = _case_dir(candidate.name)
    if os.path.normcase(os.path.abspath(candidate)) != os.path.normcase(os.path.abspath(directory)):
        raise ValueError("witness --case 必须对应 cases/ 下的原目录，不能只用同名目录替代")
    return directory.name, directory


def _witness_tool_contract(pack, witness_root=None):
    """Validate the domain-owned witness executable and its hashed case assets.

    A successful command is not enough: the executable must be the exact
    ``Tool/skill/<skill>/scripts/witness.py`` for this pack, its process output
    must identify this domain, and the paired witness case must bind existing
    target and output files by sha256.
    """
    errors = []
    if not isinstance(pack, dict):
        return {}, ["pack 必须是对象"]
    info = {}
    depth = pack.get("depth_contract")
    skill = str(depth.get("skill") or "").strip() if isinstance(depth, dict) else ""
    if not skill:
        skill = str(pack.get("id") or "").strip()
    if not skill or any(part in skill for part in ("/", "\\", ":")) or skill in (".", ".."):
        return info, ["无法从 pack.id/depth_contract.skill 解析 witness 所属技能"]

    witness_tool = pack.get("witness_tool")
    if not isinstance(witness_tool, dict):
        return info, ["witness_tool 必须是对象"]
    unknown_fields = set(witness_tool) - {"cmd", "why"}
    if unknown_fields:
        errors.append("witness_tool 含未知字段：%s" % ", ".join(sorted(unknown_fields)))
    if "why" in witness_tool and (
        not isinstance(witness_tool.get("why"), str) or not witness_tool["why"].strip()
    ):
        errors.append("witness_tool.why 必须是非空字符串")
    raw = witness_tool.get("cmd")
    expected = "Tool/skill/%s/scripts/witness.py" % skill
    if not isinstance(raw, str) or raw.replace("\\", "/") != expected:
        errors.append("witness_tool.cmd 必须是当前技能唯一脚本 %s（不得带参数/内联代码）" % expected)
        return info, errors
    script_root = Path(witness_root or ROOT)
    script_ref = expected
    try:
        if witness_root is not None:
            script_root = Path(witness_root).absolute()
            if not script_root.is_dir():
                raise ValueError("staged witness root 不是目录")
            if os.path.normcase(os.path.realpath(script_root)) != os.path.normcase(
                    os.path.abspath(script_root)):
                raise ValueError("staged witness root 不得经过 symlink/reparse")
            script_ref = "scripts/witness.py"
        script = _local_path(script_root, script_ref)
        identity = file_identity(script_root, script_ref)
    except (OSError, ValueError, TypedAssetError) as exc:
        errors.append("witness_tool 脚本无法按身份读取：%s" % str(exc)[:100])
        return info, errors
    info.update(script=expected, script_sha256=identity["sha256"])
    if witness_root is not None:
        info["script_source"] = "staged"

    try:
        case_name, case_dir = _witness_ref(pack)
        case_doc = _json_object(_local_path(case_dir, "case.json"))
    except (OSError, ValueError, TypedAssetError) as exc:
        errors.append("witness_tool 无法绑定 witness case：%s" % str(exc)[:100])
        return info, errors
    info["case"] = case_name

    target_hashes = []
    for index, item in enumerate(case_doc.get("target_files") or []):
        if not isinstance(item, dict):
            errors.append("target_files[%d] 必须是对象" % index)
            continue
        try:
            target = _local_path(
                case_dir, item.get("path"), within="target",
            )
            actual = file_identity(Path(case_dir), Path(target).relative_to(case_dir).as_posix())
        except (OSError, ValueError, TypedAssetError) as exc:
            errors.append("target_files[%d] 无法绑定：%s" % (index, str(exc)[:80]))
            continue
        expected_sha = str(item.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or actual["sha256"] != expected_sha:
            errors.append("target_files[%d] sha256 与案例原件不符" % index)
        else:
            target_hashes.append(expected_sha)
    if not target_hashes:
        errors.append("witness case 没有可核验的 target_files[] 原件")

    artifact_hashes = []
    artifacts = case_doc.get("artifacts")
    if artifacts is None:
        artifacts = []
    if not isinstance(artifacts, list):
        errors.append("case.json.artifacts 必须是数组")
        artifacts = []
    for index, item in enumerate(artifacts):
        if isinstance(item, str):
            rel = item
            expected_sha = ""
            expected_size = None
        elif isinstance(item, dict):
            rel = item.get("path")
            expected_sha = str(item.get("sha256") or "").strip().lower()
            expected_size = item.get("size")
        else:
            errors.append("artifacts[%d] 必须是路径字符串或对象" % index)
            continue
        try:
            artifact = _local_path(case_dir, rel)
            relative = Path(artifact).relative_to(case_dir).as_posix()
            actual = file_identity(Path(case_dir), relative)
        except (OSError, ValueError, TypedAssetError) as exc:
            errors.append("artifacts[%d] 无法绑定：%s" % (index, str(exc)[:80]))
            continue
        if expected_sha and (
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha)
            or actual["sha256"] != expected_sha
        ):
            errors.append("artifacts[%d] sha256 与案例产物不符" % index)
            continue
        if expected_size is not None and (
            type(expected_size) is not int or expected_size != actual["size"]
        ):
            errors.append("artifacts[%d] size 与案例产物不符" % index)
            continue
        artifact_hashes.append(actual["sha256"])
    if not artifact_hashes:
        # Older cases used string artifact paths or relied on the validated
        # facts ledger as evidence. Bind that ledger now so an empty artifacts
        # list is not treated as a successful evidence check.
        try:
            evidence = _claims(case_dir)
            facts = file_identity(Path(case_dir), "facts.jsonl")
        except (OSError, ValueError, TypedAssetError) as exc:
            errors.append("witness case 缺可核验证据：%s" % str(exc)[:80])
        else:
            if not evidence:
                errors.append("witness case 没有 artifacts[]，且 facts.jsonl 无有效 claim")
            else:
                info["evidence_sha256"] = {"facts.jsonl": facts["sha256"]}
    info["target_sha256"] = target_hashes
    info["artifact_sha256"] = artifact_hashes
    return info, errors


def _final_json_object(output):
    """Return the final top-level JSON object printed by a witness process."""
    decoder = json.JSONDecoder()
    found = None
    for match in re.finditer(r"(?m)^[ \t]*\{", output or ""):
        try:
            value, end = decoder.raw_decode((output or "")[match.end() - 1:])
        except ValueError:
            continue
        if not (output or "")[match.end() - 1 + end:].strip():
            if isinstance(value, dict):
                found = value
    return found


def _json_object(path):
    with Path(path).open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("%s 必须是 JSON 对象" % Path(path).name)
    return value


def _tool_names():
    """MCP 工具名集合：从 server 的 @server.tool() 定义处取，不猜。"""
    with Path(SERVER).open("r", encoding="utf-8", errors="strict") as f:
        text = f.read()
    names = set(re.findall(r"^def (seep_\w+)\(", text, re.M))
    if not names:
        raise ValueError("server 中未找到任何 seep_* 工具定义")
    return names


def _claims(case_dir):
    """读 claim；损坏行不能从通过判据里静默消失。其他账本种类仍保留。"""
    fp = _local_path(case_dir, "facts.jsonl")
    out = []
    seen = set()
    with fp.open("r", encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except ValueError as exc:
                raise ValueError("facts.jsonl 第 %d 行不是合法 JSON" % number) from exc
            if not isinstance(o, dict):
                raise ValueError("facts.jsonl 第 %d 行必须是对象" % number)
            if o.get("kind") is not None and not isinstance(o["kind"], str):
                raise ValueError("facts.jsonl 第 %d 行 kind 类型错误" % number)
            if str(o.get("kind") or "claim").strip().lower() not in ("", "claim"):
                continue
            if any(not isinstance(o.get(key), str) or not o[key].strip() for key in ("id", "status")):
                raise ValueError("facts.jsonl 第 %d 行 claim 缺有效 id/status" % number)
            if o["id"] in seen:
                raise ValueError("facts.jsonl 第 %d 行 claim id 重复：%s" % (number, o["id"]))
            seen.add(o["id"])
            out.append(o)
    return out


def _evidence_replayable(case_dir, value):
    """复用 case_state 的证据解析器，避免 gate 只把非空字符串当证据。

    case_state.require_evidence 会用 SystemExit 表达拒绝；gate 把它收敛为布尔结果，
    并屏蔽实现层错误文案，防止自检输出污染按包汇总。
    """
    if not str(value or "").strip():
        return False
    try:
        import contextlib
        import importlib.util
        import io
        path = os.path.join(ROOT, "Tool", "scripts", "case_state.py")
        spec = importlib.util.spec_from_file_location("seep_case_state_for_gate", path)
        mod = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(mod)
            result = mod.require_evidence(str(value), case_dir)
        return bool(result)
    except (SystemExit, Exception):
        return False


# required_fields 里 gate 有明确语义的字段；其余声明字段按“存在 + 非空值”检查。
REQUIRED_STRING_FIELDS = ("claim", "confidence", "authority")


def _required_field_defects(fact, field):
    """逐条执行 pack.evidence_contract.required_fields 的一项。返回缺陷文案（空=合格）。

    白名单语义（缺失即红）：
      claim             非空字符串（空格/空串不算有主张）
      confidence/authority 非空字符串（枚举取值由 G5 既有判据另查）
      evidence          非空**字符串数组**（单个字符串不是数组，不能按字符逐字通过）
    未内建的声明字段：按声明检查“存在且有值”，不做语义猜测，也**不静默跳过**。
    """
    if not isinstance(fact, dict) or field not in fact:
        return ["required_fields 缺声明字段 %s" % field]
    value = fact.get(field)
    if field in REQUIRED_STRING_FIELDS:
        if not isinstance(value, str) or not value.strip():
            return ["required_fields.%s 必须是非空字符串" % field]
        return []
    if field == "evidence":
        if not isinstance(value, list) or not value:
            return ["required_fields.evidence 必须是非空字符串数组（字符串/空数组不算）"]
        if any(not isinstance(x, str) or not x.strip() for x in value):
            return ["required_fields.evidence 含非字符串或空白项"]
        return []
    if isinstance(value, str):
        return [] if value.strip() else ["required_fields.%s 声明了但值为空白字符串" % field]
    if isinstance(value, (list, tuple, dict, set)):
        return [] if len(value) else ["required_fields.%s 声明了但值为空容器" % field]
    if value is None:
        return ["required_fields.%s 声明了但值为 null" % field]
    if isinstance(value, (bool, int, float)) and not value:
        # 未内建语义的字段不做类型猜测，但零/false 不能当作“有值”：宁可报红也不静默放过。
        return ["required_fields.%s 声明了但值为空值（%r）" % (field, value)]
    return []


def _nonempty(value):
    """Basic adapter shape check; path and nested value semantics live elsewhere."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def g2_schema(pack, witness_root=None):
    """G2: strict top-level keys plus basic checks for declared adapter contracts.

    The five adapter contracts are optional for compatibility with the original
    seep.pack/1 shape.  Once present, each must be an object with its required
    non-empty members; domain-adapter-check owns path and nested type semantics.
    """
    if not isinstance(pack, dict):
        return ["pack 必须是对象"]
    bad = []
    keys = set(pack)
    extra, miss = keys - PACK_SCHEMA_KEYS, PACK_KEYS - keys
    if extra:
        bad.append("多出未声明字段：%s" % ",".join(sorted(extra)))
    if miss:
        bad.append("缺字段：%s" % ",".join(sorted(miss)))
    if pack.get("schema") != "seep.pack/1":
        bad.append("schema 必须是 seep.pack/1")
    for field, required in ADAPTER_FIELDS.items():
        if field not in pack:
            continue
        value = pack.get(field)
        if not isinstance(value, dict):
            bad.append("%s 必须是对象" % field)
            continue
        missing = [key for key in required if key not in value]
        if missing:
            bad.append("%s 缺必要字段：%s" % (field, ",".join(missing)))
        for key in required:
            if key in value and not _nonempty(value.get(key)):
                bad.append("%s.%s 不能为空" % (field, key))
    # depth_contract 的**严格**校验（区间/未知字段/skill 目录/SKILL.md/归档目录）：
    # 允许“没写”（legacy pack 兼容），但不允许“写了却用小字段放宽门槛”。
    if "depth_contract" in pack:
        _depth, _depth_errors = registry_mod.validate_depth_contract(pack, ROOT)
        for reason in _depth_errors:
            if reason not in bad:
                bad.append(reason)
    l1 = str(pack.get("l1") or "")
    if not l1.strip():
        bad.append("l1 为空（进索引的唯一字符串）")
    elif len(l1) > MAX_L1:
        bad.append("l1 超长 %d > %d 字" % (len(l1), MAX_L1))
    for field in ("limitations", "invalidation", "cases", "tools", "stages"):
        v = pack.get(field)
        if not isinstance(v, list) or not v or any(not isinstance(x, str) or not x.strip() for x in v):
            bad.append("%s 必须是非空字符串数组（禁空）" % field)
    for c in pack.get("cases") if isinstance(pack.get("cases"), list) else []:
        try:
            _case_dir(c)
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append("案例无效：%s（%s）" % (c, exc))
    roles = pack.get("case_roles")
    if not isinstance(roles, dict):
        bad.append("case_roles 必须是对象")
    else:
        extra_roles = set(roles) - {"witness", "depth_gate"}
        if extra_roles:
            bad.append("case_roles 含未知角色：%s" % ",".join(sorted(extra_roles)))
        missing_roles = [name for name in ("witness", "depth_gate") if name not in roles]
        if missing_roles:
            bad.append("case_roles 缺必要数组：%s" % ",".join(missing_roles))
        for name in ("witness", "depth_gate"):
            value = roles.get(name)
            if name not in roles:
                continue
            if not isinstance(value, list) or not value or any(
                    not isinstance(x, str) or not x.strip() for x in value):
                bad.append("case_roles.%s 必须是非空字符串数组（禁空）" % name)
        if isinstance(roles.get("witness"), list) and roles.get("witness") != pack.get("cases"):
            bad.append("case_roles.witness 必须与 cases 一致")
    try:
        names = _tool_names()
    except (OSError, UnicodeError, ValueError) as exc:
        bad.append("无法读取 MCP 工具清单，不能把工具存在性检查当成通过：%s" % exc)
        names = set()
    for t in pack.get("tools") if isinstance(pack.get("tools"), list) else []:
        if str(t) not in names:
            bad.append("工具不存在：%s（不在 @server.tool() 清单里）" % t)
    w = pack.get("witness")
    if not isinstance(w, dict) or not str(w.get("cmd") or "").strip():
        bad.append("witness.cmd 为空：没有可执行判据")
    elif not str(w.get("expect") or "").strip():
        bad.append("witness.expect 为空")
    elif type(w.get("budget_s")) is not int or w["budget_s"] <= 0:
        bad.append("witness.budget_s 必须是正整数")
    ec = pack.get("evidence_contract")
    if not isinstance(ec, dict):
        bad.append("evidence_contract 必须是对象")
    else:
        need = {"required_fields", "authority_allow", "pass_forbids_confidence"}
        if set(ec) != need:
            bad.append("evidence_contract 字段必须恰好是 %s" % "/".join(sorted(need)))
        for k in need:
            if not isinstance(ec.get(k), list) or not ec.get(k) or any(
                    not isinstance(x, str) or not x.strip() for x in ec[k]):
                bad.append("evidence_contract.%s 必须是非空字符串数组" % k)
        # required_fields 是 G5 逐条执行判据的输入：这里只校验声明本身是否可用
        # （非字符串 / 空白 / 重复 / null 都不能被当成“有声明”）。值语义由 G5 逐 claim 检查。
        required_fields = ec.get("required_fields")
        if isinstance(required_fields, list):
            seen_fields = set()
            for name in required_fields:
                if not isinstance(name, str) or not name.strip():
                    bad.append("evidence_contract.required_fields 含非字符串或空白项：%r" % (name,))
                    continue
                key = name.strip()
                if key in seen_fields:
                    bad.append("evidence_contract.required_fields 重复：%s" % key)
                seen_fields.add(key)
        for c in ec.get("pass_forbids_confidence") if isinstance(ec.get("pass_forbids_confidence"), list) else []:
            if c not in CONFIDENCE:
                bad.append("pass_forbids_confidence 里有非法值：%s" % c)
    _tool_info, tool_errors = _witness_tool_contract(pack, witness_root=witness_root)
    bad.extend(tool_errors)
    return bad


def g3_routes(pack, route_index):
    bad = []
    if not pack.get("routes"):
        bad.append("routes 为空：该包不可路由")
    mine = [r for r in (route_index.get("rows") or []) if r[1] == pack.get("id")]
    if len(mine) != len(pack.get("routes") or []):
        bad.append("routes 数量不一致：pack.json %d / 索引 %d"
                   % (len(pack.get("routes") or []), len(mine)))
    for p in route_index.get("problems") or []:
        bad.append("route: " + p)
    return bad


def _clause_ok(clause, rc, case_dir):
    c = clause.strip().lower()
    if c in ("exit0", "exit=0"):
        return rc == 0, ("witness 退出码 %d" % rc if rc else "")
    m = re.match(r"^facts\s*>=\s*(\d+)$", c)
    if m:
        try:
            n = len(_claims(case_dir))
        except (OSError, ValueError, TypedAssetError) as exc:
            return False, "事实账无法核验：%s" % exc
        need = int(m.group(1))
        return n >= need, ("facts %d < %d" % (n, need) if n < need else "")
    if c.endswith("manifest.sha256"):
        bad, seen = [], set()
        try:
            p = _local_path(case_dir, clause.strip())
            with p.open(encoding="utf-8") as fh:
                for number, ln in enumerate(fh, 1):
                    if not ln.strip():
                        continue
                    parts = ln.strip().split(None, 1)
                    if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
                        bad.append("清单第 %d 行格式错误" % number)
                        continue
                    want, rel = parts[0].lower(), parts[1].strip()
                    fp = _local_path(case_dir, rel)
                    key = os.path.normcase(os.path.abspath(fp))
                    if key in seen:
                        bad.append("清单重复文件：%s" % rel)
                    seen.add(key)
                    if file_identity(Path(case_dir), rel)["sha256"] != want:
                        bad.append("哈希不符 %s" % rel)
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append("清单无法核验：%s" % exc)
        if not seen:
            bad.append("清单无有效文件条目")
        return (not bad), ("；".join(bad[:3]) if bad else "")
    return False, "无法机检的 expect 子句：%r（不当作通过）" % clause


def g4_witness(pack, run=True):
    if not run:  # 跳过实跑 = skipped：按判据「skipped 不得计 pass」处理，不是通过
        return ["G4 skipped（--no-witness）：witness 未实跑，不得计 pass"], {"ran": False}
    try:
        _case, case_dir = _witness_ref(pack)
        w = pack["witness"]
        cmd = w["cmd"]
        argv = _command_argv(cmd)
        budget = w.get("budget_s")
        if type(budget) is not int or budget <= 0:
            raise ValueError("witness.budget_s 必须是正整数")
        if not isinstance(w.get("expect"), str) or not w["expect"].strip():
            raise ValueError("witness.expect 必须是非空字符串")
    except (OSError, ValueError, TypedAssetError) as exc:
        return ["witness 配置无效：%s" % exc], {"ran": False}
    try:
        r = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=budget)
        rc, out = r.returncode, ((r.stdout or "") + (r.stderr or ""))[-400:]
    except subprocess.TimeoutExpired:
        return ["witness 超预算 %ds：%s" % (budget, cmd)], {"ran": True, "rc": None}
    except Exception as e:  # noqa: BLE001
        return ["witness 无法执行：%s" % str(e)[:80]], {"ran": True, "rc": None}
    bad = ["witness 退出码 %d" % rc] if rc else []
    # witness_tool 的真运行必须绑定“当前技能的唯一 witness.py”及其案例
    # target/artifact 哈希；任意成功的 python -c 不得充当域见证。
    tool_info, tool_errors = _witness_tool_contract(pack)
    bad.extend(tool_errors)
    if not tool_errors:
        try:
            r2 = subprocess.run(
                [sys.executable, "-B", os.path.join(ROOT, tool_info["script"]), "--self-test"],
                cwd=ROOT, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=180,
            )
            if r2.returncode != 0:
                tail = ((r2.stdout or "") + (r2.stderr or ""))[-300:]
                bad.append("witness_tool 失败(rc=%d)：%s" % (r2.returncode, tail[:180]))
            else:
                payload = _final_json_object(r2.stdout or "")
                if not isinstance(payload, dict) or payload.get("ok") is not True:
                    bad.append("witness_tool 未输出最终 ok=true JSON 结论")
                elif payload.get("domain") != pack.get("id"):
                    bad.append("witness_tool domain=%r 与 pack.id=%r 不一致" % (
                        payload.get("domain"), pack.get("id")))
                elif not str(payload.get("witness") or "").strip():
                    bad.append("witness_tool 未声明 witness 证据状态")
        except Exception as e:  # noqa: BLE001
            bad.append("witness_tool 无法执行：%s" % str(e)[:80])
    for clause in str(w.get("expect") or "").split("+"):
        ok, why = _clause_ok(clause, rc, case_dir)
        if not ok:
            bad.append(why or ("不满足：%s" % clause.strip()))
    return bad, {
        "ran": True, "rc": rc, "tail": out.strip().splitlines()[-3:],
        "witness_tool": tool_info,
    }


def g5_evidence(pack):
    bad, total_claims, strong = [], 0, 0
    contract = pack.get("evidence_contract")
    fields = ("authority_allow", "pass_forbids_confidence", "required_fields")
    if not isinstance(contract, dict) or any(
            not isinstance(contract.get(key), list) or not contract[key] or any(
                not isinstance(value, str) or not value.strip() for value in contract[key]) for key in fields):
        return ["evidence_contract 必须声明有效的 authority_allow/pass_forbids_confidence/required_fields 字符串数组"], {"claims": 0, "strong": 0}
    allowed_authority = {str(x).strip().lower() for x in (contract.get("authority_allow") or [])}
    forbidden_confidence = {str(x).strip().lower() for x in (contract.get("pass_forbids_confidence") or [])}
    required_fields = [str(x).strip() for x in (contract.get("required_fields") or [])
                       if isinstance(x, str) and str(x).strip()]
    cases = pack.get("cases")
    if not isinstance(cases, list) or not cases:
        return ["cases 必须是非空案例数组"], {"claims": 0, "strong": 0}
    for cname in cases:
        try:
            cdir = _case_dir(cname)
            claims = _claims(cdir)
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append("%s 事实账无法核验：%s" % (cname, exc))
            continue
        total_claims += len(claims)
        for f in claims:
            conf = str(f.get("confidence") or "").strip().lower()
            auth = str(f.get("authority") or "").strip().lower()
            fid = f.get("id")
            status = str(f.get("status") or "").strip().lower()
            if status not in ("hypothesis", "proven", "refuted"):
                bad.append("%s/%s claim 状态不能为 pass 背书：%s" % (cname, fid, status))
            if auth and auth not in AUTHORITY:
                bad.append("%s/%s authority 非法：%s" % (cname, fid, auth))
            if status == "proven" and auth not in allowed_authority:
                bad.append("%s/%s proven authority 不在本包 evidence_contract.authority_allow：%s" % (cname, fid, auth or "<empty>"))
            # 证据契约只管「能替 pass 背书的 claim」（proven）；refuted / hypothesis 是历史记录，
            # 不参与 pass（verify 也不把它们当通过）。
            if status == "proven":
                # required_fields 必须**逐条真执行**：只查 authority/confidence 会让
                # “缺 claim 但 evidence 是真日志”的 claim 混过 G5（本轮修复的缺口）。
                failed_fields = set()
                for field in required_fields:
                    defects = _required_field_defects(f, field)
                    if defects:
                        failed_fields.add(field)
                        for why in defects:
                            bad.append("%s/%s %s" % (cname, fid, why))
                if "confidence" not in failed_fields and conf not in CONFIDENCE:
                    bad.append("%s/%s proven 缺 confidence（按 unknown 计，不计 pass）" % (cname, fid))
                if conf in forbidden_confidence:
                    bad.append("%s/%s proven confidence 被本包 evidence_contract 禁止：%s" % (cname, fid, conf or "<empty>"))
                if conf in STRONG and auth in allowed_authority:
                    strong += 1
                evidence = f.get("evidence")
                if "evidence" in failed_fields:
                    pass  # 上面已按 required_fields 报过缺/类型错，不重复报同一件事
                elif not isinstance(evidence, list) or not evidence or any(
                        not isinstance(e, str) or not e.strip() for e in evidence):
                    bad.append("%s/%s proven 的 evidence 必须是非空字符串数组" % (cname, fid))
                elif not any(_evidence_replayable(cdir, e) for e in evidence):
                    bad.append("%s/%s proven 的 evidence 无法解析为本案可复核材料" % (cname, fid))
    if total_claims == 0:
        bad.append("本包所有案例 facts 为空：0 条 claim（unknown 不得计 pass）")
    elif strong == 0:
        bad.append("本包 0 条 observed/derived 证据（%d 条 claim 全是 unknown/inferred）" % total_claims)
    return bad, {"claims": total_claims, "strong": strong}



def _receipt_paths(case):
    """docs/verification/<case>-<date>.json 里最新的一份。"""
    directory = _local_path(ROOT, "docs/verification")
    if not directory.is_dir():
        return ""
    found = sorted(p for p in directory.iterdir() if p.name.startswith(case + "-") and p.suffix == ".json")
    return str(found[-1]) if found else ""


def _case_cohort(case_dir):
    """现算 cohort：claims / proven / strong。与 case_state verify 同口径。"""
    facts = _claims(case_dir)
    proven = [f for f in facts if f["status"].strip().lower() == "proven"]
    strong = sum(1 for f in proven if str(f.get("confidence") or "").strip().lower() in STRONG
                 and str(f.get("authority") or "none").strip().lower()
                 in ("shipped-artifact", "controlled-replay", "external-service"))
    return {"claims": len(facts), "proven": len(proven), "strong": strong}


def g6_receipt(pack):
    """G6：每个包的 witness 案例必须有一份可核对的 verification receipt。

    判据（三条，任一不满足即红）：
      1) docs/verification/<case>-<date>.json 存在；
      2) cohorts.baseline / cohorts.final 都在，且 final 的 claims/proven/strong 与**现算值**一致
         （不能手填一个好看的数）；
      3) source_sha256 里每个文件的哈希与当前工作树一致（改了事实账就必须更新回执）。
    """
    bad = []
    try:
        case, case_dir = _witness_ref(pack)
        rp = _receipt_paths(case)
    except (OSError, ValueError, TypedAssetError) as exc:
        return ["回执案例无法定位：%s" % exc], {}
    if not rp:
        return ["缺 verification receipt：docs/verification/%s-<date>.json" % case], {"case": case}
    try:
        relative = os.path.relpath(rp, ROOT).replace(os.sep, "/")
        d = _json_object(_local_path(ROOT, relative))
    except (OSError, ValueError, TypedAssetError) as e:
        return ["回执解析失败：%s" % str(e)[:60]], {"case": case}
    if d.get("schema") != "seep.verification/1" or d.get("case") != case:
        bad.append("回执 schema/case 与当前案例不一致")
    co = d.get("cohorts")
    if not isinstance(co, dict) or any(not isinstance(co.get(key), dict) for key in ("baseline", "final")):
        bad.append("回执缺 cohorts.baseline 或 cohorts.final（前后配对是这份回执的全部意义）")
    else:
        counts_valid = True
        for stage in ("baseline", "final"):
            counts = co[stage]
            if any(type(counts.get(k)) is not int or counts[k] < 0 for k in ("claims", "proven", "strong")):
                bad.append("cohorts.%s 计数必须是非负整数" % stage)
                counts_valid = False
            elif not counts["claims"] >= counts["proven"] >= counts["strong"]:
                bad.append("cohorts.%s claims/proven/strong 次序无效" % stage)
                counts_valid = False
        try:
            now = _case_cohort(case_dir)
            if counts_valid:
                for k in ("claims", "proven", "strong"):
                    if co["final"][k] != now[k]:
                        bad.append("final.%s=%s 与现算 %d 不一致（回执过期或手填）" % (k, co["final"][k], now[k]))
                if co["baseline"]["strong"] >= co["final"]["strong"] > 0:
                    bad.append("baseline.strong 不小于 final.strong：这次改动没有产生可测的差异")
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append("事实账无法核验：%s" % exc)
    sha = d.get("source_sha256")
    if not isinstance(sha, dict) or not sha:
        bad.append("回执缺有效 source_sha256（无法证明回执对应的是当前这份事实账）")
        sha = {}
    bound_facts = False
    for rel, want in sha.items():
        try:
            fp = _local_path(case_dir, rel)
            if not isinstance(want, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", want):
                raise ValueError("摘要必须是 64 位 sha256")
            identity = file_identity(case_dir, rel)
            if identity["sha256"] != want.lower():
                bad.append("%s 的哈希与回执不一致（事实账改过，回执需重写）" % rel)
            if fp == case_dir / "facts.jsonl":
                bound_facts = True
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append("source_sha256.%s 无法核验：%s" % (rel, exc))
    if not bound_facts:
        bad.append("source_sha256 必须绑定本案 facts.jsonl")
    return bad, {"case": case, "receipt": os.path.relpath(rp, ROOT).replace(os.sep, "/")}




def _owed_vs_ledger(pack):
    """案例声称的交付档 vs 账本里真实的重放记录（第 5 轮评审 P1：修过仍不成立）。

    ★ 为什么单独列一行：`golden-crackme` 在报告里写 M3，但 facts.jsonl 里 0 条 repro，
      `deliver` 会拒绝——也就是说"该域可用"的承诺没有账本支撑。
      这里不改结构判定（9/9 仍是 9/9），但把"承诺 > 证据"的案例点名，避免 9/9 被读成"都能用"。
    """
    try:
        case, cd = _witness_ref(pack)
        cj = _json_object(_local_path(cd, "case.json"))
    except (OSError, ValueError, TypedAssetError):
        return None
    claimed = str(cj.get("goal_level") or cj.get("max_level") or "").upper()
    if not re.match(r"^(M[2-4]|L[2-9])$", claimed):
        return None
    repro = 0
    try:
        with _local_path(cd, "facts.jsonl").open(encoding="utf-8") as stream:
            for ln in stream:
                if not ln.strip():
                    continue
                d = json.loads(ln)
                if isinstance(d, dict) and d.get("kind") == "repro" and d.get("consistent") is True \
                        and type(d.get("runs")) is int and d["runs"] >= 2:
                    repro += 1
    except (OSError, ValueError, TypedAssetError):
        pass
    if repro == 0:
        return (case, claimed)
    return None


def g4b_target(pack):
    """G4b：witness 案例必须有**真实输入资产**（D1 的机检版）。

    判据：
      1) `<case>/target/` 存在且至少 1 个文件（不是空目录占位）；
      2) `case.json.target_files[]` 里每个文件都在、哈希与磁盘一致
         （防止"写了 sha256 但文件换过"）；
      3) target_files 至少 1 条（没登记等于没资产）。
    """
    try:
        case, cdir = _witness_ref(pack)
        tdir = _local_path(cdir, "target")
        if not tdir.is_dir():
            raise ValueError("缺 target/（无可复跑的真实输入）")
        rec = _json_object(_local_path(cdir, "case.json")).get("target_files")
        if not isinstance(rec, (list, dict)) or not rec:
            raise ValueError("case.json 缺非空 target_files[]（资产未登记 sha256）")
    except (OSError, ValueError, TypedAssetError) as exc:
        return ["目标资产无法核验：%s" % exc], {}
    entries = list(rec.items()) if isinstance(rec, dict) else [(None, item) for item in rec]
    bad, seen, verified = [], set(), 0
    for key, meta in entries:
        try:
            if not isinstance(meta, dict):
                raise ValueError("target_files 元素必须是对象")
            rel = meta.get("path", key)
            if key is not None and "path" in meta and meta["path"] != key:
                raise ValueError("target_files 键与 path 不一致")
            fp = _local_path(cdir, rel)
            if not fp.is_relative_to(tdir) or fp == tdir:
                raise ValueError("target_files 必须登记 target/ 内的文件")
            identity_key = os.path.normcase(os.path.abspath(fp))
            if identity_key in seen:
                raise ValueError("target_files 文件重复：%s" % rel)
            seen.add(identity_key)
            want = meta.get("sha256")
            if not isinstance(want, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", want):
                raise ValueError("target_files.sha256 必须是 64 位摘要")
            identity = file_identity(cdir, rel)
            if want.lower() != identity["sha256"]:
                raise ValueError("%s 的 sha256 与登记值不一致（资产被替换过）" % rel)
            if "size" in meta and (type(meta["size"]) is not int or meta["size"] != identity["size"]):
                raise ValueError("%s 的 size 与实际文件不一致" % rel)
            verified += 1
        except (OSError, ValueError, TypedAssetError) as exc:
            bad.append(str(exc))
    return bad, {"case": case, "targets": verified}


def judge(pack, route_index, run_witness=True):
    gates = {}

    def add(name, bad, info=None):
        gates[name] = {"status": "pass" if not bad else "fail",
                       "reasons": bad[:6], "info": info or {}}

    schema_errors = g2_schema(pack)
    add("G2 pack-schema", schema_errors)
    try:
        add("G3 route-parity", g3_routes(pack, route_index))
    except (TypeError, ValueError, AttributeError, IndexError) as exc:
        add("G3 route-parity", ["路由输入无效：%s" % exc])
    if schema_errors:
        bad4, info4 = ["pack-schema 失败，witness 未执行"], {"ran": False}
    else:
        bad4, info4 = g4_witness(pack, run=run_witness)
    add("G4 pack-witness", bad4, info4)
    bad5, info5 = g5_evidence(pack)
    add("G5 evidence-ledger", bad5, info5)
    bad6, info6 = g6_receipt(pack)
    add("G6 verification-receipt", bad6, info6)
    bad7, info7 = g4b_target(pack)
    add("G4b target-asset", bad7, info7)
    verdict = "pass" if all(g["status"] == "pass" for g in gates.values()) else "fail"
    return {"pack": pack.get("id"), "verdict": verdict, "gates": gates}



def judge_answer(trap_id, answer):
    """对一段真实回答打分（D2 持续回归）。

    判据：`expect_tokens` 每组**至少命中一个**；`forbidden_tokens` **一个都不许出现**。
    缺任一组 / 命中任一禁忌词 → FAIL（不做"差不多就行"的模糊判定）。
    """
    import glob as _glob
    tps = []
    for f in _glob.glob(os.path.join(ROOT, "Tool", "config", "traps.json")):
        with open(f, encoding="utf-8") as stream:
            tps = json.load(stream).get("traps") or []
    trap = next((t for t in tps if t.get("id") == trap_id), None)
    if not trap:
        return {"ok": False, "error": "no_such_trap", "id": trap_id}
    low = (answer or "").lower()
    missing, hit_forbidden = [], []
    for gi, group in enumerate(trap.get("expect_tokens") or [], 1):
        if not any(tok.lower() in low for tok in group):
            missing.append("第%d组缺一：%s" % (gi, " / ".join(group)))
    for tok in trap.get("forbidden_tokens") or []:
        if tok.lower() in low:
            hit_forbidden.append(tok)
    ok = not missing and not hit_forbidden
    return {"ok": ok, "id": trap_id, "pack": trap.get("pack"),
            "missing_groups": missing, "forbidden_hits": hit_forbidden,
            "chars": len(answer or "")}


def _witness_case(pack):
    """witness.cmd 里的 --case 案例名（没写就返回空）。"""
    try:
        return _witness_ref(pack)[0]
    except (OSError, ValueError, TypedAssetError):
        return ""


def _evidence_kind(case):
    """案例的真实性类型：case.json 的 evidence_kind。

    读不到了（没 case.json / 没字段 / 解析失败）= "unknown" → **按 fixture 计**。
    宁可把真样本误报成 fixture，也不要把夹具冒充成「该域真实可用」。

    分档（语义唯一来源 Tool/scripts/lib/domain_spec.EVIDENCE_KINDS）：
      real       = 客户真实目标（来源与授权可追）
      public     = 公开可分发的**真实产物**（教学靶场 / CTF / 公开 crackme / MIT 示例）
      self-built = 自己编译的（流程证据，不算该域可用）
      fixture    = 合成/教学夹具（不是真实产物）
      historical = 历史归档
    """
    if not case:
        return "unknown"
    try:
        d = _json_object(_local_path(_case_dir(case), "case.json"))
        k = str((d or {}).get("evidence_kind") or "").strip().lower()
        return k or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


# 「有真实产物见证」的两档：real（客户目标）+ public（公开真实产物）。
# self-built / fixture / historical / unknown **不算** —— 它们只证明流程跑得通。
REAL_ARTIFACT_KINDS = ("real", "public")

# ★ 2026-10-26 审计（第 2 条否决）：`public` 曾是**纯标签**——evidence_source 有 0 处代码读它，
#   于是"public 必须带来源与 sha256""不许把 self-built 改叫 public 凑可用"两条都只是文档。
#   这里补机检，让标签骗不过去。判据（全部满足才算 public，否则**降回 self-built**）：
#     ① case.json 有 evidence_source 字典，含非空 source 与 basis
#     ② source 里能捞到 sha256（64 hex）或明确 sha256 字段
#     ③ basis/source 不得自述"本机 gcc/msvc/clang 编译"——那是 self-built 的定义
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
# "本机编译"只有在**肯定句**里描述被见证的产物时才降档；
# 否定句（"不是本机编译的"）与加壳/压缩语境不算。
_LOCAL_BUILD_RE = re.compile(r"(?<![不非没未])(本机|本地|自己)\s*(gcc|msvc|clang|编译)")
_NEGATED_RE = re.compile(r"(不是|并非|非|不属于|不算)\s*(本机|本地|自己)?\s*(编译|gcc|msvc|clang)")
_PACKER_RE = re.compile(r"(upx|压缩|加壳|packed|重打包|脱壳)", re.I)


def _public_claim_defects(case):
    """校验 evidence_kind=public 的案例是否**当得起** public。返回缺陷列表（空=合格）。

    ★ 2026-10-26 审计（第 2 条否决）：`public` 曾是**纯标签**——没有代码读 evidence_source，
      于是"public 必须带来源与 sha256""不许把 self-built 叫 public 凑可用"两条都只是文档。
      这里补机检：public 必须在 case.json 写清来源 + 实测 sha256，且不得自述"本机编译"。
      不合格 → 调用方应降回 self-built（gate 会如实报 NOT PROVEN，不许涂绿）。
    """
    if not case:
        return ["无案例目录"]
    try:
        d = _json_object(_local_path(_case_dir(case), "case.json"))
    except (OSError, ValueError, TypedAssetError) as e:
        return ["case.json 解析失败(%s)" % type(e).__name__]
    es = d.get("evidence_source")
    if not isinstance(es, dict):
        return ["缺 evidence_source（public 必须写来源与 sha256）"]
    src = str(es.get("source") or "")
    basis = str(es.get("basis") or "")
    bad = []
    if not src.strip():
        bad.append("evidence_source.source 为空")
    if not basis.strip():
        bad.append("evidence_source.basis 为空")
    blob = src + " " + basis + " " + str(es.get("sha256") or "")
    if not _SHA256_RE.search(blob.replace("\\", "")):
        bad.append("来源/依据里找不到 64 位 sha256")
    for seg in re.split(r"[。；;\n]", blob):
        if _PACKER_RE.search(seg):
            continue
        if _NEGATED_RE.search(seg):
            continue
        m = _LOCAL_BUILD_RE.search(seg)
        if m:
            bad.append("自述「%s」→ 按定义应记 self-built" % m.group(0))
            break
    return bad


def witness_cohort(packs):
    """见证证据分四档计数（real / public / self-built / fixture），不是两档。

    为什么要这一行：`gate --all` 9/9 只说明「每个包的判据都跑通了」，**不说明 9 个域
    都有真实产物生例**。real 与 public 都是真实可复现的产物（客户目标 / 公开靶场·CTF·
    公开 crackme），可以背书「该域可用」；self-built / fixture 只证明流程可跑，不得背书。

    返回 (cohorts, witnessed, not_witnessed)：
      cohorts      = {"real": [...], "public": [...], "self-built": [...], "fixture": [...]}
                     （historical / unknown 并入 fixture 桶，因为它们同属「不能背书可用」）
      witnessed    = 有真实产物见证的包记录（real|public）
      not_witnessed= 没有真实产物见证的包记录（self-built|fixture|unknown）
    """
    cohorts = {"real": [], "public": [], "self-built": [], "fixture": []}
    witnessed, not_witnessed = [], []
    for p in packs:
        case = _witness_case(p.get("raw") or p)
        kind = _evidence_kind(case)
        # ★ public 不是标签就能拿：不合格（缺来源/sha256、自述本机编译）自动降回 self-built。
        #   理由写进 rec["downgrade_reason"]，输出里点名，避免"改标签凑可用"。
        dg = ""
        if kind == "public":
            defects = _public_claim_defects(case)
            if defects:
                dg = "；".join(defects)
                kind = "self-built"
        rec = {"pack": p.get("id"), "case": case, "evidence_kind": kind}
        if dg:
            rec["downgrade_reason"] = dg
        bucket = kind if kind in ("real", "public", "self-built") else "fixture"
        cohorts[bucket].append(rec)
        (witnessed if kind in REAL_ARTIFACT_KINDS else not_witnessed).append(rec)
    return cohorts, witnessed, not_witnessed


def main():
    ap = argparse.ArgumentParser(description="按包判定（G2/G3/G4/G5）：红=失败，unknown 不计 pass")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--pack", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-witness", action="store_true", help="跳过 G4 实跑（只做静态判据）")
    ap.add_argument("--require-usable", action="store_true",
                    help="可用性 NOT PROVEN 时返回 1（把“可用”当门槛；默认返回 3）")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--trap", default="", help="对一个真实回答打分（陷阱 id）")
    ap.add_argument("--answer", default="", help="回答文本文件（配合 --trap）")
    a = ap.parse_args()
    packs, problems = route_mod.load_packs(a.skill_dir or None)
    if problems:
        if a.json:
            print(json.dumps({"ok": False, "problems": problems}, ensure_ascii=False, indent=2))
        else:
            for p in problems:
                print("[FAIL] " + p)
        return 1

    if a.trap:
        if not a.answer or not os.path.isfile(a.answer):
            print("[ERR] --trap 需要 --answer <文件>")
            return 2
        with open(a.answer, encoding="utf-8", errors="replace") as stream:
            answer = stream.read()
        res = judge_answer(a.trap, answer)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1

    if a.list:
        for p in packs:
            print("%-24s %s" % (p["id"], p["l1"][:60]))
        return 0

    if a.all:
        selected = packs
    elif a.pack:
        selected = [p for p in packs if p["id"] == a.pack]
        if not selected:
            print("[ERR] 没有这个包：%s（用 --list 看现有包）" % a.pack)
            return 2
    else:
        ap.print_help()
        return 2

    route_index = route_mod.check(a.skill_dir or None)
    results = [judge(p["raw"], route_index, run_witness=not a.no_witness) for p in selected]
    npass = sum(1 for r in results if r["verdict"] == "pass")
    summary = {"packs": len(results), "pass": npass, "fail": len(results) - npass,
               "unknown_as_pass": 0}  # 结构上不可能：verdict 只有 pass/fail
    cohorts, witnessed, not_witnessed = witness_cohort(selected)
    summary["witness"] = {
        "real": len(cohorts["real"]), "public": len(cohorts["public"]),
        "self_built": len(cohorts["self-built"]), "fixture": len(cohorts["fixture"]),
        # 兼容旧消费方：witnessed = real+public（有真实产物见证）；其余归入 not_witnessed
        "witnessed": len(witnessed),
        "not_witnessed_packs": [x["pack"] for x in not_witnessed],
        "fixture_packs": [x["pack"] for x in not_witnessed],
    }
    # 可用性 ≠ 结构：“无真实产物见证”或“声称高档但账本 0 条 repro”都不足以说该域能用。
    # 三档口径：real 或 public → 计入有见证；self-built / fixture / unknown → 不计入。
    owed = [x for x in (_owed_vs_ledger(p["raw"]) for p in selected) if x]
    usable = bool(results) and not summary["fail"] and (not not_witnessed) and (not owed)
    summary["usability"] = {"proven": usable,
                            "witnessed": len(witnessed),
                            "not_witnessed": len(not_witnessed),
                            "not_witnessed_packs": [x["pack"] for x in not_witnessed],
                            "failed_packs": [r["pack"] for r in results if r["verdict"] != "pass"],
                            "zero_repro": len(owed),
                            "zero_repro_cases": [c for c, _lv in owed]}
    if a.json:
        print(json.dumps({"schema": "seep.gate/1", "summary": summary, "results": results,
                          "witness_cohort": cohorts},
                         ensure_ascii=False, indent=2))
    else:
        for r in results:
            print("[%s] %s" % ("PASS" if r["verdict"] == "pass" else "FAIL", r["pack"]))
            for name, g in r["gates"].items():
                mark = "ok  " if g["status"] == "pass" else "FAIL"
                info = g.get("info") or {}
                extra = ""
                if name.startswith("G5") and info:
                    extra = "（claim %d / strong %d）" % (info.get("claims", 0), info.get("strong", 0))
                if name.startswith("G4") and info.get("ran"):
                    extra = "（rc=%s）" % info.get("rc")
                print("   %s %s%s" % (mark, name, extra))
                for why in g["reasons"]:
                    print("        - " + why)
        # ── 诚实摘要（第 4 轮评审 P1-2）──
        # 第一行：结构判定（判据未放宽，9/9 就是 9/9）。
        # 第二行：见证证据的四档计数（real / public / self-built / fixture）——
        #         这是「能不能说该域可用」的边界：只有 real 与 public 算真实产物见证。
        # 第三行：哪些包没有真实产物见证，点名到位，省得把 9/9 读成「九个域都能用」。
        print("[GATE] %d 个包：结构 pass %d / fail %d（unknown 记为 fail，不计 pass）"
              % (summary["packs"], summary["pass"], summary["fail"]))
        print("[GATE] 见证证据：real %d / public %d / self-built %d / fixture %d"
              "（real+public 计真实产物见证；可用性另须全部门禁通过）"
              % (len(cohorts["real"]), len(cohorts["public"]),
                 len(cohorts["self-built"]), len(cohorts["fixture"])))
        if owed:
            print("[GATE] 交付承诺 vs 账本：%d 个案例声称的档位没有一条可重放记录（不能当“该域可用”的证据）"
                  % len(owed))
            print("[GATE]   点名：" + "、".join("%s(声称 %s / 账本 0 条 repro)" % (c, lv) for c, lv in owed))
        else:
            print("[GATE] 交付承诺 vs 账本：一致（没有“声称高档但零重放”的案例）")
        if not_witnessed:
            print("[GATE] 无真实产物见证 %d 个：%s" % (len(not_witnessed), "、".join(
                "%s(%s:%s)" % (x["pack"], x["case"] or "?", x["evidence_kind"])
                for x in not_witnessed)))
        else:
            print("[GATE] 无真实产物见证 0 个：%d 个包的见证案例都是 evidence_kind=real|public"
                  % len(witnessed))
        # ── 可用性结论（与结构判定分开；结构 9/9 不等于九个域都能用）──
        if usable:
            print("[GATE] 可用性：PROVEN（%d 个包有真实产物见证：real %d / public %d；零重放 0 案例）"
                  % (len(witnessed), len(cohorts["real"]), len(cohorts["public"])))
        else:
            print("[GATE] 可用性：NOT PROVEN（门禁失败 %d 域 / 无真实产物见证 %d 域 / 零重放 %d 案例）"
                  "—— 不得对外称\"该域可用\"" % (summary["fail"], len(not_witnessed), len(owed)))
    # 结构 fail 优先于可用性；结构全绿时 NOT PROVEN = 3（--require-usable 则升级为 1）。
    if summary["fail"]:
        return 1
    if usable:
        return 0
    return 1 if a.require_usable else 3


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
