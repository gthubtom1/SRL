#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain_registry.py —— 正式域注册表的**唯一载入 API**（单向读 pack，不 import route）。

身份口径（2026-10-27 主对话裁定，见 work/goal-recovery/DOMAIN-REGISTRY-DECISION.md）：
    * 正式域 = 带 `pack.json` 的技能目录，且 `pack.json.id == 目录名`。
      **不按“恰好 9 个目录”定义**，也不按关键词/别名定义。
    * `seep-router`（判型层）/ `unpack-loop`（横切层）不是客户可见正式域：它们在
      `Tool/config/domain-aliases.json#cross_cutting` 里，即使将来出现 pack 也只报错、
      不进正式域全集。
    * `_pending/**`、`safe-skills/*` 是归档/待迁移命名空间，不参与正式域全集。
    * `aliases` 只解释历史命名（reverse → softseep 等），**不能再定义正式全集**；
      alias 与正式域同名 / 指向不存在的正式域都是显式错误（alias_conflict）。

逐域静态深度要求（skill/board/matrix/case_globs/ext_scripts/kb_line_max/archive_*）
写在**该域自己的 pack.json `depth_contract`** 里；公共下限/上限仍然只有一份，在
`lib/domain_spec.py` 的 `LIMITS`。本模块的职责是**校验**，不是再造一份阈值表：

    * 字段集合严格（`DEPTH_FIELDS`）：未知字段（例如偷偷写 `cases_min`）直接报错，
      因此 pack 没有“把下限改小”的口子。
    * `kb_line_max` ∈ [200, 400]（200 = 公共 `LIMITS.kb_max`，400 = `LIMITS.ref_max`）。
      400 是 softseep / apkseep 的**既有特例**（KB 长文），不是给新域随手抬上限用的。
    * `cases_max` ∈ [3, 7]（3 = 公共 `LIMITS.cases_min`，7 = 当前公共上限）。

错误一律进 `Registry.errors` / `facts()["incomplete"]`，**不抛异常**：任何 pack 坏掉都不能
让 import 本模块的 CLI 全部崩掉（更不能静默把坏域过滤掉）。
"""
from __future__ import annotations

import glob
import json
import os
import re

SKILL_ROOT_REL = "Tool/skill"
CONFIG_REL = "Tool/config"
CASES_REL = "Tool/cases"
KB_ROOT_REL = "Tool/mcp/Tool/reverselab/kb"
ALIAS_REL = "Tool/config/domain-aliases.json"

DEPTH_KEY = "depth_contract"
DEPTH_REQUIRED = ("skill", "board", "matrix", "case_globs")
DEPTH_OPTIONAL = ("ext_scripts", "kb_line_max", "cases_max",
                  "archive_cases", "archive_kb")
DEPTH_FIELDS = DEPTH_REQUIRED + DEPTH_OPTIONAL

# (下限, 上限) —— 两侧都取自 lib/domain_spec.LIMITS 的公共值（不是第二份阈值表）：
#   * 下限 = 公共默认值（`kb_max` / `cases_min`）：pack **不能**把它调得更松，
#     所以“用 metadata 把下限改小”在机制上不可表达。
#   * 上限 = 已核对过的最大合法值（`ref_max` / `cases_max`）：“随意抬上限”会直接判错。
#   * `cases_min` / `refs_min` / `scripts_min` / `matrix_min` 等**不允许**出现在 pack 里
#     （DEPTH_FIELDS 严格）。
#   注：kb_line_max 的 400 是 softseep / apkseep 的**既有特例**（KB 长文），已核对这两域
#   的全部 KB 单篇行数；新域如声明 400 必须自带同等证据（adapter 会显示声明值）。
DEPTH_LIMITS = {
    "kb_line_max": (200, 400),   # 200 == LIMITS["kb_max"]；400 == LIMITS["ref_max"]
    "cases_max": (3, 7),         # 3 == LIMITS["cases_min"]；7 == LIMITS["cases_max"]
}
# 与 LIMITS 的一致性自检表（domain_spec 载入时比对；不一致 → 显式报错，不静默）。
DEPTH_LIMIT_SOURCE = {
    "kb_line_max": ("kb_max", "ref_max"),
    "cases_max": ("cases_min", "cases_max"),
}

PACK_SCHEMA = "seep.pack/1"


def repo_root():
    """默认仓库根 = 本文件向上 4 层（lib → scripts → Tool → 仓库根）。

    这是“自身 repo 结构”，不是另一个全局 Root 真相源；测试/多仓用显式参数覆盖。
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle), None
    except Exception as exc:  # noqa: BLE001 —— 坏 pack 只报错，不炸调用方
        return None, "%s: %s" % (os.path.basename(path), str(exc)[:160])


def _rel(root, path):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except Exception:  # noqa: BLE001
        return str(path).replace(os.sep, "/")


def _nonempty_str(value):
    return isinstance(value, str) and bool(value.strip())


def _safe_contract_path(value):
    """Reject absolute/UNC/drive/upward paths in pack-owned contract fields."""
    if not _nonempty_str(value):
        return False
    text = value.replace("\\", "/").strip()
    if "\x00" in text or any(ch in text for ch in ("\n", "\r")):
        return False
    if text.startswith("/") or text.startswith("//") or re.match(r"^[A-Za-z]:", text):
        return False
    return all(part not in ("", ".", "..") for part in text.split("/"))


def _within(root, path):
    try:
        return os.path.commonpath((os.path.realpath(root), os.path.realpath(path))) == \
            os.path.realpath(root)
    except (OSError, ValueError):
        return False


def validate_depth_contract(raw, root=None, skill_dir=None):
    """校验一个 pack 的 `depth_contract`。

    返回 (depth_or_None, errors)。缺字段/类型错/未知字段/超界都进 errors；
    depth 只在完全合法时返回 dict（否则 None），消费者据此显式报“不完整”。
    """
    root = os.path.abspath(root or repo_root())
    skill_dir = os.path.abspath(skill_dir or os.path.join(root, SKILL_ROOT_REL))
    errors = []
    if not isinstance(raw, dict) or DEPTH_KEY not in raw:
        return None, ["pack 缺 %s（逐域 skill/board/matrix/case_globs 等静态深度要求）" % DEPTH_KEY]
    depth = raw.get(DEPTH_KEY)
    if not isinstance(depth, dict):
        return None, ["pack.%s 必须是对象" % DEPTH_KEY]
    unknown = sorted(set(depth) - set(DEPTH_FIELDS))
    if unknown:
        errors.append("pack.%s 含未声明字段 %s（不允许用自定义字段改小下限/抬上限）"
                      % (DEPTH_KEY, ",".join(unknown)))
    missing = [key for key in DEPTH_REQUIRED if key not in depth]
    if missing:
        errors.append("pack.%s 缺必要字段 %s" % (DEPTH_KEY, ",".join(missing)))
    for key in ("skill", "board", "matrix"):
        if key in depth and not _nonempty_str(depth.get(key)):
            errors.append("pack.%s.%s 必须是非空字符串" % (DEPTH_KEY, key))
        elif key in depth and not _safe_contract_path(depth.get(key)):
            errors.append("pack.%s.%s 必须是包内相对路径，不得绝对路径或上跳"
                          % (DEPTH_KEY, key))
    skill = depth.get("skill")
    if isinstance(skill, str) and "/" in skill.replace("\\", "/"):
        errors.append("pack.%s.skill 必须是一个技能目录名" % DEPTH_KEY)
    matrix = depth.get("matrix")
    if isinstance(matrix, str) and _safe_contract_path(matrix):
        matrix_path = os.path.join(root, CONFIG_REL, matrix.replace("\\", "/"))
        if not _within(os.path.join(root, CONFIG_REL), matrix_path):
            errors.append("pack.%s.matrix 越出 Tool/config" % DEPTH_KEY)
    board = depth.get("board")
    if isinstance(board, str) and _safe_contract_path(board):
        board_path = os.path.join(root, KB_ROOT_REL, board.replace("\\", "/"))
        if not _within(os.path.join(root, KB_ROOT_REL), board_path):
            errors.append("pack.%s.board 越出 KB 根" % DEPTH_KEY)
    globs = depth.get("case_globs")
    if "case_globs" in depth:
        if not isinstance(globs, list) or not globs or any(not _nonempty_str(x) for x in globs):
            errors.append("pack.%s.case_globs 必须是非空字符串数组" % DEPTH_KEY)
        elif any(not _safe_contract_path(x) for x in globs):
            errors.append("pack.%s.case_globs 只能是 cases 根内相对模式，"
                          "不得绝对路径或上跳" % DEPTH_KEY)
    ext = depth.get("ext_scripts")
    if "ext_scripts" in depth:
        if not isinstance(ext, list) or any(not isinstance(x, str) or not x.strip() for x in ext):
            errors.append("pack.%s.ext_scripts 必须是字符串数组（可为空）" % DEPTH_KEY)
    for key, (low, high) in DEPTH_LIMITS.items():
        if key not in depth:
            continue
        value = depth.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append("pack.%s.%s 必须是整数" % (DEPTH_KEY, key))
        elif not (low <= value <= high):
            errors.append("pack.%s.%s=%d 超出登记区间 %d–%d（不许改小下限/随意抬上限）"
                          % (DEPTH_KEY, key, value, low, high))
    for key in ("archive_cases", "archive_kb"):
        if key not in depth:
            continue
        value = depth.get(key)
        if not _nonempty_str(value):
            errors.append("pack.%s.%s 必须是非空相对路径" % (DEPTH_KEY, key))
            continue
        if os.path.isabs(value) or "://" in value:
            errors.append("pack.%s.%s 必须是仓库内相对路径：%r" % (DEPTH_KEY, key, value))
            continue
        if not _safe_contract_path(value):
            errors.append("pack.%s.%s 不得包含空段、点目录或上跳" % (DEPTH_KEY, key))
            continue
        archive_path = os.path.join(root, value.replace("\\", "/"))
        if not os.path.isdir(archive_path) or not _within(root, archive_path):
            errors.append("pack.%s.%s 指向的归档目录不存在：%s" % (DEPTH_KEY, key, value))
    if not errors:
        path = os.path.join(skill_dir, str(skill))
        if not os.path.isdir(path) or not _within(skill_dir, path):
            errors.append("pack.%s.skill 指向的技能目录不存在：%s"
                          % (DEPTH_KEY, _rel(root, path)))
        elif not os.path.isfile(os.path.join(path, "SKILL.md")):
            errors.append("pack.%s.skill 目录缺 SKILL.md：%s"
                          % (DEPTH_KEY, _rel(root, path)))
    return (dict(depth) if not errors else None), errors


def _namespace_defaults():
    return {
        "path": "",
        "formal_domains_declared": [],
        "aliases": {},
        "cross_cutting": set(),
        "pending_patterns": ["_pending/**/*"],
        "pending_skills": set(),
        "errors": [],
        # 分类表缺失不算“域注册错误”（正式域全集只来自 pack.id），但要显式报出。
        "warnings": [],
        "present": False,
        "load_error": None,
    }


def load_namespace(root=None):
    """读 domain-aliases.json：只取**命名空间分类**（alias/横切/待迁移），正式全集不取它。"""
    root = os.path.abspath(root or repo_root())
    out = _namespace_defaults()
    path = os.path.join(root, ALIAS_REL)
    out["path"] = _rel(root, path)
    if not os.path.isfile(path):
        # 分类表缺失不影响“正式域全集”（只来自 pack.id），但横切/别名无从区分：
        # 记 warning 而非 error —— 最小 fixture（只有 Tool/skill）不应因此判红。
        out["warnings"].append("缺 %s（命名空间分类表；横切/别名无从区分）" % ALIAS_REL)
        return out
    out["present"] = True
    data, error = _load_json(path)
    if error:
        out["load_error"] = error
        out["errors"].append(error)
        return out
    if not isinstance(data, dict):
        out["load_error"] = "domain-aliases.json 顶层不是对象"
        out["errors"].append(out["load_error"])
        return out
    aliases = data.get("aliases")
    if isinstance(aliases, dict):
        for name, value in aliases.items():
            if not isinstance(name, str) or not _nonempty_str(name):
                out["errors"].append("aliases 名必须是非空字符串：%r" % (name,))
                continue
            if not isinstance(value, dict):
                out["errors"].append("aliases.%s 必须是对象" % name)
                continue
            if not _nonempty_str(value.get("status")):
                out["errors"].append("aliases.%s.status 必须是非空字符串" % name)
            target = value.get("alias_to")
            if target is not None and not _nonempty_str(target):
                out["errors"].append("aliases.%s.alias_to 必须是非空字符串或 null" % name)
                target = None
            out["aliases"][name] = {"alias_to": target, "status": value.get("status")}
    elif aliases is not None:
        out["errors"].append("aliases 必须是对象")
    cross = data.get("cross_cutting")
    if isinstance(cross, list):
        for item in cross:
            name = item if isinstance(item, str) else (
                item.get("name") if isinstance(item, dict) else None)
            if not _nonempty_str(name):
                out["errors"].append("cross_cutting 项必须是名称字符串或带 name 的对象")
                continue
            out["cross_cutting"].add(name)
    elif cross is not None:
        out["errors"].append("cross_cutting 必须是数组")
    declared = data.get("formal_domains")
    if declared is not None:
        if not isinstance(declared, list) or any(not _nonempty_str(x) for x in declared):
            out["errors"].append("formal_domains 必须是字符串数组（或删掉，它只是派生兼容快照）")
        else:
            out["formal_domains_declared"] = [x.strip() for x in declared]
    patterns = data.get("pending_patterns")
    if isinstance(patterns, list):
        out["pending_patterns"] = [x for x in patterns if _nonempty_str(x)]
    elif patterns is not None:
        out["errors"].append("pending_patterns 必须是字符串数组")
    pending = data.get("pending_skills")
    if isinstance(pending, list):
        out["pending_skills"] = {x for x in pending if _nonempty_str(x)}
    elif pending is not None:
        out["errors"].append("pending_skills 必须是字符串数组")
    return out


class Pack:
    """一个正式域包的原始声明 + 显式错误（不抛异常）。"""

    def __init__(self, domain, dirname, path, raw, root, skill_dir):
        self.id = domain
        self.dir = dirname
        self.path = path
        self.raw = raw
        self.root = root
        self.skill_dir = skill_dir
        self.load_errors = []
        self.depth, self.depth_errors = validate_depth_contract(raw, root, skill_dir)

    @property
    def declared_skill(self):
        if isinstance(self.depth, dict):
            return str(self.depth.get("skill"))
        value = (self.raw or {}).get("depth_contract")
        if isinstance(value, dict) and _nonempty_str(value.get("skill")):
            return str(value["skill"]).strip()
        return self.id


class Registry:
    """正式域全集 + 每域结构事实 + 命名空间分类。所有查询都不抛异常。"""

    def __init__(self, root, skill_dir, packs, errors, namespace, warnings=None):
        self.root = root
        self.skill_dir = skill_dir
        self.packs = packs
        self.errors = errors
        self.warnings = list(warnings or [])
        self.namespace = namespace
        self._facts = {}

    # ---------------------------------------------------------------- 全集
    def ids(self):
        return sorted(self.packs)

    def __contains__(self, domain):
        return domain in self.packs

    def get(self, domain):
        return self.packs.get(domain)

    def depth(self, domain):
        pack = self.packs.get(domain)
        return dict(pack.depth) if pack is not None and pack.depth else None

    def case_roles(self, domain):
        pack = self.packs.get(domain)
        roles = (pack.raw or {}).get("case_roles") if pack is not None else None
        return roles if isinstance(roles, dict) else {}

    # ---------------------------------------------------------------- 事实
    def facts(self, domain):
        """逐域**分开**的结构事实（没有单一 effective 布尔）。

        registered / depth / skill / 材料 / 路由声明 / 见证声明 / 别名冲突各自独立；
        运行期（工具探活、部署哈希、Pi 加载、行为验收）不在这里假装。
        """
        if domain in self._facts:
            return self._facts[domain]
        root, skill_dir = self.root, self.skill_dir
        pack = self.packs.get(domain)
        facts = {
            "domain": domain, "pack_present": pack is not None,
            "id_matches_dir": False, "schema_ok": False, "routes_declared": False,
            "skill_dir_present": False, "skill_md_present": False,
            "references_present": False, "matrix_present": False, "board_present": False,
            "template_present": False, "depth_declared": False, "depth_valid": False,
            "case_roles_valid": False, "witness_declared": False,
            "alias_conflict": [], "incomplete": [],
        }
        if pack is None:
            facts["incomplete"].append("没有 pack.json（未声明为正式域）")
            self._facts[domain] = facts
            return facts
        raw = pack.raw if isinstance(pack.raw, dict) else {}
        facts["id_matches_dir"] = (pack.id == pack.dir)
        facts["schema_ok"] = (raw.get("schema") == PACK_SCHEMA)
        facts["depth_declared"] = isinstance(raw.get(DEPTH_KEY), dict)
        facts["depth_valid"] = bool(pack.depth)
        facts["routes_declared"] = isinstance(raw.get("routes"), list) and bool(raw.get("routes"))
        facts["witness_declared"] = isinstance(raw.get("witness_tool"), dict) or \
            isinstance(raw.get("witness"), dict)
        skill = pack.declared_skill
        sdir = os.path.join(skill_dir, str(skill))
        facts["skill_dir_present"] = os.path.isdir(sdir)
        facts["skill_md_present"] = os.path.isfile(os.path.join(sdir, "SKILL.md"))
        facts["references_present"] = os.path.isdir(os.path.join(sdir, "references"))
        depth = pack.depth or {}
        if _nonempty_str(depth.get("matrix")):
            facts["matrix_present"] = os.path.isfile(
                os.path.join(root, CONFIG_REL, str(depth["matrix"]).replace("\\", "/")))
        if _nonempty_str(depth.get("board")):
            facts["board_present"] = os.path.isdir(
                os.path.join(root, KB_ROOT_REL, str(depth["board"])))
        facts["template_present"] = os.path.isfile(
            os.path.join(root, CASES_REL, "_templates", "%s.json" % domain))
        roles = raw.get("case_roles")
        if isinstance(roles, dict):
            witness = roles.get("witness")
            depth_gate = roles.get("depth_gate")
            shape_ok = (set(roles) <= {"witness", "depth_gate"}
                        and isinstance(witness, list) and bool(witness)
                        and isinstance(depth_gate, list) and bool(depth_gate)
                        and all(_nonempty_str(x) for x in witness + depth_gate))
            cases = raw.get("cases")
            same_as_cases = (isinstance(cases, list) and isinstance(witness, list)
                             and witness == cases)
            facts["case_roles_valid"] = bool(shape_ok and same_as_cases)
        # alias / 横切 命名空间冲突（正式域身份不允许被别名或横切层冒名）
        ns = self.namespace
        if domain in ns["cross_cutting"]:
            facts["alias_conflict"].append("域名在 cross_cutting 里（横切技能不能是正式域）")
        if domain in ns["aliases"]:
            facts["alias_conflict"].append("域名在 aliases 里（别名不能再定义正式域）")
        if domain in ns["pending_skills"]:
            facts["alias_conflict"].append("域名在 pending_skills 里（待迁移命名空间不是正式域）")
        for name, value in ns["aliases"].items():
            target = (value or {}).get("alias_to")
            if target == domain:
                continue          # 历史别名指向本域是合法的解释
            if name == domain:
                facts["alias_conflict"].append("alias 键与正式域名相同：%s" % name)
        # 不完整原因（显式列出，绝不静默过滤）
        facts["incomplete"].extend(pack.depth_errors)
        if not facts["id_matches_dir"]:
            facts["incomplete"].append("pack.json id=%r 与目录名 %r 不一致" % (pack.id, pack.dir))
        if not facts["schema_ok"]:
            facts["incomplete"].append("pack.schema 必须是 %s" % PACK_SCHEMA)
        if not facts["skill_md_present"]:
            facts["incomplete"].append("缺技能入口 %s/SKILL.md" % _rel(root, sdir))
        facts["incomplete"].extend(facts["alias_conflict"])
        self._facts[domain] = facts
        return facts

    def status(self, domain):
        """把事实压成**分开的**字段（注册/路由声明/静态深度/材料/见证声明）。

        没有 `effective`：结构注册可以 true 而运行期（工具可用/Pi 加载/行为见证）未验。
        """
        facts = self.facts(domain)
        return {
            "registered": bool(facts["pack_present"] and facts["id_matches_dir"]
                               and facts["schema_ok"]),
            "route_declared": bool(facts["routes_declared"]),
            "depth_declared": bool(facts["depth_declared"]),
            "depth_contract_valid": bool(facts["depth_valid"]),
            "skill_present": bool(facts["skill_md_present"]),
            "materials": {
                "references": bool(facts["references_present"]),
                "matrix": bool(facts["matrix_present"]),
                "kb_board": bool(facts["board_present"]),
                "case_template": bool(facts["template_present"]),
            },
            "case_roles_valid": bool(facts["case_roles_valid"]),
            "witness_declared": bool(facts["witness_declared"]),
            "alias_conflict": list(facts["alias_conflict"]),
            "incomplete": list(facts["incomplete"]),
        }

    def incomplete(self):
        """{domain: [原因]} —— 只含确有缺口的域；空 dict = 每个声明域都齐全。"""
        out = {}
        for domain in self.ids():
            reasons = self.status(domain)["incomplete"]
            if reasons:
                out[domain] = reasons
        return out

    # ---------------------------------------------------------------- 兼容视图
    def as_domains(self, include_incomplete=True):
        """旧 `domain_spec.DOMAINS` 形状的兼容视图（原消费者不用改）。

        值 = 该 pack 的 depth_contract 字段；不完整的域也**保留在集合里**，
        额外带 `_incomplete`（有缺口时）与 `_pack`（来源），消费方显式报红。
        """
        out = {}
        for domain in self.ids():
            facts = self.facts(domain)
            if facts["incomplete"] and not include_incomplete:
                continue
            pack = self.packs[domain]
            spec = dict(pack.depth or {})
            spec.setdefault("skill", pack.declared_skill)
            spec.setdefault("case_globs", [])
            spec.setdefault("ext_scripts", [])
            spec["_pack"] = _rel(self.root, pack.path)
            if facts["incomplete"]:
                spec["_incomplete"] = list(facts["incomplete"])
            out[domain] = spec
        return out


def load_registry(root=None, skill_dir=None):
    """载入正式域注册表（唯一入口）。绝不抛异常；错误进 `Registry.errors`。"""
    root = os.path.abspath(root or repo_root())
    skill_dir = os.path.abspath(skill_dir or os.path.join(root, SKILL_ROOT_REL))
    namespace = load_namespace(root)
    errors = list(namespace["errors"])
    warnings = list(namespace["warnings"])
    packs = {}
    if not os.path.isdir(skill_dir):
        errors.append("缺技能根目录：%s" % _rel(root, skill_dir))
        return Registry(root, skill_dir, packs, errors, namespace, warnings)
    for dirname in sorted(os.listdir(skill_dir)):
        if dirname.startswith(("_", ".")):
            continue                      # 归档 / 待迁移命名空间：不是正式域
        path = os.path.join(skill_dir, dirname, "pack.json")
        if not os.path.isfile(path):
            if dirname in namespace["cross_cutting"]:
                continue                  # 横切技能本来就没有 pack
            continue
        raw, error = _load_json(path)
        if error:
            errors.append("%s/pack.json 解析失败：%s" % (dirname, error))
            continue
        if not isinstance(raw, dict):
            errors.append("%s/pack.json 顶层不是对象" % dirname)
            continue
        domain = str(raw.get("id") or "").strip()
        if not domain:
            errors.append("%s/pack.json 缺非空 id（正式身份只能来自 pack.id）" % dirname)
            continue
        if dirname in namespace["cross_cutting"]:
            errors.append("%s 是横切技能（cross_cutting），不得登记为正式域" % dirname)
            continue
        if dirname in namespace["aliases"]:
            errors.append("%s 是历史别名，不得登记为正式域" % dirname)
            continue
        if dirname in namespace["pending_skills"] or domain in namespace["pending_skills"]:
            errors.append("%s 是待迁移技能（pending_skills），不得登记为正式域" % dirname)
            continue
        if domain in packs:
            errors.append("pack id 重复：%s（%s 与 %s）" % (domain, packs[domain].dir, dirname))
            continue
        packs[domain] = Pack(domain, dirname, path, raw, root, skill_dir)
    # alias 指向不存在的正式域（legacy 别名必须指向真实 pack；pending/archived 允许 null）
    declared = set(packs)
    for name, value in namespace["aliases"].items():
        target = (value or {}).get("alias_to")
        status = str((value or {}).get("status") or "")
        if target and status == "legacy" and target not in declared:
            errors.append("alias %s → %s（legacy 别名必须指向真实 pack id）" % (name, target))
        if name in declared:
            errors.append("alias %s 与正式域同名（别名不能再定义正式域）" % name)
        if name in namespace["cross_cutting"]:
            errors.append("alias %s 与横切技能同名" % name)
    return Registry(root, skill_dir, packs, errors, namespace, warnings)


def formal_domain_ids(root=None, skill_dir=None):
    """正式域 id 全集（动态；不硬编码 9/10）。"""
    return load_registry(root, skill_dir).ids()


def depth_contract(domain, root=None, skill_dir=None):
    """取某正式域的深度契约（来自该域 pack）；不存在/不合法 → (None, errors)。"""
    registry = load_registry(root, skill_dir)
    pack = registry.get(domain)
    if pack is None:
        return None, ["%s 不是正式域（没有 pack.json）" % domain]
    return (dict(pack.depth) if pack.depth else None), list(pack.depth_errors)


def case_dirs(root, domain, skill_dir=None):
    """按该域 pack 的 case_globs 现算案例目录名（结果与顺序稳定）。"""
    registry = load_registry(root, skill_dir)
    depth = registry.depth(domain) or {}
    globs = depth.get("case_globs") or []
    cases_root = os.path.join(os.path.abspath(root), CASES_REL)
    found = set()
    for pattern in globs:
        for path in glob.glob(os.path.join(cases_root, str(pattern))):
            if os.path.isdir(path) and _within(cases_root, path):
                found.add(os.path.basename(os.path.normpath(path)))
    return sorted(found)


if __name__ == "__main__":  # 只读自检：打印当前仓库的正式域全集与缺口
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    reg = load_registry()
    print("formal domains (%d): %s" % (len(reg.ids()), ", ".join(reg.ids())))
    for domain in reg.ids():
        status = reg.status(domain)
        gaps = status["incomplete"]
        print("  %-24s %s" % (domain, "；".join(gaps) if gaps else "structure complete"))
    if reg.errors:
        print("errors: %s" % "; ".join(reg.errors))
        raise SystemExit(1)
