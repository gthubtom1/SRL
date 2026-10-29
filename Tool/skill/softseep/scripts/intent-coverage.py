#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""intent-coverage.py —— 用真实口吻意图探针，量化「一句话 -> 配方 / 能力」的覆盖率。

数据来源（按优先级）：
  1. Tool/playbooks/*.md 的「触发词」段与「用到的能力（capability id）」段；
  2. Tool/capabilities/*.json 的 id / title / triggers（存在时）；
  3. 仓库内的 tool-capabilities、apkseep capabilities.py、scripts 扫描结果。

匹配方式：触发词子串 / 正则 + 词边界 + 关键词打分。每条探针给出：
  - 主落点（最高分 playbook / capability）
  - 期望目标是否命中
  - 未命中时的 capability 组合建议（2-3 个 id）

用法：
    python Tool/skill/softseep/scripts/intent-coverage.py
    python Tool/skill/softseep/scripts/intent-coverage.py --json
    python Tool/skill/softseep/scripts/intent-coverage.py --self-test
    python Tool/skill/softseep/scripts/intent-coverage.py --json > work/intent-coverage.json

退出码：0 = 全部探针覆盖；1 = 存在未覆盖/误命中缺口；
        2 = 配置/目录不可用（输出 ok=false 的 JSON）。
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root
from seep_runtime import self_test as _runtime_self_test


import argparse
import ast
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SCHEMA = "intent-coverage/v1"
DEFAULT_MAX_COMBINATION = 3

# 能力别名：只补充机器名无法覆盖的口语词；不改变仓库已有的 id。
CAP_ALIASES = {
    "tool:playwright": ["浏览器", "截图", "页面", "自动化", "像素对比"],
    "mcp:playwright": ["浏览器", "截图", "页面", "自动化", "像素对比"],
    "tool:fiddler": ["抓包", "代理", "请求"],
    "tool:tshark": ["抓包", "pcap", "流量", "报文"],
    "tool:dumpcap": ["抓包", "pcap"],
    "tool:binwalk": ["binwalk", "固件", "解包", "镜像"],
    "tool:ida": ["ida", "伪代码", "交叉引用", "反编译"],
    "tool:r2": ["radare2", "r2", "无头分析", "函数列表"],
    "tool:x64dbg": ["x64dbg", "调试器", "断点"],
    "tool:frida": ["frida", "hook", "注入"],
    "tool:apktool": ["apktool", "解包 apk"],
    "tool:jadx": ["jadx", "反编译 apk"],
    "tool:katana": ["爬虫", "crawl", "整站"],
    "tool:ffuf": ["目录枚举", "爆破"],
    "tool:nuclei": ["漏洞扫描", "模板"],
    "tool:pe-sieve": ["内存转储", "dump"],
    "tool:diec": ["壳检测", "判壳", "die"],
    "repo:pcap-summary": ["抓包", "pcap", "报文"],
    "repo:web-check": ["网页检查", "安全头", "侦察"],
    "repo:web-repro": ["复现", "重放"],
    "repo:web-accept": ["验收"],
    "repo:patch-verify": ["补丁", "验收", "校验"],
    "repo:case-state": ["案例", "状态", "证据"],
    "repo:budget": ["预算", "限速"],
    "repo:env-ledger": ["env", "环境变量", "账号"],
    "repo:fw-triage": ["固件", "分诊"],
    "repo:fw-repro": ["固件复现"],
    "repo:forensics-check": ["取证", "时间线"],
    "repo:fs-timeline": ["时间线"],
    "repo:evidence-accept": ["证据链"],
    "repo:mal-triage": ["样本分诊", "ioc"],
    "repo:ioc-extract": ["ioc"],
    "repo:plugin-triage": ["插件", "扩展"],
    "repo:plugin-repro": ["插件复现"],
    "repo:sc-check": ["sbom", "供应链", "依赖"],
    "repo:sbom-reach": ["sbom", "可达性"],
    "repo:ci-perm-audit": ["ci", "权限"],
    "repo:preflight-classify": ["判型", "结构"],
    "repo:pwn-check": ["pwn", "利用"],
    "repo:driver-triage": ["驱动", "反作弊"],
    "repo:migrate": ["追版", "迁移"],
    "repo:proto-repro": ["协议", "重放"],
    "repo:proto-accept": ["协议验收"],
    "repo:protobuf_decode_raw": ["protobuf", "字段"],
    "repo:temp_ocr": ["验证码", "ocr"],
}

# 缺口组合：按缺口所属配方给出可执行的能力组合（只用仓库已登记的 id）。
PLAYBOOK_COMBOS = {
    "site-clone-1to1": ["mcp:playwright", "repo:web-check", "repo:pcap-summary"],
    "license-hookup": ["tool:ida", "tool:x64dbg", "repo:patch-verify"],
    "reverse-survey": ["tool:r2", "repo:preflight-classify", "repo:reverse-accept"],
    "firmware-extract": ["repo:fw-triage", "repo:fw-repro", "repo:preflight-classify"],
    "forensics-timeline": ["repo:forensics-check", "repo:fs-timeline", "repo:evidence-accept"],
}

# 缺口建议的兜底池：只在探针自身命中不足 2 个能力时使用。
GENERIC_COMBOS = [
    "repo:case-state",
    "repo:pcap-summary",
    "tool:playwright",
    "repo:web-check",
    "repo:preflight-classify",
    "repo:budget",
]


def _load_json(path: Path):
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def _formal_domains(root: Path) -> set:
    """正式域来自有效 pack.json#id；历史/待迁移目录不能进入自动能力匹配。"""
    formal = set()
    skill_root = root / "Tool" / "skill"
    if not skill_root.is_dir():
        return formal
    for path in sorted(skill_root.glob("*/pack.json")):
        try:
            data = _load_json(path)
        except Exception:
            continue
        pid = data.get("id") if isinstance(data, dict) else None
        if pid == path.parent.name and isinstance(data.get("depth_contract"), dict):
            formal.add(pid)
    return formal


def _bare_capability_ids(root: Path) -> set:
    """Collect capability ids that capability-gate accepts without a namespace."""
    ids = set()

    def add(item):
        if not isinstance(item, dict):
            return
        cid = item.get("id") or item.get("capability")
        if not isinstance(cid, str) or not cid:
            return
        if item.get("archived") is True or item.get("reserved") is True:
            return
        if item.get("maturity") not in ("usable", "battle-tested"):
            return
        ids.add(cid)

    for path in sorted((root / "Tool" / "capabilities").glob("*.json")):
        try:
            data = _load_json(path)
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("id"), str):
            add(data)
            continue
        entries = data
        if isinstance(data, dict):
            entries = (data.get("capabilities") or data.get("items")
                       or data.get("tools") or [])
        if not isinstance(entries, list):
            continue
        for item in entries:
            add(item)
    return ids


CAPABILITY_TOKEN_RE = re.compile(
    r"`([A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?)`"
)


def _capability_tokens(text: str, bare_ids: set) -> list:
    """Accept valid bare capability ids as well as namespaced references."""
    tokens = CAPABILITY_TOKEN_RE.findall(text)
    return [
        token for token in tokens
        if ":" in token or token in bare_ids
    ]


def _norm(text: str) -> str:
    return (text or "").strip().lower()


def _is_ascii_token(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9_.+#:/@ -]+", value))


def _literal_hit(text: str, value: str) -> bool:
    value = _norm(value)
    if len(value) < 2:
        return False
    if _is_ascii_token(value):
        if len(value) <= 3:
            pat = r"(?<![a-z0-9])" + re.escape(value) + r"(?![a-z0-9])"
            return re.search(pat, text) is not None
        return value in text
    return value in text


def _trigger_hit(text: str, trigger: str) -> bool:
    trigger = str(trigger or "").strip()
    if trigger.startswith("re:"):
        try:
            return re.search(trigger[3:], text, re.IGNORECASE) is not None
        except re.error:
            return False
    return _literal_hit(text, trigger)


def _split_triggers(raw: str):
    parts = re.split(r"[、,，;；/|]", raw or "")
    out = []
    for part in parts:
        item = part.strip().strip("`*\"'“”‘’ ")
        if not item or len(item) > 60 or "→" in item:
            continue
        out.append(item)
    return out


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return ""


class Catalog:
    def __init__(self, root: Path):
        self.root = root
        self.playbooks = {}
        self.capabilities = {}
        self.sources = {}
        self.warnings = []
        self.excluded_capabilities = []

    # ------------------------------------------------------------------
    # playbooks
    # ------------------------------------------------------------------
    def load_playbooks(self):
        pdir = self.root / "Tool" / "playbooks"
        bare_capability_ids = _bare_capability_ids(self.root)
        files = []
        if pdir.is_dir():
            files = sorted(p for p in pdir.glob("*.md") if p.name.lower() not in {"readme.md", "index.md"})
        self.sources["playbooks_dir"] = str(pdir.relative_to(self.root)) if pdir.is_dir() else ""
        self.sources["playbook_files"] = [str(p.relative_to(self.root)) for p in files]

        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            pid = path.stem
            triggers = []
            cap_ids = []
            for line in text.splitlines():
                stripped = line.strip()
                if "触发词" in stripped:
                    raw = stripped.split("触发词", 1)[1].lstrip("：: ")
                    triggers.extend(_split_triggers(raw))
                if "capability id" in stripped.lower() or "用到的能力" in stripped:
                    cap_ids.extend(_capability_tokens(
                        stripped, bare_capability_ids))
            deduped = []
            seen = set()
            for item in triggers:
                key = _norm(item)
                if key and key not in seen:
                    seen.add(key)
                    deduped.append(item)
            self.playbooks[pid] = {
                "id": pid,
                "title": _first_heading(text),
                "triggers": deduped,
                "capability_ids": list(dict.fromkeys(cap_ids)),
                "source": str(path.relative_to(self.root)),
            }

        # 仓库没有 playbook 时，用 routing.json 的技能落点做只读兜底，
        # 这样工具在较早的检出上仍能给出可解释结果。
        if not self.playbooks:
            self._load_routing_fallback()

    def _load_routing_fallback(self):
        """没有 playbook 时用 pack.json 的路由做只读兜底（S3：routing.json 已删）。"""
        skill_root = self.root / "Tool" / "skill"
        if not skill_root.is_dir():
            return
        for pj in sorted(skill_root.glob("*/pack.json")):
            try:
                pack = _load_json(pj)
            except Exception:
                continue
            pid = str(pack.get("id") or pj.parent.name)
            entry = self.playbooks.setdefault(pid, {
                "id": pid, "title": str(pack.get("l1") or pid)[:80],
                "triggers": [], "capability_ids": [],
                "source": "pack:" + pid, "priority": 999,
            })
            for r in pack.get("routes") or []:
                for m in (r.get("must") or []):
                    entry["triggers"].append("re:" + str(m))
                entry["priority"] = min(entry["priority"], 1000 - int(r.get("priority") or 0))
        self.sources["playbooks_dir"] = "pack.json (fallback)"

    # ------------------------------------------------------------------
    # capabilities
    # ------------------------------------------------------------------
    def load_capabilities(self):
        self._load_explicit_capabilities()
        self._load_tool_capabilities()
        self._load_apk_capabilities()
        self._load_repo_scripts()
        self._load_playbook_capability_ids()
        self._attach_playbook_trigger_inheritance()
        self._apply_aliases()
        self.sources["capability_count"] = len(self.capabilities)
        self.sources["excluded_capabilities"] = self.excluded_capabilities

    def _add_cap(self, cid, title=None, source="", triggers=None, weight=4):
        # 能力层 SSOT（Tool/capabilities/*.json）用的是裸 id；这里不再要求命名空间。
        if not cid or not str(cid).strip():
            return
        cid = str(cid)
        entry = self.capabilities.setdefault(cid, {
            "id": cid,
            "title": title or cid,
            "source": source,
            "triggers": [],
            "weight": weight,
        })
        if title and entry.get("title") == cid:
            entry["title"] = title
        for item in triggers or []:
            if isinstance(item, str):
                item = item.strip()
                if len(item) >= 2 and _norm(item) not in {_norm(x) for x in entry["triggers"]}:
                    entry["triggers"].append(item)

    def _load_explicit_capabilities(self):
        cdir = self.root / "Tool" / "capabilities"
        self.sources["capabilities_dir"] = str(cdir.relative_to(self.root)) if cdir.is_dir() else ""
        if not cdir.is_dir():
            return
        formal_domains = _formal_domains(self.root)
        self.sources["formal_domains"] = sorted(formal_domains)
        if not formal_domains:
            self.warnings.append("没有可用正式域 pack.json；显式能力目录不会进入自动匹配")
        files = sorted(cdir.glob("*.json"))
        self.sources["capability_files"] = [str(p.relative_to(self.root)) for p in files]
        for path in files:
            try:
                data = _load_json(path)
            except Exception as exc:  # noqa: BLE001
                self.warnings.append(f"{path.name}: {exc}")
                continue
            if isinstance(data, dict):
                if data.get("id"):
                    # 单对象文件：Tool/capabilities/<id>.json
                    entries = [data]
                else:
                    entries = data.get("capabilities") or data.get("items") or data.get("tools") or []
            elif isinstance(data, list):
                entries = data
            else:
                entries = []
            for item in entries:
                if not isinstance(item, dict):
                    continue
                cid = item.get("id") or item.get("capability")
                reason = ""
                if item.get("archived") is True:
                    reason = "archived"
                elif item.get("reserved") is True:
                    reason = "reserved"
                elif item.get("maturity") == "probe":
                    reason = "probe"
                elif item.get("domain") not in formal_domains:
                    reason = "non-formal-domain:%s" % item.get("domain")
                if reason:
                    self.excluded_capabilities.append({
                        "id": cid,
                        "file": str(path.relative_to(self.root)),
                        "reason": reason,
                    })
                    continue
                title = item.get("title") or item.get("name") or cid
                triggers = item.get("triggers") or item.get("keywords") or item.get("match") or []
                if isinstance(triggers, str):
                    triggers = [triggers]
                aliases = item.get("aliases") or []
                if isinstance(aliases, str):
                    aliases = [aliases]
                self._add_cap(cid, title, str(path.relative_to(self.root)),
                              list(triggers) + list(aliases), weight=8)

    def _load_tool_capabilities(self):
        path = self.root / "Tool" / "config" / "tool-capabilities.json"
        if not path.is_file():
            return
        self.sources["tool_capabilities"] = str(path.relative_to(self.root))
        try:
            data = _load_json(path)
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"tool-capabilities.json: {exc}")
            return
        for tid, item in (data.get("tools") or {}).items():
            display = (item or {}).get("display") or tid
            self._add_cap(f"tool:{tid}", display, str(path.relative_to(self.root)),
                          [tid, display], weight=5)

    def _load_apk_capabilities(self):
        path = self.root / "Tool" / "skill" / "apkseep" / "scripts" / "capabilities.py"
        if not path.is_file():
            return
        self.sources["apk_capabilities"] = str(path.relative_to(self.root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            self.warnings.append(f"apk capabilities.py: {exc}")
            return
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "CAPABILITIES" for t in node.targets):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            for key, value in zip(node.value.keys, node.value.values):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    continue
                cid = key.value
                name = cid
                if isinstance(value, ast.Dict):
                    for k, v in zip(value.keys, value.values):
                        if isinstance(k, ast.Constant) and k.value == "name" and isinstance(v, ast.Constant):
                            name = str(v.value)
                self._add_cap(f"apk:{cid}", name, str(path.relative_to(self.root)),
                              [cid, cid.replace("_", " "), name], weight=4)

    def _load_repo_scripts(self):
        patterns = [
            "Tool/scripts/*.py",
            "Tool/skill/*/scripts/*.py",
            "Tool/skill/_pending/safe-skills/*/scripts/*.py",
            "Tool/skill/*/scripts/*/*.py",
        ]
        found = []
        for pattern in patterns:
            found.extend(self.root.glob(pattern))
        seen = set()
        for path in sorted(found):
            if path.name.startswith("__") or path.name in seen:
                continue
            seen.add(path.name)
            stem = path.stem
            cid = f"repo:{stem}"
            self._add_cap(cid, stem, "script-scan", [stem, stem.replace("_", "-")], weight=3)

    def _load_playbook_capability_ids(self):
        declared = set()
        excluded_ids = {
            row.get("id") for row in self.excluded_capabilities
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        for pb in self.playbooks.values():
            for cid in pb.get("capability_ids", []):
                declared.add(cid)
                if cid in excluded_ids:
                    continue
                self._add_cap(cid, cid, "playbook:" + pb["id"], [], weight=4)
        self.sources["declared_capability_ids"] = sorted(declared)

    def _attach_playbook_trigger_inheritance(self):
        # 配方声明用到的能力，天然继承配方的触发词（弱权重，只用于候选排序）。
        for pb in self.playbooks.values():
            for cid in pb.get("capability_ids", []):
                cap = self.capabilities.get(cid)
                if not cap:
                    continue
                for trig in pb.get("triggers", []):
                    if len(trig) >= 2 and _norm(trig) not in {_norm(x) for x in cap["triggers"]}:
                        cap["triggers"].append(trig)

    def _apply_aliases(self):
        for cid, aliases in CAP_ALIASES.items():
            cap = self.capabilities.get(cid)
            if not cap:
                continue
            for alias in aliases:
                if _norm(alias) not in {_norm(x) for x in cap["triggers"]}:
                    cap["triggers"].append(alias)


def _score_playbook(text, pb):
    score = 0
    hits = []
    for trig in pb.get("triggers", []):
        if _trigger_hit(text, trig):
            score += 10
            hits.append(trig)
    return score, hits


def _score_capability(text, cap):
    score = 0
    hits = []
    for trig in cap.get("triggers", []):
        if _trigger_hit(text, trig):
            score += cap.get("weight", 4)
            hits.append(trig)
    return score, hits


def _rank(text, catalog: Catalog):
    pbs = []
    for pb in catalog.playbooks.values():
        score, hits = _score_playbook(text, pb)
        if score > 0:
            pbs.append({
                "id": pb["id"],
                "title": pb.get("title", ""),
                "score": score,
                "hits": hits[:8],
            })
    pbs.sort(key=lambda item: (-item["score"], item["id"]))

    caps = []
    for cap in catalog.capabilities.values():
        score, hits = _score_capability(text, cap)
        if score > 0:
            caps.append({
                "id": cap["id"],
                "title": cap.get("title", ""),
                "score": score,
                "hits": hits[:8],
            })
    caps.sort(key=lambda item: (-item["score"], item["id"]))
    return pbs, caps


def _parse_expect(expect: str, catalog: Catalog):
    raw = (expect or "").strip()
    if raw.startswith("playbook:"):
        return "playbook", raw.split(":", 1)[1]
    if raw.startswith("capability:"):
        return "capability", raw.split(":", 1)[1]
    if raw.startswith("cap:"):
        return "capability", raw.split(":", 1)[1]
    if raw in catalog.playbooks:
        return "playbook", raw
    if raw in catalog.capabilities:
        return "capability", raw
    # 未登记的期望按 playbook 处理；这样缺口会明确指出缺的是配方。
    return "playbook", raw


def _pick_combination(probe, pbs, caps, catalog: Catalog):
    picked = []
    kind, target = _parse_expect(probe.get("expect", ""), catalog)

    if kind == "playbook" and target in PLAYBOOK_COMBOS:
        for cid in PLAYBOOK_COMBOS[target]:
            if cid in catalog.capabilities and cid not in picked:
                picked.append(cid)

    # 其次使用期望配方自身声明的能力，避免给出与缺口无关的通用工具。
    if kind == "playbook":
        entry = catalog.playbooks.get(target, {})
        for cid in entry.get("capability_ids", []):
            if len(picked) >= DEFAULT_MAX_COMBINATION:
                break
            if cid in catalog.capabilities and cid not in picked:
                picked.append(cid)

    # 再用探针实际命中的能力补齐。
    for item in caps:
        if len(picked) >= DEFAULT_MAX_COMBINATION:
            break
        cid = item["id"]
        if cid in catalog.capabilities and cid not in picked:
            picked.append(cid)

    for cid in GENERIC_COMBOS:
        if len(picked) >= DEFAULT_MAX_COMBINATION:
            break
        if cid in catalog.capabilities and cid not in picked:
            picked.append(cid)
    return picked[:DEFAULT_MAX_COMBINATION]


def evaluate(probes, catalog: Catalog):
    results = []
    covered = 0
    uncovered = 0
    violations = 0

    for probe in probes:
        pid = str(probe.get("id", ""))
        text = _norm(probe.get("text", ""))
        expect = probe.get("expect", "")
        forbid = probe.get("forbid") or []
        kind, target = _parse_expect(expect, catalog)
        pbs, caps = _rank(text, catalog)

        matched_pb_ids = {item["id"] for item in pbs if item["score"] >= 10}
        matched_cap_ids = {item["id"] for item in caps if item["score"] >= 4}
        target_matched = (target in matched_pb_ids) if kind == "playbook" else (target in matched_cap_ids)

        forbid_hits = []
        for item in list(pbs) + list(caps):
            if item["id"] in forbid and item["score"] >= 4:
                forbid_hits.append(item["id"])

        status = "covered" if target_matched else "uncovered"
        reason = ""
        if target_matched:
            if kind == "playbook":
                landed = {"kind": "playbook", "id": target, "score": next(
                    (x["score"] for x in pbs if x["id"] == target), 0)}
            else:
                landed = {"kind": "capability", "id": target, "score": next(
                    (x["score"] for x in caps if x["id"] == target), 0)}
        else:
            if pbs and caps:
                if pbs[0]["score"] >= caps[0]["score"]:
                    landed = {"kind": "playbook", "id": pbs[0]["id"], "score": pbs[0]["score"]}
                else:
                    landed = {"kind": "capability", "id": caps[0]["id"], "score": caps[0]["score"]}
            elif pbs:
                landed = {"kind": "playbook", "id": pbs[0]["id"], "score": pbs[0]["score"]}
            elif caps:
                landed = {"kind": "capability", "id": caps[0]["id"], "score": caps[0]["score"]}
            else:
                landed = {"kind": "none", "id": "", "score": 0}

        if forbid_hits:
            status = "uncovered"
            violations += 1
            reason = "命中跨域候选: " + ", ".join(sorted(set(forbid_hits)))
        elif not target_matched:
            if kind == "playbook" and target not in catalog.playbooks:
                reason = "目录中没有该配方，按缺口记录"
            elif kind == "capability" and target not in catalog.capabilities:
                reason = "目录中没有该能力，按缺口记录"
            else:
                reason = "触发词未命中期望目标"

        if status == "covered":
            covered += 1
        else:
            uncovered += 1

        combination = [] if status == "covered" else _pick_combination(probe, pbs, caps, catalog)

        results.append({
            "id": pid,
            "text": probe.get("text", ""),
            "expect": expect,
            "expect_kind": kind,
            "expect_id": target,
            "forbid": forbid,
            "status": status,
            "landed": landed,
            "primary_playbook": pbs[0]["id"] if pbs else "",
            "primary_capability": caps[0]["id"] if caps else "",
            "matched_playbooks": pbs[:5],
            "matched_capabilities": caps[:5],
            "reason": reason,
            "combination": combination,
        })

    summary = {
        "total": len(results),
        "covered": covered,
        "uncovered": uncovered,
        "violations": violations,
        "coverage_pct": round((covered * 100.0 / len(results)), 2) if results else 0.0,
    }
    return summary, results


SELF_TEST_PROBES = [
    {"id": "self-apk", "text": "APK 加固脱壳，il2cpp 的 global-metadata 怎么解", "expect": "apk-unpack", "forbid": []},
    {"id": "self-replay", "text": "私有协议抓包，报文怎么分帧", "expect": "protocol-replay", "forbid": []},
    {"id": "self-fw", "text": "路由器固件解包，找 squashfs 和 rootfs", "expect": "firmware-extract", "forbid": []},
    {"id": "self-mal", "text": "分析这个恶意样本的 IOC 和 YARA", "expect": "malware-triage", "forbid": []},
    {"id": "self-license", "text": "卡密校验跳过去，出个可用成品", "expect": "license-bypass-deliver", "forbid": []},
]


def run_self_test(catalog: Catalog):
    summary, results = evaluate(SELF_TEST_PROBES, catalog)
    failed = [r["id"] for r in results if r["status"] != "covered"]
    runtime_result = _runtime_self_test()
    if not runtime_result.get("ok"):
        failed.append("runtime-locator")

    protocol = catalog.playbooks.get("protocol-replay") or {}
    if not protocol.get("triggers"):
        failed.append("protocol-replay:triggers")
    if not protocol.get("capability_ids"):
        failed.append("protocol-replay:capability-ids")

    parsed_tokens = _capability_tokens(
        "- 用到的能力（capability id）：`captcha-gap` `repo:case_state` "
        "`unknown-bare-capability` `rootfs-emulate`",
        {"captcha-gap"},
    )
    if parsed_tokens != ["captcha-gap", "repo:case_state"]:
        failed.append("bare-capability-token-parser")
    bare_ids = _bare_capability_ids(catalog.root)
    if not {"captcha-gap", "captcha-angle"}.issubset(bare_ids):
        failed.append("bare-capability-allowlist-omits-active")
    if {"rootfs-emulate", "sign-recompute"} & bare_ids:
        failed.append("bare-capability-allowlist-includes-non-auto")
    captcha = catalog.playbooks.get("captcha-handling") or {}
    if not {"captcha-gap", "captcha-angle"}.issubset(
            set(captcha.get("capability_ids") or [])):
        failed.append("captcha-handling:bare-capability-ids")

    negative_ok = False
    with tempfile.TemporaryDirectory(prefix="intent-coverage-selftest-") as tmp:
        probes_path = Path(tmp) / "negative-probes.json"
        probes_path.write_text(json.dumps({
            "probes": [{
                "id": "negative-gap",
                "text": "完全没有匹配目标的口语描述",
                "expect": "missing-playbook",
                "forbid": [],
            }],
        }, ensure_ascii=False), encoding="utf-8")
        negative_payload, negative_rc = build_payload(catalog.root, probes_path, catalog)
        negative_ok = (negative_rc == 1 and negative_payload.get("ok") is False
                       and bool(negative_payload.get("gaps")))
    if not negative_ok:
        failed.append("negative-gap-exit")

    excluded = {row.get("id"): row.get("reason")
                for row in catalog.excluded_capabilities
                if isinstance(row, dict)}
    if "ad-enum" in catalog.capabilities or "ad-enum" in excluded:
        failed.append("archived-capability-filter")
    if "rootfs-emulate" not in excluded or excluded.get("rootfs-emulate") != "reserved":
        failed.append("reserved-capability-filter")
    if "sign-recompute" not in excluded or excluded.get("sign-recompute") != "probe":
        failed.append("probe-capability-filter")
    for row in results:
        for cid in row.get("combination", []):
            cap = catalog.capabilities.get(cid) or {}
            if cid.startswith("tool:") or cid.startswith("apk:") or cid.startswith("mcp:"):
                continue
            source = cap.get("source", "")
            if source.startswith("Tool/capabilities/") and source.endswith(".json"):
                try:
                    raw = _load_json(catalog.root / source)
                except Exception:
                    continue
                if raw.get("reserved") is True or raw.get("maturity") == "probe":
                    failed.append("non-auto-combination:" + cid)

    payload = {
        "ok": not failed,
        "self_test": {
            "passed": summary["covered"],
            "failed": len(failed),
            "total": summary["total"],
        },
        "runtime_locator": runtime_result,
        "negative_gap_check": negative_ok,
        "capability_filters": {
            "archived": "ad-enum" not in catalog.capabilities,
            "reserved": "rootfs-emulate" in excluded,
            "probe": "sign-recompute" in excluded,
        },
        "bare_capability_ids": {
            "captcha-gap": "captcha-gap" in set(
                (catalog.playbooks.get("captcha-handling") or {}).get(
                    "capability_ids") or []),
            "captcha-angle": "captcha-angle" in set(
                (catalog.playbooks.get("captcha-handling") or {}).get(
                    "capability_ids") or []),
        },
        "results": results,
    }
    if failed:
        payload["ok"] = False
        payload["blocked_at"] = "self-test"
        payload["reason"] = "自测失败: " + ", ".join(failed)
    return payload, (0 if not failed else 2)


def build_payload(root: Path, probes_path: Path, catalog: Catalog):
    if not probes_path.is_file():
        return {
            "ok": False,
            "schema": SCHEMA,
            "blocked_at": "intent-probes",
            "reason": f"探针文件不可用: {probes_path}",
        }, 2
    try:
        data = _load_json(probes_path)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "schema": SCHEMA,
            "blocked_at": "intent-probes",
            "reason": f"探针文件不是合法 JSON: {exc}",
        }, 2

    probes = data.get("probes") if isinstance(data, dict) else data
    if not isinstance(probes, list) or not probes:
        return {
            "ok": False,
            "schema": SCHEMA,
            "blocked_at": "intent-probes",
            "reason": "探针列表为空或结构不可用",
        }, 2

    if not catalog.playbooks:
        return {
            "ok": False,
            "schema": SCHEMA,
            "blocked_at": "playbooks",
            "reason": "未找到可读的配方触发词（Tool/playbooks/*.md）",
        }, 2

    summary, results = evaluate(probes, catalog)
    gaps = [r for r in results if r["status"] != "covered"]
    payload = {
        "ok": not gaps,
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "root": str(root),
        "probes": str(probes_path.relative_to(root)) if probes_path.is_relative_to(root) else str(probes_path),
        "summary": summary,
        "covered": summary["covered"],
        "uncovered": summary["uncovered"],
        "gaps": [
            {
                "id": g["id"],
                "text": g["text"],
                "expect": g["expect"],
                "reason": g["reason"],
                "combination": g["combination"],
            }
            for g in gaps
        ],
        "results": results,
        "sources": catalog.sources,
        "warnings": catalog.warnings,
    }
    if gaps:
        payload["blocked_at"] = "intent-gaps"
        payload["reason"] = "有 %d 条意图未落到期望配方/能力" % len(gaps)
    return payload, (0 if not gaps else 1)


def _print_human(payload):
    if not payload.get("ok"):
        print(f"[intent-coverage] FAIL at {payload.get('blocked_at')}: {payload.get('reason')}")
        return
    s = payload["summary"]
    print(f"[intent-coverage] {s['covered']}/{s['total']} covered, {s['uncovered']} uncovered, "
          f"{s['violations']} violations ({s['coverage_pct']}%)")
    for row in payload["results"]:
        mark = "OK " if row["status"] == "covered" else "GAP"
        landed = row["landed"]
        target = f"{landed['kind']}:{landed['id']}" if landed["id"] else "-"
        print(f"  {mark} {row['id']:<12} -> {target:<36} expect={row['expect']}")
        if row["status"] != "covered" and row["combination"]:
            print(f"      combine: {' + '.join(row['combination'])}")


def _repo_root_path(p: Path) -> Path:
    return Path(_seep_repo_root(__file__))


def main(argv=None):
    parser = argparse.ArgumentParser(description="意图探针 -> 配方/能力 覆盖率统计")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--self-test", action="store_true", help="跑 5 条内置样本")
    parser.add_argument("--root", default="", help="仓库根（默认按脚本位置推断）")
    parser.add_argument("--probes", default="", help="探针 JSON 路径")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else _repo_root_path(Path(__file__))
    probes_path = Path(args.probes).resolve() if args.probes else root / "Tool" / "config" / "intent-probes.json"

    catalog = Catalog(root)
    catalog.load_playbooks()
    catalog.load_capabilities()

    if args.self_test:
        payload, rc = run_self_test(catalog)
    else:
        payload, rc = build_payload(root, probes_path, catalog)

    if args.json or args.self_test:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_human(payload)
    return rc


if __name__ == "__main__":
    sys.exit(main())
