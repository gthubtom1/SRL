"""Check active skill handoffs against deployed names and explicit source paths."""
from __future__ import annotations

import json
from pathlib import Path
import re


def check(root=None):
    root = Path(root or Path(__file__).resolve().parents[2])
    skills = root / "Tool/skill"
    active = sorted(p for p in skills.glob("*/SKILL.md") if not p.parent.name.startswith("_"))
    deployed = {p.parent.name for p in active}
    archived = {p.parent.name for p in (skills / "_pending").rglob("SKILL.md")} - deployed
    archived_by_prefix = {}
    for name in archived:
        if len(name) >= 2 and name[:2].isdigit():
            archived_by_prefix.setdefault(name[:2], set()).add(name)
    problems, references, archive_refs, short_archive_refs = [], 0, 0, 0
    for skill in active:
        for line_no, line in enumerate(skill.read_text(encoding="utf-8-sig").splitlines(), 1):
            for span in re.findall(r"`([^`\n]+)`", line):
                if span in archived and re.search(r"交|技能|→|转|读|裁定|承担", line):
                    problems.append({"file": str(skill.relative_to(root)), "line": line_no,
                                     "target": span, "reason": "旧技能未部署；使用正式技能名或完整源码路径"})
                for target in re.findall(r"Tool/(?:skill|playbooks)/[\w./-]+\.(?:md|py|json)", span):
                    references += 1
                    archive_refs += "/_pending/" in target
                    if not (root / target).is_file():
                        problems.append({"file": str(skill.relative_to(root)), "line": line_no,
                                         "target": target, "reason": "源码交接目标不存在"})
                if span.startswith("_pending/"):
                    problems.append({"file": str(skill.relative_to(root)), "line": line_no,
                                     "target": span, "reason": "归档参考需使用 Tool/skill/_pending 完整源码路径"})
                if re.fullmatch(r"\d{2}", span) and re.search(
                        r"交|→|转|读|裁定|承担|归档|子技能", line):
                    matches = sorted(archived_by_prefix.get(span, set()))
                    short_archive_refs += 1
                    if not matches:
                        problems.append({
                            "file": str(skill.relative_to(root)), "line": line_no,
                            "target": span,
                            "reason": "两位归档简写没有对应 Tool/skill/_pending/<编号>-* 技能",
                        })
                    elif len(matches) > 1:
                        problems.append({
                            "file": str(skill.relative_to(root)), "line": line_no,
                            "target": span,
                            "reason": "两位归档简写有歧义：" + ",".join(matches),
                        })
    return {"ok": not problems, "skills": len(active), "source_references": references,
            "archived_source_references": archive_refs,
            "archived_short_references": short_archive_refs, "problems": problems}


if __name__ == "__main__":
    result = check()
    print(json.dumps(result, ensure_ascii=True, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
