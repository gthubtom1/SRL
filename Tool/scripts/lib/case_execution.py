"""Machine-checkable execution claims for real/public evidence cases.

Labels alone do not prove that a case was executed.  A recorded case must carry
structured command and return-code fields plus at least one hashed, case-local
artifact.  Prose in ``evidence`` or ``lessons`` is only scanned for negated,
hypothetical, or future claims; it is never used to invent missing execution
fields.  Explicit ``not-recorded`` history remains valid only with a reason and
is never counted as an execution witness.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any


NEGATED_EXECUTION_RE = re.compile(
    r"(?i)(?:未|没有|并未|尚未|从未|不能|无法).{0,24}"
    r"(?:python(?:3)?|py|powershell|pwsh|bash|sh|tshark|gcc|clang|node|"
    r"curl|wget|aapt2?|jadx|r2|rabin2|apktool|zipalign|upx|go|cargo|java|"
    r"npm|pnpm|yarn|git|sha256sum|运行|执行|跑|调用|启动)"
    r"|(?:python(?:3)?|py|powershell|pwsh|bash|sh|tshark|gcc|clang|node|"
    r"curl|wget|aapt2?|jadx|r2|rabin2|apktool|zipalign|upx|go|cargo|java|"
    r"npm|pnpm|yarn|git|sha256sum).{0,24}(?:未|没有|并未|尚未|从未)"
    r".{0,12}(?:运行|执行|跑|调用|启动)"
)
HYPOTHETICAL_RE = re.compile(
    r"(?i)(?:如果|假设|假如|若|可能|也许|预计|预期|将会|打算|准备|凭经验|"
    r"未来|后续再|下次再).{0,36}(?:python(?:3)?|py|powershell|pwsh|bash|sh|"
    r"tshark|gcc|clang|node|curl|wget|aapt2?|jadx|r2|rabin2|apktool|"
    r"zipalign|upx|go|cargo|java|npm|pnpm|yarn|git|sha256sum|rc\s*=)"
)


def _clauses(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\n。；;]+", text or "") if part.strip()]


def _case_relative(value: Any, label: str) -> str:
    """Return a normalized case-relative file path or raise ``ValueError``."""
    text = str(value or "").strip().replace("\\", "/")
    ref = PurePosixPath(text)
    if (not text or ref.is_absolute() or ".." in ref.parts
            or ":" in text or "\0" in text):
        raise ValueError("%s 必须是案例内相对路径" % label)
    return ref.as_posix()


def _command_value(repro: dict[str, Any]) -> Any:
    for key in ("command", "cmd", "argv"):
        if key in repro:
            return repro[key]
    return None


def _valid_command(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and "\0" not in value
    if isinstance(value, list):
        return bool(value) and all(
            isinstance(item, str) and bool(item.strip()) and "\0" not in item
            for item in value
        )
    return False


def _returncode_value(repro: dict[str, Any]) -> Any:
    if "returncode" in repro:
        return repro["returncode"]
    if "rc" in repro:
        return repro["rc"]
    return None


def assess(case: dict[str, Any]) -> dict[str, Any]:
    """Return execution defects and whether the case is execution-bound."""
    kind = str((case or {}).get("evidence_kind") or "").strip().lower()
    result = {"state": kind or "unknown", "execution_bound": False, "defects": []}
    if kind not in {"real", "public"}:
        return result

    repro = case.get("repro")
    if not isinstance(repro, dict):
        result["state"] = "invalid"
        result["defects"].append("real/public 缺结构化 repro 对象")
        return result
    status = str(repro.get("status") or "").strip().lower()
    result["state"] = status or "unknown"
    if status == "not-recorded":
        if not str(repro.get("reason") or "").strip():
            result["state"] = "invalid"
            result["defects"].append("not-recorded 缺 reason")
        return result
    if status != "recorded":
        result["state"] = "invalid"
        result["defects"].append("real/public 的 repro.status 必须是 recorded 或 not-recorded")
        return result

    evidence = str(repro.get("evidence") or "").strip()
    lessons = "\n".join(str(item) for item in (case.get("lessons") or []))
    text = evidence + "\n" + lessons
    for clause in _clauses(text):
        if NEGATED_EXECUTION_RE.search(clause) or HYPOTHETICAL_RE.search(clause):
            result["defects"].append("否定/假设/未来语义不能认证 real: %s" % clause[:120])
            break

    command_bound = _valid_command(_command_value(repro))
    code_bound = type(_returncode_value(repro)) is int
    artifacts = case.get("artifacts")
    output_errors = []
    output_bound = False
    if isinstance(artifacts, list):
        for index, item in enumerate(artifacts):
            if not isinstance(item, dict):
                continue
            try:
                path = _case_relative(item.get("path"), "artifacts[%d].path" % index)
            except ValueError as exc:
                output_errors.append(str(exc))
                continue
            digest = str(item.get("sha256") or "")
            if path and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                output_bound = True
    if not command_bound:
        result["defects"].append("recorded real/public 缺结构化 command/cmd/argv")
    if not code_bound:
        result["defects"].append("recorded real/public 缺整数 returncode/rc")
    if not output_bound:
        result["defects"].append("recorded real/public 未绑定案例内带 sha256 的输出产物")
    result["defects"].extend(output_errors)
    result["execution_bound"] = command_bound and code_bound and output_bound and not result["defects"]
    if result["defects"]:
        result["state"] = "invalid"
    return result
