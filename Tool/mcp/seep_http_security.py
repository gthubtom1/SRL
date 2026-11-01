#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP replay redaction and session-path boundaries."""
from __future__ import annotations

import os
import re


REDACTED = "[REDACTED]"

_CRED_KEY_RE = re.compile(
    r"cookie|authorization|auth|api[-_]?key|apikey|access[-_]?key|private[-_]?key|key|token|"
    r"secret|passw|passwd|pwd|session|jwt|bearer|credential|signature|ticket|nonce|csrf|xsrf|sid|license|card|activation|otp|mfa|卡密|密码|验证码",
    re.IGNORECASE)

_CRED_META_KEYS = {
    "cookies_redacted", "cookie_counts", "cookie_count", "set_cookie_names",
    "header_keys", "request_header_keys", "response_header_keys", "session",
}

HTTP_SESSION_SCHEMA = "seep.http-session/2"


class RedactionFailure(RuntimeError):
    """Raised when output cannot be proven free of known credential values."""


def _http_iso_now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _scrub_text(text: str, secrets) -> str:
    if not isinstance(text, str):
        raise RedactionFailure("期望 str 才能清洗，实际 %s" % type(text).__name__)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def _url_secrets(url: str) -> list[str]:
    from urllib.parse import urlsplit, parse_qsl
    try:
        parsed = urlsplit(str(url))
    except Exception:
        return []
    found = []
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0]
        found.append(userinfo.split(":", 1)[0])
        if ":" in userinfo:
            found.append(userinfo.split(":", 1)[1])
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if value and (_CRED_KEY_RE.search(str(key)) or key.lower() == "code"):
            found.append(value)
    return [value for value in found if value]


def _redact_map(mapping, secrets=()) -> dict:
    if not isinstance(mapping, dict):
        raise RedactionFailure("期望 dict 才能脱敏，实际 %s" % type(mapping).__name__)
    output = {}
    for key, value in mapping.items():
        name = str(key)
        if _CRED_KEY_RE.search(name):
            output[name] = REDACTED
        elif isinstance(value, str):
            output[name] = _scrub_text(value, secrets)
        elif isinstance(value, (int, float, bool)) or value is None:
            output[name] = value
        else:
            output[name] = _scrub_text(str(value), secrets)
    return output


def _redact_cookie_map(cookie_map) -> dict:
    if not isinstance(cookie_map, dict):
        raise RedactionFailure("期望 dict 才能脱敏，实际 %s" % type(cookie_map).__name__)
    return {str(key): REDACTED for key in cookie_map}


def _redact_url(url: str, secrets=()) -> str:
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote
    try:
        parsed = urlsplit(str(url))
    except Exception as exc:
        raise RedactionFailure(
            "URL 无法解析，无法保证不泄漏: %s" % type(exc).__name__)
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _CRED_KEY_RE.search(key) or key.lower() == "code":
            pairs.append(quote(str(key), safe="") + "=" + REDACTED)
        else:
            pairs.append(quote(str(key), safe="") + "="
                         + quote(_scrub_text(value, secrets), safe=""))
    return urlunsplit(
        (parsed.scheme, netloc, _scrub_text(parsed.path, secrets), "&".join(pairs),
         _scrub_text(parsed.fragment, secrets)))


def _secret_variants(value: str) -> list[str]:
    from urllib.parse import quote, unquote
    raw = str(value)
    variants = {raw, quote(raw, safe=""), unquote(raw)}
    return [value for value in variants if value]


def _header_secret_variants(value: str) -> list[str]:
    variants = _secret_variants(value)
    match = re.match(
        r"^(?:bearer|basic|token|digest|negotiate|hoba|mutual|aws4-hmac-sha256)\s+(.+)$",
        str(value).strip(), re.IGNORECASE)
    if match:
        variants.extend(_secret_variants(match.group(1).strip()))
    return variants


def _cookie_header_secrets(value: str, set_cookie: bool = False) -> list[str]:
    """Collect individual Cookie/Set-Cookie values, including quoted values.

    A cookie jar can omit intermediate redirect cookies; the raw header remains
    a source of credentials even when no jar entry was returned.
    """
    from http.cookies import SimpleCookie
    found = []
    parsed = SimpleCookie()
    try:
        parsed.load(value)
        found.extend(morsel.value for morsel in parsed.values())
    except Exception:
        pass
    # Be conservative with nonstandard or combined headers a jar cannot parse.
    attributes = {'path', 'domain', 'expires', 'max-age', 'samesite', 'secure',
                  'httponly', 'partitioned', 'priority', 'version', 'comment'}
    for match in re.finditer(
            r'(?:^|[;,])\s*([^\s=;,]+)\s*=\s*("[^"\r\n]*"|[^;,\s]+)', value):
        if not set_cookie or match.group(1).lower() not in attributes:
            found.append(match.group(2).strip('"'))
    return [variant for item in found for variant in _secret_variants(item)]


def _payload_secret_values(text: str, opaque_is_secret: bool = False) -> list[str]:
    """Collect bounded JSON/form credential fields without changing wire bytes."""
    import json
    from urllib.parse import parse_qsl
    if not text:
        return []
    if not isinstance(text, str) or len(text) > 1024 * 1024:
        raise RedactionFailure("payload too large to inspect safely")
    try:
        if len(text.encode("utf-8")) > 1024 * 1024:
            raise RedactionFailure("payload too large to inspect safely")
    except UnicodeError:
        raise RedactionFailure("payload encoding invalid") from None
    sensitive = re.compile(_CRED_KEY_RE.pattern + r"|license|card|activation|卡密|密码|账号", re.I)
    try:
        value = json.loads(text)
    except RecursionError:
        raise RedactionFailure("payload nesting too deep") from None
    except ValueError:
        try:
            return [v for k, v in parse_qsl(text, max_num_fields=2048) if sensitive.search(k)] + ([text] if opaque_is_secret else [])
        except ValueError:
            raise RedactionFailure("payload field count too large") from None
    stack, found, visited = [(value, False)], [], 0
    while stack:
        node, private = stack.pop()
        visited += 1
        if visited > 4096:
            raise RedactionFailure("payload node count too large")
        if isinstance(node, dict):
            stack.extend((v, private or bool(sensitive.search(str(k)))) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((v, private) for v in node)
        elif (private or (opaque_is_secret and isinstance(node, str) and len(node) >= 8)) and isinstance(node, (str, int, float)) and type(node) is not bool:
            found.append(str(node))
    return found


def known_secrets(cookie_maps=(), header_maps=(), url: str = "", body: str = "",
                  opaque_body_is_secret: bool = False) -> list[str]:
    found = []
    for cookie_map in cookie_maps:
        if not isinstance(cookie_map, dict):
            continue
        for value in cookie_map.values():
            if isinstance(value, str):
                found.extend(_secret_variants(value))
    for header_map in header_maps:
        if not isinstance(header_map, dict):
            continue
        for key, value in header_map.items():
            if _CRED_KEY_RE.search(str(key)) and isinstance(value, str):
                found.extend(_header_secret_variants(value))
                if str(key).lower() in ("cookie", "set-cookie"):
                    found.extend(_cookie_header_secrets(value, str(key).lower() == "set-cookie"))
    for value in _url_secrets(url):
        found.extend(_secret_variants(value))
    for value in _payload_secret_values(body, opaque_body_is_secret):
        found.extend(_secret_variants(value))
    return sorted(set(found), key=len, reverse=True)


def assert_redacted(payload, secrets, where: str) -> None:
    leaf_values = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                name = str(key)
                child_path = f"{path}.{name}"
                if name.lower() in _CRED_META_KEYS:
                    if isinstance(value, dict):
                        walk(value, child_path)
                    continue
                if _CRED_KEY_RE.search(name):
                    sensitive_leaves = []

                    def collect(item):
                        if isinstance(item, dict):
                            for nested in item.values():
                                collect(nested)
                        elif isinstance(item, (list, tuple)):
                            for nested in item:
                                collect(nested)
                        else:
                            sensitive_leaves.append(item)

                    collect(value)
                    if sensitive_leaves and any(leaf != REDACTED for leaf in sensitive_leaves):
                        raise RedactionFailure(
                            f"{where}: 敏感键 {child_path} 的值未脱敏")
                    continue
                walk(value, child_path)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        else:
            leaf_values.append(str(node))

    walk(payload, "$")
    if any(secret in text for secret in secrets for text in leaf_values):
        raise RedactionFailure(
            f"{where}: 载荷里仍出现已知凭据值（值本身不打印）")


def http_session_snapshot(
    method, url, status, req_headers, resp_headers, set_cookie_names,
    body_len, secrets=(),
) -> dict:
    return {
        "schema": HTTP_SESSION_SCHEMA,
        "at": _http_iso_now(),
        "cookies_redacted": True,
        "last_request": {
            "method": method,
            "url": _redact_url(url, secrets),
            "status": status,
            "header_keys": sorted(str(key) for key in (req_headers or {})),
            "body_len": body_len,
        },
        "last_response": {
            "header_keys": sorted(str(key) for key in (resp_headers or {})),
            "set_cookie_names": sorted(str(name) for name in (set_cookie_names or [])),
        },
        "note": (
            "本文件只存非凭据会话快照（时间/方法/URL/头名/状态码）；"
            "Cookie、Authorization、X-Api-Key 等值不进证据面（要留存请放凭据仓）。"
            "会话保持请在同一次调用里传 cookies（内存），或先用 cred-store.py 存好再 --from 读取。"),
    }


def http_session_root(workspace_root: str) -> str:
    configured = os.environ.get("SEEP_HTTP_SESSION_ROOT", "").strip()
    root = configured or os.path.join(workspace_root, "http-sessions")
    return os.path.realpath(os.path.abspath(root))


def http_session_path(value: str, workspace_root: str) -> str:
    """Bind snapshots to a dedicated root and a regular JSON file."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("session_file 必须是非空路径")
    root = http_session_root(workspace_root)
    raw = value.strip()
    candidate = os.path.abspath(
        raw if os.path.isabs(raw) else os.path.join(root, raw))
    if os.path.splitext(candidate)[1].lower() != ".json":
        raise ValueError("session_file 必须使用 .json 扩展名")
    parent = os.path.realpath(os.path.dirname(candidate))
    candidate_real = os.path.realpath(candidate)
    if os.path.commonpath((root, parent)) != root:
        raise ValueError("session_file 必须位于专用会话目录内")
    if os.path.commonpath((root, candidate_real)) != root:
        raise ValueError("session_file 不能通过链接越出专用会话目录")
    if os.path.lexists(candidate) and (
        os.path.islink(candidate) or not os.path.isfile(candidate)
    ):
        raise ValueError("session_file 必须是普通文件且不能是链接")
    return candidate
