"""Dispatch-stage bridge; no transport backend, automatic retry or raw evidence IO."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from seep_http_security import (RedactionFailure, known_secrets as _known_secrets,
    http_session_snapshot as _http_session_snapshot, _scrub_text, _redact_url,
    _redact_map, _redact_cookie_map)

from lib.runtime_risk import RiskError, RiskStore, needs_grant, origin, retry_deadline


def response_event(status, headers, text):
    lowered = {str(k).lower(): v for k, v in headers.items()}
    if status == 429:
        return "rate_limited", retry_deadline(lowered.get("retry-after")), None
    if status in {401, 403}:
        return "access_rejected", None, False
    if 500 <= status <= 599:
        return "server_error", retry_deadline(lowered.get("retry-after")), False
    if lowered.get("cf-mitigated") == "challenge" or (
            "html" in str(lowered.get("content-type", "")).lower()
            and re.search(r"/cdn-cgi/challenge-platform/|cf-chl-widget", text[:65536])):
        return "challenge", None, False
    try:
        data = json.loads(text[:65536])
    except (ValueError, TypeError, RecursionError):
        return "none", None, None
    if not isinstance(data, dict):
        return "none", None, None
    # Server content may pause its own subject but never grant, resume or
    # change the policy. Arbitrary prose is not an executable instruction.
    event = data.get("risk_event", data.get("code"))
    allowed = {"account_restricted", "device_binding", "environment_rejected", "rate_limited"}
    return (event if isinstance(event, str) and event in allowed else "none", None,
            data.get("ok") if type(data.get("ok")) is bool else None)


class HttpPermit:
    def __init__(self, url, method, headers, cookies, body, scope_id="", subject_ref=""):
        hosts = [value for key, value in headers.items() if key.lower() == "host"]
        if len(hosts) > 1 or any(any(c in value for c in "/\\@\r\n") or
                                origin(urlsplit(url).scheme + "://" + value) != origin(url) for value in hosts):
            raise RiskError("host_header_scope_mismatch")
        try:
            self.body_secrets = _known_secrets(body=body, opaque_body_is_secret=True)
        except RedactionFailure:
            raise RiskError("request_payload_inspection_limit") from None
        self.store = RiskStore()
        payload = json.dumps([url, method, headers, cookies, body], ensure_ascii=True, sort_keys=True)
        self.fingerprint = self.store.digest(payload)
        self.operation_id = self.store.reserve(url, self.fingerprint, scope_id, subject_ref,
                                               needs_grant(url, method, headers, cookies, body))
        self.dispatched = False
        self.response_observed = False
        self.result = {"operation_id": self.operation_id, "coverage": "adapter_dispatch_single_host",
                       "redirects_followed": False, "automatic_retries": 0}

    def begin(self):
        self.store.begin(self.operation_id, self.fingerprint)
        self.dispatched = True

    def observe(self, status, headers, text):
        self.response_observed = True
        event, retry_at, business_ok = response_event(status, headers, text)
        self.result.update(event=event, paused=event != "none", business_success=business_ok,
                           request_sent=True, retry_not_before=retry_at)

    def evidence_failed(self):
        self.result.update(event="evidence_failed_after_dispatch", paused=True)

    def finish(self):
        state = self.store.finish(self.operation_id, self.result["event"], self.result.get("retry_not_before"))
        self.result.update(state)

    def unknown(self):
        self.store.finish(self.operation_id, "outcome_unknown")
        self.result.update(event="outcome_unknown", paused=True, request_sent=None, dispatch_started=True)


def prepare(url, method, headers, cookies, body, scope_id="", subject_ref=""):
    return HttpPermit(url, method, headers, cookies, body, scope_id, subject_ref)


def failure(code, permit=None):
    return json.dumps({"ok": False, "error": code, "message": "[ERROR] bounded dispatch did not complete; no automatic resend",
                       "request_sent": (True if permit and permit.response_observed else
                                        None if permit and permit.dispatched else False),
                       "dispatch_started": bool(permit and permit.dispatched),
                       "operation_id": permit.operation_id if permit else None,
                       "automatic_retry": False, "offline_work_allowed": True,
                       "next_step": "inspect runtime-risk status and existing task scope; do not blindly resend",
                       "coverage": "cooperating_adapters_single_host"}, ensure_ascii=False)


def publish_result(permit, method, url, hdr, ck, body, backend, resp_status,
                   resp_headers, resp_text, set_cookies, session_path,
                   write_snapshot, assert_output, session_read_note=""):
    # 本次已知的真实凭据值：只在内存里流转，用来「清洗 + 断言」，绝不进载荷
    try:
        secrets = _known_secrets([ck, set_cookies], [hdr, resp_headers], url) + permit.body_secrets
        secrets = sorted(set(secrets + _known_secrets(body=resp_text)), key=len, reverse=True)
    except RedactionFailure:
        permit.evidence_failed()
        try:
            permit.finish()
        except (RiskError, OSError):
            pass
        return failure("payload_redaction_failed_after_dispatch", permit)

    # 写会话快照：只写非凭据字段（P3 白名单）
    saved_note = ""
    write_ok = True
    if session_path:
        try:
            snapshot = _http_session_snapshot(method, url, resp_status, hdr, resp_headers,
                                              list(set_cookies), len(body), secrets)
            blob = json.dumps(snapshot, ensure_ascii=False, indent=2)
            # P2：先断言再落盘（顺序不能反）；不通过就抛，绝不写盘
            assert_output(snapshot, secrets, "session_file")
            write_snapshot(session_path, blob + "\n")
            saved_note = (f"非凭据会话快照已写入 {session_path}"
                          f"（cookie {len(ck)} 个 / set-cookie 名 {len(set_cookies)} 个已脱敏，值不进证据面）")
        except RedactionFailure:
            permit.evidence_failed()
            try:
                permit.finish()
            except (RiskError, OSError):
                pass
            return failure("evidence_redaction_failed_after_dispatch", permit)
        except OSError as exc:
            write_ok = False
            permit.evidence_failed()
            saved_note = f"请求已完成，但会话快照写入失败: {type(exc).__name__}: {exc}"

    # 输出：所有凭据值 → [REDACTED]（保留键名与条数，便于判断有没有登录态）
    # Scrub before cutting: otherwise a value spanning the boundary leaks its prefix.
    body_preview = _scrub_text(resp_text, secrets)[:2000]
    out = {
        "ok": write_ok and 200 <= resp_status < 300 and not permit.result["paused"] and permit.result["business_success"] is not False,
        "completion_status": "complete" if write_ok else "partial",
        "runtime_risk": permit.result,
        "backend": backend,
        "request": {"method": method, "url": _redact_url(url, secrets),
                    "headers": _redact_map(hdr, secrets),
                    "cookies": _redact_cookie_map(ck),
                    "body_len": len(body)},
        "status": resp_status,
        "response_headers": _redact_map(resp_headers, secrets),
        "set_cookies": _redact_cookie_map(set_cookies),
        "cookies_redacted": True,
        "cookie_counts": {"request": len(ck), "response_set": len(set_cookies)},
        "body_preview": body_preview,
        "body_len": len(resp_text),
    }
    if not write_ok:
        out["error"] = "session_write_failed"
        out["network_request_completed"] = True
        out["snapshot_written"] = False
    elif session_path:
        out["snapshot_written"] = True
    notes = [n for n in (session_read_note, saved_note) if n]
    if notes:
        out["session"] = "；".join(notes)
    # P2：出厂前再断言一次（这一行是“凭据不进输出”的机检闸门）
    try:
        assert_output(out, secrets, "http_replay_output")
    except RedactionFailure:
        permit.evidence_failed()
        try:
            permit.finish()
        except (RiskError, OSError):
            pass
        return failure("output_redaction_failed_after_dispatch", permit)
    try:
        permit.finish()
    except (RiskError, OSError):
        return failure("state_write_failed_after_dispatch", permit)
    out["ok"] = out["ok"] and not permit.result["paused"]
    return json.dumps(out, indent=2, ensure_ascii=False)
