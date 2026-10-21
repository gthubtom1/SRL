#!/usr/bin/env python3
"""Offline kubeconfig / AWS-credentials triage for the ad-cloud domain.

This is a *local file* checker. It never contacts an API server, STS, IAM, or
any other network endpoint. Findings that depend on live RBAC/IAM policy are
explicitly marked "unknown_offline" instead of being guessed.

Usage:
  python adcloud-check.py --kubeconfig ~/.kube/config
  python adcloud-check.py --aws-creds ~/.aws/credentials
  python adcloud-check.py --kubeconfig ./config --aws-creds ./credentials --json

Exit codes:
  0  files parsed, findings emitted
  2  missing/unreadable input or parse error (structured error is printed)
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import time

VERSION = "1.0.0"
WIDE_SA_NAMES = {"cluster-admin", "admin", "edit"}
WIDE_GROUPS = {"system:masters", "system:serviceaccounts"}
PREFIXED_ADMIN_USERS = {"kubernetes-admin", "cluster-admin", "admin"}


class CheckError(Exception):
    def __init__(self, code, message, path=""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path


# ---------------------------------------------------------------------------
# Minimal block-YAML reader (kubeconfig is a small, regular subset of YAML).
# Supports mappings, sequences, quoted/plain scalars, inline JSON, comments,
# and block scalars. Anchors/aliases and multi-document files are rejected.
# ---------------------------------------------------------------------------

class YLine:
    __slots__ = ("indent", "text", "lineno")

    def __init__(self, indent, text, lineno):
        self.indent = indent
        self.text = text
        self.lineno = lineno


def _strip_comment(line):
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if quote == '"' and ch == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                if quote == "'" and i + 1 < len(line) and line[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = None
        else:
            if ch in "'\"":
                quote = ch
                out.append(ch)
            elif ch == "#" and (i == 0 or line[i - 1].isspace()):
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _tokenize(text):
    lines = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        raw = raw.expandtabs(8)
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        token = stripped.strip()
        if token in ("---", "..."):
            continue
        if token.startswith("&") or token.startswith("*"):
            raise ValueError("YAML anchors/aliases are not supported (line %d)" % lineno)
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append(YLine(indent, stripped[indent:], lineno))
    return lines


def _split_kv(text):
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                if quote == "'" and i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                quote = None
        else:
            if ch in "'\"":
                quote = ch
            elif ch == ":":
                key = text[:i].strip()
                if re.match(r"^[A-Za-z0-9_.-]+$", key):
                    return key, text[i + 1:].strip(), True
                return text.strip(), "", False
        i += 1
    return text.strip(), "", False


def _scalar(value):
    value = value.strip()
    if value == "":
        return ""
    if value in ("~", "null", "Null", "NULL"):
        return None
    if value.lower() in ("true", "yes", "on"):
        return True
    if value.lower() in ("false", "no", "off"):
        return False
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)
        except Exception:
            return value[1:-1]
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if value[0] in "[{":
        try:
            return json.loads(value)
        except Exception as exc:
            raise ValueError("invalid inline collection %r: %s" % (value[:40], exc))
    if re.fullmatch(r"[-+]?[0-9]+", value):
        try:
            return int(value)
        except ValueError:
            pass
    if re.fullmatch(r"[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?", value):
        try:
            return float(value)
        except ValueError:
            pass
    return value


def _parse_map(lines, i, indent):
    out = {}
    n = len(lines)
    while i < n and lines[i].indent == indent and not lines[i].text.startswith("-"):
        key, rest, has_key = _split_kv(lines[i].text)
        if not has_key:
            raise ValueError("expected 'key: value' at line %d" % lines[i].lineno)
        i += 1
        if rest in ("|", "|-", "|+", ">", ">-", ">+"):
            block = []
            while i < n and lines[i].indent > indent:
                block.append(lines[i].text)
                i += 1
            out[key] = "\n".join(block)
            continue
        if rest != "":
            out[key] = _scalar(rest)
            continue
        if i < n and (lines[i].indent > indent or
                      (lines[i].indent == indent and lines[i].text.startswith("-"))):
            out[key], i = _parse_block(lines, i, lines[i].indent)
        else:
            out[key] = None
    return out, i


def _parse_seq(lines, i, indent):
    items = []
    n = len(lines)
    while i < n and lines[i].indent == indent and lines[i].text.startswith("-"):
        rest = lines[i].text[1:].strip()
        i += 1
        if rest == "":
            if i < n and lines[i].indent > indent:
                value, i = _parse_block(lines, i, lines[i].indent)
            else:
                value = None
            items.append(value)
            continue
        key, value, has_key = _split_kv(rest)
        if not has_key:
            items.append(_scalar(rest))
            continue
        item = {}
        if value != "":
            item[key] = _scalar(value)
        elif i < n and lines[i].indent > indent:
            item[key], i = _parse_block(lines, i, lines[i].indent)
        else:
            item[key] = None
        if i < n and lines[i].indent > indent:
            extra, i = _parse_map(lines, i, lines[i].indent)
            if isinstance(extra, dict):
                item.update(extra)
        items.append(item)
    return items, i


def _parse_block(lines, i, indent):
    if i >= len(lines):
        return None, i
    if lines[i].text.startswith("-"):
        return _parse_seq(lines, i, indent)
    return _parse_map(lines, i, indent)


def parse_yaml(text):
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return json.loads(text)
    lines = _tokenize(text)
    if not lines:
        return {}
    value, _ = _parse_block(lines, 0, lines[0].indent)
    return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_list(value):
    return value if isinstance(value, list) else []


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _name(item):
    return str(_as_dict(item).get("name") or "")


def _b64decode(value):
    return base64.b64decode(value.encode("ascii"), validate=False)


def _token_fingerprint(token):
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:12]


def _jwt_payload(token):
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
    except Exception:
        return None


def _cert_info(pem_bytes):
    """Decode a PEM certificate locally with the stdlib ssl module."""
    path = None
    try:
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as fh:
            fh.write(pem_bytes)
            path = fh.name
        info = ssl._ssl._test_decode_cert(path)
    except Exception:
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    subject = ", ".join("%s=%s" % (key, val) for pair in info.get("subject", ()) for key, val in pair)
    issuer = ", ".join("%s=%s" % (key, val) for pair in info.get("issuer", ()) for key, val in pair)
    not_after = info.get("notAfter", "")
    expires = None
    try:
        expires = int(ssl.cert_time_to_seconds(not_after))
    except Exception:
        pass
    return {"subject": subject, "issuer": issuer, "not_after": not_after,
            "expires_epoch": expires}


def _finding(fid, severity, category, title, evidence, criteria, false_positive):
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "criteria": criteria,
        "false_positive": false_positive,
    }


def _now():
    return int(time.time())


# ---------------------------------------------------------------------------
# kubeconfig
# ---------------------------------------------------------------------------

def analyse_kubeconfig(path):
    if not os.path.exists(path):
        raise CheckError("KUBECONFIG_NOT_FOUND", "kubeconfig does not exist", path)
    if not os.path.isfile(path):
        raise CheckError("KUBECONFIG_NOT_A_FILE", "kubeconfig is not a regular file", path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        data = parse_yaml(text)
    except Exception as exc:
        raise CheckError("KUBECONFIG_PARSE_ERROR", "cannot parse kubeconfig: %s" % exc, path)
    if not isinstance(data, dict):
        raise CheckError("KUBECONFIG_PARSE_ERROR", "kubeconfig root is not a mapping", path)

    clusters = _as_list(data.get("clusters"))
    contexts = _as_list(data.get("contexts"))
    users = _as_list(data.get("users"))
    current = data.get("current-context")
    current = str(current) if current is not None else ""
    base_dir = os.path.dirname(os.path.abspath(path))
    findings = []
    limits = []

    cluster_rows = []
    for item in clusters:
        obj = _as_dict(item)
        body = _as_dict(obj.get("cluster"))
        row = {
            "name": _name(obj),
            "server": body.get("server", ""),
            "insecure_skip_tls_verify": bool(body.get("insecure-skip-tls-verify", False)),
            "has_ca": bool(body.get("certificate-authority-data") or body.get("certificate-authority")),
            "proxy_url": body.get("proxy-url", ""),
        }
        cluster_rows.append(row)
        if str(row["server"]).lower().startswith("http://"):
            findings.append(_finding(
                "K8S-TRANSPORT-001", "high", "transport",
                "API server uses plaintext HTTP",
                "%s server=%s" % (row["name"] or "<unnamed>", row["server"]),
                "Any bearer token/certificate sent over this endpoint is exposed to the network path.",
                "Loopback-only lab clusters may intentionally use HTTP; confirm the endpoint is not reachable off-host."))
        if row["insecure_skip_tls_verify"]:
            findings.append(_finding(
                "K8S-TRANSPORT-002", "medium", "transport",
                "insecure-skip-tls-verify=true",
                "%s" % (row["name"] or "<unnamed>"),
                "Server certificate is not validated, so a MITM can impersonate the API server.",
                "A local disposable test cluster may accept this; never for shared/production clusters."))
        if not row["has_ca"] and not row["insecure_skip_tls_verify"] and row["server"]:
            findings.append(_finding(
                "K8S-TRANSPORT-003", "medium", "transport",
                "No CA material pinned for a configured server",
                "%s server=%s" % (row["name"] or "<unnamed>", row["server"]),
                "Without certificate-authority(-data), verification relies on host trust or fails closed; verify explicitly.",
                "kubectl may fall back to system roots for a publicly trusted endpoint; check the actual chain."))

    context_rows = []
    for item in contexts:
        obj = _as_dict(item)
        body = _as_dict(obj.get("context"))
        context_rows.append({
            "name": _name(obj),
            "cluster": body.get("cluster", ""),
            "user": body.get("user", ""),
            "namespace": body.get("namespace", ""),
        })

    user_rows = []
    for item in users:
        obj = _as_dict(item)
        body = _as_dict(obj.get("user"))
        row = {
            "name": _name(obj),
            "has_token": bool(body.get("token")),
            "token_file": body.get("tokenFile", ""),
            "has_client_cert": bool(body.get("client-certificate-data") or body.get("client-certificate")),
            "has_basic_auth": bool(body.get("username") or body.get("password")),
            "exec": body.get("exec"),
            "auth_provider": body.get("auth-provider"),
            "impersonation": {k: body.get(k) for k in ("as", "as-groups", "as-uid") if body.get(k)},
            "anonymous": False,
            "token": None,
            "cert": None,
            "jwt": None,
        }

        cert_pem = None
        if body.get("client-certificate-data"):
            try:
                cert_pem = _b64decode(str(body["client-certificate-data"]))
            except Exception:
                findings.append(_finding(
                    "K8S-AUTH-004", "medium", "credential",
                    "client-certificate-data is not valid base64",
                    "%s" % (row["name"] or "<unnamed>"),
                    "Unreadable certificate material cannot be assessed; fix the kubeconfig before use.",
                    "The file may be truncated by a copy/paste tool."))
        elif body.get("client-certificate"):
            cert_path = str(body["client-certificate"])
            if not os.path.isabs(cert_path):
                cert_path = os.path.join(base_dir, cert_path)
            try:
                with open(cert_path, "rb") as fh:
                    cert_pem = fh.read()
            except OSError as exc:
                findings.append(_finding(
                    "K8S-AUTH-005", "medium", "credential",
                    "client certificate file is missing/unreadable",
                    "%s -> %s (%s)" % (row["name"] or "<unnamed>", cert_path, exc.strerror or "error"),
                    "The context cannot authenticate as configured until the file is restored.",
                    "The file may intentionally live on another host that has the kubeconfig."))
        if cert_pem:
            info = _cert_info(cert_pem)
            if info:
                row["cert"] = info
                if info.get("expires_epoch") and info["expires_epoch"] < _now():
                    findings.append(_finding(
                        "K8S-AUTH-006", "high", "credential",
                        "Client certificate is expired",
                        "%s notAfter=%s" % (row["name"] or "<unnamed>", info.get("not_after")),
                        "Expired certificate cannot authenticate; re-issue before using this context.",
                        "A skewed local clock can make a valid certificate look expired; compare with the API server clock."))
                blob = (info.get("subject", "") + " " + info.get("issuer", "")).lower()
                if "system:masters" in blob or "cluster-admin" in blob or "system:serviceaccount" in blob:
                    findings.append(_finding(
                        "K8S-RBAC-001", "high", "rbac",
                        "Client certificate subject suggests broad/privileged identity",
                        "%s subject=%s" % (row["name"] or "<unnamed>", info.get("subject")),
                        "system:masters bypasses RBAC; a service-account subject should be checked against its bindings.",
                        "The subject string alone does not prove the current bindings; confirm with `kubectl auth can-i --list`."))

        token = body.get("token")
        if token:
            token = str(token)
        elif body.get("tokenFile"):
            token_path = str(body["tokenFile"])
            if not os.path.isabs(token_path):
                token_path = os.path.join(base_dir, token_path)
            try:
                with open(token_path, "r", encoding="utf-8", errors="replace") as fh:
                    token = fh.read().strip()
            except OSError as exc:
                findings.append(_finding(
                    "K8S-AUTH-007", "medium", "credential",
                    "tokenFile is missing/unreadable",
                    "%s -> %s (%s)" % (row["name"] or "<unnamed>", token_path, exc.strerror or "error"),
                    "Projected service-account tokens expire; a missing file means the context cannot authenticate.",
                    "The token may be mounted only inside the pod, not on this host."))
        if token:
            row["has_token"] = True
            row["token"] = {"fingerprint": _token_fingerprint(token), "length": len(token)}
            payload = _jwt_payload(token)
            if payload:
                row["jwt"] = payload
                exp = payload.get("exp")
                sub = str(payload.get("sub", ""))
                groups = payload.get("groups") or []
                if isinstance(groups, str):
                    groups = [groups]
                row["token"]["exp"] = exp
                row["token"]["sub"] = sub
                row["token"]["groups"] = groups
                if isinstance(exp, (int, float)):
                    remaining = int(exp) - _now()
                    row["token"]["expires_in_seconds"] = remaining
                    if remaining < 0:
                        findings.append(_finding(
                            "K8S-TOKEN-001", "high", "token",
                            "Bearer token is expired",
                            "%s sub=%s exp=%s" % (row["name"] or "<unnamed>", sub or "?", exp),
                            "Expired token cannot authenticate; do not present it as a live credential.",
                            "Local clock skew can produce a false expiry; compare with the API server."))
                    elif remaining < 3600:
                        findings.append(_finding(
                            "K8S-TOKEN-002", "medium", "token",
                            "Bearer token expires within one hour",
                            "%s sub=%s remaining=%ss" % (row["name"] or "<unnamed>", sub or "?", remaining),
                            "Short-lived evidence must record the expiry and be re-acquired for reproduction.",
                            "The token may be auto-refreshed by an exec plugin even if this copy is short-lived."))
                else:
                    findings.append(_finding(
                        "K8S-TOKEN-003", "medium", "token",
                        "JWT has no exp claim",
                        "%s sub=%s" % (row["name"] or "<unnamed>", sub or "?"),
                        "A token without exp is long-lived or non-standard; treat it as a static credential.",
                        "Some non-Kubernetes JWT issuers intentionally omit exp; confirm the issuer."))
                if sub.startswith("system:serviceaccount:"):
                    parts = sub.split(":", 3)
                    if len(parts) == 4:
                        sa = parts[3]
                        row["service_account"] = {"namespace": parts[2], "name": sa}
                        if sa in WIDE_SA_NAMES:
                            findings.append(_finding(
                                "K8S-RBAC-002", "high", "rbac",
                                "Service-account identity uses a broad built-in name",
                                "%s sub=%s" % (row["name"] or "<unnamed>", sub),
                                "Names such as cluster-admin/admin/edit usually map to broad permissions; confirm the actual binding.",
                                "A custom RoleBinding may grant the same name only narrow rights; names are not proof."))
                if any(group in WIDE_GROUPS for group in groups):
                    findings.append(_finding(
                        "K8S-RBAC-003", "high", "rbac",
                        "JWT groups include a cluster-wide privileged group",
                        "%s groups=%s" % (row["name"] or "<unnamed>", ",".join(map(str, groups))),
                        "system:masters bypasses RBAC; system:serviceaccounts covers all service accounts.",
                        "The API server may reject the token or the group mapping may differ in this cluster."))
            else:
                findings.append(_finding(
                    "K8S-TOKEN-004", "medium", "token",
                    "Opaque/static bearer token (no JWT expiry readable)",
                    "%s fingerprint=%s" % (row["name"] or "<unnamed>", row["token"]["fingerprint"]),
                    "Opaque tokens cannot be checked for expiry offline; record acquisition time and test with a read-only call.",
                    "The token may be a JWT variant with an encrypted payload; treat expiry as unknown."))

        if row["has_basic_auth"]:
            findings.append(_finding(
                "K8S-AUTH-001", "medium", "credential",
                "Static basic-auth username/password in kubeconfig",
                "%s username=%s" % (row["name"] or "<unnamed>", body.get("username", "<set>")),
                "Basic auth is long-lived and often disallowed by modern API servers; it is a static secret at rest.",
                "A lab API server may still accept it; confirm support and rotate after testing."))

        exec_cfg = _as_dict(row["exec"])
        if exec_cfg:
            command = str(exec_cfg.get("command", ""))
            args = exec_cfg.get("args") or []
            env = exec_cfg.get("env") or []
            env_keys = []
            for entry in _as_list(env):
                entry = _as_dict(entry)
                env_keys.append(str(entry.get("name", "")))
                value = str(entry.get("value", ""))
                if re.search(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", value):
                    findings.append(_finding(
                        "K8S-AWS-001", "high", "cloud",
                        "AWS access key appears in kubeconfig exec env",
                        "%s env=%s value=%s" % (row["name"] or "<unnamed>", entry.get("name", "?"),
                                                re.sub(r"((?:AKIA|ASIA)[0-9A-Z]{4})[0-9A-Z]{12}", r"\1************", value)),
                        "Hardcoded AK in a local file is a credential leak; validate with `aws sts get-caller-identity` only if authorized.",
                        "The value may be a placeholder or a key already revoked; never print the full key."))
            findings.append(_finding(
                "K8S-AUTH-002", "info", "credential",
                "Exec credential plugin supplies authentication",
                "%s command=%s args=%s env=%s" % (row["name"] or "<unnamed>", command,
                                                 " ".join(map(str, _as_list(args)))[:120],
                                                 ",".join(env_keys) or "-"),
                "Expiry and identity are determined at runtime; offline checks cannot see the returned token.",
                "The plugin may cache a token with a long lifetime; inspect its cache/config separately."))

        if row["impersonation"]:
            findings.append(_finding(
                "K8S-RBAC-004", "high", "rbac",
                "Kubeconfig requests impersonation",
                "%s %s" % (row["name"] or "<unnamed>", row["impersonation"]),
                "as/as-groups changes the effective identity; the resulting permissions must be verified live.",
                "The API server may deny impersonation; authorization is still required."))

        if not any([row["has_token"], row["token_file"], row["has_client_cert"],
                    row["has_basic_auth"], exec_cfg, row["auth_provider"]]):
            row["anonymous"] = True
            findings.append(_finding(
                "K8S-AUTH-003", "high", "anonymous",
                "Context/user has no authentication material",
                "%s" % (row["name"] or "<unnamed>"),
                "If the API server allows anonymous requests, this context is effectively system:anonymous; "
                "if it does not, authentication fails.",
                "Some clusters deliberately map an empty user to a limited anonymous role; verify with a read-only request."))
        if row["name"] in ("system:anonymous", "system:unauthenticated"):
            findings.append(_finding(
                "K8S-AUTH-008", "high", "anonymous",
                "Kubeconfig names an anonymous/unauthenticated identity",
                "%s" % row["name"],
                "This identity is only meaningful if anonymous auth is enabled; confirm the API server flags and bindings.",
                "The name may be documentation-only and unused by the current context."))
        if row["name"] in PREFIXED_ADMIN_USERS:
            findings.append(_finding(
                "K8S-RBAC-005", "high", "rbac",
                "Context user name is a conventional cluster-admin identity",
                "%s" % row["name"],
                "kubeadm's kubernetes-admin certificate is commonly bound to cluster-admin; confirm the live binding.",
                "The name alone does not prove the binding; a renamed user can have any role."))
        user_rows.append(row)

    clusters_by_name = {row["name"]: row for row in cluster_rows}
    contexts_by_name = {row["name"]: row for row in context_rows}
    users_by_name = {row["name"]: row for row in user_rows}
    selected_context = contexts_by_name.get(current)
    selected_cluster = clusters_by_name.get(selected_context["cluster"]) if selected_context else None
    selected_user = users_by_name.get(selected_context["user"]) if selected_context else None

    if not current:
        findings.append(_finding(
            "K8S-CONFIG-001", "medium", "config",
            "current-context is not set",
            "kubeconfig has %d contexts but no current-context" % len(context_rows),
            "Commands without an explicit --context will fail or use an unexpected default.",
            "Some tooling sets context via environment/flags instead of the file."))
    elif not selected_context:
        findings.append(_finding(
            "K8S-CONFIG-002", "high", "config",
            "current-context does not resolve",
            "current-context=%s" % current,
            "The kubeconfig is internally inconsistent; the intended identity/cluster cannot be determined offline.",
            "A merged kubeconfig may be intentionally partial; supply the full file before use."))
    else:
        if selected_context["cluster"] not in clusters_by_name:
            findings.append(_finding(
                "K8S-CONFIG-003", "high", "config",
                "Context references an unknown cluster",
                "context=%s cluster=%s" % (selected_context["name"], selected_context["cluster"]),
                "The cluster entry is missing; no endpoint can be selected.",
                "The cluster may be supplied by another merged kubeconfig file."))
        if selected_context["user"] not in users_by_name:
            findings.append(_finding(
                "K8S-CONFIG-004", "high", "config",
                "Context references an unknown user",
                "context=%s user=%s" % (selected_context["name"], selected_context["user"]),
                "No credential is available for the selected context; anonymous auth is the only remaining possibility.",
                "The user may be supplied by another merged kubeconfig file."))
        if selected_user and selected_user.get("anonymous"):
            findings.append(_finding(
                "K8S-ANON-001", "high", "anonymous",
                "Selected context resolves to an anonymous/no-credential user",
                "context=%s user=%s" % (selected_context["name"], selected_context["user"]),
                "If anonymous auth is enabled, the effective identity is system:anonymous; otherwise the context fails.",
                "Offline inspection cannot see API server anonymous-auth flags or RBAC bindings."))

    if selected_user and selected_user.get("service_account"):
        sa = selected_user["service_account"]
        if sa["name"] in WIDE_SA_NAMES:
            findings.append(_finding(
                "K8S-RBAC-006", "high", "rbac",
                "Selected context authenticates as a broad-named service account",
                "namespace=%s sa=%s" % (sa["namespace"], sa["name"]),
                "Broad built-in names usually indicate cluster-wide rights; confirm with `kubectl auth can-i --list`.",
                "RBAC bindings are authoritative; the name is only a heuristic."))

    if selected_user and selected_user.get("jwt"):
        payload = selected_user["jwt"]
        if payload.get("exp") and int(payload["exp"]) < _now():
            findings.append(_finding(
                "K8S-TOKEN-005", "high", "token",
                "Selected context token is expired",
                "context=%s sub=%s" % (selected_context["name"] if selected_context else "?",
                                       payload.get("sub", "?")),
                "An expired token cannot reproduce the claimed access; re-acquire before evidence collection.",
                "Clock skew can make a live token look expired; compare host time with the API server."))

    limits.extend([
        "RBAC effective permissions are not evaluated offline: run `kubectl auth can-i --list` and inspect bindings.",
        "Anonymous access depends on API server --anonymous-auth and RBAC bindings, which are not in the kubeconfig.",
        "Token expiry is compared against the local clock; clock skew is unknown.",
        "Client certificate subjects/expiry are decoded locally; bindings and revocation are not visible offline.",
    ])

    return {
        "path": os.path.abspath(path),
        "current_context": current,
        "clusters": cluster_rows,
        "contexts": context_rows,
        "users": user_rows,
        "selected": {
            "context": selected_context,
            "cluster": selected_cluster,
            "user": selected_user,
        },
        "anonymous_risk": bool(selected_user and selected_user.get("anonymous")),
        "wide_privilege_indicators": [f["evidence"] for f in findings
                                      if f["category"] == "rbac" and f["severity"] == "high"],
        "findings": findings,
        "offline_limits": limits,
        "next_commands": [
            "kubectl --kubeconfig %s config current-context" % path,
            "kubectl --kubeconfig %s auth can-i --list" % path,
            "kubectl --kubeconfig %s get clusterrolebinding -o wide" % path,
            "kubectl --kubeconfig %s get rolebinding -A -o wide" % path,
            "kubectl --kubeconfig %s get secrets -A" % path,
            "kubectl --kubeconfig %s get pods -A -o wide" % path,
        ],
    }


# ---------------------------------------------------------------------------
# AWS credentials/config
# ---------------------------------------------------------------------------

def _redact_ak(value):
    value = value.strip()
    if re.fullmatch(r"(?:AKIA|ASIA)[0-9A-Z]{16}", value):
        return value[:4] + "*" * 12 + value[-4:]
    if len(value) <= 8:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _secret_fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def analyse_aws_creds(path):
    if not os.path.exists(path):
        raise CheckError("AWS_CREDS_NOT_FOUND", "AWS credentials file does not exist", path)
    if not os.path.isfile(path):
        raise CheckError("AWS_CREDS_NOT_A_FILE", "AWS credentials path is not a regular file", path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise CheckError("AWS_CREDS_UNREADABLE", str(exc), path)

    parser = configparser.RawConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise CheckError("AWS_CREDS_PARSE_ERROR", "cannot parse AWS credentials INI: %s" % exc, path)

    findings = []
    profiles = []
    all_ak = sorted(set(re.findall(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", text)))
    for section in parser.sections():
        items = {key.lower(): value for key, value in parser.items(section)}
        ak = items.get("aws_access_key_id", "").strip()
        secret = items.get("aws_secret_access_key", "")
        session = items.get("aws_session_token", "")
        row = {
            "profile": section,
            "access_key": _redact_ak(ak) if ak else "",
            "access_key_kind": ("temporary" if ak.startswith("ASIA") else
                                "long_term" if ak.startswith("AKIA") else
                                "env_ref" if "${" in ak else
                                "unknown" if ak else "missing"),
            "has_secret_key": bool(secret),
            "secret_fingerprint": _secret_fingerprint(secret) if secret else "",
            "has_session_token": bool(session),
            "region": items.get("region", ""),
            "role_arn": items.get("role_arn", ""),
            "source_profile": items.get("source_profile", ""),
            "credential_process": bool(items.get("credential_process")),
            "sso": any(key.startswith("sso_") for key in items),
            "web_identity": bool(items.get("web_identity_token_file")),
            "mfa_serial": items.get("mfa_serial", ""),
        }
        profiles.append(row)
        if ak:
            if row["access_key_kind"] == "long_term" and not row["has_session_token"]:
                findings.append(_finding(
                    "AWS-CRED-001", "high", "credential",
                    "Long-term AWS access key stored in a local plaintext file",
                    "%s access_key=%s" % (section, row["access_key"]),
                    "AKIA keys do not expire automatically; possession is sufficient for replay until rotated/revoked.",
                    "The key may be a low-privilege or already-revoked test key; verify with `aws sts get-caller-identity` only if authorized."))
            elif row["access_key_kind"] == "temporary":
                findings.append(_finding(
                    "AWS-CRED-002", "medium", "credential",
                    "Temporary AWS access key stored on disk",
                    "%s access_key=%s session_token=%s" % (section, row["access_key"],
                                                          "present" if row["has_session_token"] else "missing"),
                    "ASIA keys expire; record the expiry from the issuing metadata/STS response before treating them as evidence.",
                    "Without a session token an ASIA key is not usable; the file may be incomplete."))
            elif row["access_key_kind"] == "unknown":
                findings.append(_finding(
                    "AWS-CRED-003", "medium", "credential",
                    "Unrecognised AWS access-key format",
                    "%s access_key=%s" % (section, row["access_key"]),
                    "The value is treated as a secret at rest; confirm it is not a placeholder/ARN before use.",
                    "Custom/legacy or redacted values may not match the modern AKIA/ASIA format."))
            elif row["access_key_kind"] == "env_ref":
                findings.append(_finding(
                    "AWS-CRED-004", "low", "credential",
                    "Access key is referenced from the environment, not hardcoded",
                    "%s value=%s" % (section, _redact_ak(ak)),
                    "The file does not itself contain the key; the environment/secret store is the real trust boundary.",
                    "The referenced environment variable may still be exported in plaintext on the same host."))
        if secret:
            findings.append(_finding(
                "AWS-CRED-005", "high", "credential",
                "AWS secret access key present in plaintext",
                "%s secret_fingerprint=%s length=%d" % (section, row["secret_fingerprint"], len(secret)),
                "Plaintext secret at rest is a leak; report only the fingerprint and rotate if exposure is confirmed.",
                "A test/placeholder secret may not authenticate; do not print it to prove that."))
        if row["role_arn"]:
            findings.append(_finding(
                "AWS-ROLE-001", "info", "cloud",
                "Assume-role chain configured",
                "%s role_arn=%s source_profile=%s" % (section, row["role_arn"], row["source_profile"] or "-"),
                "The effective permissions belong to the target role, not to this key; verify with STS after assuming it.",
                "The role may reject the assume-role call or require MFA; offline files cannot confirm."))
        if row["credential_process"]:
            findings.append(_finding(
                "AWS-ROLE-002", "info", "cloud",
                "External credential_process configured",
                "%s" % section,
                "Credentials are produced at runtime; expiry and identity are unknown offline.",
                "The process may cache a long-lived credential; inspect its own configuration separately."))
        if row["web_identity"]:
            findings.append(_finding(
                "AWS-ROLE-003", "info", "cloud",
                "Web identity/OIDC credential source configured",
                "%s" % section,
                "The trust policy's sub/aud conditions determine whether this can be abused; inspect the role trust policy.",
                "A strict trust policy may make the token useless outside its intended workload."))

    file_mode = None
    if os.name == "posix":
        try:
            file_mode = oct(os.stat(path).st_mode & 0o777)
            if os.stat(path).st_mode & 0o077:
                findings.append(_finding(
                    "AWS-CRED-006", "medium", "credential",
                    "Credentials file is group/world readable",
                    "%s mode=%s" % (path, file_mode),
                    "Any local user can read and replay the key; restrict to 0600.",
                    "A single-user workstation may have compensating controls, but the mode is still a leak surface."))
        except OSError:
            pass

    findings.append(_finding(
        "AWS-SCOPE-001", "info", "cloud",
        "IAM permission scope is unknown offline",
        "profiles=%d, AK patterns=%d" % (len(profiles), len(all_ak)),
        "Effective IAM permissions require an authorized `aws sts get-caller-identity` plus policy enumeration; "
        "do not infer admin/narrow from the credential file.",
        "This is an explicit non-finding: absence of evidence is not evidence of narrow permissions."))

    return {
        "path": os.path.abspath(path),
        "profiles": profiles,
        "access_key_hardcoded": any(
            row["access_key_kind"] in ("long_term", "temporary", "unknown") for row in profiles
        ),
        "hardcoded_ak_occurrences": len(all_ak),
        "file_mode": file_mode,
        "iam_scope": "unknown_offline",
        "findings": findings,
        "offline_limits": [
            "IAM policy/effective permissions cannot be derived from a credentials file offline.",
            "AWS account ID, role trust policy, permission boundaries, and SCPs are not present in the credentials file.",
            "Secret values are never printed; only presence, length, and a SHA-256 fingerprint are reported.",
            "Key validity/revocation is not checked offline; use `aws sts get-caller-identity` only within authorization.",
        ],
        "next_commands": [
            "aws sts get-caller-identity --profile <profile>",
            "aws iam list-attached-user-policies --user-name <user>",
            "aws iam list-user-policies --user-name <user>",
            "aws iam list-attached-role-policies --role-name <role>",
            "aws iam get-role --role-name <role>  # inspect trust policy",
        ],
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _flatten_findings(result):
    findings = []
    kube = result.get("kubeconfig")
    aws = result.get("aws_creds")
    if kube:
        findings.extend(kube.get("findings", []))
    if aws:
        findings.extend(aws.get("findings", []))
    return findings


def print_human(result):
    print("=" * 78)
    print("adcloud-check %s  offline local-file analysis" % VERSION)
    print("=" * 78)
    if not result.get("ok"):
        for err in result.get("errors", []):
            print("[ERROR] %s: %s (%s)" % (err["code"], err["message"], err.get("path", "")))
    kube = result.get("kubeconfig")
    if kube:
        print("\n[kubeconfig] %s" % kube["path"])
        print("  current-context: %s" % (kube["current_context"] or "<unset>"))
        print("  clusters=%d contexts=%d users=%d" %
              (len(kube["clusters"]), len(kube["contexts"]), len(kube["users"])))
        for row in kube["clusters"]:
            print("  cluster %-24s server=%s tls_verify=%s ca=%s" %
                  (row["name"] or "<unnamed>", row["server"] or "<none>",
                   "no" if row["insecure_skip_tls_verify"] else "yes",
                   "yes" if row["has_ca"] else "no"))
        for row in kube["contexts"]:
            print("  context %-24s cluster=%s user=%s ns=%s" %
                  (row["name"] or "<unnamed>", row["cluster"] or "-",
                   row["user"] or "-", row["namespace"] or "default"))
        for row in kube["users"]:
            bits = []
            if row["has_token"]:
                t = row["token"] or {}
                bits.append("token(%s)" % t.get("fingerprint", "?"))
                if t.get("expires_in_seconds") is not None:
                    bits.append("expires_in=%ss" % t["expires_in_seconds"])
            if row["has_client_cert"]:
                bits.append("client-cert")
            if row["has_basic_auth"]:
                bits.append("basic-auth")
            if row["exec"]:
                bits.append("exec-plugin")
            if row.get("service_account"):
                bits.append("sa=%s/%s" % (row["service_account"]["namespace"],
                                         row["service_account"]["name"]))
            if row.get("anonymous"):
                bits.append("NO-CREDENTIAL")
            print("  user    %-24s %s" %
                  (row["name"] or "<unnamed>", ", ".join(bits) or "no auth material"))
        print("  anonymous_risk=%s wide_privilege_indicators=%d" %
              (kube["anonymous_risk"], len(kube["wide_privilege_indicators"])))
    aws = result.get("aws_creds")
    if aws:
        print("\n[aws credentials] %s" % aws["path"])
        print("  profiles=%d hardcoded_ak=%s occurrences=%d iam_scope=%s" %
              (len(aws["profiles"]), aws["access_key_hardcoded"],
               aws["hardcoded_ak_occurrences"], aws["iam_scope"]))
        for row in aws["profiles"]:
            print("  [%s] ak=%s kind=%s secret=%s session=%s role=%s" %
                  (row["profile"], row["access_key"] or "-", row["access_key_kind"],
                   "yes" if row["has_secret_key"] else "no",
                   "yes" if row["has_session_token"] else "no",
                   row["role_arn"] or "-"))

    findings = _flatten_findings(result)
    print("\n[findings] %d" % len(findings))
    if not findings:
        print("  (none)")
    for finding in findings:
        print("  [%s] %-8s %s" % (finding["severity"].upper(), finding["id"], finding["title"]))
        print("    evidence: %s" % finding["evidence"])
        print("    criteria: %s" % finding["criteria"])
        print("    false-positive: %s" % finding["false_positive"])
    print("\n[offline limits]")
    for section in ("kubeconfig", "aws_creds"):
        obj = result.get(section)
        if obj:
            for limit in obj["offline_limits"]:
                print("  - " + limit)
    print("\n[next commands (not executed)]")
    for section in ("kubeconfig", "aws_creds"):
        obj = result.get(section)
        if obj:
            for cmd in obj["next_commands"]:
                print("  " + cmd)


def _self_test():
    """Offline smoke test: synthetic kubeconfig + AWS creds, no network."""
    import tempfile

    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = b64({"alg": "RS256", "typ": "JWT"})
    payload = b64({"iss": "https://kubernetes.default.svc",
                   "sub": "system:serviceaccount:kube-system:cluster-admin",
                   "aud": ["https://127.0.0.1:6443"], "iat": 1700000000,
                   "exp": 4102444800,
                   "groups": ["system:masters", "system:serviceaccounts"]})
    token = "%s.%s.%s" % (header, payload, b64({"sig": "self-test-only"}))
    kube = """apiVersion: v1
kind: Config
clusters:
- name: self-test
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
contexts:
- name: self-test
  context:
    cluster: self-test
    user: self-test
    namespace: kube-system
current-context: self-test
users:
- name: self-test
  user:
    token: %s
""" % token
    aws = """[default]
aws_access_key_id = AKIAIOSFODNN7SELFTEST
aws_secret_access_key = self-test-secret-not-real
"""
    checks = 0
    tmpdir = tempfile.mkdtemp(prefix="adcloud-selftest-")
    try:
        kp = os.path.join(tmpdir, "config")
        ap = os.path.join(tmpdir, "credentials")
        with open(kp, "w", encoding="utf-8") as fh:
            fh.write(kube)
        with open(ap, "w", encoding="utf-8") as fh:
            fh.write(aws)
        kube_result = analyse_kubeconfig(kp)
        ids = {f["id"] for f in kube_result["findings"]}
        if "K8S-TRANSPORT-002" not in ids or "K8S-RBAC-003" not in ids:
            raise CheckError("SELF_TEST", "expected kubeconfig findings are missing")
        if token in json.dumps(kube_result, ensure_ascii=False):
            raise CheckError("SELF_TEST", "raw token leaked into output")
        checks += 1
        aws_result = analyse_aws_creds(ap)
        if not aws_result.get("access_key_hardcoded"):
            raise CheckError("SELF_TEST", "expected hardcoded access key finding")
        if "self-test-secret-not-real" in json.dumps(aws_result, ensure_ascii=False):
            raise CheckError("SELF_TEST", "raw secret leaked into output")
        checks += 1
    finally:
        for name in ("config", "credentials"):
            try:
                os.unlink(os.path.join(tmpdir, name))
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
    print(json.dumps({"ok": True, "tool": "adcloud-check", "checks": checks},
                     ensure_ascii=False))
    return 0


def _base_result():
    return {
        "tool": "adcloud-check",
        "version": VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ok": True,
        "mode": "offline_local_files",
        "kubeconfig": None,
        "aws_creds": None,
        "errors": [],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline kubeconfig/AWS-credentials triage. No network calls; live RBAC/IAM is marked unknown.")
    parser.add_argument("--kubeconfig", help="local kubeconfig file (YAML or JSON)")
    parser.add_argument("--aws-creds", help="local AWS credentials/config INI file")
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("--self-test", action="store_true",
                        help="run embedded offline kubeconfig/AWS fixtures")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    if args.self_test:
        try:
            return _self_test()
        except CheckError as exc:
            print(json.dumps({"ok": False, "blocked_at": "self-test",
                              "reason": exc.message}, ensure_ascii=False))
            return 2
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"ok": False, "blocked_at": "self-test",
                              "reason": "%s: %s" % (type(exc).__name__, exc)},
                             ensure_ascii=False))
            return 2

    if not args.kubeconfig and not args.aws_creds:
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "provide --kubeconfig and/or --aws-creds"},
                         ensure_ascii=False))
        return 2

    result = _base_result()
    if args.kubeconfig:
        try:
            result["kubeconfig"] = analyse_kubeconfig(args.kubeconfig)
        except CheckError as exc:
            result["ok"] = False
            result["errors"].append({"code": exc.code, "message": exc.message, "path": exc.path})
        except Exception as exc:  # keep the CLI structured on unexpected parser input
            result["ok"] = False
            result["errors"].append({"code": "KUBECONFIG_INTERNAL_ERROR",
                                     "message": "%s: %s" % (type(exc).__name__, exc),
                                     "path": args.kubeconfig})
    if args.aws_creds:
        try:
            result["aws_creds"] = analyse_aws_creds(args.aws_creds)
        except CheckError as exc:
            result["ok"] = False
            result["errors"].append({"code": exc.code, "message": exc.message, "path": exc.path})
        except Exception as exc:
            result["ok"] = False
            result["errors"].append({"code": "AWS_CREDS_INTERNAL_ERROR",
                                     "message": "%s: %s" % (type(exc).__name__, exc),
                                     "path": args.aws_creds})

    if not result["ok"]:
        first = (result.get("errors") or [{}])[0]
        print(json.dumps({"ok": False,
                          "blocked_at": str(first.get("code") or "parse").lower(),
                          "reason": first.get("message") or "input could not be parsed",
                          "path": first.get("path") or ""},
                         ensure_ascii=False))
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
