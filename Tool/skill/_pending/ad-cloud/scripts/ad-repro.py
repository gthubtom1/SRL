#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ad-repro.py — AD / cloud kill-chain judgement recomputation, fully offline.

Input is a JSON "evidence bundle" (one check or a list of checks).  The script
recomputes the decision rules used by the ad-cloud skill and never contacts a
DC, CA, API server or cloud endpoint.  Hashes / passwords / tokens in input are
never echoed: only a sha256 fingerprint is reported.

Examples:
  python ad-repro.py --kind kerberoast --input evidence.json
  python ad-repro.py --kind adcs-esc --input adcs-find.json     # ESC9-ESC17 offline
  python ad-repro.py --kind ntlm-type2 --input ntlm-type2.json  # 445 只读外部视角
  python ad-repro.py --kind edge-fingerprint --fixture Tool/cases/ad-cloud01
  python ad-repro.py --kind edge-fingerprint --url https://vpn.example.com/
  python ad-repro.py --kind edge-fingerprint --input targets.json  # [{"url","product_hint"}]
  python ad-repro.py --input bundle.json --json
  python ad-repro.py --extract-evtx-xml security.xml --redact --out events.json
  python ad-repro.py --self-test

Exit codes:
  0  judgement computed (individual checks may be "blocked")
  2  bad input / unsupported schema / internal error
  3  --strict and at least one edge-fingerprint target is "blocked"
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import ssl
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

VERSION = "1.0.0"
def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录（S3 后脚本可能位于 _pending/ 下，不能靠固定层数）。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.dirname(os.path.dirname(os.path.abspath(start)))


REPO_ROOT = _repo_root(os.path.dirname(os.path.abspath(__file__)))
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
KINDS = ("kerberoast", "asrep", "adcs", "adcs-esc", "delegation", "k8s-rbac",
         "windows-events", "ntlm-type2", "edge-fingerprint")


class ReproError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def _fp(value):
    """Fingerprint without leaking the secret itself."""
    if value is None or value == "":
        return ""
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value[:16].lower()
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:16]


def _bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def _list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _check(name, ok, detail, severity="info"):
    return {"check": name, "ok": bool(ok), "detail": detail, "severity": severity}


def _result(kind, verdict, checks, findings=None, failure=None, **extra):
    out = {
        "kind": kind,
        "verdict": verdict,
        "checks": checks,
        "findings": findings or [],
        "failure_criteria": failure or [],
    }
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Kerberoast / AS-REP
# ---------------------------------------------------------------------------
def eval_kerberoast(d):
    tickets = d.get("tickets") or []
    policy = d.get("lockout_policy") or {}
    observed = int(policy.get("failures_observed") or d.get("auth_failures") or 0)
    threshold = int(policy.get("threshold") or 5)
    checks, rows, findings = [], [], []
    if not tickets:
        return _result(
            "kerberoast", "blocked",
            [_check("tgs-collected", False, "no TGS rows in evidence")],
            failure=["没有 TGS：先确认账号有 SPN 且请求成功（4769/RC4 事件）。",
                     "只有 SPN 列表没有票据，不能写成 Kerberoast 成功。"],
        )
    if observed >= min(2, max(1, threshold - 1)):
        return _result(
            "kerberoast", "blocked",
            [_check("lockout-budget", False,
                    "auth failures observed=%d, threshold=%d" % (observed, threshold), "high")],
            failure=["认证失败已达预算：停止同一账号的请求，换账号或换来源。",
                     "继续请求可能触发锁定并制造业务中断。"],
        )
    for i, t in enumerate(tickets):
        spn = str(t.get("spn") or "")
        account = str(t.get("account") or t.get("principal") or "")
        etype = t.get("etype")
        try:
            etype = int(etype) if etype is not None else None
        except (TypeError, ValueError):
            etype = None
        hash_present = _bool(t.get("hash_present"), bool(t.get("hash")))
        cracked = _bool(t.get("cracked"))
        reusable = _bool(t.get("reusable"))
        disabled = _bool(t.get("account_disabled")) or account.endswith("$") or account.lower() == "krbtgt"
        crackable = etype in (23, 17, 18) and not disabled
        row = {
            "index": i,
            "principal_fp": _fp(account),
            "spn_fp": _fp(spn),
            "etype": etype,
            "hash_present": hash_present,
            "hash_fp": _fp(t.get("hash") or t.get("hash_sha256")),
            "crackable_offline": crackable,
            "cracked": cracked,
            "reusable": reusable,
            "disabled_or_machine": disabled,
        }
        if not spn:
            row["blocker"] = "missing-spn"
        if disabled:
            row["blocker"] = "machine-or-krbtgt-account"
        if etype is None:
            row["blocker"] = "missing-etype"
        rows.append(row)
        if crackable and (cracked or reusable):
            findings.append({"severity": "high", "title": "TGS material usable for the target account",
                             "evidence": "ticket[%d] etype=%s" % (i, etype)})
        elif crackable and hash_present:
            findings.append({"severity": "medium", "title": "crackable TGS collected, not yet cracked",
                             "evidence": "ticket[%d] etype=%s" % (i, etype)})
    confirmed = any(r["crackable_offline"] and (r["cracked"] or r["reusable"]) for r in rows)
    candidate = any(r["crackable_offline"] and r["hash_present"] for r in rows)
    verdict = "confirmed" if confirmed else ("candidate" if candidate else "blocked")
    checks.append(_check("etype-crackable", candidate or confirmed,
                         "RC4(23)/AES(17/18) TGS identified; etype 23 is cheapest offline"))
    checks.append(_check("plaintext-or-reuse", confirmed,
                         "cracked plaintext or directly reusable ticket"))
    return _result(
        "kerberoast", verdict, checks, findings, tickets=rows,
        failure=[
            "只拿到 TGS hash 未破解：这是素材，不是打穿；继续字典/规则或转委派/ADCS。",
            "账号是机器号或 krbtgt：不是 Kerberoast 目标，换有 SPN 的用户账号。",
            "etype 17/18（AES）：仍可离线破解但成本高；不要用 RC4 的模式/字典直接下结论。",
            "认证失败已达锁定预算：立即停手，换账号或换来源。",
        ],
    )


def eval_asrep(d):
    users = d.get("users") or []
    policy = d.get("lockout_policy") or {}
    observed = int(policy.get("failures_observed") or d.get("auth_failures") or 0)
    threshold = int(policy.get("threshold") or 5)
    if not users:
        return _result("asrep", "blocked",
                       [_check("asrep-collected", False, "no user rows in evidence")],
                       failure=["没有 AS-REP 行：先确认 DONT_REQ_PREAUTH 与账号状态。"])
    if observed >= min(2, max(1, threshold - 1)):
        return _result("asrep", "blocked",
                       [_check("lockout-budget", False,
                               "auth failures observed=%d" % observed, "high")],
                       failure=["认证失败已达预算：停止批量 GetNPUsers，避免锁定。"])
    rows, findings = [], []
    for i, u in enumerate(users):
        account = str(u.get("account") or u.get("principal") or "")
        preauth = _bool(u.get("dont_req_preauth"))
        present = _bool(u.get("asrep_present"), bool(u.get("hash")))
        cracked = _bool(u.get("cracked"))
        reusable = _bool(u.get("reusable"))
        disabled = _bool(u.get("account_disabled"))
        etype = u.get("etype")
        try:
            etype = int(etype) if etype is not None else None
        except (TypeError, ValueError):
            etype = None
        rows.append({
            "index": i,
            "principal_fp": _fp(account),
            "dont_req_preauth": preauth,
            "asrep_present": present,
            "etype": etype,
            "hash_fp": _fp(u.get("hash") or u.get("hash_sha256")),
            "cracked": cracked,
            "reusable": reusable,
            "account_disabled": disabled,
        })
        if preauth and present and not disabled:
            findings.append({"severity": "high" if (cracked or reusable) else "medium",
                             "title": "AS-REP material for a pre-auth-disabled account",
                             "evidence": "user[%d] etype=%s" % (i, etype)})
    confirmed = any(r["dont_req_preauth"] and r["asrep_present"] and not r["account_disabled"]
                    and (r["cracked"] or r["reusable"]) for r in rows)
    candidate = any(r["dont_req_preauth"] and r["asrep_present"] and not r["account_disabled"]
                    for r in rows)
    checks = [
        _check("preauth-disabled", candidate or confirmed,
               "DONT_REQ_PREAUTH observed; AS-REP is requestable without a password"),
        _check("plaintext-or-reuse", confirmed, "cracked plaintext or reusable material"),
    ]
    return _result(
        "asrep", "confirmed" if confirmed else ("candidate" if candidate else "blocked"),
        checks, findings, users=rows,
        failure=[
            "账号已启用预认证：AS-REP 请求会失败，转 Kerberoast/ADCS。",
            "只拿到 AS-REP hash 未破解：是素材不是打穿。",
            "批量请求导致 4625/4771 告警或锁定：立即降速/停手。",
            "账号已禁用：即使有 AS-REP 也不能用于登录。",
        ],
    )


# ---------------------------------------------------------------------------
# ADCS
# ---------------------------------------------------------------------------
def eval_adcs(d):
    templates = d.get("templates") or []
    ca = d.get("ca") or {}
    auth_ok = _bool(d.get("auth_succeeded"))
    pfx = _bool(d.get("pfx_obtained"))
    if not templates:
        return _result("adcs", "blocked",
                       [_check("template-data", False, "no template rows; run certipy find first")],
                       failure=["没有模板数据：离线不能凭 CA 名称猜 ESC，先只读枚举模板/ACL/CA flag。"])
    rows, findings, esc = [], [], {}
    for i, t in enumerate(templates):
        name = str(t.get("name") or ("template-%d" % i))
        enroll = _bool(t.get("enroll_allowed"))
        san_restricted = _bool(t.get("san_enforced"), True)
        client_auth = _bool(t.get("client_auth_eku")) or _bool(t.get("any_purpose"))
        any_purpose = _bool(t.get("any_purpose"))
        approval = _bool(t.get("manager_approval"))
        ca_san = _bool(t.get("ca_san_allowed"), True)
        acl_write = _bool(t.get("acl_writable"))
        agent = _bool(t.get("agent_template"))
        ca_manage = _bool(t.get("ca_manage_principals"))
        http = _bool(t.get("http_endpoint"))
        relay = _bool(t.get("ntlm_relay_allowed"))
        flags = []
        if enroll and not san_restricted and client_auth and not approval and ca_san:
            flags.append("ESC1")
        if enroll and any_purpose and not approval:
            flags.append("ESC2")
        if enroll and agent and not approval:
            flags.append("ESC3")
        if acl_write:
            flags.append("ESC4")
        if _bool(t.get("editf_attributesubmitsubject")) and ca_san:
            flags.append("ESC6")
        if ca_manage:
            flags.append("ESC7")
        if http and relay:
            flags.append("ESC8")
        blockers = []
        if not enroll:
            blockers.append("no-enroll-right")
        if san_restricted and "ESC1" in flags:
            blockers.append("san-enforced")
        if approval:
            blockers.append("manager-approval")
        if not client_auth:
            blockers.append("no-client-auth-eku")
        row = {"index": i, "template_fp": _fp(name), "enroll_allowed": enroll,
               "san_enforced": san_restricted, "client_auth_eku": client_auth,
               "any_purpose": any_purpose, "manager_approval": approval,
               "ca_san_allowed": ca_san, "acl_writable": acl_write,
               "agent_template": agent, "http_endpoint": http,
               "ntlm_relay_allowed": relay, "esc": flags, "blockers": blockers}
        rows.append(row)
        for e in flags:
            esc[e] = esc.get(e, 0) + 1
            findings.append({"severity": "high" if e in ("ESC1", "ESC4", "ESC8") else "medium",
                             "title": "%s candidate on a template" % e,
                             "evidence": "template[%d]" % i})
    # 血案（R2 审计）：pfx 只证明"手里有证书"，PKINIT 成功才证明"能换到 TGT"。
    # 原写法 `auth_ok or pfx` 会把"只拿到 pfx"升级成 confirmed，与 01-criteria 冲突。
    confirmed = bool(auth_ok)
    viable = bool(esc)
    verdict = "confirmed" if (viable and confirmed) else ("candidate" if viable else "blocked")
    checks = [
        _check("esc-rule-hit", viable, "ESC families matched: %s" % (",".join(sorted(esc)) or "none")),
        _check("enroll-and-approval", any(r["enroll_allowed"] and not r["manager_approval"] for r in rows),
               "current principal can enroll without manager approval"),
        _check("auth-succeeded", confirmed, "certipy auth / PKINIT obtained a TGT"),
        _check("pfx-present", bool(pfx), "pfx obtained (prerequisite, not proof)"),
        _check("pfx-present", bool(pfx), "pfx obtained (prerequisite, not proof)"),
    ]
    return _result(
        "adcs", verdict, checks, findings, templates=rows,
        ca={"name_fp": _fp(ca.get("name")), "http_endpoint": _bool(ca.get("http_endpoint")),
            "ntlm_relay_allowed": _bool(ca.get("ntlm_relay_allowed"))},
        failure=[
            "certipy find 报 vulnerable 但当前账号无 Enroll：不可利用，转 ESC4/ESC5/ESC7。",
            "模板要求 manager approval 或 CA 拒绝 SAN：ESC1/ESC6 不成立，别反复试。",
            "只拿到 pfx、certipy auth 失败：证书用途/UPN/DC 不匹配，是素材不是打穿。",
            "EPA/LDAP signing/SMB signing 已开：ESC8 relay 基本不可用，转凭据直连。",
            "没有模板/ACL 数据：不要凭 CA 名称或默认模板猜 ESC。",
        ],
    )


# ---------------------------------------------------------------------------
# ADCS ESC9-ESC17 (certipy find -json style, offline)
# ---------------------------------------------------------------------------
CERT_MAPPING_BITS = {"subject": 0x1, "issuer": 0x2, "upn": 0x4, "s4u2self": 0x8}
SECURITY_EXT_OID = "1.3.6.1.4.1.311.25.2"      # szOID_NTDS_CA_SECURITY_EXT
NIST_SHA256_OID = "2.16.840.1.101.3.4.2.1"     # szOID_NIST_sha256
WEAK_MARKERS = ("<SR>", "SKI>", "SHA1", "SHA256", "RFC822")


def _first(d, keys, default=None):
    """First present, non-empty field among several spellings."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d:
            v = d[k]
            if v is not None and v != "":
                return v
    return default


def _int_or_none(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _mapping_mask(value):
    """CertificateMappingMethods bits: 0x1 subject, 0x2 issuer, 0x4 UPN, 0x8 S4U2Self."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple)):
        mask = 0
        for item in value:
            key = str(item).strip().lower().replace("-", "").replace("_", "")
            mask |= CERT_MAPPING_BITS.get(key, 0)
        return mask
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        pass
    mask, found = 0, False
    for token in re.split(r"[,;|/\s]+", text.lower()):
        token = token.replace("-", "").replace("_", "")
        if token in CERT_MAPPING_BITS:
            mask |= CERT_MAPPING_BITS[token]
            found = True
    return mask if found else None


def _eku_has(policies, *needles):
    blob = " ".join(str(x) for x in _list(policies)).lower()
    return any(n.lower() in blob for n in needles)


def eval_adcs_esc(d):
    """ESC9-ESC17 from a certipy-find-shaped document; never contacts the CA."""
    cas = [c for c in _list(_first(d, ("Certificate Authorities", "cas", "ca"), []))
           if isinstance(c, dict)]
    templates = [t for t in _list(_first(d, ("Certificate Templates", "templates"), []))
                 if isinstance(t, dict)]
    accounts = [a for a in _list(d.get("accounts")) if isinstance(a, dict)]
    scb = _int_or_none(_first(d, ("StrongCertificateBindingEnforcement", "strong_cert_binding",
                                  "strong_cert_binding_enforcement")))
    mm = _mapping_mask(_first(d, ("CertificateMappingMethods", "mapping_methods")))
    icpr_raw = _first(d, ("icpr_encrypt",))
    icpr = None if icpr_raw is None else _bool(icpr_raw, None)
    if icpr is None:
        enf = _first(d, ("Enforce Encryption for Requests", "enforce_encryption"))
        if enf is None:
            for c in cas:
                enf = _first(c, ("Enforce Encryption for Requests", "enforce_encryption"))
                if enf is not None:
                    break
        if enf is not None:
            icpr = str(enf).strip().lower() in ("enabled", "true", "yes", "1", "on")
    wsus = d.get("wsus") if isinstance(d.get("wsus"), dict) else {}
    wsus_raw = _first(d, ("wsus_https", "WSUS HTTPS"))
    if wsus_raw is None:
        wsus_raw = wsus.get("https")
    wsus_https = None if wsus_raw is None else _bool(wsus_raw, None)
    if not (cas or templates or accounts or scb is not None or mm is not None
            or icpr is not None or wsus_https is not None):
        raise ReproError("adcs-esc-schema",
                         "no CA/template/account/binding fields found; refusing to guess ESC")

    flags, findings, rows, blockers = [], [], [], []
    for i, t in enumerate(templates):
        name = str(_first(t, ("Template Name", "name", "template_name")) or ("template-%d" % i))
        schema = _int_or_none(_first(t, ("Schema Version", "schema_version",
                                         "msPKI-Template-Schema-Version")))
        enroll = _bool(_first(t, ("enroll_allowed", "Enroll")), False)
        san_enforced = _bool(_first(t, ("san_enforced",)), True)
        app = _first(t, ("Application Policies", "application_policies",
                         "msPKI-Certificate-Application-Policy"), [])
        client_auth = _eku_has(app, "client authentication", "smart card logon", "any purpose",
                               "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0")
        server_auth = _bool(t.get("server_auth_eku")) or _eku_has(
            app, "server authentication", "1.3.6.1.5.5.7.3.1")
        dns_san = _bool(t.get("dns_san_allowed")) or not san_enforced
        group_link = _first(t, ("issuance_policy_group", "msDS-OIDToGroupLink", "oid_group_link"))
        group_links = [str(x) for x in _list(t.get("issuance_policy_groups")
                                             or t.get("oid_group_links"))]
        policy_group = bool(group_link) or any(
            x.strip().lower() not in ("", "none", "null") for x in group_links)
        app_editable = _bool(t.get("application_policies_editable"),
                             schema is not None and schema <= 1)
        tflags = []
        if enroll and policy_group:
            tflags.append("ESC13")
        if enroll and schema is not None and schema <= 1 and (not _list(app) or app_editable):
            tflags.append("ESC15")
        row = {"index": i, "template_fp": _fp(name), "schema": schema, "enroll_allowed": enroll,
               "san_enforced": san_enforced, "client_auth_eku": client_auth,
               "server_auth_eku": server_auth, "dns_san_allowed": dns_san,
               "policy_group_link": policy_group, "application_policies": len(_list(app)),
               "esc": tflags}
        rows.append(row)
        for e in tflags:
            if e not in flags:
                flags.append(e)
            findings.append({"severity": "high" if e == "ESC13" else "medium",
                             "title": "%s candidate on a template" % e,
                             "evidence": "template[%d]" % i})
        if not enroll:
            blockers.append("no-enroll-right(template[%d])" % i)

    ca_rows, sec_ext_off, nist_limited = [], False, False
    for i, c in enumerate(cas):
        dis = [str(x) for x in _list(_first(c, ("DisableExtensionList", "disable_extension_list")))]
        blob = " ".join(dis).lower()
        sec_off = _bool(_first(c, ("security_ext_disabled", "Security Extension Disabled")), False) \
            or SECURITY_EXT_OID in blob
        nist = NIST_SHA256_OID in blob or "szoid_nist_sha256" in blob
        ca_rows.append({"index": i,
                        "ca_fp": _fp(_first(c, ("CA Name", "name", "ca_name"))),
                        "security_ext_disabled": sec_off, "nist_sha256_limited": nist})
        sec_ext_off = sec_ext_off or sec_off
        nist_limited = nist_limited or nist

    weak_alt_ids = []
    for i, a in enumerate(accounts):
        vals = [str(x) for x in _list(_first(a, ("altSecurityIdentities", "alt_security_identities")))]
        for v in vals:
            strong = any(m in v.upper() for m in WEAK_MARKERS)
            weak_alt_ids.append({"account_fp": _fp(_first(a, ("account", "name", "sam"))),
                                 "value_fp": _fp(v), "strong": strong})
        if _bool(a.get("alt_security_identities_writable")):
            weak_alt_ids.append({"account_fp": _fp(_first(a, ("account", "name", "sam"))),
                                 "value_fp": "", "strong": False})

    server_auth_obtainable = _bool(d.get("server_auth_cert_obtained")) or any(
        r["server_auth_eku"] and r["dns_san_allowed"] and r["enroll_allowed"] for r in rows)

    if scb is not None and scb < 2:
        flags.append("ESC9")
        findings.append({"severity": "high", "title": "Esc9 weak certificate binding (UPN still honoured)",
                         "evidence": "StrongCertificateBindingEnforcement=%d" % scb})
    elif scb is not None:
        blockers.append("strong-binding-enforced")
    if mm is not None and mm & CERT_MAPPING_BITS["upn"]:
        flags.append("ESC10")
        findings.append({"severity": "high", "title": "Esc10 UPN certificate mapping enabled",
                         "evidence": "CertificateMappingMethods=0x%x" % mm})
    if icpr is False:
        flags.append("ESC11")
        findings.append({"severity": "high", "title": "Esc11 ICPR does not enforce encryption",
                         "evidence": "Enforce Encryption for Requests=Disabled"})
    elif icpr is True:
        blockers.append("icpr-encrypted")

    # ESC12（CA 主机本地权限）无法离线判定：输入若声明该面，只登记 blocker，不产出 esc 家族。
    _raw = json.dumps(d).lower() if isinstance(d, dict) else ""
    if ("esc12" in _raw) or ("private_key_exported" in _raw):
        blockers.append("esc12-local-ca-access(\u9700 CA \u4e3b\u673a\u672c\u5730\u6743\u9650\uff0c\u79bb\u7ebf\u4e0d\u5224\u5b9a)")
    if any(not x["strong"] for x in weak_alt_ids):
        flags.append("ESC14")
        findings.append({"severity": "high", "title": "Esc14 weak explicit mapping (altSecurityIdentities)",
                         "evidence": "weak mappings=%d" % sum(1 for x in weak_alt_ids if not x["strong"])})
    if sec_ext_off or nist_limited:
        flags.append("ESC16")
        findings.append({"severity": "high", "title": "Esc16 CA-wide extension restriction (no SID extension)",
                         "evidence": "security_ext_disabled=%s nist_sha256_limited=%s"
                                     % (sec_ext_off, nist_limited)})
    if wsus_https is True:
        if server_auth_obtainable:
            flags.append("ESC17")
            findings.append({"severity": "high",
                             "title": "Esc17 HTTPS WSUS relayable with an ADCS server-auth cert",
                             "evidence": "wsus_https=true server_auth_obtainable=true"})
        else:
            blockers.append("no-server-auth-template")
    elif wsus_https is False:
        blockers.append("wsus-not-https")

    # 固定顺序，避免输出随遍历顺序漂移
    esc_order = ["ESC9", "ESC10", "ESC11",  "ESC13", "ESC14", "ESC15", "ESC16", "ESC17"]
    flags = [e for e in esc_order if e in flags]

    auth_ok = _bool(d.get("auth_succeeded"))
    relay_ok = _bool(d.get("relay_cert_obtained"))
    update_ok = _bool(d.get("update_delivered")) or _bool(wsus.get("update_delivered"))
    proven = auth_ok or relay_ok or update_ok
    if flags and not proven:
        blockers.append("no-last-step-evidence")
    verdict = "confirmed" if (flags and proven) else ("candidate" if flags else "blocked")
    checks = [
        _check("strong-cert-binding", scb is not None,
               "StrongCertificateBindingEnforcement=%s (0/1 = ESC9)" % (
                   "unknown" if scb is None else scb)),
        _check("certificate-mapping", mm is not None,
               "CertificateMappingMethods=%s (0x4 = UPN => ESC10)" % (
                   "unknown" if mm is None else "0x%x" % mm)),
        _check("icpr-encryption", icpr is not None,
               "ICPR Enforce Encryption for Requests=%s (False => ESC11)" % (
                   "unknown" if icpr is None else icpr)),
        _check("wsus-https", wsus_https is not None,
               "WSUS HTTPS=%s (true => ESC17 when a server-auth cert is issuable)" % (
                   "unknown" if wsus_https is None else wsus_https)),
        _check("esc-rule-hit", bool(flags),
               "ESC families matched: %s" % (",".join(flags) or "none")),
        _check("last-step-proof", proven,
               "auth/relay/update evidence present=%s" % proven),
    ]
    return _result(
        "adcs-esc", verdict, checks, findings,
        esc_flags=flags, strong_cert_binding=scb, mapping_methods=mm,
        icpr_encrypt=icpr, wsus_https=wsus_https,
        templates=rows, cas=ca_rows, alt_security_identities=weak_alt_ids,
        blockers=blockers,
        failure=[
            "没有 CA/模板/绑定字段：不要凭 CA 名称或默认模板猜 ESC（脚本会 rc=2 拒判）。",
            "StrongCertificateBindingEnforcement=2 或证书带 SID 扩展：ESC9/ESC10 不成立。",
            "Enforce Encryption for Requests=Enabled：ESC11 relay 会 rpc_s_access_denied，转 ESC8/凭据直连。",
            "只有配置位命中（candidate）：先补一次授权内的只读/低影响验证，再写 confirmed。",
            "ESC17 有 Server Auth 证书但没有 MITM 位置/客户端拒绝证书：最多 candidate。",
            "装了更新不等于提权：要写清落地标记文件与执行账号。",
        ],
    )


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------
def eval_delegation(d):
    accounts = d.get("accounts") or []
    if not accounts:
        return _result("delegation", "blocked",
                       [_check("delegation-data", False, "no account rows")],
                       failure=["没有委派属性：先 findDelegation/certipy 只读枚举。"])
    rows, findings = [], []
    for i, a in enumerate(accounts):
        name = str(a.get("account") or a.get("name") or ("account-%d" % i))
        unconstrained = _bool(a.get("trusted_for_delegation"))
        allowed = [str(x) for x in _list(a.get("allowed_to_delegate_to"))]
        target = str(a.get("target_spn") or "")
        protocol = _bool(a.get("protocol_transition"))
        rbcd = _bool(a.get("rbcd_write"))
        controlled = _bool(a.get("has_controlled_host"))
        ticket = _bool(a.get("ticket_obtained"))
        target_principal = str(a.get("target_principal") or "")
        paths = []
        if unconstrained and controlled:
            paths.append("unconstrained")
        if allowed and (target in allowed or "*" in allowed):
            paths.append("constrained")
            if protocol:
                paths.append("constrained-protocol-transition")
        if rbcd and target_principal:
            paths.append("rbcd")
        blockers = []
        if unconstrained and not controlled:
            blockers.append("no-controlled-host")
        if allowed and target and target not in allowed and "*" not in allowed:
            blockers.append("spn-not-in-allowed-list")
        if rbcd and not target_principal:
            blockers.append("no-target-principal")
        rows.append({"index": i, "account_fp": _fp(name), "paths": paths,
                     "blockers": blockers, "ticket_obtained": ticket,
                     "target_fp": _fp(target or target_principal)})
        for p in paths:
            findings.append({"severity": "high" if p != "constrained" else "medium",
                             "title": "delegation path: " + p,
                             "evidence": "account[%d] target=%s" % (i, _fp(target or target_principal))})
    confirmed = any(r["ticket_obtained"] for r in rows)
    candidate = any(r["paths"] for r in rows)
    checks = [
        _check("delegation-attribute", candidate, "unconstrained/constrained/RBCD attribute seen"),
        _check("target-in-scope", any("spn-not-in-allowed-list" not in r["blockers"] for r in rows),
               "target SPN/principal is inside the delegation scope"),
        _check("service-ticket", confirmed, "S4U/getST returned a usable service ticket"),
    ]
    return _result(
        "delegation", "confirmed" if (candidate and confirmed) else ("candidate" if candidate else "blocked"),
        checks, findings, accounts=rows,
        failure=[
            "msDS-AllowedToDelegateTo 不含目标 SPN：constrained 不成立，换目标或转 RBCD。",
            "没有可控主机：unconstrained 拿不到 TGT，先找可控机器或转其他路径。",
            "目标禁用协议转换/TGT 委派：S4U2Self/S4U2Proxy 会失败，别重复请求。",
            "只有属性没有服务票据：是候选路径，不是打穿。",
            "RBCD 无写权限或目标已设置 msDS-AllowedToActOnBehalfOfOtherIdentity：先清理/换目标。",
        ],
    )


# ---------------------------------------------------------------------------
# Kubernetes RBAC
# ---------------------------------------------------------------------------
def eval_k8s_rbac(d):
    can_i = d.get("can_i") or d.get("rules") or []
    pod = d.get("pod_security") or {}
    secret = d.get("secrets") or {}
    escape = d.get("escape") or {}
    if not can_i:
        return _result("k8s-rbac", "blocked",
                       [_check("authz-data", False, "no auth can-i rows; run kubectl auth can-i --list")],
                       failure=["没有 auth can-i 输出：离线不能判断 RBAC，禁止用 SA 名称猜权限。"])
    allowed = []
    for r in can_i:
        if not isinstance(r, dict):
            continue
        verb = str(r.get("verb") or "").lower()
        resource = str(r.get("resource") or "").lower()
        ok = _bool(r.get("allowed"))
        if ok:
            allowed.append((verb, resource))
    def has(verb, resource):
        for v, res in allowed:
            if v in (verb, "*") and res in (resource, "*"):
                return True
        return False
    create_pods = has("create", "pods") or has("create", "daemonsets") or has("create", "jobs")
    can_priv = _bool(pod.get("privileged")) or _bool(pod.get("host_path")) \
        or _bool(pod.get("host_pid")) or _bool(pod.get("host_network"))
    get_secrets = has("get", "secrets") or has("list", "secrets")
    impersonate = has("impersonate", "users") or has("impersonate", "groups") \
        or has("impersonate", "serviceaccounts")
    bind = has("bind", "clusterroles") or has("escalate", "clusterroles")
    host_escape = _bool(escape.get("host_id")) or _bool(escape.get("host_fs_read"))
    secret_usable = _bool(secret.get("readable")) and _bool(secret.get("usable"))
    paths = []
    if create_pods and can_priv:
        paths.append("pod-escape")
    if create_pods and _bool(pod.get("host_path")) and host_escape:
        paths.append("hostpath-escape")
    if get_secrets and secret_usable:
        paths.append("secret-credential")
    if impersonate:
        paths.append("impersonate")
    if bind:
        paths.append("bind-escalate")
    findings = []
    for p in paths:
        findings.append({"severity": "high", "title": "RBAC path: " + p,
                         "evidence": "allowed=%d rules" % len(allowed)})
    blocked = []
    if create_pods and not can_priv:
        blocked.append("PSA/Admission may reject privileged/hostPath")
    if get_secrets and not secret_usable:
        blocked.append("secret readable but not proven usable")
    checks = [
        _check("authz-allowed", bool(allowed), "allowed rules=%d" % len(allowed)),
        _check("create-pods", create_pods, "create pods/daemonsets/jobs"),
        _check("escape-primitive", can_priv, "privileged/hostPath/hostPID/hostNetwork"),
        _check("host-proof", host_escape, "host id or host filesystem read"),
        _check("secret-proof", secret_usable, "secret read and proven usable"),
    ]
    if paths:
        # impersonate 只是一条权限，不等于"已冒充成功并读到数据"；最多算 candidate。
        verdict = "confirmed" if (host_escape or secret_usable) else "candidate"
    else:
        verdict = "blocked"
    return _result(
        "k8s-rbac", verdict, checks, findings,
        paths=paths, blockers=blocked, allowed_count=len(allowed),
        failure=[
            "can-i 全为 no：停止提权尝试，转 Secret/CI 凭据或应用层。",
            "有 create pods 但 PSA/Quota/Admission 拒绝：不是逃逸成功，记录拒绝原因。",
            "hostNetwork 存在不等于宿主文件系统可读；必须有宿主 id/文件证据。",
            "Secret 可读但为空/过期/不能登录：是素材不是凭据。",
            "SA 名称像 cluster-admin 不能替代 auth can-i 与绑定核对。",
        ],
    )


# ---------------------------------------------------------------------------
# Windows Security event log (real wevtutil export)
# ---------------------------------------------------------------------------
def eval_windows_events(d):
    events = d.get("events") or []
    if not events:
        return _result("windows-events", "blocked",
                       [_check("events", False, "no events in JSON")],
                       failure=["事件为空：检查 wevtutil 查询/时间范围/日志是否启用。"])
    counts, logon_types, failed_users = {}, {}, {}
    for e in events:
        eid = str(e.get("event_id") or e.get("id") or "")
        counts[eid] = counts.get(eid, 0) + 1
        lt = e.get("logon_type")
        if lt not in (None, ""):
            logon_types[str(lt)] = logon_types.get(str(lt), 0) + 1
        if eid in ("4625", "4771"):
            u = str(e.get("target_user") or e.get("subject_user") or "unknown")
            failed_users[u] = failed_users.get(u, 0) + 1
    kerb = sum(counts.get(x, 0) for x in ("4768", "4769", "4770", "4771"))
    ntlm = counts.get("4776", 0)
    special = counts.get("4672", 0)
    explicit = counts.get("4648", 0)
    enum = counts.get("4798", 0)
    network = logon_types.get("3", 0)
    rdp = logon_types.get("10", 0)
    max_fail = max(failed_users.values()) if failed_users else 0
    # EventRecordID 连续性：Windows 安全日志是追加写的，导出片段若 record_id 跳号，
    # 说明中间有事件被过滤/删除/覆盖，据此下的「没看到攻击」结论不可信。
    ids = []
    for e in events:
        rid = e.get("record_id")
        if rid in (None, ""):
            continue
        try:
            ids.append(int(rid))
        except (TypeError, ValueError):
            continue
    gaps = []
    for a, b in zip(ids, ids[1:]):
        if b > a + 1:
            gaps.append([a, b])
    telemetry_untrusted = bool(gaps)
    findings = []
    if kerb:
        findings.append({"severity": "medium", "title": "Kerberos telemetry present",
                         "evidence": "4768/4769/4770/4771=%d" % kerb})
    if ntlm:
        findings.append({"severity": "low", "title": "NTLM authentication telemetry",
                         "evidence": "4776=%d" % ntlm})
    if special:
        findings.append({"severity": "medium", "title": "Special privileges assigned",
                         "evidence": "4672=%d" % special})
    if explicit:
        findings.append({"severity": "medium", "title": "Explicit credential use",
                         "evidence": "4648=%d" % explicit})
    if enum:
        findings.append({"severity": "low", "title": "Account enumeration telemetry",
                         "evidence": "4798=%d" % enum})
    if telemetry_untrusted:
        findings.append({"severity": "high", "title": "Event log gaps (telemetry untrusted)",
                         "evidence": "record_id gaps=%d, first=%s" % (len(gaps), gaps[:1])})
    if max_fail >= 5:
        findings.append({"severity": "high", "title": "Repeated logon failures",
                         "evidence": "max failures for one principal=%d" % max_fail})
    if rdp or network:
        findings.append({"severity": "low", "title": "Remote/network logon observed",
                         "evidence": "type3=%d type10=%d" % (network, rdp)})
    if kerb:
        verdict = "candidate"
    else:
        verdict = "blocked"
    checks = [
        _check("kerberos-events", kerb > 0, "4768/4769/4770/4771=%d" % kerb),
        _check("ntlm-events", ntlm > 0, "4776=%d" % ntlm),
        _check("special-privileges", special > 0, "4672=%d" % special),
        _check("account-enumeration", enum > 0, "4798=%d" % enum),
        _check("lockout-budget", max_fail < 5, "max failures for one principal=%d" % max_fail,
               "high" if max_fail >= 5 else "info"),
        _check("record-id-continuity", not telemetry_untrusted,
               "gaps=%d (%s)" % (len(gaps), gaps[:3]),
               "high" if telemetry_untrusted else "info"),
    ]
    return _result(
        "windows-events", verdict, checks, findings,
        summary={
            "events": len(events),
            "record_id_gaps": gaps[:20],
            "telemetry_untrusted": telemetry_untrusted,
            "counts": dict(sorted(counts.items())),
            "logon_types": dict(sorted(logon_types.items())),
            "kerberos_events": kerb,
            "ntlm_events": ntlm,
            "special_privileges": special,
            "explicit_credentials": explicit,
            "account_enumeration": enum,
            "max_failures_one_principal": max_fail,
        },
        failure=[
            "没有 4768/4769：要么不是域主机、要么 Kerberos 审计未开；不能据此说‘域内无攻击’。",
            "4776 多而 4768 少：可能在用 NTLM，检查 LmCompatibilityLevel/审计策略后再判断。",
            "4625 集中在同一账号：立即停止任何口令尝试，先读锁定策略。",
            "只有 4624 类型 3/10：是网络/RDP 登录面，不等于拿到凭据或提权。",
            "日志被清空/缺口：先记录 EventRecordID 断档，再决定是否可信。",
        ],
    )


# ---------------------------------------------------------------------------
# EVTX XML -> JSON (no secrets; redaction on by default for users/host)
# ---------------------------------------------------------------------------
def _data_map(node):
    out = {}
    for data in node.findall(EVENT_NS + "EventData/" + EVENT_NS + "Data"):
        name = data.get("Name") or ("param%d" % len(out))
        out[name] = (data.text or "").strip()
    return out


def extract_evtx_xml(path, redact=True):
    if not os.path.isfile(path):
        raise ReproError("read-xml", "file not found: %s" % path)
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            raw = fh.read()
        stripped = raw.lstrip()
        if stripped.startswith("<Event") and not stripped.startswith("<Events"):
            # wevtutil /f:xml emits a sequence of <Event> roots, not one document.
            root = ET.fromstring("<Events>%s</Events>" % raw)
        else:
            root = ET.fromstring(raw)
    except Exception as exc:  # noqa: BLE001
        raise ReproError("parse-xml", "%s: %s" % (type(exc).__name__, exc))
    events = []
    for ev in root.iter(EVENT_NS + "Event"):
        system = ev.find(EVENT_NS + "System")
        if system is None:
            continue
        eid = system.findtext(EVENT_NS + "EventID")
        time_node = system.find(EVENT_NS + "TimeCreated")
        computer = system.findtext(EVENT_NS + "Computer") or ""
        data = _data_map(ev)
        rec = {
            "event_id": str(eid or ""),
            "time": (time_node.get("SystemTime") if time_node is not None else "") or "",
            "computer": "HOST" if redact and computer else computer,
            "channel": system.findtext(EVENT_NS + "Channel") or "",
            "record_id": system.findtext(EVENT_NS + "EventRecordID") or "",
        }
        field_map = {
            "TargetUserName": "target_user",
            "SubjectUserName": "subject_user",
            "TargetDomainName": "target_domain",
            "SubjectDomainName": "subject_domain",
            "LogonType": "logon_type",
            "IpAddress": "ip",
            "Status": "status",
            "SubStatus": "sub_status",
            "ServiceName": "service_name",
            "TicketOptions": "ticket_options",
            "EncryptionType": "encryption_type",
            "ProcessName": "process_name",
            "CommandLine": "command_line",
            "TargetServerName": "target_server",
        }
        for key, out_key in field_map.items():
            if key in data:
                val = data[key]
                if redact and key in ("TargetUserName", "SubjectUserName",
                                      "TargetDomainName", "SubjectDomainName"):
                    val = "USER" if val else ""
                if redact and key == "IpAddress" and val:
                    val = "IP"
                if val != "":
                    rec[out_key] = val
        events.append(rec)
    if not events:
        raise ReproError("parse-xml", "no <Event> elements found")
    return {"source": os.path.basename(path), "redacted": bool(redact),
            "event_count": len(events), "events": events}


# ---------------------------------------------------------------------------
# NTLM type 2 challenge (445/389 external view, read-only)
# ---------------------------------------------------------------------------
NTLM_FLAGS = [
    (0x00000001, "UNICODE"), (0x00000002, "OEM"),
    (0x00000004, "REQUEST_TARGET"), (0x00000010, "SIGN"),
    (0x00000020, "SEAL"), (0x00000040, "DATAGRAM"),
    (0x00000080, "LM_KEY"), (0x00000200, "NTLM"),
    (0x00000800, "ANONYMOUS"), (0x00008000, "ALWAYS_SIGN"),
    (0x00010000, "TARGET_TYPE_DOMAIN"), (0x00020000, "TARGET_TYPE_SERVER"),
    (0x00080000, "EXTENDED_SESSIONSECURITY"), (0x00100000, "IDENTIFY"),
    (0x00800000, "TARGET_INFO"), (0x02000000, "VERSION"),
    (0x20000000, "128"), (0x40000000, "KEY_EXCH"), (0x80000000, "56"),
]
NTLM_AV = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer",
           4: "dns_domain", 5: "dns_tree", 6: "av_flags", 7: "timestamp",
           8: "single_host", 9: "target_name", 10: "channel_bindings"}
NTLM_NEGOTIATE_VERSION = 0x02000000
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _u16(raw):
    return raw.decode("utf-16-le", "replace")


def _filetime(value):
    try:
        return (FILETIME_EPOCH + datetime.timedelta(microseconds=value / 10)).isoformat() \
            .replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return "invalid"


def _ntlm_message(value):
    """Accept base64 (SMB/LDAP capture) or hex (pcap copy); never contact network."""
    if not isinstance(value, str) or not value.strip():
        raise ReproError("schema", "ntlm-type2 needs message=<base64|hex>")
    s = re.sub(r"\s+", "", value)
    try:
        if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
            return bytes.fromhex(s)
        return base64.b64decode(s, validate=True)
    except Exception:  # noqa: BLE001
        raise ReproError("schema", "message is neither base64 nor hex")


def _parse_ntlm_type2(raw):
    out = {"signature_ok": False, "message_type": None, "target_name": "",
           "flags": [], "flags_hex": "", "challenge_fp": "", "os_version": "",
           "av": {}, "timestamp": ""}
    if len(raw) < 32 or raw[:8] != b"NTLMSSP\x00":
        return out
    out["signature_ok"] = True
    mtype = struct.unpack_from("<I", raw, 8)[0]
    out["message_type"] = mtype
    if mtype != 2:
        return out
    tlen, _, toff = struct.unpack_from("<HHI", raw, 12)
    flags = struct.unpack_from("<I", raw, 20)[0]
    out["flags_hex"] = "0x%08x" % flags
    out["flags"] = [name for bit, name in NTLM_FLAGS if flags & bit]
    out["challenge_fp"] = _fp(raw[24:32])
    tinfo_len, _, tinfo_off = struct.unpack_from("<HHI", raw, 40)
    if flags & NTLM_NEGOTIATE_VERSION and len(raw) >= 56:
        out["os_version"] = "%d.%d.%d" % (
            raw[48], raw[49], struct.unpack_from("<H", raw, 50)[0])
    if tlen and toff + tlen <= len(raw):
        out["target_name"] = _u16(raw[toff:toff + tlen])
    p, end = tinfo_off, min(len(raw), tinfo_off + tinfo_len)
    while p + 4 <= end:
        aid, ln = struct.unpack_from("<HH", raw, p)
        p += 4
        val = raw[p:p + ln]
        p += ln
        if aid == 0:
            break
        if aid == 7 and len(val) >= 8:
            out["timestamp"] = _filetime(struct.unpack_from("<Q", val)[0])
        elif aid == 6 and len(val) >= 4:
            out["av"]["av_flags"] = "0x%08x" % struct.unpack_from("<I", val)[0]
        elif aid in NTLM_AV:
            out["av"][NTLM_AV[aid]] = _u16(val)
    return out


def eval_ntlm_type2(d):
    parsed = _parse_ntlm_type2(_ntlm_message(d.get("message") or d.get("ntlm")))
    av = parsed["av"]
    domain = av.get("dns_domain") or av.get("nb_domain") or ""
    computer = av.get("dns_computer") or av.get("nb_computer") or ""
    ok = parsed["signature_ok"] and parsed["message_type"] == 2
    checks = [
        _check("signature", parsed["signature_ok"], "NTLMSSP signature"),
        _check("message-type-2", parsed["message_type"] == 2,
               "message_type=%r" % parsed["message_type"]),
        _check("target-info", bool(av), "av_pairs=%d" % len(av)),
        _check("domain-identified", bool(domain), "domain=%s" % (domain or "-")),
        _check("os-version", bool(parsed["os_version"]), "os=%s" % (parsed["os_version"] or "-")),
        _check("timestamp", bool(parsed["timestamp"]),
               "timestamp=%s" % (parsed["timestamp"] or "-")),
    ]
    verdict = "candidate" if ok else "blocked"
    findings = []
    if ok:
        findings.append({
            "severity": "info",
            "title": "NTLM type 2 challenge exposed (read-only)",
            "evidence": "domain=%s computer=%s os=%s" % (domain or "-", computer or "-",
                                                         parsed["os_version"] or "-"),
        })
    return _result(
        "ntlm-type2", verdict, checks, findings,
        target_name=parsed["target_name"],
        nb_domain=av.get("nb_domain", ""),
        dns_domain=av.get("dns_domain", ""),
        dns_tree=av.get("dns_tree", ""),
        nb_computer=av.get("nb_computer", ""),
        dns_computer=av.get("dns_computer", ""),
        os_version=parsed["os_version"],
        timestamp=parsed["timestamp"],
        flags=parsed["flags"],
        flags_hex=parsed["flags_hex"],
        challenge_fp=parsed["challenge_fp"],
        auth_attempted=False,
        summary={"av_pairs": len(av), "domain": domain, "computer": computer,
                 "os_version": parsed["os_version"], "timestamp": parsed["timestamp"]},
        failure=[
            "只拿到 type 2 challenge：这是暴露面证据，不是登录成功；不得写 confirmed。",
            "challenge 是服务端随机数，不可复用；不要当凭据保存或回传。",
            "OS 版本/域名字段可能被策略伪装或伪造，只能当指纹，不能当补丁级结论。",
            "SMB signing 强制或目标只收 Kerberos 时 relay 仍不可用；转只读枚举或凭据直连。",
            "非 NTLMSSP/非 type 2 的字节流：先核对抓包方向与端口，不要猜。",
        ],
    )


# ---------------------------------------------------------------------------
# Edge access surface fingerprints (VPN / OWA / Zimbra / Okta / M365)
# ---------------------------------------------------------------------------
# 只读口径：HEAD 优先、GET 兜底，不提交凭据、不带 Cookie jar、不跟随登录、
# 不发利用包。confidence 只描述「指纹吻合度」，不是可利用性。
EDGE_PRODUCTS = {
    "cisco-asa": {
        "label": "Cisco ASA / AnyConnect",
        "cookies": ("webvpn",),
        "specific_cookies": ("webvpn",),
        "headers": {"server": ("cisco",)},
        "specific_headers": (),
        "paths": ("/+cscoe+/logon.html", "/+cscoe+/saml/sp/metadata", "/+cscoe+/"),
        "body": ("anyconnect", "cisco adaptive security appliance", "cscoe"),
        "specific_body": ("anyconnect", "cscoe"),
        "next_readonly": "GET /+CSCOE+/saml/sp/metadata（只读 XML，看 AuthnRequestsSigned）",
    },
    "fortinet-fortigate": {
        "label": "Fortinet FortiGate SSL-VPN",
        "cookies": ("svpncookie",),
        "specific_cookies": ("svpncookie",),
        "headers": {},
        "specific_headers": (),
        "paths": ("/remote/login", "/remote/saml/metadata"),
        "body": ("fortigate", "fortinet", "ssl-vpn"),
        "specific_body": ("fortigate", "fortinet"),
        "next_readonly": "GET /remote/saml/metadata（只读 XML）",
    },
    "citrix-netscaler": {
        "label": "Citrix NetScaler / ADC",
        "cookies": ("nsc_aaa", "nsc_*", "lastmrh_session"),
        "specific_cookies": ("nsc_aaa", "nsc_*", "lastmrh_session"),
        "headers": {},
        "specific_headers": (),
        "paths": ("/vpn/index.html", "/menu/neo", "/vpn/"),
        "body": ("netscaler", "citrix gateway", "citrix adc"),
        "specific_body": ("netscaler", "citrix gateway"),
        "next_readonly": "GET /vpn/index.html（只读首页，确认网关面）",
    },
    "paloalto-globalprotect": {
        "label": "Palo Alto GlobalProtect",
        # PHPSESSID 是通用 cookie，只能算弱线索；版本串 panui- 才是专属。
        "cookies": ("phpsessid",),
        "specific_cookies": (),
        "headers": {},
        "specific_headers": (),
        "paths": ("/global-protect/login.esp", "/global-protect/portal/"),
        "body": ("globalprotect portal", "panui-", "palo alto networks"),
        "specific_body": ("globalprotect portal", "panui-"),
        "next_readonly": "GET /global-protect/login.esp（只读，记 panui- 版本串）",
    },
    "pulse-ivanti": {
        "label": "Pulse Secure / Ivanti Connect Secure",
        "cookies": ("dsauthsession", "dsid"),
        "specific_cookies": ("dsauthsession",),
        "headers": {},
        "specific_headers": (),
        "paths": ("/dana-na/auth/url_default/welcome.cgi", "/dana-na/"),
        "body": ("pulse secure", "ivanti", "connect secure"),
        "specific_body": ("pulse secure", "ivanti"),
        "next_readonly": "GET /dana-na/auth/url_default/welcome.cgi（只读欢迎页）",
    },
    "sonicwall-f5": {
        "label": "SonicWall / F5 BIG-IP",
        "cookies": ("swap", "swapauth", "lastmrh_session", "mrhsession",
                    "bigipserver*"),
        "specific_cookies": ("swap", "swapauth", "lastmrh_session", "mrhsession",
                             "bigipserver*"),
        "headers": {},
        "specific_headers": (),
        "paths": ("/my.policy", "/cgi-bin/welcome", "/cgi-bin/welcome.cgi",
                  "/sonicui/"),
        "body": ("sonicwall", "netextender", "big-ip", "f5 networks"),
        "specific_body": ("sonicwall", "netextender", "big-ip"),
        "next_readonly": "GET /my.policy 或 /cgi-bin/welcome（只读，区分 F5 APM 与 SonicWall）",
    },
    "microsoft-owa": {
        "label": "Microsoft Exchange / OWA",
        # ASP.NET_SessionId 是通用 cookie；X-OWA-Version / X-OWA-CANARY 才是专属。
        "cookies": ("x-owa-canary", "cadata", "asp.net_sessionid"),
        "specific_cookies": ("x-owa-canary",),
        "headers": {"x-owa-version": (), "x-feserver": (),
                    "www-authenticate": ("negotiate", "ntlm")},
        "specific_headers": ("x-owa-version",),
        "paths": ("/owa/", "/owa", "/autodiscover/autodiscover.xml", "/ecp/"),
        "body": ("outlook web app", "outlook on the web", "exchange"),
        "specific_body": (),  # 正文不算专属，避免无 X-OWA-Version 时误判 high
        "next_readonly": "HEAD /owa/ 只看 X-OWA-Version / X-FEServer；NTLM 证据转 --kind ntlm-type2",
    },
    "zimbra": {
        "label": "Zimbra Collaboration",
        "cookies": ("zm_auth_token", "zm_test", "zm_login"),
        "specific_cookies": ("zm_auth_token", "zm_test", "zm_login"),
        "headers": {},
        "specific_headers": (),
        "paths": ("/zimbra/", "/zimbraadmin/", "/service/soap/"),
        "body": ("zimbra",),
        "specific_body": ("zimbra",),
        "next_readonly": "匿名 POST /service/soap/ GetVersionInfoRequest（不认证、不枚举用户）",
    },
    "okta": {
        "label": "Okta",
        "cookies": ("dt", "idx", "sid", "jsessionid"),
        "specific_cookies": ("dt", "idx"),
        "headers": {"x-okta-request-id": ()},
        "specific_headers": ("x-okta-request-id",),
        "paths": ("/.well-known/okta-organization", "/oauth2/", "/login/default",
                  "/.well-known/openid-configuration"),
        "body": ("okta",),
        "specific_body": ("okta-organization", "okta.com"),
        "next_readonly": "GET /.well-known/okta-organization 与 openid-configuration（只读）",
    },
    "m365-entra": {
        "label": "Microsoft 365 / Entra ID",
        "cookies": ("estsauth", "estsauthpersistent", "aadsso"),
        "specific_cookies": ("estsauth", "estsauthpersistent", "aadsso"),
        "headers": {},
        "specific_headers": (),
        "paths": ("/getuserrealm.srf", "/.well-known/openid-configuration",
                  "/common/oauth2/"),
        "body": ("namespacetype", "login.microsoftonline.com", "microsoftonline.com",
                 "sts.windows.net"),
        "specific_body": ("namespacetype", "login.microsoftonline.com",
                          "sts.windows.net"),
        "next_readonly": "GET getuserrealm.srf?login=<user>@<domain>&xml=1（不提交凭据）",
    },
}

EDGE_CONF_RANK = {"high": 3, "med": 2, "low": 1, "none": 0}
EDGE_VERDICT_TEXT = {
    "high": "指纹置信 high（专属 cookie/版本串 + 专属路径）；暴露面 candidate，不等于可利用。",
    "med": "指纹置信 med（两条独立线索一致）；暴露面 candidate，需公开 metadata/版本串补证。",
    "low": "指纹置信 low（单条线索）；只记疑似暴露面，不得据此判版本或漏洞。",
    "none": "无厂商指纹；记 blocked/unknown，不猜服务、不用默认口令或 CVE 路径字典升级。",
}


def _norm_headers(raw):
    """dict / ["Name: value"] / [{name,value}] → [(lower-name, value)]。"""
    out = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            for vv in _list(v):
                out.append((str(k).strip().lower(), str(vv).strip()))
    else:
        for item in _list(raw):
            if isinstance(item, dict):
                out.append((str(item.get("name") or "").strip().lower(),
                            str(item.get("value") or "").strip()))
            elif isinstance(item, str) and ":" in item:
                name, value = item.split(":", 1)
                out.append((name.strip().lower(), value.strip()))
    return [(n, v) for n, v in out if n]


def _cookie_names(headers):
    names = set()
    for name, value in headers:
        if name != "set-cookie":
            continue
        first = value.split(";", 1)[0]
        if "=" in first:
            names.add(first.split("=", 1)[0].strip().lower())
    return names


def _cookie_hit(names, patterns):
    for pat in patterns:
        pat = pat.lower()
        if pat.endswith("*"):
            if any(n.startswith(pat[:-1]) for n in names):
                return True
        elif pat in names:
            return True
    return False


def _norm_path(value):
    text = str(value or "/").strip()
    if "://" in text:
        tail = text.split("://", 1)[1]
        text = ("/" + tail.split("/", 1)[1]) if "/" in tail else "/"
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    return text or "/"


def _norm_edge_responses(raw):
    rows = []
    for item in _list(raw):
        if not isinstance(item, dict):
            continue
        headers = _norm_headers(item.get("headers"))
        body = " ".join(str(item.get(k) or "") for k in
                        ("title", "body", "body_excerpt", "snippet", "text"))
        rows.append({
            "path": _norm_path(item.get("path") or item.get("url")),
            "status": item.get("status"),
            "method": str(item.get("method") or "HEAD").upper(),
            "headers": headers,
            "body": body,
            "location": [v for n, v in headers if n == "location"],
        })
    return rows


def _edge_path_hit(actual, patterns):
    path = actual.lower()
    for pat in patterns:
        pat = pat.lower()
        if path == pat or (pat.endswith("/") and path.startswith(pat)):
            return pat
    return None


def _edge_clues(spec, responses):
    clues, seen = [], set()

    def push(family, header, path, value, strong):
        key = (family, header.lower(), path.lower(), value.lower())
        if key in seen:
            return
        seen.add(key)
        clues.append({"family": family, "header": header, "path": path,
                      "value": value, "strong": bool(strong)})

    for row in responses:
        cookies = _cookie_names(row["headers"])
        for name in sorted(cookies):
            if _cookie_hit({name}, spec["cookies"]):
                push("cookie", "Set-Cookie", row["path"], name,
                     _cookie_hit({name}, spec["specific_cookies"]))
        for name, value in row["headers"]:
            if name in spec["headers"]:
                wanted = spec["headers"][name]
                if not wanted or any(w in value.lower() for w in wanted):
                    push("header", name, row["path"], value[:80] or "present",
                         name in spec["specific_headers"])
        for pat in spec["paths"]:
            if _edge_path_hit(row["path"], (pat,)):
                push("path", "", row["path"], "%s" % (row["status"] or "hit"), True)
            for loc in row["location"]:
                if _edge_path_hit(_norm_path(loc), (pat,)):
                    push("path", "Location", _norm_path(loc),
                         "%s" % (row["status"] or "hit"), True)
        lowered = row["body"].lower()
        for marker in spec["body"]:
            if marker in lowered:
                push("body", "", row["path"], marker, marker in spec["specific_body"])
    return clues


def _edge_confidence(clues):
    families = {c["family"] for c in clues}
    strong_non_path = any(c["strong"] and c["family"] != "path" for c in clues)
    if strong_non_path and "path" in families:
        return "high"
    if len(families) >= 2:
        return "med"
    if families:
        return "low"
    return "none"


def eval_edge_target(target, responses, mode="fixture", requests=0):
    """One target → one classified result.  Never authenticates."""
    url = str(target.get("url") or "")
    hint = str(target.get("product_hint") or "").strip()
    response_rows = _norm_edge_responses(responses)
    if not url and response_rows:
        url = str(target.get("label") or "fixture")
    per_product = {}
    for pid, spec in EDGE_PRODUCTS.items():
        clues = _edge_clues(spec, response_rows)
        if clues:
            per_product[pid] = (clues, _edge_confidence(clues))
    hint_known = hint in EDGE_PRODUCTS
    hint_unknown = bool(hint) and not hint_known
    if not per_product:
        return {
            "url": url,
            "product": None,
            "product_label": None,
            "confidence": "none",
            "verdict": "blocked",
            "judgement": EDGE_VERDICT_TEXT["none"],
            "evidence": [],
            "clues": [],
            "auth_attempted": False,
            "credentials_sent": False,
            "mode": mode,
            "requests": requests,
            "product_hint": hint or None,
            "hint_mismatch": False,
            "hint_unknown": hint_unknown,
            "alternatives": [],
            "blocked_at": "no-fingerprint",
            "next_readonly": None,
        }
    ranked = sorted(
        per_product.items(),
        key=lambda kv: (EDGE_CONF_RANK[kv[1][1]],
                        sum(1 for c in kv[1][0] if c["strong"]),
                        len(kv[1][0]),
                        1 if hint_known and kv[0] == hint else 0),
        reverse=True,
    )
    pid, (clues, confidence) = ranked[0]
    alternatives = [k for k, v in ranked[1:] if v[1] == confidence]
    if confidence == "med" and alternatives:
        confidence = "low"
    evidence = []
    for c in sorted(clues, key=lambda x: (x["family"] != "path", x["family"], x["value"])):
        evidence.append({"clue": c["family"], "header": c["header"],
                         "path": c["path"], "value": c["value"]})
    spec = EDGE_PRODUCTS[pid]
    judgement = EDGE_VERDICT_TEXT[confidence]
    if hint_known and pid != hint:
        judgement += " product_hint=%s 与实际指纹不一致，以实际响应为准。" % hint
    elif hint_known:
        judgement += " product_hint 与指纹一致。"
    if alternatives:
        judgement += " 存在同分候选（%s），按路径线索人工复核。" % ", ".join(alternatives)
    return {
        "url": url,
        "product": pid,
        "product_label": spec["label"],
        "confidence": confidence,
        "verdict": "candidate",
        "judgement": judgement,
        "evidence": evidence,
        "clues": ["%s:%s" % (c["family"], c["value"]) for c in clues],
        "auth_attempted": False,
        "credentials_sent": False,
        "mode": mode,
        "requests": requests,
        "product_hint": hint or None,
        "hint_mismatch": bool(hint_known and pid != hint),
        "hint_unknown": hint_unknown,
        "alternatives": alternatives,
        "blocked_at": None,
        "next_readonly": spec["next_readonly"],
    }


def _edge_blocked_result(target, reason, blocked_at="edge-network", mode="live"):
    """Network/probe failure 不能中断其它目标；按单目标 blocked 记。"""
    return {
        "url": str(target.get("url") or target.get("label") or ""),
        "product": None,
        "product_label": None,
        "confidence": "none",
        "verdict": "blocked",
        "judgement": EDGE_VERDICT_TEXT["none"],
        "evidence": [],
        "clues": [],
        "auth_attempted": False,
        "credentials_sent": False,
        "mode": mode,
        "requests": 0,
        "product_hint": str(target.get("product_hint") or "") or None,
        "hint_mismatch": False,
        "hint_unknown": False,
        "alternatives": [],
        "blocked_at": blocked_at,
        "reason": reason,
        "next_readonly": None,
    }


# 只读在线探测：HEAD 优先，GET 兜底；不跟随重定向、不带 Cookie、不加 Authorization。
EDGE_LIVE_PATHS = ("/+CSCOE+/logon.html", "/remote/login", "/vpn/index.html",
                   "/global-protect/login.esp", "/dana-na/auth/url_default/welcome.cgi",
                   "/owa/", "/zimbra/", "/.well-known/okta-organization",
                   "/getuserrealm.srf", "/.well-known/openid-configuration")
EDGE_TIMEOUT = 6
EDGE_MAX_PROBES = 7


def _edge_live_guard(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ReproError("edge-target", "url must be absolute http(s): %r" % url)
    host = parts.hostname.lower()
    if (host.endswith(".invalid") or host in ("example.com", "example.org")
            or host.endswith(".example")):
        raise ReproError("edge-network",
                         "refusing to probe placeholder host %s; use --fixture" % host)
    return parts


class _EdgeNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _redact_cookie(value):
    first, _, rest = str(value).partition(";")
    name = first.split("=", 1)[0].strip()
    return "%s=REDACTED%s" % (name, (";" + rest) if rest else "")


def _edge_probe(url, method):
    parts = _edge_live_guard(url)
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "seep-edge-fingerprint/%s (read-only)" % VERSION,
        "Accept": "*/*",
    })
    ctx = ssl._create_unverified_context()  # 与 curl -k 同义，只读指纹
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), _EdgeNoRedirect())
    try:
        resp = opener.open(req, timeout=EDGE_TIMEOUT)
        status, headers, body = resp.status, resp.headers, resp.read(4096)
    except urllib.error.HTTPError as exc:
        status, headers, body = exc.code, exc.headers, exc.read(4096)
    except Exception as exc:  # noqa: BLE001
        raise ReproError("edge-network", "%s %s failed: %s: %s" % (
            method, parts.path or "/", type(exc).__name__, exc))
    keep = {}
    for name in ("server", "x-powered-by", "x-owa-version", "x-feserver",
                 "www-authenticate", "location", "x-okta-request-id"):
        value = headers.get(name)
        if value:
            keep[name.title()] = value
    set_cookie = headers.get_all("set-cookie") or []
    if set_cookie:
        keep["Set-Cookie"] = [_redact_cookie(c) for c in set_cookie]
    text = body.decode("utf-8", "replace")
    return {"path": parts.path or "/", "method": method, "status": status,
            "headers": keep, "body_excerpt": text[:1200]}


def probe_edge_live(target):
    url = str(target.get("url") or "")
    base = _edge_live_guard(url)
    root = "%s://%s%s" % (base.scheme, base.netloc, base.path or "/")
    hint = str(target.get("product_hint") or "")
    wanted = list(EDGE_PRODUCTS[hint]["paths"]) if hint in EDGE_PRODUCTS else []
    if not wanted:
        wanted = list(EDGE_LIVE_PATHS)
    responses, sent = [], 0
    for path in [base.path or "/"] + wanted:
        if sent >= EDGE_MAX_PROBES:
            break
        full = urllib.parse.urljoin(root, path)
        if any(r["path"] == _norm_path(full) for r in responses):
            continue
        try:
            row = _edge_probe(full, "HEAD")
            if row["status"] in (405, 501) or not row["headers"]:
                row = _edge_probe(full, "GET")
        except ReproError as exc:
            if exc.blocked_at == "edge-network":
                continue
            raise
        responses.append(row)
        sent += 1
    if not responses:
        raise ReproError("edge-network", "no response for %s (offline? use --fixture)" % url)
    return responses, sent


def run_edge(targets, offline=False):
    if not targets:
        raise ReproError("edge-input", "provide --url, --input or --fixture")
    results, any_live = [], False
    for target in targets:
        if not isinstance(target, dict):
            raise ReproError("edge-input", "each target must be an object")
        recorded = (target.get("responses") or target.get("samples")
                    or target.get("probes"))
        if recorded:
            results.append(eval_edge_target(target, recorded, mode="fixture", requests=0))
            continue
        if offline:
            raise ReproError("edge-input", "fixture target %r has no recorded responses"
                             % (target.get("url") or target.get("label")))
        any_live = True
        try:
            responses, count = probe_edge_live(target)
        except ReproError as exc:
            if exc.blocked_at != "edge-network":
                raise
            results.append(_edge_blocked_result(target, exc.reason,
                                                blocked_at=exc.blocked_at))
            continue
        results.append(eval_edge_target(target, responses, mode="live", requests=count))
    summary = {}
    for r in results:
        key = "%s/%s" % (r["verdict"], r["confidence"])
        summary[key] = summary.get(key, 0) + 1
    return {
        "ok": True,
        "kind": "edge-fingerprint",
        "offline": not any_live,
        "auth_attempted": False,
        "credentials_sent": False,
        "results": results,
        "summary": summary,
        "blocked_at": None,
    }


def _edge_targets_from_doc(doc):
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        for key in ("probes", "targets", "checks", "entries"):
            if isinstance(doc.get(key), list):
                items = doc[key]
                break
        else:
            items = [doc]
    else:
        raise ReproError("edge-input", "edge-fingerprint input must be an object or a list")
    out = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ReproError("edge-input", "target[%d] is not an object" % i)
        if item.get("kind") and item.get("kind") != "edge-fingerprint":
            raise ReproError("edge-input", "target[%d] kind is not edge-fingerprint" % i)
        out.append(item)
    return out


def _edge_fixture_file(path):
    if os.path.isfile(path):
        return path
    if not os.path.isdir(path):
        raise ReproError("edge-input", "fixture path not found: %s" % path)
    for rel in ("edge-fingerprint.json", os.path.join("input", "edge-fingerprint.json")):
        cand = os.path.join(path, rel)
        if os.path.isfile(cand):
            return cand
    import glob
    cands = sorted(glob.glob(os.path.join(path, "*edge*fixture*.json")) +
                   glob.glob(os.path.join(path, "input", "*edge*.json")))
    if len(cands) == 1:
        return cands[0]
    raise ReproError("edge-input", "no edge-fingerprint.json under %s" % path)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def eval_one(d):
    kind = str(d.get("kind") or "")
    if kind not in KINDS:
        raise ReproError("schema", "unsupported kind %r (allowed: %s)" % (kind, ", ".join(KINDS)))
    if kind == "kerberoast":
        return eval_kerberoast(d)
    if kind == "asrep":
        return eval_asrep(d)
    if kind == "adcs":
        return eval_adcs(d)
    if kind == "adcs-esc":
        return eval_adcs_esc(d)
    if kind == "delegation":
        return eval_delegation(d)
    if kind == "k8s-rbac":
        return eval_k8s_rbac(d)
    if kind == "ntlm-type2":
        return eval_ntlm_type2(d)
    if kind == "edge-fingerprint":
        recorded = d.get("responses") or d.get("samples") or d.get("probes") or []
        if not recorded:
            raise ReproError("edge-input",
                             "bundle edge-fingerprint needs recorded responses; "
                             "use --url/--fixture for live or fixture probes")
        return eval_edge_target(d, recorded, mode="fixture", requests=0)
    return eval_windows_events(d)


def run_bundle(bundle, force_kind=None):
    if not isinstance(bundle, dict):
        raise ReproError("schema", "top-level JSON must be an object")
    if "checks" in bundle:
        checks = bundle["checks"]
        if not isinstance(checks, list) or not checks:
            raise ReproError("schema", "checks must be a non-empty list")
    else:
        checks = [bundle]
    results = []
    for i, item in enumerate(checks):
        if not isinstance(item, dict):
            raise ReproError("schema", "check[%d] is not an object" % i)
        if force_kind:
            if item.get("kind") and item.get("kind") != force_kind:
                raise ReproError("schema", "check[%d] kind differs from --kind" % i)
            item = dict(item, kind=force_kind)
        results.append(eval_one(item))
    summary = {}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    return {
        "tool": "ad-repro",
        "version": VERSION,
        "generated_at": (os.environ.get("SEEP_TIMESTAMP") or None),
        "ok": True,
        "offline": True,
        "results": results,
        "summary": summary,
    }


def _self_test():
    checks = 0
    fixtures = [
        ({"kind": "kerberoast", "tickets": [
            {"spn": "MSSQLSvc/db01:1433", "account": "svc_sql", "etype": 23,
             "hash_present": True, "cracked": True}], "lockout_policy": {"threshold": 5}},
         "confirmed"),
        ({"kind": "asrep", "users": [
            {"account": "alice", "dont_req_preauth": True, "asrep_present": True,
             "etype": 23, "hash_present": True}]}, "candidate"),
        ({"kind": "adcs", "templates": [
            {"name": "WebServer", "enroll_allowed": True, "san_enforced": False,
             "client_auth_eku": True, "manager_approval": False,
             "ca_san_allowed": True}]}, "candidate"),
        ({"kind": "delegation", "accounts": [
            {"account": "web01$", "trusted_for_delegation": True,
             "has_controlled_host": True, "ticket_obtained": False}]}, "candidate"),
        ({"kind": "k8s-rbac", "can_i": [
            {"verb": "create", "resource": "pods", "allowed": True},
            {"verb": "get", "resource": "secrets", "allowed": True}],
          "pod_security": {"privileged": True, "host_path": True},
          "secrets": {"readable": True, "usable": True},
          "escape": {"host_id": True}}, "confirmed"),
        ({"kind": "windows-events", "events": [
            {"event_id": "4769", "logon_type": "3"},
            {"event_id": "4672", "logon_type": "5"},
            {"event_id": "4798"}]}, "candidate"),
    ]
    for bundle, expected in fixtures:
        out = run_bundle(bundle)
        got = out["results"][0]["verdict"]
        if got != expected:
            raise ReproError("self-test", "expected %s, got %s for %s" % (expected, got, bundle["kind"]))
        checks += 1
    ntlm_b64 = "TlRMTVNTUAACAAAACAAIADgAAAAzgoriAAECAwQFBgcAAAAAAAAAAHoAegBAAAAACgB8TwAAAA9DAE8AUgBQAAEACABEAEMAMAAxAAIACABDAE8AUgBQAAMAHgBkAGMAMAAxAC4AYwBvAHIAcAAuAGwAbwBjAGEAbAAEABQAYwBvAHIAcAAuAGwAbwBjAGEAbAAFABQAYwBvAHIAcAAuAGwAbwBjAGEAbAAHAAgAAHBHdmRh3QEAAAAA"
    ntlm = run_bundle({"kind": "ntlm-type2", "message": ntlm_b64})["results"][0]
    if (ntlm["verdict"] != "candidate" or ntlm["dns_domain"] != "corp.local"
            or ntlm["os_version"] != "10.0.20348"
            or not ntlm["timestamp"].startswith("2026-10-21T14:00:00")):
        raise ReproError("self-test", "ntlm-type2 parse failed: %s" % json.dumps(
            {k: ntlm.get(k) for k in ("verdict", "dns_domain", "os_version", "timestamp")}))
    checks += 1
    esc_doc = {
        "kind": "adcs-esc",
        "StrongCertificateBindingEnforcement": 0,
        "CertificateMappingMethods": "0x4",
        "Certificate Authorities": [{
            "CA Name": "LAB-CA",
            "Enforce Encryption for Requests": "Disabled",
            "DisableExtensionList": ["1.3.6.1.4.1.311.25.2", "2.16.840.1.101.3.4.2.1"],
        }],
        "Certificate Templates": [
            {"Template Name": "WebServer", "Schema Version": 1, "Enroll": True,
             "Application Policies": ["Server Authentication"], "san_enforced": False},
            {"Template Name": "OpsIssuance", "Schema Version": 2, "Enroll": True,
             "Application Policies": ["Client Authentication"],
             "issuance_policy_group": "CN=Helpdesk-Ops,OU=Groups,DC=corp,DC=local"},
        ],
        "accounts": [
            {"account": "svc_wsus", "altSecurityIdentities": ["X509:<I>DC=corp,DC=local<SR>1a2b3c"]},
            {"account": "helpdesk", "altSecurityIdentities": ["X509:<I>DC=corp,DC=local<S>CN=helpdesk"]},
        ],
        "wsus": {"https": True},
        "update_delivered": True,
    }
    esc_out = run_bundle(esc_doc)["results"][0]
    if esc_out["verdict"] != "confirmed":
        raise ReproError("self-test", "adcs-esc expected confirmed, got %s" % esc_out["verdict"])
    want_flags = ["ESC9", "ESC10", "ESC11", "ESC13", "ESC14", "ESC15", "ESC16", "ESC17"]
    missing = [f for f in want_flags if f not in esc_out["esc_flags"]]
    if missing:
        raise ReproError("self-test", "adcs-esc missed flags %s" % ",".join(missing))
    if (esc_out["strong_cert_binding"] != 0 or esc_out["mapping_methods"] != 0x4
            or esc_out["icpr_encrypt"] is not False or esc_out["wsus_https"] is not True):
        raise ReproError("self-test", "adcs-esc normalised fields wrong: %s" % json.dumps(
            {k: esc_out[k] for k in ("strong_cert_binding", "mapping_methods",
                                     "icpr_encrypt", "wsus_https")}))
    checks += 1
    try:
        run_bundle({"kind": "adcs-esc", "note": "no CA/template/binding fields"})
    except ReproError as exc:
        if exc.blocked_at == "self-test":
            raise
        checks += 1
    else:
        raise ReproError("self-test", "adcs-esc accepted an empty document (should refuse)")
    xml = ("<Events xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<Event><System><EventID>4624</EventID><TimeCreated SystemTime='2026-01-01T00:00:00Z'/>"
           "<Computer>LAB-PC</Computer><Channel>Security</Channel><EventRecordID>7</EventRecordID></System>"
           "<EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>3</Data>"
           "<Data Name='IpAddress'>10.0.0.5</Data></EventData></Event></Events>")
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(xml)
        parsed = extract_evtx_xml(tmp, redact=True)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if parsed["event_count"] != 1 or parsed["events"][0]["target_user"] != "USER":
        raise ReproError("self-test", "evtx xml extraction failed")
    checks += 1

    # -- edge-fingerprint: 10 类全部正确分类（仓库内脱敏样例） -------------------------------------------------
    fixture = os.path.join(REPO_ROOT, "Tool", "cases", "ad-cloud01", "input",
                           "edge-fingerprint.json")
    if not os.path.isfile(fixture):
        raise ReproError("self-test", "missing edge fixture: %s" % fixture)
    with open(fixture, encoding="utf-8-sig") as fh:
        edge_doc = json.load(fh)
    edge_out = run_edge(_edge_targets_from_doc(edge_doc), offline=True)
    want_edge = {
        "cisco-asa": "high",
        "fortinet-fortigate": "high",
        "citrix-netscaler": "high",
        "paloalto-globalprotect": "high",
        "pulse-ivanti": "high",
        "sonicwall-f5": "high",
        "microsoft-owa": "med",       # 样例故意缺 X-OWA-Version：不得判 high
        "zimbra": "high",
        "okta": "high",
        "m365-entra": "high",
    }
    if len(edge_out["results"]) != len(want_edge):
        raise ReproError("self-test", "edge fixture has %d probes, want %d" % (
            len(edge_out["results"]), len(want_edge)))
    for row in edge_out["results"]:
        got = row["confidence"]
        want = want_edge.get(row["product"])
        if want is None or got != want:
            raise ReproError("self-test", "edge %r expected %r, got %r/%r" % (
                row["url"], want, row["product"], got))
        if (row["verdict"] != "candidate" or row["auth_attempted"]
                or row["credentials_sent"]):
            raise ReproError("self-test", "edge classification crossed the read-only line: %s"
                             % json.dumps(row, ensure_ascii=False)[:160])
        checks += 1

    # 错配不误判：OWA 无 X-OWA-Version/专属 cookie 时最高只能 med。
    owa_neg = eval_edge_target({"url": "https://owa.edge.invalid/owa/",
                                "product_hint": "microsoft-owa"}, [
        {"path": "/owa/auth/logon.aspx", "status": 401,
         "headers": {"X-FEServer": "MAIL01", "WWW-Authenticate": "Negotiate",
                     "Set-Cookie": ["ASP.NET_SessionId=REDACTED; path=/"]},
         "title": "Sign in", "body_excerpt": "Exchange"}])
    if owa_neg["product"] != "microsoft-owa" or owa_neg["confidence"] == "high":
        raise ReproError("self-test", "OWA without X-OWA-Version must not be high: %s"
                         % owa_neg["confidence"])
    checks += 1
    owa_pos = eval_edge_target({"url": "https://owa.edge.invalid/owa/"}, [
        {"path": "/owa/", "status": 200,
         "headers": {"X-OWA-Version": "15.2.1258.12",
                     "Set-Cookie": ["X-OWA-CANARY=REDACTED; path=/"]},
         "title": "Outlook"}])
    if owa_pos["product"] != "microsoft-owa" or owa_pos["confidence"] != "high":
        raise ReproError("self-test", "OWA with X-OWA-Version should be high")
    checks += 1
    # 错配 hint 不能凭空造产品。
    mismatch = eval_edge_target({"url": "https://asa.edge.invalid/",
                                 "product_hint": "zimbra"}, [
        {"path": "/+CSCOE+/logon.html", "status": 200,
         "headers": {"Set-Cookie": ["webvpn=REDACTED"]}, "title": "AnyConnect"}])
    if mismatch["product"] != "cisco-asa" or not mismatch["hint_mismatch"]:
        raise ReproError("self-test", "hint must not override observed fingerprint")
    checks += 1
    # 无厂商指纹时记 blocked，而不是猜服务。
    generic = eval_edge_target({"url": "https://www.edge.invalid/"}, [
        {"path": "/", "status": 200, "headers": {"Server": "nginx"}, "title": "Welcome"}])
    if generic["product"] is not None or generic["verdict"] != "blocked" \
            or generic["confidence"] != "none":
        raise ReproError("self-test", "generic page must stay blocked/none")
    checks += 1

    print(json.dumps({"ok": True, "tool": "ad-repro", "checks": checks,
                      "kinds": len(KINDS), "edge_products": len(EDGE_PRODUCTS)},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline recomputation of ad-cloud judgement rules (Kerberoast/AS-REP/ADCS/ESC9-17/delegation/K8s RBAC/Windows events/NTLM type2/edge fingerprints).",
        epilog="退出码：0 判定完成 / 2 输入错误或 blocked / 3 --strict 下有 blocked 目标")
    ap.add_argument("--input", help="JSON evidence bundle (or edge target list)")
    ap.add_argument("--kind", help="force one check kind: " + ", ".join(KINDS))
    ap.add_argument("--url", help="edge-fingerprint: probe one read-only URL (HEAD first)")
    ap.add_argument("--fixture", metavar="DIR_OR_FILE",
                    help="edge-fingerprint: replay recorded responses from a fixture")
    ap.add_argument("--strict", action="store_true",
                    help="edge-fingerprint: exit 3 when any target is blocked")
    ap.add_argument("--json", action="store_true", help="emit one JSON object (default)")
    ap.add_argument("--out", help="write JSON to this file instead of stdout")
    ap.add_argument("--extract-evtx-xml", metavar="XML",
                    help="convert a wevtutil /f:xml export to sanitized JSON")
    ap.add_argument("--no-redact", action="store_true", help="keep user/host/IP fields in XML extraction")
    ap.add_argument("--self-test", action="store_true", help="run embedded offline fixtures")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    try:
        if args.self_test:
            return _self_test()
        if args.extract_evtx_xml:
            doc = extract_evtx_xml(args.extract_evtx_xml, redact=not args.no_redact)
            text = json.dumps(doc, ensure_ascii=False, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text + "\n")
                print(json.dumps({"ok": True, "out": args.out, "events": doc["event_count"]},
                                 ensure_ascii=False))
            else:
                print(text)
            return 0
        edge_mode = (args.kind == "edge-fingerprint") or bool(args.fixture) or bool(args.url)
        if edge_mode:
            if args.kind and args.kind != "edge-fingerprint":
                raise ReproError("schema", "--url/--fixture only support --kind edge-fingerprint")
            targets = []
            if args.url:
                targets.append({"url": args.url})
            if args.input:
                if not os.path.isfile(args.input):
                    raise ReproError("read-input", "file not found: %s" % args.input)
                with open(args.input, encoding="utf-8-sig") as fh:
                    targets += _edge_targets_from_doc(json.load(fh))
            if args.fixture:
                fx = _edge_fixture_file(args.fixture)
                with open(fx, encoding="utf-8-sig") as fh:
                    targets += _edge_targets_from_doc(json.load(fh))
            out = run_edge(targets, offline=bool(args.fixture))
            out["fixture"] = args.fixture
            text = json.dumps(out, ensure_ascii=False, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text + "\n")
                print(json.dumps({"ok": True, "out": args.out, "kind": out["kind"],
                                  "summary": out["summary"]}, ensure_ascii=False))
            else:
                print(text)
            if args.strict and any(r["verdict"] == "blocked" for r in out["results"]):
                return 3
            return 0
        if not args.input:
            raise ReproError("input", "provide --input, --url, --fixture, --extract-evtx-xml or --self-test")
        if not os.path.isfile(args.input):
            raise ReproError("read-input", "file not found: %s" % args.input)
        with open(args.input, encoding="utf-8-sig") as fh:
            bundle = json.load(fh)
        out = run_bundle(bundle, force_kind=args.kind)
        text = json.dumps(out, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
            print(json.dumps({"ok": True, "out": args.out,
                              "verdicts": out["summary"]}, ensure_ascii=False))
        else:
            print(text)
        return 0
    except ReproError as exc:
        err = {"ok": False, "blocked_at": exc.blocked_at, "reason": exc.reason}
        if args.kind:
            err["kind"] = args.kind
        print(json.dumps(err, ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001
        err = {"ok": False, "blocked_at": "internal",
               "reason": "%s: %s" % (type(exc).__name__, exc)}
        if args.kind:
            err["kind"] = args.kind
        print(json.dumps(err, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
