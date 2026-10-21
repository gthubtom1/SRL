#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cloud-iam-eval.py — offline AWS-style IAM policy evaluator for ad-cloud.

It answers one narrow question: for a given identity policy set, action and
resource, does the JSON policy *as written* allow, deny, or remain unknown?
No network, no SigV4, no credential use.  Conditions that cannot be evaluated
from the supplied context are reported as "unknown", never guessed.

Examples:
  python cloud-iam-eval.py --input policy.json --action s3:GetObject \
      --resource arn:aws:s3:::demo/a.txt
  python cloud-iam-eval.py --input policy.json --action iam:CreatePolicyVersion \
      --resource arn:aws:iam::123456789012:policy/demo
  python cloud-iam-eval.py --self-test

Exit codes:
  0  decision computed
  2  malformed input / unsupported policy shape
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

VERSION = "1.0.0"
DANGEROUS = {
    "iam:createpolicyversion": ("critical", "rewrite a managed policy to grant full admin"),
    "iam:setdefaultpolicyversion": ("high", "activate an older permissive policy version"),
    "iam:attachuserpolicy": ("high", "attach an admin policy to a controlled user"),
    "iam:putuserpolicy": ("high", "inline an admin policy on a controlled user"),
    "iam:createaccesskey": ("high", "create long-lived keys for another identity"),
    "iam:updaterolepolicy": ("high", "rewrite a role trust policy"),
    "iam:updateassumerolepolicy": ("critical", "let an attacker-controlled principal assume a role"),
    "iam:passrole": ("high", "pass a privileged role into a compute service"),
    "sts:assumerole": ("medium", "pivot into another role/account"),
    "lambda:createfunction": ("high", "execute with a passed role"),
    "ec2:runinstances": ("high", "execute with a passed instance profile"),
    "s3:getobject": ("high", "read objects if the resource is broad"),
    "s3:listbucket": ("medium", "enumerate objects across buckets"),
    "secretsmanager:getsecretvalue": ("high", "read stored credentials"),
    "ssm:getparameter": ("high", "read parameters that often hold credentials"),
    "kms:decrypt": ("medium", "decrypt data with a reachable key"),
}


class EvalError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _match(pattern, value, insensitive=True):
    pattern = str(pattern)
    value = str(value)
    if insensitive:
        pattern, value = pattern.lower(), value.lower()
    # IAM wildcards are glob-like; fnmatch handles * and ?.
    return fnmatch.fnmatchcase(value, pattern)


def _action_match(statement, action):
    actions = [str(x) for x in _as_list(statement.get("Action"))]
    not_actions = [str(x) for x in _as_list(statement.get("NotAction"))]
    if actions:
        return any(_match(a, action) for a in actions)
    if not_actions:
        return not any(_match(a, action) for a in not_actions)
    return False


def _resource_match(statement, resource):
    resources = [str(x) for x in _as_list(statement.get("Resource"))]
    not_resources = [str(x) for x in _as_list(statement.get("NotResource"))]
    if resources:
        return any(_match(r, resource) for r in resources)
    if not_resources:
        return not any(_match(r, resource) for r in not_resources)
    return False


def _condition_eval(condition, context):
    """Return True/False/None (unknown). Supports equality-like operators only."""
    if not condition:
        return True
    if not isinstance(condition, dict):
        return None
    unknown = False
    for operator, pairs in condition.items():
        if not isinstance(pairs, dict):
            return None
        op = operator.lower()
        if op not in ("stringequals", "stringlike", "arnequals", "arnlike",
                      "bool", "stringequalsignorecase"):
            unknown = True
            continue
        for key, expected in pairs.items():
            if key not in context:
                unknown = True
                continue
            actual = context.get(key)
            exp_values = [str(x) for x in _as_list(expected)]
            if op in ("stringequals", "arnequals", "stringequalsignorecase"):
                ok = any(str(actual).lower() == e.lower() for e in exp_values)
            elif op in ("stringlike", "arnlike"):
                ok = any(_match(e, actual) for e in exp_values)
            else:  # bool
                ok = any(str(actual).lower() == e.lower() for e in exp_values)
            if not ok:
                return False
    return None if unknown else True


def _document_statements(document, label):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except Exception as exc:  # noqa: BLE001
            raise EvalError("parse-policy", "%s is not valid JSON: %s" % (label, exc))
    if not isinstance(document, dict):
        raise EvalError("parse-policy", "%s must be an object" % label)
    statements = document.get("Statement")
    if statements is None:
        raise EvalError("parse-policy", "%s has no Statement" % label)
    return _as_list(statements)


def evaluate(bundle, action, resource):
    policies = bundle.get("policies") or []
    if not policies:
        raise EvalError("schema", "input needs a non-empty policies list")
    context = bundle.get("conditions_context") or {}
    decision = "deny"
    matched, unknown_conditions, denies = [], [], []
    for p in policies:
        if not isinstance(p, dict):
            continue
        for st in _document_statements(p.get("document"), p.get("name") or "policy"):
            if not isinstance(st, dict):
                continue
            if not (_action_match(st, action) and _resource_match(st, resource)):
                continue
            cond = _condition_eval(st.get("Condition"), context)
            effect = str(st.get("Effect") or "").lower()
            entry = {
                "policy": p.get("name") or "",
                "effect": effect,
                "condition": "true" if cond is True else ("false" if cond is False else "unknown"),
            }
            matched.append(entry)
            if effect == "deny" and cond is not False:
                denies.append(entry)
            if effect == "allow" and cond is True:
                decision = "allow"
            if cond is None:
                unknown_conditions.append(entry)
    if denies:
        decision = "deny"
    elif unknown_conditions and decision != "allow":
        decision = "unknown"

    # Boundary / SCP are allow-lists: if present and no Allow, the result is deny.
    boundary = bundle.get("boundary")
    if boundary:
        b_allow = False
        b_unknown = False
        for st in _document_statements(boundary, "boundary"):
            if not isinstance(st, dict) or str(st.get("Effect") or "").lower() != "allow":
                continue
            if _action_match(st, action) and _resource_match(st, resource):
                cond = _condition_eval(st.get("Condition"), context)
                b_allow = b_allow or cond is True
                b_unknown = b_unknown or cond is None
        if not b_allow:
            decision = "unknown" if b_unknown else "deny"
    for scp in _as_list(bundle.get("scps")):
        allow = False
        for st in _document_statements(scp, "scp"):
            if not isinstance(st, dict) or str(st.get("Effect") or "").lower() != "allow":
                continue
            if _action_match(st, action) and _resource_match(st, resource):
                allow = True
        if not allow:
            decision = "deny"
            break

    privesc = []
    seen = set()
    for p in policies:
        if not isinstance(p, dict):
            continue
        for st in _document_statements(p.get("document"), p.get("name") or "policy"):
            if not isinstance(st, dict) or str(st.get("Effect") or "").lower() != "allow":
                continue
            acts = [str(x).lower() for x in _as_list(st.get("Action"))]
            resources = [str(x) for x in _as_list(st.get("Resource"))]
            broad = any(r in ("*", "arn:aws:*:*:*:*") for r in resources)
            for act in acts:
                base = act.split("*")[0]
                for name, (sev, why) in DANGEROUS.items():
                    if _match(act, name) or (act.endswith("*") and name.startswith(base)):
                        key = name + ":" + ("broad" if broad else "scoped")
                        if key in seen:
                            continue
                        seen.add(key)
                        privesc.append({"action": name, "severity": sev, "why": why,
                                        "resource_broad": broad,
                                        "policy": p.get("name") or ""})
    return {
        "tool": "cloud-iam-eval",
        "version": VERSION,
        "ok": True,
        "offline": True,
        "identity": bundle.get("identity") or "",
        "action": action,
        "resource": resource,
        "decision": decision,
        "matched": matched,
        "unknown_conditions": unknown_conditions,
        "deny_statements": denies,
        "privesc": privesc,
        "limits": [
            "Conditions other than StringEquals/StringLike/ArnEquals/ArnLike/Bool are not evaluated.",
            "Permissions boundaries and SCPs are treated as allow-lists; resource policies and session policies are not modelled.",
            "A written Allow is not proof that the credential is live; call sts get-caller-identity online.",
        ],
    }


def _self_test():
    checks = 0
    admin = {"policies": [{"name": "admin", "document": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]}
    out = evaluate(admin, "iam:CreatePolicyVersion", "arn:aws:iam::123456789012:policy/demo")
    assert out["decision"] == "allow", out
    assert any(x["action"] == "iam:createpolicyversion" for x in out["privesc"]), out
    checks += 1

    scoped = {"policies": [{"name": "read", "document": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::demo/*"}]}}]}
    out = evaluate(scoped, "s3:GetObject", "arn:aws:s3:::demo/a.txt")
    assert out["decision"] == "allow", out
    out = evaluate(scoped, "s3:GetObject", "arn:aws:s3:::other/a.txt")
    assert out["decision"] == "deny", out
    checks += 1

    guarded = {"policies": [{"name": "admin", "document": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}],
        "boundary": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}
    out = evaluate(guarded, "iam:CreatePolicyVersion", "arn:aws:iam::123456789012:policy/demo")
    assert out["decision"] == "deny", out
    checks += 1

    conditional = {"policies": [{"name": "cond", "document": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*",
                       "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::1:role/x"}}}]}}]}
    out = evaluate(conditional, "sts:AssumeRole", "arn:aws:iam::1:role/y")
    assert out["decision"] == "unknown", out
    checks += 1

    print(json.dumps({"ok": True, "tool": "cloud-iam-eval", "checks": checks},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline AWS-style IAM policy evaluator. No network, no credential use.")
    ap.add_argument("--input", help="JSON bundle: {identity,policies,boundary,scps,conditions_context}")
    ap.add_argument("--action", help="action to test, e.g. s3:GetObject")
    ap.add_argument("--resource", help="resource ARN to test")
    ap.add_argument("--json", action="store_true", help="emit one JSON object (default)")
    ap.add_argument("--self-test", action="store_true", help="run embedded offline fixtures")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)
    try:
        if args.self_test:
            return _self_test()
        if not args.input or not args.action or not args.resource:
            raise EvalError("input", "provide --input, --action and --resource")
        if not os.path.isfile(args.input):
            raise EvalError("read-input", "file not found: %s" % args.input)
        with open(args.input, encoding="utf-8-sig") as fh:
            bundle = json.load(fh)
        print(json.dumps(evaluate(bundle, args.action, args.resource),
                         ensure_ascii=False, indent=2))
        return 0
    except EvalError as exc:
        print(json.dumps({"ok": False, "blocked_at": exc.blocked_at,
                          "reason": exc.reason}, ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "internal",
                          "reason": "%s: %s" % (type(exc).__name__, exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
