"""Local shared dispatch coordination. No credentials, project ledger or network IO.

Grants record an existing task scope; they are not proof of user authorization.
Only adapters calling reserve/begin/finish are covered. An expired lease never
proves that the old target or an in-flight request has stopped.
"""
from __future__ import annotations

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import parse_qsl, urlsplit

SCHEMA = "seep.runtime-risk/1"
_REF = re.compile(r"[A-Za-z\u3400-\u9fff][A-Za-z0-9_.:/\-\u3400-\u9fff]{0,95}\Z")
_EVENTS = {"none", "rate_limited", "account_restricted", "device_binding", "environment_rejected", "challenge", "access_rejected", "server_error", "outcome_unknown", "evidence_failed_after_dispatch"}
_SENSITIVE = re.compile(r"(?:^|[/_-])(login|signin|auth|activate|activation|license|refresh|bind|otp|sms|pay|payment)(?:$|[/_.?-])", re.I)


class RiskError(ValueError):
    """Stable error codes only: callers must not echo input or exception payloads."""


def origin(url: str) -> str:
    try:
        p = urlsplit(url)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname:
            raise ValueError()
        host = p.hostname.encode("idna").decode("ascii").lower()
        if ":" in host:
            host = "[" + host + "]"
        port = p.port if p.port is not None else (443 if p.scheme.lower() == "https" else 80)
        return "%s://%s:%d" % (p.scheme.lower(), host, port)
    except (ValueError, UnicodeError, AttributeError):
        raise RiskError("invalid_origin") from None


def reference(value: str) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value):
        raise RiskError("invalid_opaque_reference")
    return value


def needs_grant(url, method, headers, cookies, body) -> bool:
    p = urlsplit(url)
    # Caller labels cannot downgrade these observable effects. Unknown GET
    # business semantics remain a declared coverage limit, not a safety claim.
    return bool(method.upper() not in {"GET", "HEAD", "OPTIONS"} or body or cookies
                or p.username or any(re.search(r"auth|cookie|key|token|secret|password|session|ticket|nonce|license|card|activation|csrf|xsrf|otp|mfa|卡密|密码|验证码|^code$", k, re.I)
                                     for k, _ in parse_qsl(p.query)) or _SENSITIVE.search(p.path)
                or any(re.search(r"authorization|cookie|key|token|secret|license|card|session|csrf|xsrf|otp|mfa|method[-_]override", k, re.I) for k in headers))


def retry_deadline(value, now=None):
    now = time.time() if now is None else now
    try:
        if re.fullmatch(r"\d{1,9}", str(value)):
            return now + int(value)
        d = parsedate_to_datetime(str(value))
        if d.tzinfo is None:
            raise ValueError()
        return max(now, d.timestamp())
    except (ValueError, TypeError, OverflowError):
        return None


class RiskStore:
    def __init__(self, root=None):
        self.root = Path(root or os.environ.get("SEEP_RISK_ROOT") or Path.home() / ".seep" / "runtime-risk").expanduser().absolute()
        if self.root.is_symlink():
            raise RiskError("state_root_link")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("state.sqlite3", "identity.key"):
            if (self.root / name).is_symlink():
                raise RiskError("state_file_link")
        keyfile = self.root / "identity.key"
        try:
            with self.tx() as db:
                # The database transaction also serializes first-time key
                # publication; another process must never read a partial key.
                existing_key = keyfile.exists()
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in {0, 1}:
                    raise RiskError("state_version_unsupported")
                if version == 1 and not existing_key:
                    raise RiskError("state_key_missing_existing_database")
                if version == 0 and (existing_key or db.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone()):
                    raise RiskError("state_database_missing_metadata")
                if not existing_key:
                    fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(secrets.token_bytes(32))
                self.key = keyfile.read_bytes()
                if len(self.key) != 32:
                    raise RiskError("state_key_invalid")
                db.execute("CREATE TABLE IF NOT EXISTS subjects (id TEXT PRIMARY KEY, reason TEXT NOT NULL, epoch INTEGER NOT NULL, since REAL NOT NULL, retry_at REAL)")
                db.execute("CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, origin TEXT NOT NULL, subject TEXT NOT NULL, capacity INTEGER NOT NULL, used INTEGER NOT NULL, expires REAL NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, origin TEXT NOT NULL, subjects TEXT NOT NULL, epochs TEXT NOT NULL, fingerprint TEXT NOT NULL, phase TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL)")
                db.execute("CREATE INDEX IF NOT EXISTS operation_phase ON operations(phase)")
                db.execute("CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, key_id TEXT NOT NULL, last_wall REAL NOT NULL)")
                key_id = hashlib.sha256(self.key).hexdigest()
                meta = db.execute("SELECT * FROM metadata WHERE id=1").fetchone()
                if version == 1 and meta is None:
                    raise RiskError("state_database_missing_metadata")
                if meta and (meta["key_id"] != key_id or meta["last_wall"] > time.time() + 5):
                    raise RiskError("state_identity_or_clock_mismatch")
                db.execute("INSERT OR REPLACE INTO metadata VALUES (1,?,?)", (key_id, time.time()))
                db.execute("PRAGMA user_version=1")
            os.chmod(self.root / "state.sqlite3", 0o600)
        except (sqlite3.Error, OSError):
            raise RiskError("state_unavailable") from None

    @contextmanager
    def tx(self):
        db = None
        try:
            db = sqlite3.connect(self.root / "state.sqlite3", timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone():
                meta = db.execute("SELECT last_wall FROM metadata WHERE id=1").fetchone()
                if meta and meta[0] > time.time() + 5:
                    raise RiskError("clock_moved_backwards")
                db.execute("UPDATE metadata SET last_wall=? WHERE id=1", (time.time(),))
            yield db
            db.commit()
        except sqlite3.Error:
            if db is not None:
                db.rollback()
            raise RiskError("state_unavailable") from None
        except BaseException:
            if db is not None:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def digest(self, value):
        return hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def subjects(self, url, subject_ref=""):
        values = [self.digest("origin:" + origin(url))]
        if subject_ref:
            values.append(self.digest("subject:" + reference(subject_ref)))
        return values

    def _states(self, db, subjects):
        rows = []
        for sid in subjects:
            db.execute("INSERT OR IGNORE INTO subjects VALUES (?, '', 0, ?, NULL)", (sid, time.time()))
            rows.append(db.execute("SELECT * FROM subjects WHERE id=?", (sid,)).fetchone())
        return rows

    def _ready(self, db, subjects):
        rows = self._states(db, subjects)
        if any(r["reason"] for r in rows):
            raise RiskError("subject_paused")
        for op in db.execute("SELECT subjects FROM operations WHERE phase IN ('reserved','dispatching','outcome_unknown')"):
            if set(subjects) & set(json.loads(op["subjects"])):
                raise RiskError("subject_has_unresolved_operation")
        return rows

    def grant(self, url, subject_ref, max_attempts=1, lifetime_seconds=900):
        reference(subject_ref)
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10000:
            raise RiskError("invalid_attempt_limit")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 86400:
            raise RiskError("invalid_scope_lifetime")
        sid = self.subjects(url, subject_ref)[1]
        gid = "scope-" + secrets.token_hex(16)
        with self.tx() as db:
            self._ready(db, self.subjects(url, subject_ref))
            existing = db.execute("SELECT id,capacity,used FROM grants WHERE origin=? AND subject=?",
                                  (origin(url), sid)).fetchone()
            if existing:
                return {"ok": True, "scope_id": existing["id"], "max_attempts": existing["capacity"],
                        "used": existing["used"], "reused_existing": True,
                        "scope_basis": "existing_scope_not_renewed_or_reset"}
            db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, 0, ?)",
                       (gid, origin(url), sid, max_attempts, time.time() + lifetime_seconds))
        return {"ok": True, "scope_id": gid, "max_attempts": max_attempts,
                "scope_basis": "caller_declared_existing_task_scope_not_authorization_proof"}

    def extend(self, url, subject_ref, scope_id, additional_attempts, lifetime_seconds, evidence_ref):
        reference(evidence_ref)
        if type(additional_attempts) is not int or not 1 <= additional_attempts <= 10000:
            raise RiskError("invalid_attempt_limit")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 86400:
            raise RiskError("invalid_scope_lifetime")
        subjects = self.subjects(url, subject_ref)
        with self.tx() as db:
            self._ready(db, subjects)
            grant = db.execute("SELECT * FROM grants WHERE id=?", (reference(scope_id),)).fetchone()
            if not grant or len(subjects) != 2 or grant["origin"] != origin(url) or grant["subject"] != subjects[1]:
                raise RiskError("scope_binding_mismatch")
            if grant["capacity"] + additional_attempts > 10000:
                raise RiskError("invalid_attempt_limit")
            db.execute("UPDATE grants SET capacity=capacity+?,expires=? WHERE id=?",
                       (additional_attempts, time.time() + lifetime_seconds, scope_id))
        return {"ok": True, "scope_id": scope_id, "budget_reset": False,
                "additional_attempts": additional_attempts, "basis": "caller_declared_new_scope_decision"}

    def reserve(self, url, fingerprint, scope_id="", subject_ref="", required=False):
        subjects = self.subjects(url, subject_ref)
        if required and (not scope_id or not subject_ref):
            raise RiskError("explicit_scope_and_subject_required")
        oid = "op-" + secrets.token_hex(16)
        with self.tx() as db:
            states = self._ready(db, subjects)
            if scope_id:
                grant = db.execute("SELECT * FROM grants WHERE id=?", (reference(scope_id),)).fetchone()
                if not grant or grant["origin"] != origin(url) or not subject_ref or grant["subject"] != subjects[1]:
                    raise RiskError("scope_binding_mismatch")
                if grant["expires"] <= time.time():
                    raise RiskError("scope_expired")
                if grant["used"] >= grant["capacity"]:
                    raise RiskError("scope_exhausted")
                db.execute("UPDATE grants SET used=used+1 WHERE id=?", (scope_id,))
            db.execute("INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?)",
                       (oid, scope_id, origin(url), json.dumps(subjects), json.dumps([r["epoch"] for r in states]),
                        fingerprint, time.time(), time.time()))
        return oid

    def begin(self, operation_id, fingerprint):
        with self.tx() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (reference(operation_id),)).fetchone()
            if not op or op["phase"] != "reserved" or not hmac.compare_digest(op["fingerprint"], fingerprint):
                raise RiskError("operation_binding_mismatch")
            states = self._states(db, json.loads(op["subjects"]))
            if any(r["reason"] for r in states) or [r["epoch"] for r in states] != json.loads(op["epochs"]):
                raise RiskError("operation_paused_or_stale")
            if op["grant_id"]:
                g = db.execute("SELECT expires FROM grants WHERE id=?", (op["grant_id"],)).fetchone()
                if not g or g["expires"] <= time.time():
                    raise RiskError("scope_expired")
            db.execute("UPDATE operations SET phase='dispatching', updated=? WHERE id=?", (time.time(), operation_id))

    def finish(self, operation_id, event="none", retry_at=None):
        if event not in _EVENTS:
            raise RiskError("invalid_event")
        with self.tx() as db:
            op = db.execute("SELECT * FROM operations WHERE id=?", (reference(operation_id),)).fetchone()
            if not op or op["phase"] != "dispatching":
                raise RiskError("invalid_operation_phase")
            phase = "outcome_unknown" if event == "outcome_unknown" else "completed"
            db.execute("UPDATE operations SET phase=?, updated=? WHERE id=?", (phase, time.time(), operation_id))
            if event != "none":
                self._pause(db, json.loads(op["subjects"]), event, retry_at)
            states = self._states(db, json.loads(op["subjects"]))
            return {"paused": any(r["reason"] for r in states),
                    "reasons": sorted(set(r["reason"] for r in states if r["reason"]))}

    def _pause(self, db, subjects, reason, retry_at=None):
        self._states(db, subjects)
        for sid in subjects:
            db.execute("UPDATE subjects SET reason=?, epoch=epoch+1, since=?, retry_at=? WHERE id=?",
                       (reason, time.time(), retry_at, sid))

    def status(self, url, subject_ref="", scope_id=""):
        with self.tx() as db:
            rows = self._states(db, self.subjects(url, subject_ref))
            grant = db.execute("SELECT * FROM grants WHERE id=?", (reference(scope_id),)).fetchone() if scope_id else None
            if scope_id and not grant:
                raise RiskError("scope_binding_mismatch")
            if grant and (grant["origin"] != origin(url) or not subject_ref or grant["subject"] != self.subjects(url, subject_ref)[1]):
                raise RiskError("scope_binding_mismatch")
            unresolved = [dict(id=op["id"], phase=op["phase"], created=op["created"])
                          for op in db.execute("SELECT * FROM operations WHERE phase IN ('reserved','dispatching','outcome_unknown')")
                          if set(self.subjects(url, subject_ref)) & set(json.loads(op["subjects"]))]
            return {"ok": True, "paused": any(r["reason"] for r in rows),
                    "reasons": sorted(set(r["reason"] for r in rows if r["reason"])),
                    "retry_not_before": max((r["retry_at"] or 0 for r in rows), default=0) or None,
                    "unresolved_operations": len(unresolved), "operations": unresolved[:20],
                    "scope": {k: grant[k] for k in ("capacity", "used", "expires")} if grant else None,
                    "coverage": "cooperating_adapters_single_host"}

    def pause(self, url, subject_ref="", event="environment_rejected"):
        if event not in _EVENTS - {"none"}:
            raise RiskError("invalid_event")
        with self.tx() as db:
            self._pause(db, self.subjects(url, subject_ref), event)
        return {"ok": True, "paused": True, "offline_work_allowed": True}

    def resolve(self, operation_id, evidence_ref):
        reference(evidence_ref)
        with self.tx() as db:
            op = db.execute("SELECT phase FROM operations WHERE id=?", (reference(operation_id),)).fetchone()
            if not op or op["phase"] not in {"reserved", "dispatching", "outcome_unknown"}:
                raise RiskError("operation_not_unresolved")
            # Explicit reconciliation consumes the reservation. Never refund a
            # request because a model, a timeout or an expired lease said so.
            db.execute("UPDATE operations SET phase='reconciled', updated=? WHERE id=?", (time.time(), operation_id))
        return {"ok": True, "reconciled": True, "budget_refunded": False}

    def resume(self, url, subject_ref, evidence_ref):
        reference(evidence_ref)
        subjects = self.subjects(url, subject_ref)
        with self.tx() as db:
            rows = self._states(db, subjects)
            if any(r["retry_at"] and r["retry_at"] > time.time() for r in rows):
                raise RiskError("cooldown_not_elapsed")
            if any(r["since"] > time.time() + 5 for r in rows):
                raise RiskError("clock_moved_backwards")
            for op in db.execute("SELECT subjects FROM operations WHERE phase IN ('reserved','dispatching','outcome_unknown')"):
                if set(subjects) & set(json.loads(op["subjects"])):
                    raise RiskError("subject_has_unresolved_operation")
            for sid in subjects:
                db.execute("UPDATE subjects SET reason='',epoch=epoch+1,retry_at=NULL WHERE id=?", (sid,))
        return {"ok": True, "paused": False, "budget_reset": False}


def state_action(action="status", url="", subject_ref="", scope_id="", max_attempts=1,
                 lifetime_seconds=900, operation_id="", evidence_ref=""):
    if action not in {"status", "grant", "extend", "pause", "resume", "resolve"}:
        raise RiskError("invalid_state_action")
    if action != "resolve":
        origin(url)
    store = RiskStore()
    if action == "status":
        return store.status(url, subject_ref, scope_id)
    if action == "grant":
        return store.grant(url, subject_ref, max_attempts, lifetime_seconds)
    if action == "extend":
        return store.extend(url, subject_ref, scope_id, max_attempts, lifetime_seconds, evidence_ref)
    if action == "pause":
        return store.pause(url, subject_ref)
    if action == "resume":
        return store.resume(url, subject_ref, evidence_ref)
    if action == "resolve":
        return store.resolve(operation_id, evidence_ref)
    raise RiskError("invalid_state_action")
