#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""osint-secret-scan.py —— 本地代码/配置里的密钥与内部信息扫描（只读，OSINT 资产面）。

回答一个问题：**这份 JS / JSON / YAML / 源码里有没有能直接开门的凭据，或值得
继续追的内部资产线索？** 输出只登记「类型 + 位置 + 脱敏片段」，不复制明文。

输入（二选一）：
  --path <文件或目录>    本地静态文本（只读；不修改、不上传、不执行）
  --url  <单个 JS 地址>  远程单文件；必须显式加 --allow-remote（默认拒绝）

模式库 60+ 条：AWS AK/SK、GCP service account、Azure 连接串、GitHub/Slack/
Stripe/Telegram/Firebase/Supabase token、JWT、私钥块、内网 IP、内部域名、
数据库 URL、SMTP 凭据、webhook URL、包仓库 token、AI API key 等。

脱敏（默认）：命中片段只留前 4 + 后 4 字符，中间用 * 代替；确需核对时用
`--show-full`，此时会在 stderr 打印「不要贴到群里」的提醒。

输出 JSON：
  {"ok":bool,"hits":[{pattern,severity,category,file,line,match,masked,length}],
   "counts":{"critical":n,"high":n,"medium":n,"low":n,"total":n,
             "files_scanned":n,"files_skipped":n},
   "blocked_at":null|"..."}

用法:
    python Tool/scripts/osint-secret-scan.py --path <OUT> --json
    python Tool/scripts/osint-secret-scan.py --path work/<case>/js --json --out work/<case>/secrets.json
    python Tool/scripts/osint-secret-scan.py --path main.js --show-full
    python Tool/scripts/osint-secret-scan.py --url https://<host>/app.js --allow-remote --json
    python Tool/scripts/osint-secret-scan.py --self-test

退出码：0 扫描完成且无命中 / 1 有命中（需要人看）/ 2 参数或输入错误。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.osint-secret-scan/1"
SEVERITY_ORDER = ("critical", "high", "medium", "low")
DEFAULT_MAX_FILE_MB = 10.0
DEFAULT_MAX_HITS = 500
DEFAULT_TIMEOUT = 10

# 目录扫描跳过：依赖树与构建产物既慢又基本是第三方代码，扫了等于噪音。
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", "out", "coverage", ".cache", ".next", ".nuxt",
             ".idea", ".vscode", "vendor", "bower_components", ".terraform"}
TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".json", ".json5", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".config", ".properties", ".env", ".xml", ".plist", ".gradle",
    ".java", ".kt", ".scala", ".py", ".rb", ".php", ".go", ".rs", ".cs",
    ".swift", ".m", ".ps1", ".sh", ".bash", ".zsh", ".bat", ".sql", ".pem",
    ".key", ".crt", ".tf", ".tfvars", ".lock", ".md", ".txt", ".html", ".htm",
}

# 顺序有意义：先把具体厂商模式排在前面，泛化模式（generic）只做兜底。
# 每条：(name, severity, category, regex)；一行一条，避免跨行误吞。
PATTERNS = [
    # ---------- AWS ----------
    ("AWS_ACCESS_KEY_ID", "critical", "aws",
     r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_ACCESS_KEY", "critical", "aws",
     r"(?i)aws[_\- ]{0,2}(?:secret|sk)[_\- ]{0,2}(?:access[_\- ]{0,2})?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE", "high", "aws",
     r"(?i)(?:secret_access_key|aws_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ("AWS_SESSION_TOKEN", "medium", "aws",
     r"(?i)aws[_\- ]{0,2}session[_\- ]{0,2}token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{60,})"),
    # ---------- GCP ----------
    ("GCP_SERVICE_ACCOUNT", "critical", "gcp", r'"type"\s*:\s*"service_account"'),
    ("GCP_PRIVATE_KEY_ID", "high", "gcp", r'"private_key_id"\s*:\s*"[0-9a-f]{40}"'),
    ("GOOGLE_API_KEY", "high", "gcp", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GCP_OAUTH_CLIENT_SECRET", "high", "gcp",
     r'"client_secret"\s*:\s*"GOCSPX-[A-Za-z0-9_\-]{20,}"'),
    # ---------- Azure ----------
    ("AZURE_STORAGE_CONNECTION_STRING", "critical", "azure",
     r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("AZURE_SQL_CONNECTION_STRING", "high", "azure",
     r"(?i)Server=tcp:[^;\s]+;.{0,120}?(?:Password|Pwd)=[^;\s]+"),
    ("AZURE_CLIENT_SECRET", "high", "azure",
     r"(?i)azure[_\- ]{0,2}(?:client|app)[_\- ]{0,2}secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~._\-]{34,44})"),
    ("AZURE_SAS_TOKEN", "medium", "azure",
     r"\?sv=\d{4}-\d{2}-\d{2}&(?:[a-z]+=[^&\s]*&){1,}sig=[A-Za-z0-9%+/=]{16,}"),
    # ---------- GitHub ----------
    ("GITHUB_PAT_CLASSIC", "critical", "github", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GITHUB_PAT_FINEGRAINED", "critical", "github", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("GITHUB_OAUTH_TOKEN", "high", "github", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GITHUB_APP_TOKEN", "high", "github", r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),
    ("GITHUB_WEBHOOK_SECRET", "medium", "github",
     r"(?i)github[_\- ]{0,2}webhook[_\- ]{0,2}secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"),
    # ---------- Slack ----------
    ("SLACK_TOKEN", "high", "slack", r"\bxox[abposr]-[A-Za-z0-9\-]{10,60}\b"),
    ("SLACK_WEBHOOK_URL", "medium", "webhook",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}"),
    # ---------- Stripe ----------
    ("STRIPE_LIVE_KEY", "critical", "stripe", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("STRIPE_TEST_KEY", "low", "stripe", r"\b[sr]k_test_[0-9A-Za-z]{20,}\b"),
    ("STRIPE_WEBHOOK_SECRET", "medium", "webhook", r"\bwhsec_[0-9A-Za-z]{20,}\b"),
    # ---------- Telegram ----------
    ("TELEGRAM_BOT_TOKEN", "high", "telegram", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
    # ---------- Firebase / Supabase ----------
    ("FIREBASE_DB_URL", "low", "firebase",
     r"\bhttps?://[a-z0-9][a-z0-9\-]{1,40}\.firebaseio\.com\b"),
    ("FIREBASE_SERVER_KEY", "high", "firebase",
     r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}\b"),
    ("SUPABASE_SECRET_KEY", "high", "supabase", r"\bsb_secret_[A-Za-z0-9_\-]{20,}\b"),
    ("SUPABASE_ANON_JWT", "low", "supabase",
     r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("SUPABASE_KEY_LOOSE", "high", "supabase",
     r"(?i)supabase[_\- ]{0,2}(?:service[_\- ]{0,2}role|secret|anon)[_\- ]{0,2}key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{40,})"),
    # ---------- JWT / 认证 ----------
    ("JWT", "medium", "jwt",
     r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("BEARER_AUTH_HEADER", "medium", "jwt",
     r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL", "medium", "credentials",
     r"\b[a-z][a-z0-9+.\-]{1,10}://[^/\s:@'\"]{2,}:[^/\s:@'\"]{3,}@[^/\s'\"]+"),
    # ---------- 私钥 / 证书 ----------
    ("RSA_PRIVATE_KEY", "critical", "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVATE_KEY", "critical", "private_key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVATE_KEY", "critical", "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("PGP_PRIVATE_KEY", "critical", "private_key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("GENERIC_PRIVATE_KEY", "critical", "private_key",
     r"-----BEGIN (?:DSA |ENCRYPTED |)PRIVATE KEY-----"),
    ("PUBLIC_CERT_PEM", "low", "certificate", r"-----BEGIN CERTIFICATE-----"),
    # ---------- 内网 IP / 内部域名 ----------
    ("INTERNAL_IPV4", "medium", "internal_network",
     r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    ("LINK_LOCAL_ADDRESS", "low", "internal_network",
     r"\b(?:169\.254\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b"),
    ("INTERNAL_DOMAIN", "medium", "internal_domain",
     r"(?i)\b[a-z0-9][a-z0-9\-]{0,62}\.(?:internal|intranet|corp|local|lan|svc|home\.arpa)\b"),
    ("K8S_CLUSTER_HOST", "medium", "internal_domain",
     r"(?i)\b[a-z0-9][a-z0-9\-]{0,62}\.svc\.cluster\.local\b"),
    ("INTERNAL_HOSTNAME", "low", "internal_domain",
     r"(?i)\b(?:jenkins|gitlab|jira|confluence|nexus|sonar|grafana|kibana|vault|consul|minio|harbor)\.[a-z0-9\-]+\.[a-z]{2,6}\b"),
    # ---------- 数据库 URL ----------
    ("DATABASE_URL", "high", "database_url",
     r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|clickhouse|couchdb|elasticsearch)://[^/\s:@'\"]{1,64}:[^/\s:@'\"]{3,}@[^/\s'\"]+"),
    ("JDBC_CREDENTIALS", "high", "database_url",
     r"(?i)jdbc:[a-z]+://[^\s'\"]{0,200}?(?:user|password)=[^&\s'\"]+"),
    ("MONGO_ATLAS_URI", "high", "database_url",
     r"\bmongodb\+srv://[^/\s:@'\"]+:[^/\s:@'\"]+@[a-z0-9.\-]+\.mongodb\.net\b"),
    # ---------- SMTP / 邮件 ----------
    ("SMTP_CREDENTIAL", "high", "smtp",
     r"(?i)smtp[_\- ]{0,2}(?:user(?:name)?|pass(?:word)?|login)['\"]?\s*[:=]\s*['\"]?([^\"'\s,;]{3,})"),
    ("SMTP_URL", "medium", "smtp",
     r"(?i)\bsmtps?://[^/\s:@'\"]+:[^/\s:@'\"]{3,}@[^/\s'\"]+"),
    ("SENDGRID_API_KEY", "high", "smtp", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_API_KEY", "high", "smtp", r"\bkey-[0-9a-f]{32}\b"),
    # ---------- Webhook ----------
    ("GENERIC_WEBHOOK_URL", "medium", "webhook",
     r"(?i)https://(?:discord(?:app)?\.com/api/webhooks|outlook\.office\.com/webhook|api\.telegram\.org/bot|hooks\.zapier\.com|webhook\.site)[^\s'\"]{8,}"),
    ("TEAMS_WEBHOOK_URL", "low", "webhook",
     r"https://[a-z0-9\-]+\.webhook\.office\.com/[^\s'\"]+"),
    # ---------- 包仓库 / CI ----------
    ("NPM_TOKEN", "high", "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN", "high", "package_registry",
     r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b"),
    ("DOCKER_HUB_PAT", "high", "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b"),
    # ---------- AI API ----------
    ("OPENAI_API_KEY", "critical", "ai_api",
     r"\b(?:sk-proj-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"),
    ("ANTHROPIC_API_KEY", "critical", "ai_api", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ("HUGGINGFACE_TOKEN", "high", "ai_api", r"\bhf_[A-Za-z0-9]{30,}\b"),
    # ---------- SaaS / 消息 ----------
    ("TWILIO_AUTH_TOKEN", "high", "saas",
     r"(?i)twilio[_\- ]{0,2}(?:auth|token|api[_\- ]{0,2}key)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})"),
    ("TWILIO_ACCOUNT_SID", "medium", "saas", r"\bAC[a-f0-9]{32}\b"),
    ("DISCORD_BOT_TOKEN", "high", "messaging",
     r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("NGROK_AUTHTOKEN", "medium", "tunneling",
     r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b"),
    ("MAILCHIMP_API_KEY", "medium", "saas", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    # ---------- 泛化兜底 ----------
    ("GENERIC_API_KEY", "medium", "generic",
     r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|secret[_\-]?token|auth[_\-]?token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{24,})"),
    ("PASSWORD_LITERAL", "medium", "generic",
     r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^\"'\s]{8,})['\"]"),
    ("ENV_SECRET_ASSIGNMENT", "low", "generic",
     r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*\S{8,}"),
]

COMPILED = [(name, sev, cat, re.compile(rx)) for name, sev, cat, rx in PATTERNS]


def mask_value(value: str) -> str:
    """默认脱敏：只留前 4 + 后 4，中间打码（短串直接全码）。"""
    v = value.strip()
    if not v:
        return ""
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * min(len(v) - 8, 32) + v[-4:]


def scan_text(text: str, source: str = "<stdin>", show_full: bool = False,
              max_hits: int = DEFAULT_MAX_HITS):
    """逐行匹配；返回 (hits, truncated)。同一行同一模式只记第一次，避免重复刷屏。"""
    hits = []
    truncated = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        seen = set()
        for name, sev, cat, rx in COMPILED:
            if name in seen:
                continue
            m = rx.search(line)
            if not m:
                continue
            seen.add(name)
            # 有捕获组时优先取组 1：那才是凭据本体，前缀只是键名，不该算进片段
            raw = (m.group(1) if m.groups() and m.group(1) else m.group(0)).strip()[:200]
            hits.append({
                "pattern": name,
                "severity": sev,
                "category": cat,
                "file": source,
                "line": line_no,
                "match": raw if show_full else mask_value(raw),
                "masked": not show_full,
                "length": len(raw),
            })
            if len(hits) >= max_hits:
                return hits, True
    return hits, truncated


def iter_files(path: str, max_bytes: int, stats: dict):
    """产出 (文件路径, 文本)；按扩展名与体积过滤，跳过项在 stderr 说明并计入 stats。"""
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d.lower() not in SKIP_DIRS)
            for name in sorted(files):
                yield from iter_files(os.path.join(root, name), max_bytes, stats)
        return
    ext = os.path.splitext(path)[1].lower()
    if ext and ext not in TEXT_EXT:
        stats["skipped"] += 1
        print("[skip] 非文本后缀，未扫描: %s" % path, file=sys.stderr)
        return
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        stats["skipped"] += 1
        print("[skip] 读不到（未扫描）: %s (%s)" % (path, exc), file=sys.stderr)
        return
    if size > max_bytes:
        stats["skipped"] += 1
        print("[skip] 超过 %d MB（未扫描，不能当作干净）: %s"
              % (max(1, max_bytes // (1024 * 1024)), path), file=sys.stderr)
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            yield path, fh.read()
    except OSError as exc:
        stats["skipped"] += 1
        print("[skip] 读取失败（未扫描）: %s (%s)" % (path, exc), file=sys.stderr)


def scan_path(path: str, show_full: bool, max_file_mb: float,
              max_hits: int) -> dict:
    max_bytes = int(max_file_mb * 1024 * 1024)
    hits, truncated = [], False
    files_scanned = 0
    stats = {"skipped": 0}
    for fp, text in iter_files(path, max_bytes, stats):
        files_scanned += 1
        more, cut = scan_text(text, source=fp, show_full=show_full, max_hits=max_hits)
        hits.extend(more)
        truncated = truncated or cut
        if len(hits) >= max_hits:
            truncated = True
            break
    return {"hits": hits[:max_hits], "truncated": truncated,
            "files_scanned": files_scanned, "files_skipped": stats["skipped"]}


def fetch_remote(url: str, timeout: int, max_bytes: int) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; seep-osint-secret-scan/1.0)",
        "Accept": "text/javascript,application/javascript,*/*;q=0.8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", "replace")


def counts_for(hits) -> dict:
    out = {sev: 0 for sev in SEVERITY_ORDER}
    for hit in hits:
        out[hit["severity"]] = out.get(hit["severity"], 0) + 1
    out["total"] = len(hits)
    return out


def sort_hits(hits):
    rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    return sorted(hits, key=lambda h: (rank.get(h["severity"], 9), h["file"], h["line"]))


def emit(payload: dict, out_path: str | None) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if out_path:
        target = os.path.abspath(out_path)
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text + "\n")
        print("[out] 已写入 %s" % out_path, file=sys.stderr)
    print(text)


def render_text(payload: dict) -> str:
    lines = ["osint-secret-scan: %s" % ("HITS" if payload["hits"] else "CLEAN")]
    counts = payload["counts"]
    lines.append("命中 %d（critical %d / high %d / medium %d / low %d）/ 扫描文件 %s"
                 % (counts.get("total", 0), counts.get("critical", 0),
                    counts.get("high", 0), counts.get("medium", 0),
                    counts.get("low", 0), counts.get("files_scanned", "-")))
    for hit in payload["hits"]:
        lines.append("  [%s] %s (%s) %s:%d  %s"
                     % (hit["severity"].upper(), hit["pattern"], hit["category"],
                        hit["file"], hit["line"], hit["match"]))
    if payload.get("truncated"):
        lines.append("  注意：命中数达到上限被截断，结果不完整")
    if payload["hits"]:
        lines.append("  只登记类型与位置；片段默认脱敏，勿把明文凭据贴到群里。")
    return "\n".join(lines)


def self_test() -> int:
    """12 条正例（覆盖 16 类高价值线索）+ 6 条负例；不联网、不读仓库外文件。"""
    checks, bad = [], []

    def expect(label, cond):
        checks.append(label)
        if not cond:
            bad.append(label)

    hex40 = "0123456789abcdef0123456789abcdef01234567"
    aws_sk = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    positives = [
        ("AWS AK/SK",
         "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
         "aws_secret_access_key = %s\n" % aws_sk,
         ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]),
        ("GCP service account",
         '{"type": "service_account", "private_key_id": "%s", "project_id": "demo"}' % hex40,
         ["GCP_SERVICE_ACCOUNT", "GCP_PRIVATE_KEY_ID"]),
        ("Azure 存储连接串",
         "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=%s==;"
         "EndpointSuffix=core.windows.net" % ("A" * 60),
         ["AZURE_STORAGE_CONNECTION_STRING"]),
        ("GitHub token",
         "token1 = ghp_%s\ntoken2 = github_pat_%s\n"
         % ("A" * 36, "B" * 70),
         ["GITHUB_PAT_CLASSIC", "GITHUB_PAT_FINEGRAINED"]),
        ("Slack token + webhook",
         "SLACK=xoxb-1234567890-abcdefghij\n"
         "hook=https://hooks.slack.com/services/T0000000/B0000000/%s\n" % ("c" * 24),
         ["SLACK_TOKEN", "SLACK_WEBHOOK_URL"]),
        ("Stripe live key", "const k = 'sk_live_%s';" % ("d" * 24),
         ["STRIPE_LIVE_KEY"]),
        ("Telegram bot token", 'bot = "987654321:%s";' % ("E" * 35),
         ["TELEGRAM_BOT_TOKEN"]),
        ("Firebase URL + Supabase secret",
         'db = "https://demo-project.firebaseio.com"\nkey = "sb_secret_%s"\n'
         % ("f" * 30),
         ["FIREBASE_DB_URL", "SUPABASE_SECRET_KEY"]),
        ("JWT",
         "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
         "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
         ["JWT"]),
        ("私钥块", "-----BEGIN RSA PRIVATE KEY-----\n", ["RSA_PRIVATE_KEY"]),
        ("内网 IP + 内部域名",
         'upstream = "http://10.20.30.40:8080/api"\nadmin = "https://jira.corp.internal/login"',
         ["INTERNAL_IPV4", "INTERNAL_DOMAIN"]),
        ("数据库 URL + SMTP 凭据",
         'dsn = "postgresql://app:S3cretPassw0rd@db.internal:5432/app"\n'
         'smtp_password = "Xy9passw0rd!"\n',
         ["DATABASE_URL", "SMTP_CREDENTIAL"]),
    ]
    for label, text, expected in positives:
        hits, _ = scan_text(text, source="fixture.js")
        names = {h["pattern"] for h in hits}
        missing = [p for p in expected if p not in names]
        expect("正例命中：%s" % label, not missing)
        if not missing:
            # 默认必须脱敏：不能把明文片段原样带出去
            expect("正例默认脱敏：%s" % label,
                   all(h["masked"] and ("*" in h["match"] or h["length"] <= 8)
                       for h in hits))

    negatives = [
        ("普通接口地址", 'const endpoint = "https://api.example.com/v1/users";'),
        ("GCP 普通配置", '{"project_id": "demo-project", "region": "europe-west1"}'),
        ("公钥块", "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK\n"
                   "-----END PUBLIC KEY-----"),
        ("环境变量提示文案", "// 生产环境从环境变量读取，不要写死在代码里"),
        ("公网测试网段", 'const clientIp = "203.0.113.10"; // TEST-NET-3'),
        ("本地调试地址", 'fetch("http://localhost:3000/health").then(r => r.json());'),
    ]
    for label, text in negatives:
        hits, _ = scan_text(text, source="clean.js")
        expect("负例零命中：%s" % label, hits == [])

    expect("模式库 ≥ 40 条（实际 %d）" % len(PATTERNS), len(PATTERNS) >= 40)
    expect("正例 ≥ 12 条", len(positives) >= 12)
    expect("负例 ≥ 6 条", len(negatives) >= 6)
    expect("脱敏保留前 4 后 4",
           mask_value("AKIAIOSFODNN7EXAMPLE") == "AKIA" + "*" * 12 + "MPLE")
    expect("短串全脱敏", mask_value("abcd") == "****")
    payload = {"ok": True, "hits": [], "counts": counts_for([]),
               "blocked_at": None}
    expect("空命中计数为 0", payload["counts"]["total"] == 0)
    full_hits, _ = scan_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "x.js",
                             show_full=True)
    expect("--show-full 显示明文",
           bool(full_hits) and full_hits[0]["match"].startswith("AKIA")
           and full_hits[0]["masked"] is False)

    if bad:
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "tool": "osint-secret-scan.py", "failures": bad},
                         ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "checks": len(checks),
                      "tool": "osint-secret-scan.py",
                      "patterns": len(PATTERNS),
                      "positives": len(positives), "negatives": len(negatives)},
                     ensure_ascii=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="OSINT 密钥/内部信息扫描（只读；默认脱敏输出，供 case_state claim 登记位置）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("--path", default=None,
                    help="本地文件或目录（只读；目录会跳过 node_modules/.git/dist 等）")
    ap.add_argument("--url", default=None,
                    help="单个远程 JS 地址（需同时加 --allow-remote，默认拒绝）")
    ap.add_argument("--allow-remote", action="store_true",
                    help="显式允许 --url 出网（默认拒绝，避免误打第三方）")
    ap.add_argument("--json", action="store_true", help="输出 JSON（默认也是 JSON，保留兼容）")
    ap.add_argument("--show-full", action="store_true",
                    help="显示命中明文（危险：会在 stderr 提醒，勿贴群/公开渠道）")
    ap.add_argument("--out", default=None, help="把 JSON 结果写入文件（自动建目录）")
    ap.add_argument("--max-file-mb", type=float, default=DEFAULT_MAX_FILE_MB,
                    help="单文件大小上限 MB（默认 10，超限跳过并在 stderr 说明)")
    ap.add_argument("--max-hits", type=int, default=DEFAULT_MAX_HITS,
                    help="命中上限（默认 500，超出截断并在结果里标注）")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="--url 抓取超时秒数（默认 10）")
    ap.add_argument("--self-test", action="store_true", help="内置正负例自测（不联网）")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.path and args.url:
        msg = {"ok": False, "hits": [], "counts": counts_for([]),
               "blocked_at": "args", "reason": "--path 与 --url 只能二选一"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2
    if not args.path and not args.url:
        msg = {"ok": False, "hits": [], "counts": counts_for([]),
               "blocked_at": "args", "reason": "必须给 --path 或 --url"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2
    if args.max_hits <= 0 or args.max_file_mb <= 0 or args.timeout <= 0:
        msg = {"ok": False, "hits": [], "counts": counts_for([]),
               "blocked_at": "args", "reason": "数值参数必须为正数"}
        print(json.dumps(msg, ensure_ascii=False))
        return 2

    if args.show_full:
        print("[!] --show-full 已开启：输出含明文凭据，不要贴到群里或公开渠道；"
              "只留在本地证据目录。", file=sys.stderr)

    if args.url:
        if not args.allow_remote:
            msg = {"ok": False, "hits": [], "counts": counts_for([]),
                   "blocked_at": "remote-disabled",
                   "reason": "--url 默认拒绝出网；确认目标在授权范围后加 --allow-remote"}
            print(json.dumps(msg, ensure_ascii=False))
            return 2
        if not re.match(r"(?i)^https?://", args.url):
            msg = {"ok": False, "hits": [], "counts": counts_for([]),
                   "blocked_at": "args", "reason": "--url 只接受 http(s) 绝对地址"}
            print(json.dumps(msg, ensure_ascii=False))
            return 2
        try:
            text = fetch_remote(args.url, args.timeout,
                                int(args.max_file_mb * 1024 * 1024))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            msg = {"ok": False, "hits": [], "counts": counts_for([]),
                   "blocked_at": "network-error", "reason": str(exc)[:160]}
            print(json.dumps(msg, ensure_ascii=False))
            return 2
        hits, truncated = scan_text(text, source=args.url, show_full=args.show_full,
                                    max_hits=args.max_hits)
        result = {"hits": hits, "truncated": truncated,
                  "files_scanned": 1, "files_skipped": 0}
    else:
        target = os.path.abspath(args.path)
        if not os.path.exists(target):
            msg = {"ok": False, "hits": [], "counts": counts_for([]),
                   "blocked_at": "path", "reason": "路径不存在: " + args.path}
            print(json.dumps(msg, ensure_ascii=False))
            return 2
        result = scan_path(target, args.show_full, args.max_file_mb, args.max_hits)
        args.path = target

    hits = sort_hits(result["hits"])
    counts = counts_for(hits)
    counts["files_scanned"] = result["files_scanned"]
    counts["files_skipped"] = result["files_skipped"]
    payload = {
        "ok": True,
        "schema": SCHEMA,
        "target": args.url or args.path,
        "hits": hits,
        "counts": counts,
        "truncated": result["truncated"],
        "show_full": bool(args.show_full),
        "blocked_at": None,
    }
    if args.json:
        emit(payload, args.out)
    else:
        emit(payload, args.out)
        print(render_text(payload))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
