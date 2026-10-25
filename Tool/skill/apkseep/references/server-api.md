# Server-side analysis — deciding whether a patch can even matter

If the behavior you want to change is produced by a response, patch the client all you like: nothing real changes. Establishing server authority early is the cheapest high-value step in any "crack this" task.

## Harvest the API surface from the client

```bash
python scripts/dex_strings.py <dex_dir> --urls
python scripts/dex_strings.py <dex_dir> --find 'https?://'
```

Collect: base URL(s), path constants, auth headers, and any dynamic-gateway mechanism.

Two patterns to watch for:

- **Static base URL** — straightforward.
- **Dynamic gateway** — the real host is fetched at runtime (commonly a DNS TXT record over DoH, or a small config endpoint). The hardcoded host may be a fallback. Symptom: requests go to a host that differs from anything in the dex.
  ```bash
  # TXT lookup, the usual shape:
  #   https://<doh-provider>/resolve?name=<domain>&type=txt
  # returns something like  "https://<gateway-host>"
  ```
  This is an anti-blocking technique; it does not block repacking, but it means your static host guess may be stale.

## Reproduce requests faithfully

```bash
python scripts/probe_api.py --base <base_url> --path /some/path --header 'X-App-Name: <value>'
```

Rules that make the difference between 403 and 200:

- **Send the app's real headers.** A single custom header (e.g. an app-name header) frequently decides whether a WAF lets the request through. The header value is a string constant in the dex.
- **`User-Agent` matters** — often `okhttp/x.y.z` or a runtime-specific default (e.g. `ktor-client`).
- **Watch for a CDN/WAF in front.** A 403 with an HTML body naming a WAF means your request shape is wrong, not that the endpoint is gone. Compare with what the app sends (capture it from the device).
- **Beware your own egress.** If your host goes through a proxy/VPN, a WAF may block by geography while the device succeeds. Do not conclude "the server rejects the app" from a host-side 403.
- **`/health`-style endpoints are gold** — a 200 with a small JSON body proves the backend and its response envelope are alive before you debug anything else.

## Response envelope

Most apps wrap responses uniformly, e.g. `{"code":0,"msg":"","data":{...}}`. Learn it once, then read endpoints by shape rather than guessing:

- `code != 0` + a message → business error, and **the message often enumerates valid inputs** (this is how an ad `position` whitelist was discovered).
- `data:null` with HTTP 200 → soft failure.
- `401` with a null envelope → auth gate.

## Prove who owns the gate

Run this matrix and record it. It is the single most decisive artifact for a paywall or entitlement question.

| Request | Expected if client-owned | Expected if server-owned |
|---|---|---|
| protected endpoint, no credentials | would still succeed | **401 / 403** |
| same, with a forged token | would still succeed | **401 / 403** |
| metadata endpoint | — | 200, often **omitting** the protected field |
| list/config endpoints | — | 200 with data |

If the valuable field is simply **absent** from an otherwise-200 metadata response, no client change can invent it. Say so, with the evidence.

## Also test the *unknown input* case

When you plan to change a request parameter (a path, a `position`, an id), probe what the server does with an **invalid** value first:

- A `400` with a validation message tells you the field is whitelisted, and hands you the full list of valid values.
- A `404` tells you the path is exact.

**This matters before you patch**: redirecting a parameter to an invalid value may produce an error status that the client treats as fatal (`pitfalls-1-packaging-and-dex.md`). Knowing the failure mode in advance prevents breaking the app.

## Behaviors that help you and behaviors that do not

**Repack-friendly (do not block you):**
- Minimal auth: `Authorization: Bearer <token>` and a static app-name header, with **no request signing, no nonce, no HMAC**.
- No client-certificate pinning to the app's own signature.

**Repack-hostile (will break a re-signed client):**
- Signature/certificate checked server-side, or pinned in native code.
- Request signing derived from the APK signature — the client computes with its own
  certificate, so re-signing changes the key. Silent and easy to misdiagnose; detection,
  extraction and the differential test are in `references/signature-derived-keys.md`.
- Device attestation (Play Integrity / SafetyNet, OEM attestation).

Determine which you face **before** shipping a repack. A client that authenticates fine on first launch but silently fails features later is the classic signature-validation symptom — and when computed signing parameters (`sign`, `_p`, `uth`) evaluate to `-1` or empty, it is the signature-derived-key case rather than a server decision.

## What to record

```
base url / gateway mechanism
required headers (exact values)
auth mechanism (token? signed? attested?)
response envelope shape
endpoints actually used, and their auth requirement
protected-asset endpoints, with status codes for: none / forged / (real if available)
invalid-input behavior for any parameter you plan to change
```

## Command block: replay the app's own request, not an approximation of it

The difference between a 403 and a 200 is almost always **one header** or **one parameter**. Replaying
means: take the header set out of the dex, send exactly those, and keep your own egress out of the way.

```bash
# 0) harvest the header names/values and the paths from the dex first
python scripts/dex_strings.py ./dexdump --find '(?i)x-[a-z-]+|appkey|app-key|channel|device-id' --per-file
python scripts/dex_strings.py ./dexdump --urls

# 1) replay with the app's headers, and explicitly without your proxy
python scripts/probe_api.py --base https://<host> --path /<path> \
  --header 'X-App-Name: <value>' --header 'User-Agent: <exact value from the dex>' --no-proxy

# 2) the same call with a wrong-but-valid-shaped parameter, to learn the validation surface
python scripts/probe_api.py --base https://<host> --path /<path> --param '<key>=<invalid>'

# 3) POST a body the client actually sends (keep a copy of one real body)
python scripts/probe_api.py --base https://<host> --path /<path> --method POST --data @body.json
```

**Expected shapes:**

| # | What a *useful* result looks like | What it means |
|---|---|---|
| 1 | 200 with the app's envelope (`{"code":0,...}`) | your replay is faithful; now the server answers *your* questions, not your proxy's |
| 1 | 403 with an HTML body naming a WAF | request shape is wrong (missing header/UA) or geo-blocked — **not** an endpoint verdict |
| 2 | 400 with a message enumerating valid values | the field is whitelisted, and the server just handed you the list |
| 2 | 404 | the path is exact; the parameter is not the problem |
| 3 | 200 / 4xx with a business `code` | you now have the envelope's error taxonomy — read endpoints by shape from here on |

**Never conclude from a host-side 403 that "the server rejects the app".** A proxy, VPN or non-local
egress changes the answer; the device on the same network is the control (`tls-and-cert.md` §3).

## Command block: identify the auth mechanism before promising anything

Four mechanisms look alike in a captured request and behave completely differently after a repack.

```bash
# 1) is a certificate involved? (strict check, classified failure)
python scripts/tls_check.py <host> --json

# 2) is the signature derived from the APK signing certificate?
python scripts/sig_probe.py --apk target.apk

# 3) attestation / device integrity: look for the SDK classes and the nonce flow
python scripts/dex_strings.py ./dexdump --find '(?i)integrity|safetynet|attest|nonce|playintegrity' --per-file
```

| Mechanism | Sign in the client | What survives a repack |
|---|---|---|
| plain bearer token + static app header | no signing code, no nonce | works; this is the repack-friendly case |
| HMAC over request params with a **shipped** key | `sign`/`_p`/`uth` params, key as a string or in assets | works **if** the key is not derived from the certificate |
| HMAC keyed by the **APK certificate** | `signatures[0]`/`toCharsString()` feeding a crypto call | does **not** work: re-signing changes the key (`signature-derived-keys.md`) |
| device attestation (Play Integrity / SafetyNet / OEM) | an attestation SDK plus a nonce endpoint | does not survive a rooted/repacked device; this is a boundary, not a bug |

**The order matters**: (2) is cheapest and prevents the single most expensive silent failure in this
domain. Do it **before** the first repack, not after every signed request starts failing.

## What passing looks like (通过长什么样)

| Claim | Passing | Not passing |
|---|---|---|
| "I can talk to this API" | a 200 with the app's envelope, produced by the app's own header set | a 200 from a different host / through a proxy you forgot |
| "This endpoint is auth-gated" | 401/403 for anonymous **and** for a forged token | 401 only for anonymous (that is "presence-checked", a weaker fact) |
| "The valuable value is server-minted" | the field is **absent** from an otherwise-200 metadata response | the field is present but empty (that may be a client-side default) |
| "The gate is server-owned" | an entitled account returns the value and a non-entitled one does not, same request | everything returns 401 because your replay is unfaithful |
| "The client signs its requests" | you can name the parameter (`sign`, `_p`), the algorithm family, and where the key comes from | you saw a long hex string and assumed HMAC |
| "Attestation is in play" | the SDK class, the nonce endpoint, and a failure that appears only on a modified device | a crash on a rooted device with no attestation evidence |

## Three false verdicts, and the control that kills each

| False verdict | What produced it | Control that kills it |
|---|---|---|
| "The server blocks repacked builds" | your own host-side 403 through a VPN, or a missing app header | the **unmodified original**, same device, same network (`tls-and-cert.md`) |
| "The API is dead / 404" | a path constant that is a template (`/v2/%s/play`) or a gateway-fetched host | search for the format string, then replay with a real id from a 200 response |
| "The endpoint validates the token properly" | a 401 that is really "no `X-App-Name` header, so the WAF said no" | add the app's headers; if the status changes, the first verdict was about the WAF |

All three have the same repair: **one control run with the original build**. Without it, every
server-side verdict in this file is `inferred` at best.

## Recording a server-authority verdict

```
base / gateway:      <static host | DoH-TXT gateway | config endpoint>   evidence: <line>
required headers:    <names + exact values, or "not required" (tested)>
auth mechanism:      <bearer | HMAC(shipped key) | HMAC(cert-derived) | attestation>
envelope:            {"code":..,"msg":..,"data":..}
endpoints:           <path> <method>  anon=<status> forged=<status> entitled=<status|not-tested>
protected asset:     <field name>  present_in_metadata=no  minted_by=<endpoint>
invalid-input:       <param> -> <status + message>
control:             original build, same device/network -> <result>
verdict:             client-owned | server-owned | mixed     (label each endpoint)
```

The `control` line is not optional: it is the difference between "the server rejects this" and "my
machine's egress rejects this", and only one of those is a finding about the target.

## Verifying a dynamic gateway instead of guessing it

A gateway that is fetched at runtime makes every static host guess stale, and it makes "the request
fails" a bad reason to abandon a route. The check is small:

```bash
# 1) look for a resolver shape in the dex: DoH paths, TXT mentions, a config endpoint name
python scripts/dex_strings.py ./dexdump --find '(?i)dns|txt|resolve|gateway|config\?|bootstrap'

# 2) ask the same question the client asks (shape only — substitute the provider you found)
#    the answer is a host or a small JSON blob, and it changes over time
curl -s 'https://<doh-provider>/resolve?name=<domain>&type=txt'

# 3) compare: does the resolved host differ from every literal in the dex?
python scripts/dex_strings.py ./dexdump --urls | grep -c '<resolved-host>'
```

**Passing looks like:** step 3 returns 0 while step 2 returns a host — that combination is the evidence
that the host is runtime-supplied, and it explains why nothing you read statically matched the traffic.
If step 3 returns ≥1, the host is a fallback literal and you can work statically.

Two consequences worth writing down: a gateway does **not** block repacking (it is an anti-blocking
measure, not an anti-tamper one), and caching means your first request after a change may still hit the
old host — clear the app's cache or wait out the TTL before drawing a conclusion
(`server-config-and-updates.md` §6 is the same failure in a different disguise).

## Boundaries of this file

- **It determines ownership, not access.** A server-authoritative gate is a finding; breaking it is
  out of scope by design (`coverage-and-limits.md`).
- **It does not reverse an encrypted protocol.** protobuf/gRPC/QUIC framing lives in
  `protocol-reverse.md`; this file only reads shapes and status codes.
- **It does not certify the client's crypto.** If a `sign` parameter needs to be reproduced offline,
  that is `emulation-and-rpc.md` (call it) or `signature-derived-keys.md` (find the key material).
- **It cannot see device-side decisions.** A request that is *never sent* is a client finding; the
  symptom index row for "no request at all" points at
  `code-virtualization-and-custom-linkers.md`, not here.

## Before the first `curl`: two questions that save the round

1. **Which build am I describing?** A server verdict is about *this* client: the header set, the path
   constants and the signing scheme all move between versions. Record the build hash next to the
   status codes, or the table describes an app that no longer exists.
2. **Which side am I allowed to conclude about?** If the answer is "the server", the deliverable is a
   written boundary, not a patch. Say that early — it changes what the rest of the task is worth doing.
3. **Is my replay reproducible?** Keep the exact command (headers included) in the record. A status code
   without the request that produced it is an anecdote, and it will not survive the next reviewer.
   Two lines of command text are cheaper than re-deriving a header set from memory a week later.

The rest of the file assumes these three are answered. If the first is unanswerable (you do not know
which build the capture came from), stop and re-capture: every later table row would be about an
artifact you cannot name.

## 这一篇算"用对了"吗

- [ ] 我先从 dex 取到了真实的 header 集合与路径，再用 `--no-proxy` 重放过（不是凭猜）
- [ ] 我在第一次重打包**之前**就查过签名派生密钥（`sig_probe.py --apk`）
- [ ] 我用"匿名 / 伪造 token / 有权限账号"三列记录了每个 endpoint 的状态码
- [ ] 我把"字段缺失"与"字段为空"分开写，并且知道只有前者能证明服务端铸造
- [ ] 我的结论里有一行 `control`（原版包、同设备、同网络），否则标了 `inferred`
