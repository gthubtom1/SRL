# Membership, paywalls, and the honest limits of client-side patching

Read this **before** investing hours. Most "unlock VIP / remove the paywall" requests cannot be satisfied by patching the client, and knowing that early is the most valuable output you can produce.

## First question: who decides?

| Signal | Owner | Client patch can... |
|---|---|---|
| A local boolean/int/string field in an app model, computed locally | Client | Fully determine the outcome |
| A field that comes from an API response and is merely *read* by the UI | Server | Change display only — not access |
| Download/stream/play URLs issued by an API | Server | Nothing. You cannot mint a valid URL. |
| Entitlement checked on every protected action with a server round-trip | Server | Nothing |
| A local cache of a server value | Server (cached) | Temporarily fool the UI until it refreshes |

**Decision rule:** if the thing you want (a media URL, a decrypted payload, premium data) is *delivered by the server*, the client is not the gate. The gate is server-side and is not patchable.

## How to prove it in minutes

Do not guess. Test the API directly (`references/server-api.md`).

```
1. Call the protected endpoint with no credentials.       -> 401/403 means auth-gated
2. Call it with an obviously forged token.                -> another 401 confirms it is validated
3. Call the metadata endpoint.                            -> often 200, giving you the shape,
                                                             but deliberately omitting the asset URL
4. Compare: is the valuable field simply absent?           -> then no client change can invent it
```

A concrete, real result pattern worth remembering:

- `GET /videos/{id}` → **200**, full metadata, cast list, source list — **but no playback URL at all**
- `GET /v2/sections/{id}/play-url` → **401** with no token
- same, with `Authorization: Bearer <forged>` → **401**
- `GET /user/me` with forged token → **401**

That combination is conclusive: metadata is public, the asset URL is server-minted, and the token is verified. **Client-side patching cannot unlock it.**

## What *is* legitimately achievable client-side

Don't overclaim, and don't underclaim either. Genuinely client-side wins:

- **Remove ads / SDKs.** Ads are a client behavior (`references/ad-removal.md`).
- **Remove a UI gate** where the underlying data is already delivered and only a local check hides it (a "locked" tab whose content is already fetched, a disabled button).
- **Skip promotional interstitials and self-promo popups** driven by local flags.
- **Unlock client-only features**: debug menus, extra player settings, higher local bitrate selection, gesture options.
- **Grant a client-side reward** only if the reward is neither validated nor authoritative server-side (check first — a reward that later fails server validation is worse than no reward).
- **Bypass a client-side trial timer** whose enforcement is purely local (but expect the server to re-assert on next sync).

## What is NOT achievable, and how to say so

- **Paid content whose URL comes from the server.** State it plainly and show the 401 evidence.
- **Server-validated rewards / purchases / credits.**
- **Anything the server re-checks on the next request.** The patch may look like it works for one screen and then silently revert.

Wording that is both honest and useful:

> The client cannot unlock this. Metadata is public, but the asset URL is issued by the server, and the endpoint returns 401 for both anonymous and forged credentials — so no local change can produce a valid URL. What *is* removable client-side is X, Y, Z. To actually get access you need a real account with the required entitlement.

## The fake-VIP trap

Forcing a local `isVip()`-style method to return `true` is the classic mistake. Two failure modes:

1. **Cosmetic only** — UI shows VIP styling, but protected actions still fail server-side.
2. **Actively harmful** — the client now believes it holds entitlements it does not, so it enters code paths that expect server data it never receives. Observed result: **blank screen** (process alive, nothing rendered, only a swallowed uncaught exception in the crash buffer).

If you patch such a method, patch it in a **conservatively correct** way, and verify all screens, not just the one you cared about:
- Do not fabricate entitlements that gate data fetching.
- Prefer patching *presentation* consumers of the flag over the flag's computation, if the flag is also used for access decisions.

## Local state vs code — the deliverable question

A value can be "fixed" in two places:

| Where | Survives fresh install? | Fits an APK deliverable? |
|---|---|---|
| Code (patched dex) | Yes | Yes |
| App data (datastore/prefs/db) | **No** | No — unless you also patch the read path |

If a fix works on your device but a user reports it gone after reinstall, this is why (`references/pitfalls-2-environment-and-evidence.md`). Re-implement the fix by patching the **read path** so it always yields the desired value.

## Reporting template

```
Goal:            <what the user asked for>
Gate owner:      client | server | mixed        (evidence: ...)
Achievable:      <list, with evidence each>
Not achievable:  <list, with the 401/absent-field evidence>
Residual:        <what remains and the exact coupling that prevents removing it>
Verified on:     <device, build hash, what was exercised>
```

## Command block: turn "who decides" into four HTTP facts

The matrix earlier in this file is a hypothesis until four requests have been made. Do them in this
order — each one is cheaper than the next and one of them usually ends the question.

```bash
# 1) metadata endpoint, unauthenticated: is the valuable field even present?
python scripts/probe_api.py --base <base_url> --path /videos/<id> --json-out meta.json

# 2) the asset endpoint, unauthenticated: is the URL minted per-request?
python scripts/probe_api.py --base <base_url> --path /v2/sections/<id>/play-url

# 3) the same endpoint with an obviously forged token (does the server validate it?)
python scripts/probe_api.py --base <base_url> --path /v2/sections/<id>/play-url \
  --header 'Authorization: Bearer forged.token.value'

# 4) an identity endpoint, to separate "no token" from "bad token"
python scripts/probe_api.py --base <base_url> --path /user/me \
  --header 'Authorization: Bearer forged.token.value'
```

**What to read from each:**

| # | Observation that ends the question | Verdict |
|---|---|---|
| 1 | 200 with metadata, but **no** playback/asset field at all | server-minted value: **not patchable** |
| 2 | 401 / 403 | auth-gated; continue to 3 to learn whether it is *validated* or merely *checked for presence* |
| 3 | 401 / 403 again | the token is validated, not just required: forging is not a route |
| 4 | 401 | the identity itself is server-authoritative; a fabricated session will fail here first |
| 1–4 | 200 everywhere | the gate is client-side after all — the valuable field is being delivered, so a client patch can be real |

Send the app's own headers (`X-App-Name`, `User-Agent`, any appkey header) — without them, a WAF answers
403 and you will record a server-side refusal that never happened (`server-api.md` §reproduce requests
faithfully).

## What passing looks like (通过长什么样)

Two different deliverables have two different passing criteria. Mixing them is how "I proved it's
server-side" gets reported after a run that only proved "my request was rejected".

| Claim you want to make | Passing evidence | Not passing |
|---|---|---|
| "This is server-authoritative" | the valuable field is **absent** from an otherwise-200 metadata response, **and** the asset endpoint returns 401 for anonymous *and* forged credentials | a 403 from your own host with no app headers; a 404 because you guessed the path |
| "This is client-enforced" | the data is already delivered (visible in a capture or a response), and the gate is a local predicate you can name | the dialog vanished: dismissing a prompt is not releasing a gate |
| "The client patch releases it" | the feature works **from a signed-out state**, on the same build hash, exercised end to end | the UI shows VIP styling while the protected action still fails |
| "It survives a fresh install" | a clean install (not an upgrade) still behaves the same | it works on your device only because a datastore edit is present |
| "Nothing else broke" | the screens that consume the same flag still render, and one of them fetches data | no crash in logcat |

## The three outcomes, and how to write each one

Every membership/paywall task ends in exactly one of these. Naming which one you are in is the
deliverable — the patch is secondary.

**① Client-enforced, released.** Write what became usable, from which state, verified how. Add the
coupling that survives: e.g. "the tab is now enterable while signed out; its list is still empty because
the server answers for `this account` and there is none".

**② Mixed: UI released, data still server-side.** This is the most common honest result. The wording
matters: *"the prompt and the lock no longer appear; the content is per-account and therefore still
empty when signed out — that part is not client-patchable."* Anything shorter gets read as a
successful crack.

**③ Server-authoritative.** State it with the four facts, then name what *is* removable client-side, so
the answer is not merely a refusal. A refusal with evidence and a list of what still works is a useful
deliverable; "can't be done" alone is not.

## The fake-entitlement failure, in mechanism terms

The reason a forged VIP flag is worse than doing nothing is not cosmetic — it is that the client starts
*requesting things it cannot consume*.

| What the patch changes | What the client then does | Observable failure |
|---|---|---|
| `isVip()`-style predicate → `true` | requests entitlement-scoped endpoints with a non-entitled identity | 401/403 on those calls, swallowed into an empty-state screen |
| entitlement object fabricated in local state | renders premium containers whose data never arrives | blank page, process alive, no Java stack, only a swallowed exception |
| server field forced in the response model | one screen looks right, the next refresh overwrites it | the "fix" disappears after a pull-to-refresh or a restart |
| download/asset URL synthesized locally | player/library rejects the URL | playback error, not a paywall error — easy to misattribute |

**The rule that follows:** patch the *consumer* of the flag only when the data behind it is already
delivered; never fabricate an entitlement that gates a fetch. If you cannot tell which kind of flag you
are looking at, the four HTTP facts above decide it before you edit anything.

## Reading the flag's blast radius

A boolean named `isVip` is rarely used in one place. Before patching, count the consumers, and classify
them — the classification, not the count, decides whether the patch is safe.

```bash
# 1) how many call sites read this predicate (or this field)?
python scripts/find_refs.py ./smali --method 'Lcom/x/User;->isVip()Z'

# 2) which of them are *display* and which are *access* decisions?
python scripts/dex_strings.py ./dexdump --find 'vip|premium|upgrade|subscribe' --per-file
```

**What passing looks like:** you can put every call site into one of three buckets — *display only*,
*gates a request*, *gates local functionality* — and your patch only changes the first and third. If a
consumer in the second bucket changes behaviour, expect the empty-screen symptom above, not a win.

## When the honest answer is "not worth it"

Some paywalls are technically client-side but economically pointless to patch:

- every protected action re-checks with the server (the patch saves one screen, not the feature);
- the asset is DRM-wrapped and the key is minted per session (breaking it is a different discipline);
- the app is under active anti-tamper development and every release moves the check (a maintenance
  treadmill, not a deliverable).

Saying "here is what the client can and cannot do, and here is why the rest is out of scope" is a
complete answer. It is also the answer that keeps the next person from repeating the investigation.

## Trial timers and local quotas — the one shape that is often genuinely local

A "3 free articles / 7-day trial / 5 exports" limit is sometimes enforced entirely on the device: a
counter in preferences, a first-seen timestamp, a local quota table. This is the one membership-shaped
feature where a client patch is usually real — and also the one where the patch is most likely to be
undone by the server on the next sync.

| Where the counter lives | How to tell | What a patch can do |
|---|---|---|
| preferences / datastore, read before rendering | the value survives airplane mode and does not change when you clear app data *(it resets, so the server is not the source)* | reset or clamp the counter; prefer patching the **read** so it holds after reinstall |
| server response, mirrored locally | clearing app data restores the same count | nothing durable: the server re-asserts |
| signed local blob (HMAC/timestamp) | editing it produces a "corrupt state" path, not a reset | not patchable without the key — treat as server-authoritative |
| first-install timestamp, compared locally | `installTime`-shaped field, or a file created on first launch | extend the window locally; expect a server check on sync |

**Verification that distinguishes these:** run the app in airplane mode after the change. A local limit
that is truly local keeps the new behaviour; a mirrored server value either reverts on the next
connectivity or shows a "sync error" path. Record which of the two you saw — it decides whether the
result is a deliverable or a demo.

## Three versions of the same report

The same evidence supports three sentences. Only one of them is honest, and the difference is whether
the limitation is stated with its cause.

- ❌ *"VIP unlocked."* — implies the entitlement exists; the next signed request disproves it.
- ⚠️ *"The paywall is removed."* — true of the screen, silent about the data; the user will hit the
  empty state and assume the patch failed.
- ✅ *"The paywall screen and its lock are removed; the content behind it is issued per account by the
  server (`/v2/.../play-url` → 401 for anonymous and forged credentials), so it stays unavailable when
  signed out. Client-side ads and the local trial timer are removed and verified."*

Write the third one even when the task asked for the first. It is longer, it is checkable, and it is the
only version that stays true after the next launch.

## The one-sentence test

**If the thing the user wants does not exist on the device before the patch, no patch can make it
exist.** Everything else in this file is a procedure for establishing whether it exists — and for
saying which of the three outcomes you reached. That sentence is also the one to hand to the user
*before* the work, because it changes what they should expect from it.

## 这一篇算"用对了"吗

- [ ] 我用四条 HTTP 事实（元数据/资产/伪造 token/身份）判过"谁拥有这个门"，而不是凭 UI 猜
- [ ] 我分清了"对话框消失"（外观）与"功能可用"（行为），并把结论写成后者
- [ ] 我没有伪造 entitlement / session，或写了为什么必须避免
- [ ] 我给了 call site 的三分类（显示 / 触发请求 / 本地功能），补丁只动第一和第三类
- [ ] 我的结论里有"不可达成的部分 + 原因 + 仍然可做的部分"，而不只是一个补丁
