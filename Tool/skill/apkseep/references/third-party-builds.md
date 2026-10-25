# Third-party builds — auditing a "cracked" or "modded" APK before trusting it


**Load this when:** the input is a "cracked" or "modded" APK you did not produce. It gives the audit that tells you what was injected, and why such a build is never a patching workbench.

## Why this exists

A modded build of the exact app you are targeting is the most tempting shortcut available:
it appears to prove the goal is achievable, and it may already contain the patch you were
about to write. It is also the single most common source of wasted hours and of real risk,
for two reasons.

1. **It is usually not editable.** Authors who redistribute mods protect them, often with
   more layers than the original app ever had. You cannot treat someone else's build as a
   patching workbench.
2. **Its target-audience behaviour is unverified.** The binary may carry injected components,
   extra endpoints, or embedded credentials. "It runs and the ads are gone" tells you nothing
   about what else it does.

Treat a third-party build as an **untrusted sample to be audited**, never as a baseline.
The useful output of an audit is a decision plus evidence — not a binary you start from.

## Step 1: Can you even edit it?

Find the app's own package prefix (the one that appears in its own class definitions, e.g.
`com/<vendor>/<app>/`) and count how many times it appears as a **defined class** in each
plaintext dex.

```
business-prefix hits per dex:
  classes.dex    0        <- shell
  classes2.dex   0
  classes3.dex   0
  classes4.dex   0
```

Zero everywhere means the business code has been **moved out of the plaintext dexes** — the
build is protected at a level you cannot patch directly, even though it launches and works.
Stop here and treat it as a black box.

Also check the reported dex count against the file count: a manifest-declared app with only
library classes present is the same signal.

## Step 2: How many protection layers does it carry?

Mods frequently stack protection from multiple vendors, sometimes because the author
re-protected an already-protected app. Look for independent, coexisting families:

| Layer kind | Typical static evidence |
|---|---|
| Commercial packer | shell `Application`/`appComponentFactory` in the manifest, a `lib*protect*.so`, encrypted assets, `assets/*.jar` with near-maximal entropy |
| DEX-to-native (dex2c) | a "stub" `lib*.so` containing the tool's name, `EntryPoint`/`protect`-style symbols, and **business class names as strings** alongside a near-empty dex layer |
| Anti-debugging / RASP | strings such as `TracerPid`, `ptrace`, `NoNewPrivs`, `CheckPtraceSelf`, `AntiFrida`, plus a self-protection log path |
| Generic hardening marker files | small text files under `assets/` naming a protection vendor and a protection timestamp |

The practical consequence of an anti-debugging layer is that Frida-based dynamic work will hit
a self-check before it hits your hook. Note it, and prefer static conclusions on such a sample.

## Step 3: What did the author ADD?

This is where the audit earns its keep. Diff against the **original build of the same version**
(referenced as `<original>` below).

### New components

Build the set difference of `activity` / `service` / `receiver` / `provider` declarations,
then check whether each new class name actually exists in the plaintext dexes.

- Class exists and is readable → you can judge its purpose.
- Class name appears **nowhere** in plaintext but shows up inside a native library's strings →
  the logic is in the native/dex2c layer, purpose unknown. Say so.
- Nothing registered with an implicit-launch intent-filter (`BOOT_COMPLETED`, `MAIN`) → it cannot
  be started implicitly, which limits (but does not eliminate) the risk.
- A provider with an `authorities` value containing a package-name rewrite (a suffix/prefix that
  is not the current package) is a strong hint the build was produced by **repackaging or app
  cloning**, not by editing the original.

### New outbound endpoints

Extract every URL/domain/IP from the modded build's `lib/*.so`, `assets/*`, and dex strings,
and subtract the original's set. Any domain that exists **only** in the modded build is the most
important finding in the audit.

Rank what you find:
- A domain that also serves install attribution or update checks is explainable.
- A domain paired with an authorization-looking path (e.g. a `GET...`-style endpoint name
  nearby in the same string neighbourhood) is *not* explainable by de-ad work.

### Embedded secrets

Search native libraries and assets for private-key markers:
```
-----BEGIN ... PRIVATE KEY----- , PRIVATE KEY , PKCS#8 , RSA PRIVATE
```
A **private key shipped inside a client artifact** means its "authorization" or "integrity"
path is not a security boundary — anyone can extract the key. Report it as a red flag on the
build's trust claims, regardless of intent.

## Step 4: Capability picture — read both sides

A native library's import table is only half the story.

- **What it does not have** is meaningful: no `socket`/`connect`, no `execve`/`fork`/`system`,
  no `ptrace`, no installer-session strings → no direct evidence of command execution or
  silent install.
- **What it references** can override that impression: string references to Java-layer
  `java/net/Socket`, `InetSocketAddress`, reflection entry points, or executor services mean the
  capability exists **through the Java layer**, off the native import table.

State findings as "capability present / no evidence of use" rather than "safe" — an import table
is evidence of shape, not of intent.

## Step 5: The verdict

Do not hand back a binary. Hand back a decision with evidence and explicit unknowns.

```
VERDICT: use / use with caution / do not use
EVIDENCE:
  - business code plaintext?           yes/no  (+ counts)
  - protection layers                  list
  - injected components                list, each with purpose known/unknown
  - endpoints present only in this build   list
  - embedded credentials               yes/no
UNCONFIRMED:
  - <each item you could not establish, stated plainly>
```

"Use with caution" is the honest answer whenever a build is un-analysable **and** carries new
endpoints or unknown injected components. Do not upgrade it to "safe" because it launches
cleanly, and do not call it malicious without evidence — both are guesses.

## Using the audit result

Two legitimate outcomes:

1. The audit shows the mod is an honest de-ad of the same version → you may use it to **learn the
   approach** (diff its patch points against the original), but still rebuild from the original
   yourself so the artifact you ship has a known provenance.
2. The audit shows it is re-protected, injected, or un-analysable → discard it and do the work on
   the original. That is usually faster than reverse-engineering someone else's protection *and*
   your target's at the same time.

## Command block: the five diffs an audit actually needs

Each step above is a set difference against the original build of the same version. These are the
commands that produce them; the *outputs* are what the verdict cites.

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 1) entry-level diff: what was changed / added / removed (added = injection candidates)
python scripts/apk_diff.py original.apk modded.apk --summary
python scripts/apk_diff.py original.apk modded.apk --only 'lib/|classes[0-9]*\.dex|assets/' --hide-identical

# 2) can you even edit it? business classes as *defined* classes, per dex
python scripts/dex_strings.py ./modded_dex --classes 'Lcom/<vendor>/<app>/' --per-file
python scripts/dex_strings.py ./original_dex --classes 'Lcom/<vendor>/<app>/' --per-file

# 3) endpoints only in the modded build (the most important finding, if any)
python scripts/dex_strings.py ./modded_dex --urls | sort -u > mod.urls
python scripts/dex_strings.py ./original_dex --urls | sort -u > orig.urls
comm -13 orig.urls mod.urls

# 4) embedded key material (native libs and assets, not just dex)
unzip -o -q modded.apk -d mod_x
grep -rl 'PRIVATE KEY' mod_x | head
python - <<'PY'
import glob, math, collections
for p in glob.glob('mod_x/assets/*')[:40]:
    b = open(p, 'rb').read()
    if not b: continue
    c = collections.Counter(b); h = -sum(v/len(b)*math.log2(v/len(b)) for v in c.values())
    if h > 7.5: print('high-entropy asset: %s (%.2f bits/byte, %d bytes)' % (p, h, len(b)))
PY
```

**Expected shapes:**

```
# 1)
changed: 3   added: 7   removed: 0   identical: 2140
  + lib/arm64-v8a/lib<extra>.so
  + assets/<vendor>_config.json
# 2)  (modded)
classes.dex     0 hits
classes2.dex    0 hits        <- business code not in plaintext: stop here
# 3)
https://<new-host>/api/v1/device       <- present only in the modded build
# 4)
mod_x/lib/arm64-v8a/lib<name>.so       <- PRIVATE KEY marker inside a shipped library
high-entropy asset: mod_x/assets/<x>.bin (7.98 bits/byte, 412633 bytes)
```

## What passing looks like (通过长什么样)

| Question | Passing (an auditable answer) | Not passing |
|---|---|---|
| Is the business code editable? | per-dex defined-class counts for the app's own prefix, non-zero | "it opens in jadx" |
| How many protection layers? | a named layer list, each with its static evidence (manifest class, `so` name, marker string) | "it looks packed" |
| What was added? | `added:` list from the entry diff, each item classified known/unknown | comparing version strings by hand |
| Any new endpoints? | a non-empty set difference, ranked as explainable / not explainable | "I saw a domain once" |
| Any shipped secrets? | a named file and the marker found in it | "no obvious malware" |
| The verdict | use / use with caution / do not use, with the evidence table and an `UNCONFIRMED` list | a binary handed back |

## The four audit outcomes, and the artifact you produce for each

| Outcome | Evidence shape | What you hand back |
|---|---|---|
| Honest de-ad of the same version | 0 new endpoints, 0 new components, business code plaintext | "learn from it, rebuild from the original" + the patch points you diffed |
| Re-protected (stacked shell/dex2c) | 0 business classes in plaintext, extra `lib*` + markers | "do not use as a baseline"; the original is the workbench |
| Injected capability | added components with unknown purpose, or new endpoints | "do not use"; list what was added, with the evidence per item |
| Un-analysable | business code absent, native `so` with no readable symbols, high-entropy assets | "use with caution" + `UNCONFIRMED` list; still rebuild from the original |

**One rule across all four:** you never *ship* the third-party build. Either you rebuild from the
original, or you report that you did not — the audit's purpose is to protect the provenance of what you
deliver, not to certify somebody else's file.

## Failure modes of an audit

- **Auditing against the wrong original.** A mod of a different version produces a huge, meaningless
  set difference; confirm the declared version *and* the dex/`so` hashes before diffing.
- **Reading "no new endpoints" as "safe".** An injected component can call an endpoint that is already
  in the original's whitelist. The absence of new domains bounds the claim, it does not establish safety.
- **Treating an import table as intent.** Capability present ≠ capability used; say which one you have.
- **Letting the mod become the control build.** A diff against the mod tells you what the mod changed,
  never what the original does — the control must be a stock build of the same version.
- **Skipping the entropy check on assets.** Encrypted payloads and bundled payload jars hide there, and
  they are invisible to a dex-level audit.
- **Upgrading the verdict because it launches cleanly.** Clean launch is a property of the launcher, not
  of the payload.

## Quick triage: does this build even get a full audit?

A full audit is 1–3 hours. Ten minutes of triage tells you whether to spend it, and the triage answers
are exactly the ones the audit would start with.

| # | Check | If it fails | Action |
|---|---|---|---|
| 1 | Do you have a stock build of the **same version**? | you cannot diff anything | obtain it, or stop: without an original the audit is guesswork |
| 2 | Does the modded build's own prefix appear as defined classes in plaintext? | business code is out of reach | stop at "re-protected"; do the work on the original |
| 3 | Do the dex/`so` entry hashes differ from the original's in *few* places? | hundreds of entries differ | you are comparing different versions, not a mod |
| 4 | Is there an anti-debug layer (markers, RASP strings)? | dynamic work will fight a self-check | plan for static conclusions |
| 5 | Are there new endpoints or shipped key material? | this is the risk-relevant finding | full audit, and do not ship anything from it |

**Read the failures as answers, not as obstacles.** Checks 2–3 failing means "do not use it, and you
have saved two hours"; check 5 failing means "this is the one build worth auditing properly".

## Why the audit is usually cheaper than the alternative

The tempting shortcut is "the mod already removed the ads, so let me see how". The realistic cost
comparison:

| Route | Work | Risk |
|---|---|---|
| Reverse the mod's own protection, then its patch | unknown cost; the mod may carry a second, stronger layer | you learn nothing transferable, and every conclusion is about the mod |
| Audit the mod in 1–3 hours, then patch the original yourself | known cost, bounded by five diffs | you ship an artifact with known provenance |

The second row is not just safer — it is usually faster, because the original's code is the code you
would have to understand anyway. The audit's real product is **the diff**, which tells you where to patch
in the original, without inheriting anything else the mod did.

## 这一篇算"用对了"吗

- [ ] 我用同一版本的原版做 diff，并先确认了版本与关键产物哈希
- [ ] 我给出了"业务类是否在明文 dex 里"的每 dex 计数，而不是一句"能打开"
- [ ] 我的新增端点/组件/密钥三项都是**集合差**，并各自标了可解释/不可解释
- [ ] 我的结论是 use / use with caution / do not use 之一，并带 `UNCONFIRMED` 清单
- [ ] 我没有把这个构建当基线或控制组，也没有把它交回给用户当作成品
