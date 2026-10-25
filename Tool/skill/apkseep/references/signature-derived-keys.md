# Signature-derived keys — when re-signing silently breaks the app

A class of app that repack-friendly guidance does not cover: the client feeds **its own APK
signing certificate** into a native routine and uses the result as the key for request
signing or for SDK payload encryption. Re-sign the APK and the key changes, so every signed
request fails — while the app itself launches perfectly.

This is distinct from "the server checks the signature". Here the *client* uses the signature
as key material, and the server was built against the original key. The failure looks like a
server problem and is actually a signing problem.


**Load this when:** the app reads `signatures[0]`/`toCharsString()`, or a rebuilt APK installs, launches and logs nothing wrong while every signed request fails. It gives the 15-minute check that prevents the most expensive silent repack failure.

## How to spot it (four greps, minutes)

```bash
# the usual shape: signature bytes handed to a crypto helper
grep -rn "toCharsString()" <decompiled_sources>
grep -rn "getPackageInfo(.*, *64)" <decompiled_sources>      # 64 = GET_SIGNATURES
grep -rn "signatures\[0\]" <decompiled_sources>

# and the same pattern in SDK-internal helpers
grep -rn "signatures\[0\].toByteArray" <decompiled_sources>
```

Signals that confirm it matters:

- The value is passed into a `native` method (JNI) or a helper that also does HMAC/AES/DES.
- The string table of the native library contains algorithm primitives (`hmac_sha256`,
  `hmac_md5`, `des_crypt`, `sha256_update`, `initKey`, `make_SubKey`, …) but **no hardcoded
  certificate or key blob** — i.e. the key is supplied from Java.
- Request URLs carry computed parameters (`sign`, `_p`, `uth`, `sig`, `nonce`) that are not
  derivable from the visible app data.
- The same certificate value is also fed to a third-party ad/OAID SDK helper.

If those hold, **any rebuilt APK needs the original certificate value hardcoded**, not the
new one. Patch that before you patch anything else, or you cannot distinguish "my patch broke
it" from "signing broke it".

## The trap: what that value actually is

Do **not** assume `signatures[0].toByteArray()` is the whole `META-INF/*.RSA` file. It is
platform-dependent, and the difference is invisible offline:

| Platform behaviour | What you get |
|---|---|
| Old JAR-signature path | the full PKCS#7 blob (`META-INF/CERT.RSA` content) |
| Modern (v2/v3 present) | a **single certificate from the chain**, DER-encoded — not the container, and not necessarily the first one |

Measured consequence on one sample: the `.RSA` file was 1199 bytes / 2398 hex chars, but the
runtime value was **777 bytes / 1554 hex chars** — the *last* certificate inside the PKCS#7.
Hardcoding the file bytes produced correct-looking smali, a clean build, a successful install,
and every request signing parameter evaluating to `-1`.

**Therefore: never derive this value offline and trust it.** Read it from the running app
(`scripts/sig_probe.py --live`), and only fall back to offline extraction to cross-check.

## Extract the real value

**Route A — from the device (authoritative):**

```bash
python scripts/sig_probe.py --live <pkg>                  # needs Frida + a rooted device
```

`--live` takes the package name as its own argument; there is no `--pkg` flag. Verify the call
against the script's own usage (`python scripts/sig_probe.py --help`) rather than against this page —
`check_commands.py` at the repository root validates documented commands for exactly this reason.

It prints `signatures[0].toCharsString()` and its length, read from the package manager on the
device. This is the only value that is guaranteed to match what the app computes.

**Route B — offline, to cross-check:**

```bash
python scripts/sig_probe.py --apk <original.apk>
```

This enumerates the candidate certificate blobs inside `META-INF/*.RSA` (each top-level
SEQUENCE inside the PKCS#7 `certificates` set) and prints each as hex with its length. Pick the
length that Route A reported; if Route A is unavailable, generate one build per candidate —
there are rarely more than two.

## Patch it

Replace every signature read with a string constant holding the original value, rather than
trying to make the new signature look like the old one.

In smali, the pattern to replace is an invoke/move-result pair:

```smali
invoke-virtual {vX}, Landroid/content/pm/Signature;->toCharsString()Ljava/lang/String;

move-result-object vX
```

Rewrite both instructions into a single load (a regex over the smali tree handles all sites at
once):

```smali
const-string vX, "<original-value-hex>"
```

Notes that save a build cycle:

- **Do not delete the surrounding `getPackageInfo` calls.** They are harmless and removing
  them perturbs register allocation. Only the two instructions above need to change.
- **Miss one site and it still fails.** Count the sites before and after (`grep -c`), and assert
  the post-patch count is zero. There is usually more than one — one per crypto helper.
- Keep the smali file's `.orig` backup so the patch is re-runnable; some build pipelines pick
  `.orig` up as an unknown file and warn, which is harmless.
- The same treatment applies to copies of the pattern inside bundled SDK packages
  (`…/secure/…Utils`, `…/oaid/…`), not just the app's own util class.

## Verify with a control, not with a feeling

A launch that "looks fine" proves nothing here: the app starts, then quietly fails every
network call. Use a differential test.

1. **Measure the signing parameter on both builds.** Hook the request builder and print the
   computed parameter for a request the app always makes on startup.
   - original APK → a value with the normal shape (encoded / base64-ish)
   - rebuilt APK → the same shape ⇒ signing is consistent
   - rebuilt APK → `-1`, empty, or null ⇒ the key is still wrong; go back to Route A
2. **Compare a full request URL**, parameter by parameter, between the two builds. Anything
   that differs beyond a timestamp/device id is a candidate root cause.
3. **Exercise the feature**, not the launch: an API-backed screen must actually render data.
   "Network error" on a screen that is otherwise intact is the signature of exactly this bug.

Before blaming your patch: run the **unmodified original** on the same device and network. If
it also fails, the problem is environmental (`references/tls-and-cert.md`,
`references/pitfalls-2-environment-and-evidence.md`) and not the repack.

## Related variants of the same root cause

- **OAID / device-id SDKs** hash the signature (`MessageDigest("SHA1").digest(signatures[0].toByteArray())`)
  and the result goes into a request header. Same fix, different call site.
- **Ad SDKs** use the signature to encrypt their own config payloads; leaving them unpatched
  usually degrades ads rather than breaking the app, so patch them after the core path works.
- **Certificate pinning to the app's own signature** is a different problem: it is verified,
  not used as a key. See `references/tls-and-cert.md`.

## Cost of getting this wrong

Without this step the task stalls in the worst possible way: the artifact is correct, the
patch is correct, the build is correct, and the app is unusable — which reads as "the client
patch is impossible" and sends you back to static analysis for hours. Budget 15 minutes for
this before the first repack of any signed-request app.

## Command block: a 10-minute pre-repack audit that prevents the whole failure class

Run this **before** the first repack of any target, not after the first signed request fails. It produces
three artefacts: the read sites, the candidate values with lengths, and the authoritative value.

```bash
# 1) enumerate read sites over the dex strings (no decompiler needed: the API descriptors are strings)
python scripts/dex_strings.py ./dexdump --find 'toCharsString|Landroid/content/pm/Signature;|GET_SIGNATURES' --per-file

# 2) candidate certificate blobs and their lengths (offline cross-check)
python scripts/sig_probe.py --apk original.apk

# 3) the authoritative value, read from the installed original on the device
python scripts/sig_probe.py --live <pkg>

# 4) record it: the hex and its length, plus the build hash it came from
python scripts/sig_probe.py --live <pkg> > sig-live.txt
sha256sum original.apk >> sig-live.txt
```

**Expected shapes:**

```
# 1)
classes3.dex  3       <- three dex strings reference signature APIs: there are read sites to patch
# 2)
candidate 0  777 bytes  (1554 hex chars)   META-INF/CERT.RSA  seq#2
candidate 1  1199 bytes (2398 hex chars)   META-INF/CERT.RSA  container
# 3)
signatures[0].toCharsString() len=1554 chars
# 4)  <- the record: value + length + the build it belongs to
```

**The number that matters is the length.** A patched constant of the wrong length is still valid smali,
still builds, still installs, and still signs nothing — the failure surfaces only as `sign`-parameter
values of `-1`. Match the length Route A reported, and if Route A is unavailable, build one variant per
candidate (there are rarely more than two).

## What passing looks like (通过长什么样)

| Check | Passing | Not passing |
|---|---|---|
| Read sites found | a non-zero per-dex count, each site identified (class + method) | "I grepped and saw nothing" — that is a search problem, not an absence (P25) |
| Value captured | `--live` output with a length, tied to a build hash | an offline candidate promoted without a live comparison |
| Constant length | equal to the live length, verified after assembly | "the string looks right" |
| All sites patched | the read-site count before == the patched-site count after | one site missed: the failure is silent and partial (`-1` only on some requests) |
| Behaviour | a signed request succeeds from a **rebuilt** build, on device | the app launches and renders (it always does) |
| Control | the unmodified original produces the same signed parameter for the same input | nothing to compare against |

## Which read sites must be patched — the three families

Signature reads hide in three places, and patching only the first is the common half-fix.

| Family | Shape | Where it hides |
|---|---|---|
| direct app code | `getPackageInfo(pkg, 64).signatures[0]` in an app class | the app's own helper around network setup |
| SDK helper | the same call inside an ad/attribution/OAID SDK | third-party package prefixes; often in a utility class |
| native read | Java passes the `byte[]` into a `native` method that keys an HMAC | the caller looks innocuous; the *callee* is where the value is consumed |

**Rule:** patch the value at the **read**, not at the consumer. Replacing the bytes handed to the native
routine keeps every downstream path identical, which is what makes the patch verifiable — the native code
is unchanged and still computes the same algorithm.

## Failure modes

- **Trusting an offline-derived value.** The `.RSA` file is not what the platform returns (measured: 1199
  bytes on disk vs 777 bytes at runtime, a different certificate in the same chain).
- **Patching the computed parameter instead of the key.** `sign` is a function of the body and a key; a
  hardcoded `sign` breaks on the next request with different content.
- **Missing an SDK helper.** Two read sites, one patched: the app's own requests work and the SDK's
  attribution silently fails, which reads as "some features are broken after repack".
- **Equal-length assumption without verification.** Length is the only cheap proof that the constant is the
  right one; check it after assembly.
- **Verifying with a launch.** The signature-derived failure is invisible at launch by construction; verify
  by exercising a signed request and comparing against the original's parameter for the same input.
- **Forgetting the update path.** A build whose signing is fixed but whose update check is live can be
  replaced by the store version, restoring the failure (`updates-and-forced-upgrade.md`).

## Inheriting a half-finished build? Start with the length

If someone hands you a rebuilt APK whose "signing is already patched", the cheapest check is not a code
review — it is the constant's length:

1. Read the live value's length from an installed **original** (`--live`), or from the record that ships
   with the build if it has one.
2. Find the constant in the patched build (string search for its first 16 hex chars).
3. Compare lengths. Equal length plus a byte-identical prefix is strong evidence the patch is right; equal
   length with a different prefix means a different certificate; different length means the patch cannot
   be correct, whatever it looks like.

Then confirm with one signed request. Two minutes, and it replaces an afternoon of reading smali around a
value that was never going to work.

## 这一篇算"用对了"吗

- [ ] 我在第一次重打包**之前**就跑了这套审计，而不是在签名请求失败之后
- [ ] 我的常量长度来自 `--live` 的读数，并写进了记录（含构建哈希）
- [ ] 我数过 read site（含 SDK 内部与 native 调用点），并在补丁后数了一遍做对照
- [ ] 我用一次真实的签名请求证明"通了"，而不是用"应用能启动"
- [ ] 我的报告里写了离线候选与运行时值的差异，以及为什么以运行时为准
