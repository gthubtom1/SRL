> 本篇范围：Tier 3–4 runtimes, using shipped scripts, off-PATH installs, signing, tool-failure traps, offline work, and recording.
> 前后篇：part 2/2 · prev [toolchain-1-tiers-and-capability-gaps.md](toolchain-1-tiers-and-capability-gaps.md) · next — · index [toolchain.md](toolchain.md)

# Toolchain — part 2/2

## Tier 3 — runtime and network

| Tool | Invoke | Notes |
|---|---|---|
| `frida` (host) + `frida-server` (device) | `frida -U -f <pkg> -l script.js` | **host and device versions must match** — skew produces errors that look like a broken target (`pitfalls-2-environment-and-evidence.md`) |
| `objection` | `objection -g <pkg> explore` | quick Java-layer poking on top of Frida |
| `mitmproxy` | `mitmproxy --mode regular` | request/response inspection; a device proxy is usually faster to set up than a transparent one |
| `HaE` (Burp extension) | load into Burp, then read its rule set | **traffic *triage*, not traffic capture.** See below |
| `adb` | everything | the primary device interface |

**HaE is a reader, not a capture tool, and it is not always the right next step.** HaE (Highlighter and
Extractor, `overspace-labs/HaENet`) is a Burp Suite extension that tags and extracts fields from HTTP
messages — tokens, IDs, secrets, endpoints, fingerprints — so that a large session becomes readable
without hand-scanning every request. It is genuinely useful when the bottleneck is *"there is traffic
and I cannot see the parts that matter."*

It is the wrong tool when the bottleneck is one of these three, and reaching for it there costs rounds:

- **The requests never leave the client.** No capture tool can display a request that was never built
  (`code-virtualization-and-custom-linkers.md` §what the native check actually reads). **Establish
  whether traffic exists before buying tooling to read it** — a DNS/`connect`-level probe answers that
  in a single run, and on the measured target it was the observation that ended the investigation
  branch, not a capture.
- **The body is encrypted by the app**, so the capture is ciphertext (`server-api.md`).
- **Certificate pinning defeats the proxy**, in which case the empty capture is itself the finding
  (`tls-and-cert.md`).

Ordering that follows: **first prove there is readable traffic, then choose the reader.** `mitmproxy`
captures; HaE triages; neither substitutes for the DNS/connect check that decides whether there is
anything to triage. Treat "install a Burp plugin" as a step that must be justified by an existing
capture, not as recon.

Version alignment for Frida is a **hard gate**, not a nicety. Check both sides before writing a
script, and check the device architecture — the server binary is per-ABI.

## Tier 4 — cross-platform runtimes

| Runtime | Identifier | Tool |
|---|---|---|
| Flutter / Dart | `libflutter.so` + `libapp.so` | `blutter` (needs the **matching Dart version**) — `dart-aot.md` |
| Unity / IL2CPP | `libil2cpp.so` + `global-metadata.dat` | Il2CppDumper + a native decompiler |
| React Native | `libhermes.so` / `index.android.bundle` | Hermes bytecode tooling, or plain JS if the bundle is unminified |
| Cordova / hybrid | WebView + `assets/www` | read the JS directly; Java layer is usually thin |

**A version mismatch here wastes the most time of any tool in this file.** A Dart decompiler built
for a different engine version produces output that is subtly wrong rather than obviously broken.
Pin the version first (`dart-aot.md`) and do not "try it and see".

## Using the kit's scripts instead of writing your own

The scripts exist so that the *expensive, generic* parts of this work — decoding a dex instruction at an
exact offset, recomputing a dex header in the right order, writing a 4-byte-aligned archive, resolving a
PLT stub, bursting screenshots with evidence attached — are not re-derived per task.

Re-deriving them is not neutral. A hand-rolled instruction decode that silently loses sync, or a
hand-rolled repack that quietly drops alignment, produces **a confident wrong answer**, which is the
exact failure class this skill exists to prevent. The cost shows up later, as a patch that "had no
effect" or an install refused with a bare numeric code.

**The rule: before writing a script, check whether one here already does it.** The index is in
`SKILL.md`; the entry points that matter most are `doctor.py` (what can run here),
`dex_find_insn.py` (get an exact offset instead of guessing one), `dex_patch_bytes.py` (apply and prove
an equal-length patch), `apk_diff.py` (prove your own build was surgical), `repack.py` (aligned rebuild)
and `snap.py` / `coldstart.py` (look at the screen with the evidence attached).

**When a script here is genuinely wrong, that is a finding to fix and report — not a reason to quietly
route around it.** Two live examples of the difference:

- A decoder utility in this kit carried an **opcode name/width table misaligned by one entry across
  `0x16`–`0x2C`** (23 rows). Everything decoding through that range **silently lost sync** and produced
  offsets that were plausible and wrong — no exception, no warning. It was found by comparing against an
  independent decoder and noticing a disagreement. **If two tools disagree, the disagreement is the
  product**; it is the cheapest bug signal in this domain and the easiest to throw away by picking the
  answer you preferred.
- Conversely, a *tool's* negative result is not a finding about the target (§the general trap below).
  Establish that the tool could have found the thing before recording that the thing is absent —
  especially for string searches, where an empty result is exactly what an unfound string looks like.

**Corollary for reporting.** "The kit's script X reported Y, and I cross-checked it against Z" is a
conclusion. "I wrote my own parser because the script was awkward" is a gap you introduced, and it
should be reported as one.

## "Not on PATH" is not "not installed"

`doctor.py` and `preflight.py` report whether each tool resolves on `PATH`. That
is a statement about `PATH`, not about the machine, and the difference has cost
real time: a full custom zip writer was built to work around a missing
`apksigner` that was already installed in an SDK directory nothing had added to
`PATH`.

**Before treating a tool as absent, search the filesystem once:**

```bash
# POSIX
find / -name apksigner -o -name zipalign -o -name baksmali.jar 2>/dev/null | head

# Windows (PowerShell) -- list every drive letter first, then search each
(Get-PSDrive -PSProvider FileSystem).Root |
  ForEach-Object { Get-ChildItem -Path $_ -Recurse -Depth 5 -ErrorAction SilentlyContinue `
      -Include apksigner.bat,zipalign.exe,keytool.exe }
```

Common places that are *not* on `PATH`:

| Artefact | Typical location |
|---|---|
| `apksigner`, `zipalign`, `aapt2` | any `build-tools/<ver>/` under an Android SDK, and portable tool bundles |
| `apksigner.jar` | inside those same directories (runnable as `java -jar`) |
| `keytool`, `jarsigner`, `javac` | a JDK install whose `bin` was never added to `PATH`; `java -XshowSettings:properties -version 2>&1 \| grep java.home` reveals the JDK root even when `keytool` does not resolve |
| `uber-apk-signer.jar`, `baksmali*.jar` | bundled with portable APK toolkits |

Record the resolved absolute paths once, in your running notes, and pass them to
the scripts that accept `--apksigner` / `--zipalign` / `--ks` style flags. Every
script in this repository takes an explicit path for this reason.

**A useful asymmetry:** missing `apksigner` is survivable (a v2-only signature
block can be appended without reordering the archive), but missing `zipalign` is
not a reason to hand-roll alignment either -- write the archive aligned in the
first place, as `scripts/repack.py` does. Prefer producing a correct archive over
repairing one afterwards: post-hoc alignment tools rewrite the file, which
changes every offset and can break a target that fingerprints its own layout.

## Signing: pick the signer deliberately

Two signers, and the choice changes the output bytes:

- **`apksigner`** (build-tools) appends the v2/v3 signature block after the zip
  content. It does **not** reorder entries, so a carefully aligned archive stays
  aligned. This is the default choice.
- **`jarsigner`** (JDK) rewrites the archive as a side effect of adding the v1 JAR
  signature, which recompresses entries and **destroys the alignment** that
  Android R+ requires. A build signed this way can fail to install with
  `Failure [-124] ... resources.arsc ... aligned on a 4-byte boundary` even though
  the same archive installed fine moments earlier, and `jarsigner -verify` reports
  success. If you have run `jarsigner` on an archive and a previously-working
  install starts failing, re-pack and sign with `apksigner` before investigating
  anything else.

Enable **v1 + v2 + v3**. v1 keeps very old devices working; v2/v3 are what modern
platforms actually verify, and v1-only builds are rejected in more configurations
than people expect.

## The general trap: a tool's failure is not a finding about the target

A missing jar, a version skew, a forged section header, and a genuinely absent symbol all produce
**empty or partial output**. The output looks the same; the conclusions are completely different.

Before reporting "there is nothing there", confirm the tool was actually capable of finding it:

- Did it read the file at all? (entry count, segment count, non-zero output somewhere)
- Does a **known-present** item show up? (search for something you already know exists — a symbol
  you saw in the dynamic table, a string you read in the hex dump)
- Would a different method see it? (byte pattern vs decoded scan)

**This is `pitfalls-2-environment-and-evidence.md` P25 and P26 in tool form.** A self-built analyser that fails quietly reads
exactly like a clean target, and it removes routes from consideration for free.

## Working without a network

Assume nothing can be downloaded. What still works, in order of usefulness:

1. Tier 0 in full, plus the Python standard library — enough for structure, strings, hashing, and
   most ELF/dex parsing.
2. Whatever jars and binaries are already present. **Locate them once and reuse the paths** rather
   than re-searching on every command.
3. A local package cache or an offline mirror, if the environment has one.

If a tool genuinely cannot be obtained, say which step is blocked and **what a substitute would
give up** — do not silently substitute a weaker method and report its result as equivalent.

## Recording the toolchain actually used

When you report, name the tools and versions that produced each finding. Two agents with different
tool versions will reach different conclusions about the same binary, and without the version that
difference is unresolvable later.
