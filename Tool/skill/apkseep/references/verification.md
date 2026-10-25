# Verification — what "done" means

The difference between a hobby patch and a usable deliverable is verification. "It assembles" and "the log is quiet" are not verification.


**Load this when:** you are about to claim the work is done, or you need to define done for a reviewer. It gives the claim ladder, the evidence chain, and what each deliverable form has to show before it counts.

## The claim ladder

Each rung is stronger evidence. Climb as high as the task requires, and **state clearly which rung you reached**.

| Rung | Claim | Evidence required |
|---|---|---|
| 0 | "The dex was edited" | Byte-level diff of the target method |
| 1 | "The structure is intact" | `dex_classdiff`: same classes, zero `ACC_INTERFACE` drift, unchanged classes byte-identical |
| 2 | "It builds and signs" | Signature verification passes |
| 3 | "It installs and launches" | Process alive, `logcat` free of fatal signatures |
| 4 | "The target behavior changed" | The specific feature observed changed (screen exercised, endpoint observed, UI confirmed) |
| 5 | "Nothing else regressed" | Adjacent features exercised: images, playback, lists, login, settings |
| 6 | "The mechanism is proven" | Independent evidence of *why* — e.g. the SDK's domains are never resolved because init never ran, or the SDK never created its working directory under the app's private storage |
| 7 | "The *distributed* artifact is the verified one" | Re-download the published file and compare its hash against the local build you tested |

**Rung 3 is the minimum for any deliverable. Rung 4 for a claim that the patch solved the problem. Rung 5 before handing it to a user. Rung 6 when the claim is "the subsystem is dead", not merely "the ad is hidden". Rung 7 whenever the deliverable leaves your machine — an upload can truncate, a build can be re-signed by a pipeline step, and the person downloading it has no way to know.**

## The control build rule

Before blaming a patch, build a control: **the same pipeline with zero patches**.

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python scripts/repack.py --apk original.apk --dexdir <extracted> --out control.apk
```

- Control fails → your pipeline, the environment, or the device is at fault. Stop debugging the patch (`pitfalls-2-environment-and-evidence.md`).
- Control passes, patched fails → the patch is implicated. Bisect: revert one dex at a time.

Do this **whenever something unexpectedly fails**, and at least once per project.

## Structural verification (automate it)

After every dex edit:

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python scripts/dex_classdiff.py <original.dex> <patched.dex>
```
Expect exactly:
```
only_in_A=0   only_in_B=0
ACC_INTERFACE mismatch: 0
access_flags diff (same interface-ness): 0
```

Caveat, and it is an important one: **this check cannot detect code-item damage.** A whole-tree smali round-trip can pass every table check and still crash with `IncompatibleClassChangeError` (`pitfalls-1-packaging-and-dex.md`). Passing this check is necessary, not sufficient.

The checks that *can* see further — instruction-length auditing, the equal-length-replacement blind spot, and verifier-level legality (`move-result*` adjacency) — are in `references/patch-audit.md`. Use them before claiming a patch landed.

Also confirm you changed what you intended and nothing more:
- Reverse the patched dex and inspect the target method.
- Compare unmodified classes byte-for-byte against the original where feasible.

## Runtime verification

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
adb -s <serial> logcat -c
adb -s <serial> shell "am start -n <pkg>/<activity>"
sleep 5; adb -s <serial> shell "pidof <pkg>"      # empty == died
sleep 20; adb -s <serial> shell "pidof <pkg>"     # same pid == stable
adb -s <serial> logcat -d -v brief | grep -E 'FATAL|VerifyError|IncompatibleClassChange|uncaughtException|Failure starting process'
```

**Sample the pid twice, spaced apart.** A single reading catches apps that die in a crash loop.

Failure signature → cause table lives in `references/environment.md`.

**Logcat is often not enough.** If the app installs a crash handler (友盟/UCrash/Bugly), the Java stack never reaches logcat. A process that dies with only `uncaughtException time: ...` and no stack **has crashed** — treat it as a failure, not as noise. Extraction techniques: `references/environment.md` §signal extraction.

## Behavioral verification (the part people skip)

Launching proves nothing about your change. Exercise it.

- **Ads removed** → open the screens that had ads (splash, home, detail, player, reward button). Confirm absence *and* confirm the screens still function. Use **three independent signals**, not one: the screens look right, the SDK's log tags disappeared, and the SDK never created its working directory under the app's private storage. An SDK that silently failed to fill an ad slot looks exactly like an SDK that was never initialised — only the last two signals tell them apart.
- **A gate patched** → walk the gated flow end to end.
- **A timeout/limit patched** → trigger it.
- **Data patched** → stop the app, clear/re-write the value, cold start, re-check (proves it is not an in-memory artifact).

**And then test the neighbours.** The most common real-world regression is a patch that fixed its target and quietly broke something unrelated:

- Images / cover art render?
- Video or audio playback works?
- Lists scroll and paginate?
- Login / session still valid?
- Settings screens open?
- Downloads still start?

This is exactly how a "generic image-card composable" patch removed all cover art while the ad still showed (`pitfalls-1-packaging-and-dex.md`).

## Screenshot discipline

Capture before/after screenshots for each claim. Text descriptions are not evidence; a screenshot of the screen without the ad, alongside one from the control build with it, is.

## Reporting

```
Build:          <path> <sha256>
Base:           <original apk name/version>
Changes:        <dex → what changed>, one line each
Structural:     dex_classdiff result (per dex)
Signature:      verified with --min-sdk-version 21 (v1/v2/v3); report the raw command, not just "ok"
Device:         <model / android / abi / rooted?>
Runtime:        pid stable over N s; no fatal signatures
Behavior:       <screens exercised>, <before/after>
Regressions:    <adjacent features checked>
Distribution:   <where it was published> re-downloaded, sha256 matches the tested build
Rung reached:   0..7
Residual:       <what is NOT fixed, and the exact reason>
```

**Be explicit about residuals.** "Ad X remains because it is delivered inside the screen's main data payload, and suppressing it at the transport layer takes the whole screen down" is a useful, honest result. Silently omitting it is not.

**Separate the two audiences.** The artifact goes to an end user; the analysis report goes to whoever asked for the work. User-facing notes stay neutral and practical — package name and version, install prerequisites, the signature-conflict warning (a different signer means the old install must be removed first), the checksum, and a scope/disclaimer line. Keep the mechanism, the patch points, and the reasoning in your own report, not in the file the end user opens.

## Anti-patterns

- Declaring success from a successful assembly.
- Claiming "no ads" from a quiet logcat when the SDK never printed anything either way.
- Concluding from a single launch without exercising the feature.
- Quoting emulator results as device results.
- Reporting a fixed feature without checking adjacent features.
- Hiding a known residual failure.
- Blaming your own patch for a failure the **unmodified original** also has — run the control build first.
- Accepting a UI automation result as proof when the interaction may never have fired: verify field contents and look for the actual request, not just the screen.
- Treating a feature-scoped network error as a patching problem before checking the server's certificate (`references/tls-and-cert.md`).

## Command block: the six done-items, as commands

The ladder says what to prove; this block is how each rung is actually observed. Copy it, replace the
placeholders, and keep the outputs — the outputs are the evidence, not the fact that you ran it.

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# rung 2/3 — the artifact's identity, then proof the device runs *that* build
sha256sum out.apk
adb install -r out.apk
adb shell "su -c 'pm path <pkg>'"                     # app-private path
adb shell "su -c 'sha256sum $(pm path <pkg> | cut -d: -f2)'"   # must equal out.apk

# rung 3 — launched, and it is *your* app in front
adb shell "am start -W -n <pkg>/<activity>"
adb shell "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'"
python scripts/coldstart.py --pkg <pkg> --duration 14 --interval 0.8 \n  --out ./shots --expect-activity <pkg>/<activity>   # timed burst + foreground warning

# rung 4 — the changed behaviour, observed directly (not via a log)
python scripts/snap.py --out ./shots/after --count 6
adb shell "uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml ."   # control tree, if usable

# rung 5 — the neighbours still work (pick the ones your patch could plausibly touch)
python scripts/apk_diff.py original.apk out.apk --summary             # prove the change is surgical

# rung 5/6 — the mechanism, where a "no ads" claim needs it: the SDK never initialised
adb shell "run-as <pkg> ls -la files/ cache/" 2>/dev/null | grep -i '<sdk-name>'
adb logcat -d | grep -c '<sdk-log-tag>'                              # n -> 0, not "I did not see it"
```

**Expected shapes:**

```
out.apk   sha256 = 4f1e...
/data/app/~~abc==/<pkg>-1/base.apk
4f1e...                                     <- same hash: the device is running your build
mCurrentFocus=Window{... <pkg>/<activity>}  <- your app owns the screen
pid 12345 alive at t+5s and t+25s            <- not a crash loop
<sdk-log-tag> 0                             <- the SDK's own lines are gone
```

| Rung | Command output that passes | Output that does **not** pass |
|---|---|---|
| 2 | `apksigner verify` prints the schemes actually enabled for the APK's `minSdk` | "verified" from a run that used a different `--min-sdk-version` (P13) |
| 3 | on-device hash equals local, pid alive at two samples, foreground is the target | install "succeeded" but hash differs (P18), or another app is in front (P40) |
| 4 | the feature is visibly changed in a capture you looked at | a clean `logcat`, a request count of 0, or the patch's own log line |
| 5 | the neighbouring screens you listed still render and fetch | "nothing else changed" without having opened them |
| 6 | the mechanism's side effect is absent (directory not created, domains never resolved) | the symptom is hidden while the mechanism still runs |
| 7 | the re-downloaded file's hash equals the tested build | a filename match, or "the upload said complete" |

## What passing looks like (通过长什么样)

One row per claim, because the claim and its evidence are what get reported — not the activity.

| Claim you want to write | Passing evidence | How it is usually faked |
|---|---|---|
| "The build on the device is mine" | on-device hash vs local hash, printed | "I installed it" |
| "It launches" | pid stable across two samples ≥ 20 s apart, foreground = target | `am start` returned without error |
| "The feature changed" | a capture you inspected, plus the before/after pair | the absence of an error |
| "Nothing regressed" | the list of neighbours you actually opened, each with a one-line result | "no crashes in logcat" |
| "The subsystem is dead, not hidden" | mechanism-level evidence (no init, no directory, no DNS) | no log lines from that subsystem |
| "The distributed artifact is the verified one" | re-download hash equals the tested hash | a successful upload |
| "It will keep working" | update path neutralised and re-verified after a relaunch (`updates-and-forced-upgrade.md`) | it works today |

## Rung 7 in practice: the artifact that leaves your machine

Rung 7 is the one people skip because it costs thirty seconds. It exists because a build can be
re-signed by a pipeline, truncated by an upload, or replaced by a cached copy on a mirror.

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# after publishing (substitute the transport you actually used)
curl -sL <published-url> -o /tmp/redownload.apk
sha256sum /tmp/redownload.apk out.apk        # both lines must match, byte for byte
apksigner verify --print-certs /tmp/redownload.apk | head -5
```

Passing: two identical hashes **and** the same certificate fingerprint as the build you tested. Anything
else means the artifact on the wire is not the artifact you verified — a state that is worse than not
publishing, because the difference is invisible to whoever downloads it.

## Failure modes of verification itself

- **Verifying the wrong artifact.** The hash check is what makes "I verified" meaningful; without it
  every later observation may describe the previous build (P24).
- **Verifying by absence.** "No error", "no ad SDK log line", "no crash" — all three are compatible with
  the feature never having run. Use a positive observation (a screen, a request, a value).
- **Verifying with one signal.** Three independent signals is the standard because each has a false
  positive: the screen can be cached, the tag can be quiet, the directory can be created lazily.
- **Stopping at rung 3.** "It installs and launches" is the minimum for a deliverable, not for a claim
  that the problem is solved.
- **Skipping the neighbours.** The regressions that reach users are never in the feature you changed.
- **Reporting rung 4 as rung 6.** "The ad is gone" and "the SDK never initialised" are different claims;
  only the second survives a config refresh.

## Verification budget by deliverable form

The rungs do not cost the same for the four forms in G1, and the expensive ones are not always the
stronger ones. Budget before you start, so "done" is reachable rather than aspirational.

| Form | Minimum rungs | The rung that is usually skipped | Cheap way to get it |
|---|---|---|---|
| Rebuilt installable APK | 3, 4, 5, (7 if distributed) | 5 — neighbours | one 5-minute pass over the six neighbour screens |
| LSPosed / Xposed module | 3 + the target's own log showing the effect | reading the target's log channel (not the module's) | `logcat` + the framework's file log, both |
| RPC / emulation service | a returned value equal to a reference value, on a named build | the reference value itself | call it once with the original app and record the output |
| Analysis report with a boundary | the evidence chain + the boundary | the boundary ("what was not determined") | write it before the last experiment |

**If a rung is unreachable**, say which one and why — "verified to rung 4 on a rooted emulator; rung 5
and 7 not done because the deliverable's device was unavailable" is an honest, useful result. Reporting
"verified" with no rung is not.

**The rungs are ordered by strength, not by cost.** Rung 5 is cheaper than rung 6 in almost every case,
and rung 7 is cheaper than both — which is why "I skipped it because it was expensive" is rarely true
for the rungs that actually get skipped. Price them before assuming.

## 这一篇算"用对了"吗

- [ ] 我报了到达的那一级（rung 0–7），而不是笼统地说"验证过了"
- [ ] 设备上的构建哈希与本地构建一致，且我在报告里贴了这两行
- [ ] 我的行为验证是**看过**的截图/界面，不是一个日志里的不存在
- [ ] 我列出了被检查的邻居功能，并逐个写了结果
- [ ] 交付物离开我的机器后，我重新下载并比过哈希（或明确标为未做，rung < 7）
