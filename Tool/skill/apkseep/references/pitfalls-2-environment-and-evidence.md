> 本篇范围：Pitfalls P9–P22 — environment blame, runtime vs static, evidence and single-variable discipline.
> 前后篇：part 2/5 · prev [pitfalls-1-packaging-and-dex.md](pitfalls-1-packaging-and-dex.md) · next [pitfalls-3-patching-and-artifacts.md](pitfalls-3-patching-and-artifacts.md) · index [pitfalls.md](pitfalls.md)

# Pitfalls — part 2/5

## P9. Blaming the patch when the device or environment is broken

**Symptom**
Every build fails, including a completely unmodified original.

**Root causes seen in practice**
- Device in a bad state: `Failure starting process` for *all* builds (including stock). **A device reboot fixed it.**
- Offline device: app shows a generic network error, easily mistaken for a server rejection or signature problem.
- App data directory uid mismatch after reinstall: crashes in a database-init path (`Cannot open database ... Directory ... doesn't exist`). Fix with `chown -R <uid>:<uid> /data/user/0/<pkg>`.
- Emulator that cannot run the app at all (different ABI, missing platform pieces). A working emulator is not evidence about a real device.

**Do instead**
**Always run a control.** Install and launch the **unmodified original** under the exact same conditions. If the original fails too, stop debugging your patch.

---

## P10. Trusting static decompilation over runtime behavior

**Symptom**
You patch what the decompiler showed, and nothing changes; or the app crashes in a path you did not know existed.

**Root cause**
Decompiler output is a guess reconstructed from bytecode. Interface/class relationships, inlined code, and obfuscated bridges are regularly misrepresented. Also, dead code and shadowed branches look identical to live ones.

**Do instead**
Rank evidence: **live runtime behavior > captured network traffic > served assets > current process/config state > persisted state > generated artifacts > source > comments and dead code.** Use source to *explain* runtime, not to *override* it.

---

## P11. Assuming a repackaged APK ships runtime data

**Symptom**
A fix verified on the target device does not work after a fresh install.

**Root cause**
Some fixes are **runtime data**, not code: a DataStore value, a preferences file, a cached token. Those live in `/data/data/<pkg>/` and are gone on a clean install.

**Do instead**
Ask, for every fix: *is this in the APK or in app data?* If it is app data and the deliverable is an APK, re-implement it as a **code-level** change (patch the read path so it always yields the desired value).

---

## P12. PowerShell (or any shell) eats device-side commands

**Symptom**
`adb shell "su -c '...'"` fails with host-side path or parsing errors: "Could not find a part of the path", "Missing type name after '['", unexpanded `$VAR`, or a regex that got mangled.

**Root cause**
The host shell expands `$`, `|`, `>`, and quotes **before** adb sees them. Windows PowerShell additionally mangles `$var:`, `[^"]` and `$(`.

**Do instead**
Never build device commands inline in the host shell. Either:
- call adb from a small script file (`scripts/devsh.py`), or
- put the device-side logic in a script that you push and execute.

Same rule for `javac`: always pass `-encoding UTF-8` when sources contain non-ASCII, or the compiler reads them as the platform default and fails.

---

## P13. Trusting `apksigner verify` output at face value

**Symptom**
You signed with v1+v2+v3 explicitly enabled, then verification reports:
```
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): true
```
Looks like v1/v2 silently did not happen, so you go re-engineer the signing step.

**Root cause**
`apksigner verify` decides **which schemes it is meaningful to check from the APK's own `minSdkVersion`**. When `minSdkVersion >= 24`, v1 is not required for install, and the tool reports it as `false` rather than "not applicable". The signatures are present and valid.

**Why it is hard to see**
Nothing in the output says "skipped because of minSdk". It reads exactly like a failure.

**Do instead**
Always verify with an explicit range so every scheme is evaluated:
```
apksigner verify --print-certs --verbose --min-sdk-version 21 --max-sdk-version 34 <apk>
```
Cross-check the fact independently: a real v1 signature means `META-INF/*.SF` and `META-INF/*.RSA` exist in the zip.

---

## P14. Treating same-size dex dumps as duplicates

**Symptom**
You deduplicate a memory dump by file size, keep one of each, and later find the kept dex is unusable (or silently wrong).

**Root cause**
Two dumps from the same process can have **identical byte length but different content** — different classes, even different dex version headers. One may additionally be structurally broken (header fields inconsistent with body, parser walks off the end of a table).

**Why it is hard to see**
Size equality is a tempting shortcut and is usually right for *file* duplicates. Here it is coincidence: two distinct dex objects were allocated to equal-length blocks.

**Do instead**
- Deduplicate by hash, never by size.
- Validate every candidate before trusting it: check the `dex\n0xx` magic, then sanity-check the reported `file_size` / `header_size` / map offsets against the actual byte length.
- Cross-check against the packing format when possible: with length-preserving encryption, **the encrypted payload's byte length equals the plaintext dex's byte length** — that mapping is the strongest signal for which dump is the original.

---

## P15. Frida version skew produces errors that look like a broken target

**Symptom**
Attach fails or the script dies immediately with errors such as:
```
unable to locate Android dynamic linker
Java is not defined
```
on a device where Frida is clearly running.

**Root cause**
A host `frida` package newer than the device's `frida-server` (or the reverse) is unsupported. Additionally, some newer host versions dropped the built-in Java bridge, so `Java.perform` is undefined unless you inline the bridge yourself.

**Why it is hard to see**
The error names the linker or a missing global, not a version mismatch. It reads like an Android compatibility problem or an anti-instrumentation defense.

**Do instead**
- Pin host package and device server to the **identical** version before debugging anything else. Print both versions side by side first.
- If the target is an older Android release, prefer the oldest version that still supports your API needs rather than the newest.
- On a device with multiple attached targets, do not rely on automatic USB selection — see `references/dynamic-frida.md`.

---

## P16. Blaming your own patch for a server-side TLS failure

**Symptom**
After repacking, the app launches and browsing works, but **login / registration** fails with a network error. The obvious suspect is the new signature breaking the API contract, so you start hunting for a signature check in the client.

**Root cause**
The failure is at the TLS layer, not the application layer: the API host's certificate is expired (or the chain does not validate), and that particular request path validates against the **system trust store**. Shipping a different signature is irrelevant.

Crucially, one app can carry **two independent trust chains**: requests through the app's own HTTP client (which may install a permissive `SSLSocketFactory` and `HostnameVerifier`) succeed, while requests through `java.net.URL.openConnection()` use the system defaults and fail. That is why "some features work" and "login does not".

**Why it is hard to see**
The user-visible message is a generic "network error". The real exception is usually swallowed by the app's own `try/catch`. And a client-side patch is the most recent change, so it gets blamed by default.

**Do instead**
- Capture the whole exception chain before theorizing. The give-away is
  `CertPathValidatorException: timestamp check failed` → `CertificateException: Chain validation failed` → `SSLHandshakeException: Chain validation failed`.
- Confirm independently of the app: strictly validate the host's certificate from your host machine and check `notAfter` against the device clock. See `references/tls-and-cert.md`.
- Run the control: does the **unmodified original** fail the same way on the same device and network? If yes, it was never your patch.

---

## P17. Trusting UI automation to prove whether a patch worked

**Symptom**
Your script taps a button, nothing happens, and you conclude the patch broke the control. Or you tap, see no visible change, and conclude the feature is dead.

**Root cause**
Device input and screenshots are far less reliable than they look:
- `input tap` can silently fail on specific widgets even with correct coordinates (ROM-dependent).
- `input` needs `INJECT_EVENTS`; under a plain shell it fails quietly.
- `screencap` can return a **zero-byte** file on some ROMs.
- Form submission can be rejected by local validation before any request is made, so "the button does nothing" is a validation failure, not a broken handler.

**Why it is hard to see**
All of these produce the same observable: nothing happens. A zero-byte screenshot often goes unnoticed and is treated as "no change".

**Do instead**
- Read back the widget tree (`uiautomator dump`) instead of trusting pixels: it gives real `bounds`, control text, and **field contents with lengths**. Verify every field is populated correctly *before* submitting.
- Compare field values, not just presence — one case that burned an hour was two password fields of different length, causing local validation to `return` before any network call.
- Treat "no visible change" as unproven, not as a negative result: confirm with an independent signal (logcat, a runtime probe, or a server-side request appearing in the capture).
- If a tap does not register, fall back to launching the Activity directly or invoking the handler, rather than retrying coordinates.

---

## P18. The package manager reported success, but the build was never installed

**Symptom**
Every install logs `Success`, so you run the next experiment and read its result — but the app being
tested is still the previous build. Screenshots show stale UI or the launcher, and results look
"unchanged".

**Root cause**
On many ROMs a package installer interposes its own confirmation. The install command can return success
for the *request*, while the actual install waits on a prompt — sometimes a password or account
confirmation — that nobody fills in. The app stays at its old version indefinitely.

This is the most expensive failure in this skill's history: because the command "succeeded", the stale
behaviour was measured across many rounds, and each measurement looked like a genuine negative result.

**Why it is hard to see**
The success signal is real; it just answers a different question than the one you asked. Nothing in a
normal install/launch script distinguishes "installed" from "install requested".

**Do instead**
- After installing, **prove the artifact changed**: compare `dumpsys package <pkg> | grep -E 'versionName|lastUpdateTime'` before and after, or hash the on-device APK and compare it to what you built.
- If a confirmation UI exists, drive it explicitly (type the credential, press the confirm control) and then re-verify.
- Make the check a precondition of the run, not an afterthought: if the version did not change, **abort** rather than measuring.
- Keep build artifacts named after the change they contain so a stale install is obvious from a screenshot.

---

## P19. Substituting an internal signal for the user-visible outcome

**Symptom**
An error disappears from the log, no crash is recorded, and you report the problem solved. The user
immediately shows you the same problem still on screen.

**Root cause**
The internal signal and the user-visible outcome are different claims. Suppressing one error path does
not remove the symptom if the symptom is produced by a **different** path — and a blocking dialog often
is. The log going quiet proves that one code path was affected; it says nothing about whether the user's
problem is gone.

**Why it is hard to see**
The signal is specific, measurable, and genuinely changed. It is a true statement being used to support a
false one.

**Do instead**
- Define "done" as the **user-visible behaviour**: the blocking UI is gone, the app reaches its normal
  screen, the feature works. Nothing else counts.
- Treat the absence of a log line as absence of evidence, never as evidence of success.
- When a symptom persists after an internal signal improves, assume there is **another** producer of the
  symptom and go find it, rather than assuming your fix is merely incomplete.
- Also verify the opposite direction: confirm the original symptom is reproducible **before** you patch,
  so you know what disappearing would even look like.

---

## P20. "I did not capture it" treated as "it is not there"

**Symptom**
Screenshots taken every few seconds after launch show no blocking dialog, so the dialog is declared gone —
then it turns out to be present the whole time.

**Root cause**
Sampling is not observation. A transient state that appears and is then covered (a second window, a
navigation, a system prompt) can fall entirely between samples. The modal appears, gets occluded, and
every frame you happened to take shows something else.

**Why it is hard to see**
The captures are real and consistently show the same thing, which feels like corroboration. Conviction
grows with the number of frames, even though all of them share the same blind spot.

**Do instead**
- For anything time-sensitive, capture **continuously** (recording) or in a dense burst immediately after
  launch, not on a fixed slow interval.
- **Look at every frame**, not only at file sizes. A byte-size cluster that "looks familiar" is not a
  reading.
- State conclusions with their sampling: "not observed in N consecutive seconds of recording" is honest;
  "does not occur" is not.
- When something is reported present by a human who is looking at the screen, believe the screen. Your
  capture gap is the more likely explanation.

---

## P21. Changing two things at once, then attributing the result

**Symptom**
A build fails, and you conclude that the mechanism you were most curious about is the culprit — then
exclude it from consideration for a long time. Later, a clean experiment shows it was the other change
all along.

**Root cause**
Two edits, one observation, no attribution. The failure is real; the explanation is invented. Worse, the
invented explanation survives because it sounds plausible and no one re-tests it.

**Why it is hard to see**
The experiment "worked" in the sense that it produced a result. Acting on a wrong attribution feels
exactly like acting on a right one until much later.

**Do instead**
- One variable per install-and-launch cycle. Where a combination is unavoidable, add a third run that
  isolates each half.
- Write the attribution into your notes **with the run that proves it**. An unproven cause is a
  hypothesis; keep it labelled as one.
- When a route is about to be discarded, re-check whether the evidence was actually single-variable. A
  discarded route with compound evidence should be re-opened before being abandoned.
- Prefer semantically inert controls (a change nothing reads) to prove "edits of this class are allowed"
  separately from "this specific edit is allowed".

---

## P22. Waiting for something that requires a human to advance

**Symptom**
An automation loop polls for minutes or longer, waiting for a state that never arrives on its own. Time
is consumed while nothing at all can change.

**Root cause**
The awaited state is gated on a human action — a consent prompt, a permission dialog, an installer
confirmation, a captcha. No amount of waiting resolves it. Automated polling is the wrong instrument for
a state whose transition is external.

**Why it is hard to see**
Polling is cheap-looking and the loop reports progress (timestamps, unchanged screenshots), which creates
an impression of work being done.

**Do instead**
- Before waiting on a state, ask what would cause it to change. If the answer is "a person", stop waiting
  and either perform the action programmatically or hand it back.
- Bound every wait with a deadline and an explicit failure branch that **does something different**, not
  just a longer timeout.
- Detect stalls by change, not by elapsed time: if N consecutive samples are identical, break out.
- Prefer driving the prompt to completion over waiting it out — the same prompt usually recurs, so
  automating it once pays back immediately.

---

