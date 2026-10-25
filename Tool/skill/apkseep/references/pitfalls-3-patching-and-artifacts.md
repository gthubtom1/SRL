> 本篇范围：Pitfalls P23–P30 — rewritten data, wrong artifact executing, search/observation false negatives.
> 前后篇：part 3/5 · prev [pitfalls-2-environment-and-evidence.md](pitfalls-2-environment-and-evidence.md) · next [pitfalls-4-native-and-install.md](pitfalls-4-native-and-install.md) · index [pitfalls.md](pitfalls.md)

# Pitfalls — part 3/5

## P23. The fix lives in a file the app rewrites

**Symptom**
You change a value in the app's data, the write succeeds, the file reads back correctly — and after
the next launch the value is back to what it was. Often byte for byte identical, which makes it look
like nothing happened at all.

**Root cause**
The stored value is a **cache, not a source of truth**. Either the app re-fetches it and re-persists
it, or it rewrites the file from its own defaults on every start. Your edit was never authoritative.

Compounding it: the intuitive way to protect the file — a restrictive mode or a changed owner — **does
not work**, because the app does not open-and-write the existing file. It **deletes the file and
creates a new one**, and a new file is created with the app's own mode and owner. Nothing is inherited,
so `chmod`/`chown` are silently ineffective.

**Why it is hard to see**
Verification is usually done immediately after writing, while the file is still correct. The rewrite
only happens on the next start, which is one step further along than you looked. And the "fix" that
seems obviously right (tighten permissions) fails without any error.

**Do instead**
- **Verify after a relaunch, not after the write.** The write succeeding is not the finding; surviving
  a restart is.
- **Distinguish the two causes with one offline launch.** If the value survives with the network down,
  it came from the server. If it does not, the app is regenerating it locally — and then a data edit is
  the wrong layer entirely; patch the read path instead.
- To make a data edit stick, use the **immutable attribute** and confirm it took effect:
  ```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
  su -c "chattr +i <file>"; su -c "lsattr <file>"     # expect the 'i' flag
  ```
  It is enforced by the filesystem against the delete itself, which is why it holds where permissions
  do not. Undo with `chattr -i`.
- Then **exercise the feature**, not just the value. A blocked write the app depends on can make it
  misbehave; "the file still has my value" is not "the app still works".
- Remember a lock is **device state, not artifact state** — it does not travel with an APK. Record it
  as an environment requirement. The only form that ships is a code patch (`runtime-data.md`).

---

## P24. The artifact changed, but the wrong one is executing

**Symptom**
The build differs from the original, the pipeline reports success, the file on disk is genuinely
modified — and the app behaves exactly as before. Or a native hook reports nothing while the feature
plainly runs.

**Root cause**
Something other than your edit is being used at runtime:

- **Wrong ABI.** A fat APK ships several `lib/<abi>/` directories; the package manager extracts and
  loads **one**. Editing `arm64-v8a` while the device loads `armeabi-v7a` produces a byte-different,
  behaviorally identical build.
- **The library is not from the APK at all.** Some libraries are written into the app's data directory
  at runtime rather than extracted from the package. Patching the APK copy changes a file nobody loads.
- **Multiple processes.** The work was done in, or the check lives in, a different process than the one
  you are observing.
- **A stale install.** The package manager reported success for a request that did not replace what is
  on disk (`P18`).

**Why it is hard to see**
Every local indicator agrees: the diff is non-empty, the build is signed, the install returned success.
Nothing in the *build* pipeline can detect this, because the build is fine. The contradiction only
exists at runtime.

**Do instead**
- **Ask the running process what it loaded**, before editing: `scripts/lib_map.py --pkg <pkg>`.
  Libraries whose path is not under the installed APK's lib directory were materialized at runtime
  and belong to whatever produced them.
- Confirm the ABI the package manager actually chose (`dumpsys package <pkg> | grep primaryCpuAbi`)
  rather than the one you assumed from the manifest.
- **If the library you patched is not in the live mapping, stop.** No amount of re-patching helps; the
  plan is wrong.
- Treat a behaviorally identical rebuild as **positive evidence that your edit is not being loaded**,
  not as "the change had no effect". Those are different conclusions and only one of them is actionable.

---

## P25. "The search found nothing" treated as "the data is not there"

**Symptom**
You scan an artifact for a known-present value — a UI label, a marker string, an endpoint — get zero
hits, and conclude the content is stripped, encrypted, or otherwise unavailable. A route gets written
off on that basis.

**Root cause**
The search used the wrong representation. A byte scan for UTF-8 text returns nothing against content
that is stored as UTF-16, or compressed, or framed inside a container, or split across fragments. The
data is present; the needle was encoded differently from the haystack.

**Why it is hard to see**
"Zero results" is a clean, confident-looking output. It feels like a measurement, so it gets recorded
as a finding, and findings propagate into the plan.

**Do instead**
- **Before concluding absence, search more than one encoding.** UTF-8 and UTF-16LE will between them
  cover most text storage:
  ```python
  blob.find(needle.encode('utf-8')), blob.find(needle.encode('utf-16-le'))
  ```
- **Search the shortest distinctive fragment.** Text is often assembled from pieces or templates, so a
  full sentence can be absent while its parts are present.
- **Try the value without its framing.** A hit rate of zero is also the expected result for content
  that is inside a compressed or encoded container — decode the container first (`runtime-data.md`,
  `scripts/blob_decode.py`).
- **State a negative result with its scope**: "no UTF-8 or UTF-16LE literal match in this artifact"
  is a finding. "The string does not exist" is a guess wearing a finding's clothes.

## P26. A self-built analysis script fails in a way that reads as a target finding

**Symptom**
A purpose-written script emits something that looks like a result -- an offset table, a count, a
"no matches" verdict -- and it is wrong. Nothing in the output says so, so it gets recorded as a
finding and the plan is built on top of it.

**Root cause**
Three variants, all hit in a single project:

- **A silent arithmetic error.** `(w >> 10) & 0xFFF << 12` binds as `& (0xFFF << 12)` in Python, so
  the intended mask silently became a different one. The script ran clean and printed a plausible
  table; every offset in it was wrong.
- **A helper script shadowing a stdlib module.** A local file named `dis.py` captures any
  `import dis` performed inside a third-party package. The symptom appears as a circular-import
  error *inside that package*, which reads like a broken dependency rather than a local name clash.
- **Measuring against an incomplete reference.** A "precision" number computed against a partial
  listing reports the reference's gaps as your errors. Here it scored a working extractor at ~30%
  when the reference itself was the incomplete side.

**Why it is hard to see**
The tool is trusted by default, because you wrote it for this exact job. Its output is well-formed
and arrives fast, which reads as competence.

**Do instead**
- **Sanity-check the shape before the content.** A ratio or distribution that is implausible for the
  domain is a bug signal -- e.g. an average of 31 references per offset when the rest of the picture
  implies ~3.
- **Cross-check against an independently built artifact.** Two independent producers agreeing to
  ~99% is evidence; one producer's own output never is.
- **Histogram before choosing a threshold, and re-measure after changing it.** If moving a knob does
  not move the metric, the knob is not doing what you think (a run-length filter here barely changed
  accuracy across a 10x range, which is how it was caught).
- **Exercise any fallback path against a case whose answer is already known.** An accuracy claim
  derived only from the tool's own output means nothing.
- **Name helpers so they cannot shadow a module** (`dart_disasm.py`, not `dis.py`), and keep a
  timeout on every scan (SKILL.md).

---

## P27. Every request fails after a repack because the signing certificate *is* the key

**Symptom**

The rebuilt app installs, launches, and draws its shell — but every API-backed screen shows a
generic network error. Computed request parameters (`sign`, `_p`, `uth`) come out as `-1`,
empty, or null. No Java exception anywhere, and the app's own UI still looks healthy.

**Root cause**

The client uses **its own APK signing certificate as key material**: it reads
`PackageInfo.signatures[0]` and hands that value to a native HMAC/DES routine which produces the
request signature. Re-signing changed the certificate, so the derived key changed, so the server
rejects every signed request. This is not "the server checks the signature" — the *client* is
computing with it, and the server was built against the original key.

**Why it is hard to see**

It reads as a server problem or a bad patch. The artifact is valid, the patch is correct, the
build verifies, and the app runs — so the natural conclusion is "a client patch is not possible
here", which sends you back into static analysis for hours. A naive fix also survives inspection:
hardcoding *a* signature value produces correct-looking smali and a clean build, and nothing
complains until a request is actually sent.

A second trap sits inside the first: `signatures[0].toByteArray()` is **not** the
`META-INF/*.RSA` file. On modern Android it is a certificate DER taken from inside the PKCS#7
chain. Hardcoding the whole `.RSA` content (1199 bytes in one measured sample) instead of the
runtime value (777 bytes) yields a build in which every signing parameter is `-1`.

**Do instead**

1. **Detect it before repacking.** Grep the decompiled sources for `toCharsString()`,
   `getPackageInfo(..., 64)` and `signatures[0]`. If the value feeds a native method that also
   does HMAC/AES/DES, this pitfall applies.
2. **Read the real value from the device**, not from the file —
   `python scripts/sig_probe.py --live <pkg>`. Cross-check the candidate list from
   `scripts/sig_probe.py --apk <original.apk>`; the runtime length decides which candidate is
   correct.
3. **Hardcode it at every read site** (there is usually more than one), then assert the remaining
   site count is zero.
4. **Prove it differentially.** Print the computed signing parameter for the same startup request
   on the original build and the rebuilt one. Same shape ⇒ consistent. `-1`/empty ⇒ the key is
   still wrong.
5. **Check the OAID/device-id path too** — it frequently hashes the same certificate separately.

Full treatment: `references/signature-derived-keys.md`.

---

## P28. `logcat -c` does not clear the events buffer, so the previous build's crash looks like this build's

**Symptom**

After installing a fix, a search for the crash signature returns a hit. It looks like the fix did
not work — and the "hit" is convincing, because it is the exact exception and the exact frame you
were fixing.

**Root cause**

`adb logcat -c` clears `main`, `system` and `crash` **by default — not `events`**. The
system's own crash record (`am_crash`, `am_proc_died`) lives in `events`. Reading `-b all`
therefore pulls in the previous build's crash, which was never cleared.

**How to tell it apart**

Correlate **PID and wall-clock time** against the current process:

- The PID in the record belongs to a process that is no longer running.
- The timestamp **predates** the current process's start.

Both together mean history, not a finding. (In the observed case the stale record's PID was the
previous build's, and its timestamp was minutes before the current process started.)

**Do instead**

Pick one, and say which you used:

- Bound the query by timestamp — accept only records after the current process started, or
- Judge per buffer — `crash` is a fresh window after `-c`; `events` requires PID/time correlation.

**The evidence window is itself a claim that needs support.** An unexamined stale window turns
"fixed" into "still broken", and this one is invisible in the log's own text.

---

## P29. The patch landed and changed nothing, because the static data it edited is not the data the UI consumes

**Symptom**

Build is green. The patch is verifiably present in the artifact. The behaviour is unchanged.

**Root cause**

**The same type had two construction sites** — one for a static/default template, one inside the
runtime conversion of a server response — and only the second one feeds the UI. Editing the first
is a no-op that verifies cleanly and audits cleanly.

**How to see it before shipping**

From the type's constructor, count the call sites (`scripts/find_refs.py`), then ask of each:

> **Is this one on the path the UI actually reads?**

"It is constructed here" is not "it is consumed here". Two constructors of the same type can have
completely different fates.

**Do instead**

- Patch the **consumer** — the loop that converts response items into the UI model — not the
  static table.
- Prefer a predicate over a **semantic discriminator** (a business code, a task type) rather than
  a display string. The literal in the template is **not** necessarily the literal the server
  sends: the string you want to match may not exist anywhere in the response.
- If you cannot confirm the server-side value, **predicate on both candidate fields** rather than
  betting on one.

---

## P30. Two observations that cannot distinguish the hypotheses, reported as a result

**Symptom**

A verification step "passes" or "fails" while having tested nothing.

**Root cause**

The observable is identical under both hypotheses, so the measurement carries no information.
Real instance: a promotional banner was absent in the logged-in state, and that run was used to
"verify" its removal — but the same banner is also absent in the logged-out state. Neither run
could distinguish an effective patch from a no-op, and the second one was skipped as
"uninformative" — correctly, since it could not have been informative either.

**Do instead**

Before running a verification, ask:

> **What would this look like if the patch were absent?**

If the answer is the same, the measurement is void. Record it as **"not applicable under this
condition"**, never as "passed".

Two close variants of the same error:

- Treating **"the entry point is unreachable"** as proof of removal. The honest test is whether
  the **request is still issued**: a UI element that no longer renders can still fire its network
  call from elsewhere. Verify at the layer the behaviour actually lives on.
- Treating **"the screenshot hash changed"** as proof that something rendered. A hash proves
  *change*, never *what* changed — and it never proves *absence*. Look at the images: a status-bar
  clock tick or a line of text reflowing changes the hash while a full-screen overlay would not
  have been missed if the frames had actually been inspected.

---

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
