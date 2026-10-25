> 本篇范围：hook-never-fires debugging, dead `Java.choose` instances, obfuscated runtime code, anti-instrumentation, and capture.
> 前后篇：part 2/2 · prev [dynamic-frida-1-setup-and-probe.md](dynamic-frida-1-setup-and-probe.md) · next — · index [dynamic-frida.md](dynamic-frida.md)

# Dynamic analysis with Frida — part 2/2

## Hook never fires — debug in this order

`HOOK-SKIP` / `HOOK-FAIL` lines answer this before you start guessing. When every layer reports `HOOK-OK` and still no event arrives:

1. **Does the class / method / overload actually exist?** A misspelled obfuscated name, a renamed okhttp internal class, or an overload taking `Object` instead of `String` all produce a wrapper that is simply never invoked.
2. **Is the ClassLoader the right one?** Multi-dex, plugin-loaded and packed apps can hold several loaders; `Java.use` uses the app loader by default and throws `ClassNotFoundException` for a class that is plainly in the APK. Enumerate and switch:
   ```javascript
   Java.enumerateClassLoaders({
     onMatch: function (l) { try { if (l.findClass('<app.net.Class>')) Java.classFactory.loader = l; } catch (e) {} },
     onComplete: function () {}
   });
   ```
3. **Is that code path reached at all?** Layer 4 settles it: if `THROW` events show the app failing earlier, your hook's call site is never executed and no amount of hooking will help.
4. **Did your UI action trigger business logic?** A tap that looks fine but fails a local form check returns before any network call. Verify the input actually reached the field (`references/environment.md` §Driving the UI from adb), not just that the button animated.

## `Java.choose` also matches dead instances

`Java.choose('com.example.app.MainActivity', ...)` returns **every** instance the VM still tracks, including finished and destroyed ones. Walking their view tree then yields an empty list — that is normal, not a bug in your script. Filter first, and prefer a direct reflective call over simulating a tap:

```javascript
Java.choose('com.example.app.MainActivity', {
  onMatch: function (a) {
    try {
      if (a.isFinishing() || a.isDestroyed()) return;     // dead instance: skip it
      send({ tag: 'live', view: '' + a.findViewById(<viewId>) });
    } catch (e) {}
  },
  onComplete: function () {}
});
```

## Reading obfuscated code at runtime

When names are meaningless (`a7`, `x6`, `uf0`), do not patch from names. Instead:

1. Find a **unique anchor**: an API path, a preference key, or an SDK class name from the string table (`scripts/dex_strings.py`).
2. Locate the small class/method that references it (byte search in the dex + a targeted disassembly).
3. Hook that anchor, capture the **stack**, and read off the real chain.
4. Hook the classes the stack reveals — that is where semantics become visible.

## Anti-instrumentation

Signs: the app exits or freezes shortly after attach; `logcat` shows a generic process death with no Java stack; strings like `frida`, `xposed`, `magisk`, `substrate` are referenced by **app code** (not just by an SDK's string list).

**Rule this out first — it is not always a detector.** A process that dies right after you
attach is frequently the ROM rather than the app: on aggressive OEM ROMs, merely backgrounding
the app (pressing HOME, switching away) triggers a freeze, and the logcat signature is a state
transition such as `state: R -> F` while hooks stop with no Java stack. That looks identical to
a detector killing you. Check `references/environment.md` for that signature, and keep the app
in the foreground, before building an anti-anti plan.

Countermeasures, in order of least disruption:
1. Spawn + late resume, so hooks are installed before the check runs.
2. Rename `frida-server` and move it out of obvious paths.
3. Hook the detector itself and neuter it — find it by hooking the suspicious API (e.g. `/proc/self/maps` reads, `File.exists`, `Runtime.exec`) and inspecting the stack.
4. Only then consider a gadget-based approach.

**Remember:** most `frida`/`root` strings in a decompiled APK belong to third-party SDKs' own detection lists, not to the app. Verify that **app code** references them before doing anti-anti work.

### When the ROM hunts your instrumentation

Some vendor ROMs treat a device-side `frida-server` as hostile and kill it on a timer. The
symptom is not an error message — it is a working session that disappears. A later
`attach`/`spawn` fails with `unable to connect to remote frida-server`, or with
`TransportError: connection closed` **during `spawn`, before `resume`**. That second shape is
easy to misread as the target crashing during startup. It is not the target.

Measured on one vendor build: the server was killed repeatedly across a work session, and on
one occasion the whole device restarted, briefly taking `system_server` with it
(`Can't find service: activity`, `No service published for: input`). Both symptoms are
environment, not evidence about the app.

- **Check the server is alive immediately before every experiment**, not once per session:
  `adb shell "su -c 'pidof <server-name>'"`. Restart it if it is gone.
- **Distinguish the two failure shapes.** `connection closed` at `spawn` = server died or was
  killed (environment). `connection closed` just after `resume` = the target exited — *that*
  one is about the app.
- **Rename the server binary and move it off the obvious path.** It defeats simple filename
  sweeps. It does not hide from a target that lists the directory, so do not treat the rename
  as a fix for detection — only as protection from cleanup.
- **Budget a restart, not a re-analysis.** A killed server costs seconds; a round spent
  re-deriving the previous conclusion costs far more.
- **If a device reboot interrupts the run, re-establish state before measuring**: server up,
  `adb forward` re-created, screen awake and unlocked, installed-build hash re-read. A
  measurement taken across a reboot is a measurement of two states
  (`long-task-discipline.md` §keep the observation window clean).

### When live attach cannot work at all

Sometimes nothing short of "do not inject at runtime" is viable — the check runs
before your hooks can, it watches its own process, or the environment forbids
`ptrace`. Do not keep escalating on the same axis. There are non-live ways to get
runtime-grade information, and they are often enough to finish the job:

| Alternative | What it gives you | Cost |
|---|---|---|
| **Static instrumentation** — load a gadget/small agent by modifying the APK (e.g. an injected `Application` wrapper, a gadget `.so` added to `lib/<abi>/` and wired from the manifest) | Hooks run from process start with no external attach, no `ptrace`, no server process on the device to be found | Must repack and re-sign; the build you observe is no longer byte-identical to the original, so **it cannot serve as the unmodified control** (`verification.md` §the control build rule) |
| **Static read of the answer** — the check's inputs are usually visible: the field it reads, the string it compares, the response field it trusts | Often enough to plan a patch without ever observing | You do not learn the live values; combine with `runtime-data.md` for local state |
| **Self-recorded evidence** — the app's own cached responses, logs, or on-disk state | Real runtime data with no injection at all (a HTTP cache, a pref, a JSON snapshot left behind by a normal launch) | Only what the app happened to persist; needs one clean launch and then a filesystem read |

The last one is worth remembering because it is the cheapest and it is easy to
forget: a normally-launched app often leaves the exact runtime data you wanted —
server responses in its HTTP cache, config in a preferences file, feature state in
a snapshot. Read those **before** concluding that dynamic analysis is blocked.

**Two cautions that apply to every alternative above:**

- **Changed bytes change behaviour.** Any injected build is a different artifact,
  and on a target that fingerprints its own layout that difference is the finding,
  not the app's real behaviour. Always keep the unmodified run as the control.
- **Evidence from a different environment is a different claim.** A result obtained
  with the app patched-for-injection, or on a device with different privilege state,
  supports "verified under condition X". Say so; do not present it as the app's
  unmodified behaviour (`long-task-discipline.md` §the most expensive drift).

## What to capture for the record

- spawn time, hook-ready time, resume time
- every hook hit with a stack (bounded — cap output)
- DNS hosts in order, with timestamps
- the exact build under test (hash) and the control build's results

## Command block: the three checks that decide "never fires" vs "never ran"

The order in the section above is only useful if each step produces a number. These are the three that
do; run them before touching the hook.

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 1) is the class even in the loaded set? (counts, not names)
frida -U -f <pkg> -l /dev/stdin <<'JS'
Java.perform(function () {
  var hits = 0, total = 0;
  Java.enumerateLoadedClassesSync().forEach(function (n) {
    if (n.indexOf('<pkg-prefix>') === 0) { total++; if (n.indexOf('<TargetClass>') >= 0) hits++; }
  });
  send({tag: 'CLASSES', pkg_prefix: total, target_matches: hits});
});
JS

# 2) how many class loaders are there, and which one can find the class?
frida -U -f <pkg> -l /dev/stdin <<'JS'
Java.perform(function () {
  var i = 0, found = [];
  Java.enumerateClassLoadersSync().forEach(function (l) {
    i++;
    try { if (l.findClass('<TargetClass>')) found.push(i); } catch (e) {}
  });
  send({tag: 'LOADERS', count: i, can_find: found});
});
JS

# 3) did the process die before the hook could run? (time-to-death, from the outside)
adb shell "su -c 'pidof <pkg>'" ; sleep 1 ; adb shell "su -c 'pidof <pkg>'" ; sleep 1 ; adb shell "su -c 'pidof <pkg>'"
adb logcat -d --pid=<pid> | tail -20
```

**Expected shapes, and what each combination means:**

| 1 `target_matches` | 2 `can_find` | 3 alive after 2 s | Verdict | Next |
|---|---|---|---|---|
| 1 | `[n]` (one loader) | yes | hook target is valid and reachable: the *call site* is not reached | verify the UI action actually triggers the path |
| 1 | `[]` (no loader finds it) | yes | the class exists but not for the default factory: switch the loader (the snippet in §2) | re-run with `Java.classFactory.loader = l` |
| 0 | `[]` | yes | the class is not loaded **yet** — hook earlier, or hook the loader | spawn-gate, or hook `ClassLoader.loadClass` |
| 0 | `[]` | no | the process dies before the class loads | this is not a hooking problem: `native-tamper-and-suicide.md` / `detection-and-anti-analysis.md` |
| 1 | `[n]` | no, dead at ~300 ms | the check ran before your hook: spawn + late resume, or static instrumentation | §"when live attach cannot work at all" |

That table is the whole point of this section: **four different findings that all present as "zero
events"**, separated by two counts and one liveness probe.

## What passing looks like (通过长什么样)

| Claim | Passing | Not passing |
|---|---|---|
| "The hook is installed" | the script reports one `HOOK-OK` per target **and** the class/overload resolution counts match | the script loaded; the wrapper exists |
| "The hook fires" | an event with a stack, from a real UI action you triggered | a hit at process start that never repeats (likely a loader-time call, not the feature) |
| "The instance is live" | `!isFinishing() && !isDestroyed()`, and the view tree is non-empty | `Java.choose` found an instance — it also finds dead ones |
| "The code is obfuscated, not missing" | the anchor string exists and a class references it; names are non-semantic | "the names are `a.b.c`, so I cannot proceed" |
| "Something detected me" | a *control run* of the unmodified original dies the same way, or the check is named and timed | the process died while instrumented and nothing else was compared |

## The anti-instrumentation ladder, with what each rung can prove

Rungs are ordered by cost, and **each rung needs a different observation** — that is why "the app hates
Frida" is not a finding.

| Rung | Observable | What it proves | Cost |
|---|---|---|---|
| the ROM froze the app | `state: R -> F` in the activity manager, hooks stop with no Java stack, foreground/background changes it | nothing about the app | one HOME press, one logcat line |
| a library was swept | the server binary disappears; `connection closed` **at spawn** | the environment hunts instrumentation | one `pidof` before each run |
| the app checks the environment | a named API with a caller module + offset (`anti_detect_probe.js`), timed | the check exists and *where* it runs | one observer-only session |
| the check runs before your hooks | death within ~300 ms of `resume`, no Java frames | the ordering, not the mechanism | same probe + a spawn run |
| the check is in native code you cannot hook | no userspace hit at all, but the branch exists in the library | a layer boundary | static read + `svc_scan.py` |

**Rule:** move down the ladder only when the rung above has been *excluded by an observation*. Most
"anti-Frida" reports are the first two rungs, and neither of them is about the app.

## Failure modes of this file's own advice

- **Instrumenting to test whether instrumentation is the problem.** The control has to be a run *without*
  hooks; adding a lighter hook still changes the variable.
- **Believing a silent tag.** A module or script that "loaded" but printed nothing may have been writing
  to a channel you are not reading (`logd` broken; see the precedent case) — read both channels before
  concluding "it never ran".
- **Treating a crash on attach as detection.** Attaching changes timing, memory layout and thread count;
  a target with a latent race dies more readily. Reproduce without attach first.
- **Letting the obfuscation argument end the work.** Non-semantic names change *how* you locate (shape,
  anchors, stacks), not *whether* you can.
- **Chasing the sweep.** Renaming `frida-server` protects you from cleanup, not from detection; a target
  that lists `/proc/self/maps` will still see the mappings. Do not report a rename as a fix.

## A zero-event session, reduced to three lines

The useful output of this file is a short record that another person can act on. Three lines:

```
zero-event:   CLASSES target_matches=1  LOADERS count=3 can_find=[2]   alive_after_2s=yes
               -> not detected; class reachable on loader 2; hook was on the default loader
action:       set Java.classFactory.loader = loaders[1]; re-run; expect the same UI action to produce >=1 event
control:      unmodified run (no hooks) -> app alive, feature works  => the death hypothesis is excluded
```

Two properties make this record worth keeping: the numbers (so a second run can disprove it) and the
`control` line (so nobody re-opens the detection hypothesis without new evidence). A record without the
control line is how a session gets re-litigated a week later.

## Where this file stops

- **Locating a check's implementation** after it has been named: `detection-and-anti-analysis.md` §Step 3.
- **Neutralising** a check: not this file's subject — and often the wrong move (`coverage-and-limits.md`
  §not covered).
- **Replacing live attach** with a static build: the comparison table above; the packaging side is
  `repack-and-sign.md`.
- **Anything inside a runtime**: `framework-runtimes.md`, then `dart-aot.md`. A Java hook that hits
  nothing on a Flutter screen is *expected*, not a bug in your script.
- **Delivering the result**: a session is evidence, not an artifact. If the answer has to work on
  someone else's phone, the form is an APK or a module (`SKILL.md` §G1), and the session's role is to
  tell you which one. Keeping that distinction explicit is what stops a prototype being reported as a
  deliverable.

## 这一篇算"用对了"吗

- [ ] 我用两个计数（类命中、可找到该类的 loader 数）加一次存活探测，把"零事件"分成了四条分支之一
- [ ] 我按顺序排除过 ROM 冻结与 server 被杀，再谈目标检测
- [ ] 我知道 `Java.choose` 会命中死实例，并且过滤过 `isFinishing/isDestroyed`
- [ ] 我的对照是**不加 hook** 的原版运行，而不是"更轻的 hook"
- [ ] 我把"名字被混淆"当作定位方式问题，写了按形状/锚点定位的下一步
