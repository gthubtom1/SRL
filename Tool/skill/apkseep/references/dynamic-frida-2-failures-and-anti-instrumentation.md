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
