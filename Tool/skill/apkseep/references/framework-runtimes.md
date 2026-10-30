# Cross-Platform Runtimes

Load this when the app's UI is not native, or when Java-layer hooks produce no hits at all.

Many apps ship a native shell plus a cross-platform runtime. Their business logic, their UI, and their
feature gates live **inside the runtime**, not in the dex. Patching the dex then does nothing — the Java
code you can see is mostly glue. Determine the runtime before choosing where to patch.

## Identify the runtime early

Signals in the APK:

| Runtime | Giveaways |
|---|---|
| Flutter | `libflutter.so`, `libapp.so`, `assets/flutter_assets/`, Dart snapshot |
| React Native | `libhermes.so` or `libjsc.so`, `index.android.bundle`, `assets/index.android.bundle` |
| Unity | `libunity.so`, `libil2cpp.so`, `assets/bin/Data/`, `globalgamemanagers` |
| Cordova / Ionic | `assets/www/`, `cordova.js` |
| Xamarin / .NET | `libmonodroid.so`, `assemblies/` in the APK |

A `classes.dex` that is small relative to the total payload is another strong hint that the real code
lives elsewhere.

## The layer trap

The expensive mistake: seeing a UI element (dialog, paywall, gate) and assuming it is a native control,
then spending a long time looking for it in the dex.

If it is drawn by the runtime, the dex contains only the bridge. Symptoms of being on the wrong layer:

- hooking the obvious Java dialog/Activity classes produces **zero** hits while the UI clearly appears;
- the classes that do appear in stacks are the runtime's own, with obfuscated names;
- hooking a Java method changes nothing about the visible behaviour.

Establish layer ownership **before** investing in a patch direction.

### How to tell which layer drew a given UI

1. Enumerate the Java dialog and presentation classes and hook their show/creation paths.
2. Reproduce the UI. If any hook fires, the caller stack names the detection and you are on the Java
   layer.
3. If nothing fires while the UI is on screen, the UI is runtime-drawn or native-drawn. Switch axis.
4. Expect runtime-owned windows to appear as ordinary system `Dialog`/`Presentation` objects used as
   **containers** for the runtime's surface. A hit on such a container is not evidence that the visible
   element is a native dialog — read the class name carefully before drawing conclusions.

## Flutter specifics

- Business logic is compiled ahead-of-time into **`libapp.so`**; UI is rendered by `libflutter.so` with
  no per-widget Java objects.
- **Widgets, dialogs, and paywalls are not Java views.** They will never appear in Java stack traces,
  and no Java hook can intercept them.
- The Java side is thin: one Activity, plus plugin classes. Calls cross the boundary through the
  platform-channel mechanism, whose class names are frequently obfuscated.
- Because channel classes may be renamed, locate them **by method signature and call shape**, not by
  class name.

### Where to intervene in a Flutter app

| Goal | Layer | Notes |
|---|---|---|
| Stop the app being killed / refused at startup | host native library | earliest point, see `native-and-so.md` |
| Observe what the runtime is told | platform channel | shows the messages that drive the UI |
| Change a decision permanently | `libapp.so` | most direct, hardest to locate |
| Change startup behaviour only | host native library constructor | survives runtime restarts |

Editing `libapp.so` is the most durable but locating Dart AOT code is genuinely hard. This subject is
large enough to have its own reference: **`references/dart-aot.md`** covers pinning the Dart version,
building a decompiler for exactly that version, the object-pool model and how to index it, the register
and boolean conventions, the three assembly signatures that identify most business logic, the locating
workflow, and how to patch this layer safely.

## Locating logic without symbols

- **Strings first.** User-visible text (dialog bodies, feature labels) is the cheapest anchor in any
  runtime. Find it, then find what references it.
- **Search them in the encoding the runtime actually uses, or you will conclude they do not exist.**
  This is the single most common false negative in cross-platform work. A runtime snapshot does not
  necessarily store text as UTF-8; UTF-16 (little-endian on these targets) is common and entirely
  valid. A UTF-8 search of such a snapshot returns **zero hits**, which reads as "the strings were
  stripped / encrypted, this route is dead" — and that conclusion is wrong.

  ```python
  blob = open('libapp.so', 'rb').read()          # or whichever artifact holds the snapshot
  for phrase in ('<feature label>', '<dialog title>'):
      print(phrase, 'utf-8:', blob.find(phrase.encode('utf-8')),
                    'utf-16le:', blob.find(phrase.encode('utf-16-le')))
  ```

  Try both, and try a short distinctive substring rather than a long phrase. Which encoding applies
  is predictable rather than random: in a Dart AOT snapshot ASCII literals are stored one-byte (a
  UTF-8 search finds them) while CJK / non-Latin literals are UTF-16LE (a UTF-8 search returns zero).
  `dart-aot.md` §7 gives the exact framing, and `scripts/dart_pool_strings.py --find` locates either
  encoding by file offset.
- **A phrase that is absent may simply never exist as one literal.** UI text is often assembled from
  fragments or templates, so "the whole sentence" can be missing while both halves are present.
  Search the shortest distinctive token, and expect the interesting anchor to be a *label* rather
  than a sentence.
- **Landing on a string tells you where the text lives, not which code decided to show it.** Treat the
  hit as an anchor for reference-hunting, not as the answer.
- **Compare two builds.** The same feature in a slightly different version often reveals the code path.
- **Watch the boundary, not the interior.** For cross-platform apps it is usually far cheaper to observe
  what crosses between layers than to reverse the interior of the runtime.
- **Do not assume the obfuscated names are stable or meaningful.** They are not, and treating them as
  identities leads to conclusions that break on the next build.
- **Obfuscated identifiers can be non-ASCII and invisible.** Renaming passes can replace class and
  member names with characters outside ASCII (combining marks, variant selectors and similar). If a
  class exists at runtime but "cannot be found" by the name you read from a decompiler, suspect
  encoding or normalisation in your tooling rather than a missing class. Resolve such members by
  **shape** — parameter counts, types, interface implementation — instead of by name, and prefer
  runtime enumeration of loaded classes over guessing identifiers.

## What this changes about your plan

- Budget for the runtime layer **up front**. If the app is Flutter/RN/Unity, the dex is not the main
  battlefield and a dex-only plan will stall.
- Any behavioural claim must be validated **through the runtime's own UI**, because that is what the
  user sees. A patch that changes internal state without changing the UI is not a fix.
- Keep the layer you are working in explicit in your notes. "Patched the paywall" is meaningless without
  saying which layer owned it.

## Command block: identify the runtime from the artifact, then confirm it live

Two independent signals are the minimum, because a single copied `libflutter.so` name proves nothing and
a single asset directory can be a leftover. Static first (cheap), live second (confirms what runs).

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 1) static: what is actually in the package (names + sizes, not "I saw a lib")
unzip -l target.apk | grep -E 'lib/(arm64-v8a|armeabi-v7a)/|assets/' | awk '{print $1, $4}' | sort -k2

# 2) static: how small is the dex relative to the payload? (a strong hint the logic is elsewhere)
unzip -l target.apk | awk '/classes[0-9]*\.dex/ {d+=$1} /^ *[0-9]+ / {t+=$1} END {printf "dex=%.1f%% of archive\n", 100*d/t}'

# 3) static: runtime markers in one pass (Flutter / RN / Unity / Cordova / Xamarin)
python scripts/dex_strings.py ./dexdump --find '(?i)flutter|hermes|jsc|il2cpp|unity|cordova|xamarin|monodroid' --per-file

# 4) live: which libraries are actually mapped, from which path, for which ABI
python scripts/lib_map.py --pkg <pkg>
```

**Expected shapes:**

```
# 1)
  8421392 lib/arm64-v8a/libflutter.so
 18492344 lib/arm64-v8a/libapp.so
  1902488 classes.dex
# 2)
dex=5.2% of archive          <- the dex is glue, not the application
# 4)
libapp.so        /data/app/.../lib/arm64-v8a/libapp.so   elf=e_machine 183   from-apk
libflutter.so    /data/app/.../lib/arm64-v8a/libflutter.so elf=e_machine 183 from-apk
libc.so          /apex/com.android.runtime/lib64/bionic/libc.so  system
```

| Observation | Runtime | Confidence |
|---|---|---|
| `libapp.so` + `libflutter.so` + `dex < 10%` | Flutter (AOT) | high — two independent signals |
| `libhermes.so` or `index.android.bundle` | React Native / Hermes | high if the bundle exists as a file, medium from the lib alone |
| `libil2cpp.so` + `global-metadata.dat` | Unity / IL2CPP | high |
| `assets/www/` + `cordova.js` | Cordova / hybrid | high |
| `libmonodroid.so` + `assemblies/` | Xamarin / .NET | high |
| only the runtime lib, no snapshot/bundle | the runtime is linked but may not own the logic | medium — confirm with the layer experiment below |

## The layer-ownership experiment, as numbers

The question "who drew this UI" is answered by **counts per layer**, not by opinion. Install hooks on
each candidate layer, reproduce one specific screen, and read the counts.

| Layer | What to hook | A count > 0 means | A count of 0 means |
|---|---|---|---|
| Java/Kotlin | the Activity/Fragment/`Dialog.show` paths around the screen | Java owns the flow; a dex patch can change it | not Java — do not keep hunting in dex |
| Platform channel (Flutter) | the channel name and its `MethodCall` handler | the runtime is asking the host to do something; the ask is observable | the channel is unused for this screen |
| Native (host lib) | the exported symbol or the offset that decides the branch | native owns the decision | look at the runtime's own code |
| Runtime bytecode | Dart AOT / Hermes (see `dart-aot.md`) | the logic is inside the snapshot | the screen is host-side after all |

**Passing looks like:** exactly one layer has a non-zero count for the screen you reproduced, and
re-running the same probe on a *different* screen gives a different (nonzero) layer. That second half is
what distinguishes "I found the owner" from "my probe fires on everything".

## What passing looks like (通过长什么样)

| Claim | Passing | Not passing |
|---|---|---|
| "The runtime is X" | two independent signals (artifact + mapping) name X | one `libX.so` filename, or one string in the dex |
| "The logic is not in the dex" | dex is small relative to the payload **and** Java-layer hooks on the screen fire zero times while the screen works | dex is small (that alone can be resource-heavy app) |
| "The UI is runtime-drawn" | zero Java hits on a screen that is plainly visible, plus a positive control that the hook mechanism works on another screen | "I could not find it in dex" |
| "This layer owns the decision" | a hook in that layer changes the visible outcome, or its count is the only non-zero one | the hook fires but nothing changes (a pass-through, not the owner) |
| "My plan targets the right layer" | the plan names the layer explicitly and the tool that reads it | the plan says "patch the paywall" without naming a layer |

## Cost table: the runtime decides where the hours go

| Runtime | Where the logic is | Cheapest path to a first real result | Typical cost |
|---|---|---|---|
| Flutter (AOT) | `libapp.so` | locate a string in the pool, then the code site that references it (`dart-aot.md`) | hours; needs a snapshot dump front end |
| React Native | `index.android.bundle` (JS, often minified) | string search in the bundle, then the module that owns it | minutes to an hour; bundle is text |
| Unity / IL2CPP | `libil2cpp.so` + `global-metadata.dat` | runtime identification here; conditional same-build type/address mapping in `../subskills/il2cpp-dump/SKILL.md` | verify inputs, tool/version and device; original C# body recovery is not promised |
| Cordova / hybrid | `assets/www/` | read the JS directly | minutes |
| Xamarin | `assemblies/*.dll` | standard .NET tooling on the assemblies | depends on obfuscation |

**Read the last two rows as boundaries, not as routes.** They tell you where to stop with a named
reason, which is the honest deliverable when the layer is outside this skill's coverage
(`coverage-and-limits.md`).

## Failure modes

- **Confirming the runtime from one signal.** A leftover `libflutter.so` in a native app, or a
  `flutter_assets/` directory left from a migration, produces a confidently wrong plan.
- **Reading the dex and concluding "the feature does not exist".** In a runtime-owned app the dex is
  glue; absence there is expected, not a finding.
- **Fighting the runtime with Java hooks.** Zero hits after two attempts means the layer is wrong
  (two-strike rule), not that the hook needs a different overload.
- **Treating a platform channel as app logic.** A channel hit tells you the runtime asked the host for
  something; it does not tell you which business rule produced the ask.
- **Skipping the control screen.** Without a second screen that does fire, you cannot tell "the owner"
  from "a probe that fires everywhere".

## A 20-minute triage sequence

Run these in order; each one either ends the question or makes the next one cheaper.

1. **Unzip and list** `lib/` and `assets/` (command block above, step 1). Ten seconds, and it eliminates
   three of the five runtimes.
2. **Compute the dex share** (step 2). Under ~10% means the dex is glue; note the number, because it is
   the first evidence for "not the battlefield".
3. **Grep the runtime markers** (step 3) to name the candidate, not to confirm it.
4. **Map the live process** (step 4) — this is the independent second signal, and it also tells you which
   ABI is executing (`native-and-so.md` §which architecture).
5. **Reproduce one screen** and run the Java-layer probe on it. Non-zero hits: stop, this is a dex job.
   Zero hits while the screen is visible: continue.
6. **Name the layer and the tool** before touching anything else. If the layer is the runtime's own
   bytecode, the next file is `dart-aot.md` (Dart) or the bundle itself (RN); if it is Unity/IL2CPP,
   read `../subskills/il2cpp-dump/SKILL.md` for the conditional type/address route and record what is actually verified; original C# body recovery remains outside the default promise.

Two rules for the sequence: do not skip step 5 because "it is obviously Flutter" (the obviously-wrong
case is exactly the one that costs a day), and do not run step 6 without a written sentence — the layer
name is the whole output of this file.

If steps 4 and 5 disagree (mapped runtime, but Java hooks fire), that is not an ambiguity: it means the
runtime is present and the *screen you picked* is still Java-owned. Pick another screen before
re-classifying — a runtime can coexist with a mostly-Java app, and this file's job is to tell you which
one owns the screen in front of you.

## 这一篇算"用对了"吗

- [ ] 我用两个独立信号确认了运行时（静态产物 + 运行时映射），不是靠一个库名
- [ ] 我做过分层计数实验，并有一个"另一屏会命中不同层"的对照
- [ ] 我的计划写明了层（dex / 运行时字节码 / native），并点名了读它的工具
- [ ] 我把 Unity/RN/iOS 这类层当成**边界**写下来，而不是即兴发挥
- [ ] 零命中时我按两击规则换了层，而不是继续调 hook 参数
