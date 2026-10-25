# Hand-off boundaries — where this skill ends and another view begins

Four boundaries that are easy to walk into without noticing. Each names what the other side owns
rather than restating it, because two copies of the same advice drift apart. `SKILL.md` keeps the
one-line version of each so a routing decision can be made without loading this file; this file
carries the detail.

## 1. JNI — a Java `native` declaration and its implementation are two different views of one function

This skill reads the Java side (dex) and the native side (`.so`) with different tools, so the *join*
is where analyses go wrong.

| Form | What you see | How to find it |
|---|---|---|
| Static linkage | symbol `Java_<pkg>_<Class>_<method>` in `.dynsym` | search the dynamic symbol table. Under R8 the class name is a short name, so the symbol deforms with it and a search for the readable original finds nothing |
| Dynamic registration | **nothing** in the symbol table — binding happens at runtime | find `RegisterNatives` call sites, or hook it to read the binding table. Obfuscated targets prefer this, and a symbol search fails **silently** on it |
| Native → Java callbacks | native code pulling data back through Java | follow `FindClass` / `GetMethodID` / `CallObjectMethod` |

`FindClass`/`RegisterNatives` in a `.so` tell you a JNI boundary exists even when no `Java_*` symbol
does. **Strength note:** the three rows above are documented behaviour, not results from the first
verification pass, which did not trace a JNI boundary end to end; `FlutterJNI.loadLibrary` appearing
in a dex is the closest it came. Treat them as a map, not as a measurement.

**The benchmark pass then measured the failure the middle row predicts:** a real dynamically
registering library contains **zero `RegisterNatives` symbols**, because the C++ `jni.h` inlines the
call — so a symbol-based search fails structurally, not by bad luck. The combination that did fire
on a real library was *"exports `JNI_OnLoad` and zero `Java_*`"*. The authoritative treatment is
`references/java2c-and-jni-sinking.md` §The JNI boundary — why a symbol search fails silently; this
section is the pointer, not the source.

## 2. Hardening — a dex-side packer observation is a native-side implementation question

If the dex turns out to be a shell, the logic is behind a loader and the analysis moves to the `.so`
that performs the unpacking. `packers.md` owns the dex-side identification; the native deep dive
belongs on the other side of this boundary. **Not exercised by the first verification pass** — that
target had no packer, so this pointer carries no measurement from it. The benchmark pass measured the
*shape discrimination* on public samples but still did not run a live extraction shell
(the benchmark matrix (`references/evidence-summary.md` §The capability matrix) row B3).

## 3. The existing native boundaries — read native anomalies from the APK side, not from inside

`native-and-so.md` and `native-tamper-and-suicide.md` are deliberately scoped to what you can
conclude *from the APK side*: a repacked build that dies instantly with a null-looking fault, a
Java-layer check that reports success while the process dies, a terminate path you made not-return.
That judgement belongs here, because it is about deciding whether your *patch* caused the death. Deep
native work — restoring a symbol, rebuilding a call graph, reversing an OLLVM function — is a
different activity with a different toolchain. Point across rather than duplicating: if you need the
latter, say so instead of extending those two files into it.

## 4. When the deliverable stops being an APK, the verification question changes with it

`SKILL.md` §What "done" means is written for a rebuilt, installable artifact, and every word of it
assumes one. The other three forms in G1 each move the evidence somewhere else, and the failure mode
is quiet: **a privileged result gets reported in the language of a finished build.**

| Form | What "verified" now means | What is *not* evidence |
|---|---|---|
| **LSPosed / Xposed module** | The module was loaded into the target and its hook produced an observable effect **in the target's own log**, on a named build of the target | The module installed; `pm path` returned a path; the package was enabled in the manager. All three are true of a module whose entry class does not exist in its own dex |
| **Local RPC / emulation service** | A call returned the value the app itself would produce, from a named target build and a named device or emulated environment — and the harness survives a reconnect | "The script loaded"; a call that returned *something* without a reference value to compare against |
| **Analysis report with a stated boundary** | The evidence chain (commands, outputs, and the layer each conclusion belongs to) plus the boundary — what was **not** determined and why | Any implication that a route was exhausted when it was only abandoned |

The privileged-form drift R1 warns about lives here. `references/lsposed-and-modules.md`,
`references/emulation-and-rpc.md` and `references/verification.md` each carry the specific check; this
table is the reminder that changing the deliverable's form is a decision that must be re-stated out
loud, not a quiet downgrade of what counts as done.

**A fifth boundary, added by the benchmark pass:** when the deliverable is a **tool or a document in
this repository**, "verified" means an independent check exists — a second implementation, an
official disassembler, a byte-exact round trip. A tool's own self-test passing is not that check.
the benchmark matrix (`references/evidence-summary.md` §The capability matrix) records which rows have one and which do not.

## Crossing a boundary is a decision with a cost — three questions, always the same

Every boundary above turns into the same decision procedure. Answering the three questions takes
minutes; skipping them is what produces the "confident answer about the wrong layer" that
`SKILL.md` §Coverage opens with.

| Question | Why it decides the boundary | Cheap way to answer it |
|---|---|---|
| **Which side produces the observable I care about?** | a Java hook that fires zero times and a native check that never leaves a trace look identical from the outside | a probe that reports per-layer counts, not a single "no events" |
| **What does the other side need in order to be checked at all?** | a symbol search needs symbols; a JNI join needs a registration table; a VMP needs an opcode map | one command that returns *something* on a known-good input (the positive control) |
| **What would change my mind?** | a boundary claim that cannot be falsified is a preference | name the observation that would move the work to the other side, before you start |

If the third column has no answer, stop: you are about to spend hours in a layer you cannot falsify.

## Command block: locate the boundary with numbers, not with an impression

```bash
# JNI: which of the three forms is this library? ("exports JNI_OnLoad and zero Java_*" is the shape
# that fires on real dynamically-registering / Java2C-built libraries)
python scripts/java2c_probe.py --apk target.apk --json

# JNI: the raw symbol view, for one ABI at a time
unzip -o -q target.apk 'lib/arm64-v8a/*.so' -d /tmp/abi
nm -D --defined-only /tmp/abi/lib/arm64-v8a/lib<name>.so 2>/dev/null | grep -c ' Java_'
nm -D --defined-only /tmp/abi/lib/arm64-v8a/lib<name>.so 2>/dev/null | grep -c ' JNI_OnLoad'

# Hardening: dex side (is it a shell?) vs native side (is there a loader?) — two different files
python scripts/dex_strings.py ./dexdump --classes 'Lcom/' | head -5
python scripts/lib_map.py --pkg <pkg>          # which libraries are actually mapped at runtime

# Native anomaly: is the death mine or the target's?
python scripts/native_crash.py --log crash.txt --json
```

**What the numbers mean:**

| Observation | Boundary it establishes | Where the work continues |
|---|---|---|
| `JNI_OnLoad` = 1, `Java_*` = 0, dex native density ~0.0x% | dynamic registration (or hidden visibility), **not** Java2C | `java2c-and-jni-sinking.md` §The JNI boundary |
| `JNI_OnLoad` = 1, `Java_*` = 0, native density tens of % | Java2C-shaped: there is no dex to dump | `java2c-and-jni-sinking.md`, and stop looking for a dump |
| `Java_*` count matches the dex's native-method count per ABI | static linkage; a symbol search is a valid locator | `native-and-so.md` |
| `lib_map.py` shows a library that is **not** in the APK | runtime-materialised payload | `code-virtualization-and-custom-linkers.md` |
| `native_crash.py` flags a fault that looks arranged | the death is a mechanism, not a bug | `native-tamper-and-suicide.md` |

## What passing looks like (通过长什么样)

| Boundary | Passing looks like | What is **not** passing, however clean it looks |
|---|---|---|
| JNI | you can name the form (static / dynamic / Java2C) **and** the evidence: a symbol count, a density, or a registration site | "the class is in the dex and the method is native" — that is the starting observation, not the join |
| Hardening | you can name whether the loader is dex-side or native-side, and which file you are moving to | finding a shell class and stopping there: the shell is an observation, the loader is the question |
| Native anomaly | a fault site plus the mechanism that arranged it, or an explicit "ordinary fault" verdict | a `SIGSEGV` with no registers, treated as an answer |
| Module deliverable | the target's **own** log shows the hook's effect, on a named build | `pm path` returning a path; the package enabled in the manager; the module's own "loaded" line |
| RPC / emulation | a returned value identical to what the app produces, for the same input, on a named build | "the call returned something" with no reference value |
| Report deliverable | an evidence chain plus a stated boundary of what was not determined | prose that implies a route was exhausted when it was abandoned |

## The four ways a boundary gets crossed wrongly

**① Using the other side's tool on this side's question.** Dumping memory to answer "does this class
have a body" when the answer is a dex table lookup; decompiling a `.so` to answer "is this library
loaded". The tool is heavier, the answer is plausible, and plausibility is worse than nothing here.

**② Reading the join as the implementation.** A `Java_*` symbol tells you a function exists, not that
it is the one you want, and under R8 the symbol deforms with the class name. The join is a *pointer*;
the implementation is on the other side.

**③ Letting the deliverable's form change quietly.** A rooted-device hook reported in the language of a
shipped build is the drift R1 names. The form must be re-stated at every checkpoint, in the same
sentence as G1.

**④ Treating a boundary as a verdict.** "The check is in native code, so the client is unmodifiable" is
a boundary crossed and then mis-read: native code is still client code (`native-and-so.md`). A true
verdict requires the *server* to own the value (`server-api.md`).

## A boundary record, in six lines

```
observable:    <what you actually saw, with the layer it appeared in>
form:          <static JNI | dynamic registration | Java2C | loader | VMP | ordinary fault>
evidence:      <count / density / log line / trace, with the command that produced it>
crossed to:    <file or discipline that owns the next question>
not determined: <what this side cannot decide, stated as a boundary>
falsifier:     <the observation that would move this to the other side>
```

The last two lines are the ones that keep a boundary honest: an unstated "not determined" becomes an
implied claim, and an unstated falsifier makes the whole record unfalsifiable.

## The boundary map: one question, one owner

The four sections above describe the boundaries conceptually. This table is the operational version:
find your question, cross to the owner, do not re-derive it here.

| Your question | Owner | The sign that you are in the wrong file |
|---|---|---|
| Is there a packer, and which one? | `packers.md` | you are reading memory to answer a manifest question |
| No packer, and it still dies on repack | `code-virtualization-and-custom-linkers.md` | you are rebuilding the shell from the dex |
| Whole classes are bare `native` | `java2c-and-jni-sinking.md` | you are dumping memory looking for a dex that never exists |
| A `Java_*` symbol is missing | `java2c-and-jni-sinking.md` §The JNI boundary | you conclude "no native code" from a failed symbol search |
| The body decodes as private opcodes | `vmp-differential-analysis.md` | you are hand-writing a disassembler for an unknown ISA |
| The process dies without a Java stack | `native-tamper-and-suicide.md` | you are adding hooks to a process that is already gone |
| The check reads `/proc/self/status` via raw `svc` | `kernel-and-environment-hardening.md` | you are adding a third libc hook |
| A rebuilt APK is refused by several checks | `lsposed-and-modules.md` | you are patching the checks one at a time |
| You need the value, not the app | `emulation-and-rpc.md` | you are hooking to observe a function you could just call |
| The value is minted by the server | `server-api.md` | you are patching a client that only displays it |
| The target is Unity / RN / iOS | `coverage-and-limits.md` (out of scope) | you are improvising an IL2CPP route |

## Two worked boundary calls

**Case A — "the class is native, so let me dump the dex".**
Observation: `Lcom/x/y;->a(I)I` is `native`, dex is readable, no `Java_*` symbol found.
The wrong move is to start a memory window. The three questions give a cheaper path: (1) the observable
is "where does this body live", and the dex answers the *form* question directly — native density and
symbol counts (`java2c_probe.py`); (2) the other side needs `JNI_OnLoad` evidence, which is one command;
(3) what would change the mind: a `Java_*` symbol appearing for that exact signature, or a non-trivial
native density with registration sites. Result in the measured cases: density 0.03–0.04% on ordinary
JNI, 82.76% on a Java2C fixture — so the boundary is decided **before** any window is opened.

**Case B — "the repack installs but one feature never loads".**
Observation: the build runs, renders, logs nothing, and the network shows no request for the feature.
Three questions: (1) the observable is "a request that was never built", which is a *client decision*,
not a server rejection; (2) the other side needs the build's own bytes, which you have; (3) the
falsifier: a request that **is** sent and rejected would move this to `server-api.md` / `tls-and-cert.md`.
Because no request exists, this belongs to `code-virtualization-and-custom-linkers.md` §what the native
check actually reads — and the cheapest experiment is the unmodified original with the patch applied in
memory only, which separates "my patch" from "the target's own behaviour".

Both cases finish in the same shape: a named form, a named owner, and an explicit falsifier. That is
what this file exists to produce.

## Where this file stops

This file does not teach any of the five disciplines it points at. It does not restate the JNI form
table's mechanisms, the packer identification procedure, the module verification steps, or the RPC
harness. Duplicating them here would give two copies that drift — which is the exact failure the file's
opening paragraph names. If a decision needs detail beyond the table rows above, the answer is to load
the owner, not to extend this page.

## Six mis-crossings, with the cost each one has already incurred

| What you see | The boundary you think it is | The boundary it actually is | What the mis-crossing costs |
|---|---|---|---|
| A Java signature check logs "passed", then the process dies | "the check is bypassed, the crash is unrelated" | native integrity, decoy Java check (`code-virtualization-and-custom-linkers.md`) | days: the Java check is a decoy by construction |
| `UnsatisfiedLinkError` after deleting a library | "the library was the check" | the loader's `DT_NEEDED` set: removing it removes a dependency others need | an afternoon, plus a build that can never start again |
| A hook module loads, its tag is silent | "the module failed to load" | the log channel: `logd` broken, output only in the framework's file log | an evening, and a wrong conclusion recorded as fact |
| The dump validates, classes are all there, feature still missing | "my patch is wrong" | extraction shell: the bodies were never in the dump | days of re-patching a mirror that has no code |
| A re-signed build installs, every signed request returns `-1` | "the server rejects us" | signature-derived key: the client's own certificate **is** the key material | days, and a false server-side verdict |
| The UI never appears under `spawn` | "the app refuses to start under instrumentation" | spawn keeps the Activity stack down; patch in memory, detach, then launch | an hour per attempt, and a false anti-debug verdict |

The pattern in all six: **the symptom points at one side, the mechanism lives on the other.** That is
the whole reason this file exists, and why the symptom index in `SKILL.md` names a file rather than a
diagnosis.

## What the next side needs from you (boundary-specific handover)

The recipient is not "the next file" but the person who will do the work you are pointing at. Five
things, and each one is a thing they would otherwise have to re-derive:

- **The artifact**, by path and hash — not "the repacked APK", because two builds of the same change are
  two different artifacts.
- **The command that produced the observation**, with its output — so they can replay it before trusting it.
- **The layer the observation belongs to**, in their vocabulary: "dex table", "native symbol", "runtime
  mapping", "server response". A layer-free description forces them to re-classify.
- **What you did not determine**, stated as a boundary rather than omitted — an omission reads as "no
  open questions".
- **The falsifier you were working against**, so they can recognise the moment it fires.
- **The environment** the observation was made in (device, root state, ROM build) — a native behaviour
  that holds on one ROM and not another is a different claim, not a repeated one.

Anything less and the boundary crossing becomes a restart, which is the failure this whole file is
about. Two minutes of this list saves the other side an hour of reconstructing what you already knew —
and it is the only part of the handover that cannot be recovered from the artifact itself.

## 这一篇算"用对了"吗

- [ ] 我能说出这次现象的**产出方**是 dex、native、运行时还是服务端，并给出判据（不是印象）
- [ ] 我用过一条命令确认 JNI 的形态（符号数 / 密度 / 注册点），而不是只看到 `native` 就下结论
- [ ] 我在跨过去之前写下了"什么会让我改判"，并且它不是"再试一次看看"
- [ ] 交付形态变化时我重新说了一遍 G1 的那句话，而不是用"已验证"概括两种不同的证据
- [ ] 我的记录里有"未确定"和"跨到哪一篇"两行，别人可以接着做而不用重来
