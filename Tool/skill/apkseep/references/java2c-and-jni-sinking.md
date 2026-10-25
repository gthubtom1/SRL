# Java2C and JNI Sinking — the dex is not where the code is

Load this when the dex shows method bodies missing or replaced by `native` declarations, and
you are about to go looking for a decrypted DEX in memory. **Decide which of the two shapes you
have before you spend anything**, because one of them has no DEX to find at any point in the
process lifetime, and the search for it is unbounded.

Two neighbouring routes have historically folded this shape into one: `advanced-unpacking.md`'s
dump-shape table and the SKILL.md symptom index both point "whole classes are bare `native`
declarations" at `code-virtualization-and-custom-linkers.md`. That file is about protection which
leaves the code **reachable** — a private container, a loader, a private opcode interpreter, all of
which you can dump and measure. **Java2C is not reachable, because it was never bytecode.** This
file splits that row and owns both halves of it; the virtualization file stays what it is.

**Strength note, read this first.** The measurements below are **observed** — every number was
produced by `scripts/java2c_probe.py` against a real sample during this pass, recorded in
`references/evidence-summary.md` §The capability matrix. But no Java2C library exists in this repository and
none could be built here (no NDK, no clang, WSL unavailable — see that record), so **the
Java2C-specific identification criteria are inferred, not observed end to end**. What *is*
observed is the discriminating measurement that separates Java2C from JNI sinking, and the JNI
boundary behaviour. Treat the type table as a map; label your own conclusions the same way.

## The five shapes — one table, because the wrong row costs days

| Shape | Static shape in dex | What is in memory at runtime | Route | Cost of the wrong row |
|---|---|---|---|---|
| **Landing shell** | `Application` is a third-party class; dex is a small stub | A full, decrypted DEX | Dump memory, filter, patch | Cheap if you notice the stub `Application` |
| **Extraction shell** | Reads as a normal dex until you measure it; bodies are stubs | A DEX whose bodies are filled in **on invocation** | Dump, measure `stub%`, FART-style active invocation | Medium — you keep dumping, and every dump is a skeleton |
| **VMP** | Dex parses; bodies are *present* but decode as nonsense | A DEX containing **private opcodes** interpreted by a native VM | Measure, then usually stop and report | Medium — recovery cost usually exceeds task value |
| **Java2C** | Whole classes are `native`; **no code_item at all** for them | **Never a DEX.** The translated methods exist only as compiled C in a `.so` | Read the `.so`; rebuild the JNI call chain | **Highest in this table** — you hunt a decrypted DEX that is never produced, then blame your dump tooling, then your anti-detection assumptions |
| **JNI sinking** | A handful of `native` declarations; the rest of the dex is ordinary Java | A normal DEX | Locate the Java call site; reverse one or a few native functions | Low — but you may widen the job to the whole app if you read it as Java2C |

The one question that decides the table: **does the artifact ever hold dex bytecode for the
methods you care about?**

- Landing shell, extraction shell, VMP: **yes** — the bytecode is there, in some state, and the
  work is recovering or interpreting it.
- Java2C: **no** — a translated method is a `native` declaration plus an entry in a registration
  table. Nothing is decrypted, so nothing can be dumped. `[inferred]` as a runtime claim: it
  follows from the translation mechanism, and this pass did not observe a live Java2C app.
- JNI sinking: **yes** — the dex was never damaged.

## Identification

### The discriminating measurement is native density

This is the single most useful number and it separates the two shapes by roughly three orders of
magnitude. Measured on real samples with `scripts/java2c_probe.py` `[observed]`:

| Sample | dex methods | `native` methods | native ratio |
|---|---|---|---|
| JNI-sinking target A (MASTG L2) | 5081 | 2 | **0.04 %** |
| JNI-sinking target B (MASTG L3) | 11182 | 3 | **0.03 %** |
| App carrying a real JNI library | 23603 | 7 | **0.03 %** |
| Java2C-shaped fixture | 29 | 24 | **82.76 %** |

A JNI *sink* is by definition surgical: a few hot methods are moved out and the rest of the app
stays in Java. **A JNI sink is not "the app is native".** When the density is in the tens of
percent, and whole classes have zero Java methods left, you are looking at a translation pass.

`[observed]` in the same runs: two of the fixture's three classes were native-dominated (>= 70 %
of >= 3 named methods), against **zero** such classes in any of the three real targets. Note that
constructors are excluded from that test — a translation pass leaves `<init>`/`<clinit>` in Java
in practice, so "every method native" is an essentially unreachable test and should not be used.

### Native-layer signatures

| Evidence | Strength | Why |
|---|---|---|
| `.so` exports `Java_*` symbols whose count is roughly 1:1 with the dex native-method count | **strong** | Measured 2:2 (sample A) and 3:3 (sample B) `[observed]`. It is the signature of a *static-linkage* translation or sink. Note it does **not** distinguish Java2C from JNI sinking — only the density does |
| The `.so` contains one C function per Java method, each beginning `JNIEnv *env, jobject thiz, ...` | **strong** | Observed in generated, uncompiled output: every translated method became exactly one function with those leading parameters |
| Toolchain strings: `Dex2C`, `dynamic_register_compile_methods`, `ScopedLocalRef`, `well_known_classes` | **strong** | These are the runtime header and entry-point names a Dex-to-C toolchain emits. `[observed]` in generated sources; `[inferred]` that they survive compilation into the shipped `.so` |
| `JNI_OnLoad` present | **weak** | Present in nearly every JNI library. Measured true on a system library with zero `Java_*` symbols `[observed]` — it told us registration was dynamic, not that anything was hardened |
| `RegisterNatives` **string** anywhere in the `.so` | **weak** | See the boundary section: NDK's C++ headers do not emit this symbol at all |
| `libc++_shared.so` / `c++_static` | **weak** | An ordinary NDK C++ setting. The Dex-to-C toolchain read here does ship `APP_STL := c++_static`, but so do countless unrelated libraries `[observed]` |
| `classes.dex` byte-count per class far below the app's own pre-hardening build | **weak, uncalibrated** | Bodies leaving the dex should shrink it. Measured 584 B/class on the fixture versus 1152–1386 B/class on the real Java targets `[observed]` — but there is no population baseline for "normal", so this only compares an app against **itself** before and after |

`java2c_probe.py` prints every one of these with its strength attached, and prints the weak ones
as an explicit warning block. A weak hit is not a verdict and must not be reported as one.

## The route: read the .so, not memory

For Java2C the analyst's instinct — dump memory and find the dex — is not merely expensive, it is
**unbounded**, because the success condition can never occur.

1. **Do not dump.** There is no target artifact. If you dump anyway, you will recover a dex that
   still shows the same `native` declarations you started with, and the natural (wrong) reading is
   "the dump failed".
2. **List the translated functions.** With static linkage, `Java_<PKG>_<Class>_<method>__<proto>`
   names map the `.so` back onto the dex one for one. Use the dex as the index and the `.so` as
   the library.
3. **Rebuild the chain backwards.** A translated function calls *out* to Java constantly. The
   strings `FindClass` / `GetMethodID` / `GetStaticMethodID` / `Call*Method` / `NewObject` /
   `GetFieldID` inside it are the reverse edges. Following them reconstructs what the original
   Java method did, which is the only way the logic comes back.
4. **Expect a register-machine shape.** Generated code declares a slot per dex register up front
   and assigns them in sequence. Reading it as if a human wrote it wastes hours; read it as a
   linearizer output, matching each call site against the JNI signature it passes.

The decompiler choice matters less here than for obfuscated code: the generated functions are
long but flat and unoptimized, which is precisely the shape a decompiler handles well.

## The JNI boundary — why a symbol search fails silently

Two independent mechanisms erase the symbol that a reader would search for. Both are real; the
second was measured this pass.

**1. Dynamic registration.** Nothing named `Java_*` is exported. Binding is performed at runtime
by a registration table built in a JNI entry point. A grep over the symbol table returns nothing,
exits zero, and looks like a legitimate answer.

**2. `-fvisibility=hidden`, and an inline `RegisterNatives`.** The Dex-to-C toolchain read here
ships `APP_CPPFLAGS += -fvisibility=hidden` in its `Application.mk` `[observed]`, which hides the
generated functions from the dynamic symbol table — so even a statically-named translation can
present as "no `Java_*` symbols". Compounding it: NDK's C++ `jni.h` implements `RegisterNatives`
as an **inline member that calls through the function table**, so calling it emits *no*
`RegisterNatives` symbol either `[observed]`: a real system library exporting `JNI_OnLoad` and
zero `Java_*` symbols contains zero literal `RegisterNatives` symbols. A rule that greps for that
name is structurally incapable of firing.

**The check that does work** `[observed]`: a library that **exports a JNI entry point and exports
zero `Java_*` symbols** is registering dynamically. That combination is affirmative evidence, and
it fired on a real library in this pass.

**Confirming it at runtime.** Hook the registration entry point (`JNI_OnLoad`) and read the table
it builds, or hook the class-load path and enumerate the class's methods' native backing. Do not
conclude "no JNI boundary" from an empty symbol table; conclude "the binding is not visible in the
symbol table" and go find where it happens.

## Failure modes

| What you see | What it is not | What it is |
|---|---|---|
| Whole classes are `native`, you dump memory and find the same `native` declarations | "The dump failed" / "the tool is broken" | The translation moved the code out of dex permanently. Re-read the dex shape and open the `.so` |
| `grep Java_ .dynsym` returns nothing | "There is no native implementation" | Dynamic registration, or hidden visibility — see the boundary section |
| A library exports `JNI_OnLoad` and nothing else you recognise | "It is a loader" | It may be an ordinary dynamically-registering JNI library. A loader normally also has an `init_array` entry and a payload to map |
| Native density is high but every class still has Java methods | Java2C | Could be a JNI sink applied widely, or an R8-stripped app. Check whether the `native` methods have matching `Java_*` symbols before concluding |
| The dex looks completely unremarkable on a sample you were told is hardened | "Nothing is hardened" | A VMP whose payload is decrypted at runtime has an ordinary static dex. Measured this pass: a VMP-labelled sample had 7 native methods out of 23603 and a 4 % stub ratio `[observed]`. **Static dex metrics cannot see runtime-only hardening** — that needs a runtime check, not more reading |

## Where this file stops

- **It does not decompile the generated C.** That is ordinary native reversing; `native-and-so.md`
  and `native-dbi-and-deobfuscation.md` own it.
- **It does not recover a VMP.** Private-opcode interpretation is a different mechanism with a
  different cost model (`advanced-unpacking.md`).
- **The Java2C runtime claim is inferred.** That no dex bytecode exists in memory for a translated
  method follows from the mechanism, not from a measurement made here. If you get a live Java2C
  sample, that is the first thing to verify, and it is cheap: attach, force the class to load, and
  ask whether the method resolves to Java bytecode or to a registered native entry.

## Command block: the three numbers that decide the row

The table above is only usable if the numbers can be produced in a minute. They can, and they come from
two files: the dex and the `.so`.

```bash
# 1) the whole discrimination in one report (density, per-class dominance, Java_* vs native count)
python scripts/java2c_probe.py --apk target.apk --json > j2c.json
python scripts/java2c_probe.py --apk target.apk          # human report, with weak hits in a warning block

# 2) the raw symbol side, per ABI (do not mix ABIs: counts will not match across them)
unzip -o -q target.apk 'lib/arm64-v8a/*.so' -d /tmp/abi64
for so in /tmp/abi64/lib/arm64-v8a/*.so; do
  printf '%-40s Java_*=%-4s JNI_OnLoad=%s\n' "$(basename "$so")" \
    "$(nm -D --defined-only "$so" 2>/dev/null | grep -c ' Java_')" \
    "$(nm -D --defined-only "$so" 2>/dev/null | grep -c ' JNI_OnLoad')"
done

# 3) is the *class* the one that lost its Java methods? (density per class, not per app)
python scripts/dex_strings.py ./dexdump --classes 'Lcom/<vendor>/<app>/' --per-file
```

**Expected shapes** (numbers from the measured samples; yours will differ):

```
# 1)
dex methods: 11182   native: 3   ratio: 0.03%      <- JNI sinking territory
native-dominated classes (>=70% of >=3 named methods): 0
Java_* symbols: 3 (arm64)  <- matches the dex count 1:1
weak hits: JNI_OnLoad present, libc++_shared.so present  (do not use as evidence)

# 2)
libnative-lib.so        Java_*=3    JNI_OnLoad=1
libc++_shared.so        Java_*=0    JNI_OnLoad=0
```

| # | What you read | Meaning |
|---|---|---|
| 1 ratio | 0.0x % | surgical sink or ordinary JNI: the dex is the code |
| 1 ratio | tens of % | a translation pass; look for per-class dominance next |
| 1 dominance | ≥ 1 class with ≥70 % of its named methods native | Java2C shape (constructors excluded from the test by design) |
| 2 | `Java_*` ≈ dex native count, per ABI | static linkage: a symbol search is a valid locator |
| 3 | the class you care about has zero Java bodies | that class's logic is in the `.so`, whatever the app-wide ratio says |

## What passing looks like (通过长什么样)

| Claim | Passing | Not passing |
|---|---|---|
| "This is Java2C" | per-class dominance **and** the app-wide density, both in the tens of percent, plus a `.so` with matching `Java_*` count | "lots of `native` methods" |
| "This is JNI sinking" | density ~0.0x %, few native methods, the rest of the dex ordinary | one class with no Java bodies (that is a local sink, not an app-wide shape) |
| "There is no DEX to dump" | density + dominance + no code_item for the methods (`methods_no_code` in the dump validator) | "my dump did not find it" |
| "The symbol search is not evidence" | you can name the mechanism (dynamic registration / hidden visibility) and show `JNI_OnLoad` present with zero `Java_*` | an empty `grep` result |
| "This library implements method X" | a `Java_*` symbol that matches the dex signature, or a registration table entry | a function with a similar name |

## Writing the verdict (three sentences, one per row)

```
shape:      Java2C | JNI sinking | neither (ordinary JNI / shell / VMP)
evidence:   density <x>% (dex <n> methods, <m> native) | dominance: <k> class(es) >= 70%
            | .so: Java_*=<a> vs dex native=<m> on <abi> | code_item: none for those methods
next:       read the .so (Java2C) | reverse <m> native functions (sink) | continue elsewhere
not claimed: <e.g. "no live Java2C app was observed here, so the runtime claim stays inferred">
```

The third line matters: the mechanism argument for Java2C ("nothing is ever decrypted") is
`inferred` unless you observed a live one, and the report should say which parts are `observed` in *your*
run.

## Failure modes of this discrimination

- **Density from a tiny dex.** 29 methods make one `native` count as 3.4 %. Always report the raw counts
  next to the ratio, and prefer per-class dominance on small dexes.
- **A single dominant class read as an app-wide verdict.** One class moved to native is a sink or a
  hand-written JNI module; the app-wide shape is what the table decides.
- **Counting across ABIs.** A fat APK has several `lib/<abi>/` trees; mixing their symbol counts produces
  a ratio that matches nothing.
- **Treating `JNI_OnLoad` or `libc++_shared.so` as evidence.** Both are weak by construction, and the
  probe prints them in a warning block precisely so they are not promoted.
- **Assuming the dump "failed".** If the dex shows `native` for the methods you want, a dump can only
  reproduce that — the failure is the plan, not the tool.
- **Reading the `.so` as if a human wrote it.** Generated translation output is flat and linear: read it
  as a register-machine linearisation, matching each call against its JNI signature.

## The one-minute triage, when you have nothing but the APK

1. `java2c_probe.py --apk target.apk` — read the ratio and the dominance line. Two numbers, thirty seconds.
2. If the ratio is 0.0x % and dominance is 0, stop reading this file: the dex is the code, and the work is
   `dex-patching.md`.
3. If the ratio is tens of percent, read the `Java_*` count against the dex native count. Matching numbers
   mean static linkage — you can map the `.so` back onto the dex one function at a time.
4. If the class you care about has no Java bodies but the app-wide ratio is low, treat it as a **local**
   sink: reverse those specific functions, do not re-plan the app as native.
5. Write the three-sentence verdict before opening a decompiler. If you cannot write the `evidence:` line,
   you have not made the discrimination yet.

## 这一篇算"用对了"吗

- [ ] 我同时给出了 app 级的 native 密度与 per-class dominance，而不是只给其中一个
- [ ] 我按 ABI 分了 `.so`，并把 `Java_*` 数与 dex 的 native 方法数做了对照
- [ ] 我没有把 `JNI_OnLoad` / `libc++_shared.so` / `RegisterNatives` 字符串当作结论
- [ ] 我说清了"没有 DEX 可 dump"是形状判断，不是 dump 工具的失败
- [ ] 我的报告标了哪些是 `observed`、哪些只是机制推论（Java2C 的运行时断言通常是后者）
