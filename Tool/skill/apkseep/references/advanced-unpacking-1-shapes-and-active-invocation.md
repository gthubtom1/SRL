> 本篇范围：dump shapes, extraction measurement, FART/Youpk active invocation, and the `frida-dexdump` boundary.
> 前后篇：part 1/2 · prev — · next [advanced-unpacking-2-root-dump-and-vmp-boundary.md](advanced-unpacking-2-root-dump-and-vmp-boundary.md) · index [advanced-unpacking.md](advanced-unpacking.md)

# Advanced Unpacking — Extraction Shells, Active Invocation, and the VMP Boundary

Load this when a memory dump of a packed app has already landed on your desk and the
dump itself is the problem: the image parses, the classes are there, and the method
bodies are empty. The neighbouring files each own one stage — `packers.md` owns
*identifying* a shell and mapping what it validates, `recon.md` §Unpacking a dex-level
packer owns the whole-image memory dump and its first-pass filtering, and
`dynamic-frida.md` owns the runtime environment those dumps need. This file owns what
comes after: recognizing that a "successful" dump is only a skeleton, recovering the
missing code, and knowing where that recovery honestly stops.

**Strength note, read this first:** the repository's verification target carried no
extraction shell and no VMP, so nothing here was exercised end to end against a live
hardened sample by this skill's own verification pass. The FART/Youpk mechanisms and
the Android 12-16 failure analysis are **inferred** from public work (FART/Youpk
release notes and a 2026-08 Kanxue thread, `thread-292312`, on why classic
active-invocation hooks die on modern ART). The detection metric has since been
**measured against a purpose-built extraction-shell fixture set**, and that pass
invalidated the threshold this file used to state — see the calibration table in
§Measuring extraction instead of guessing and the commands behind it in
`references/evidence-summary.md` §The capability matrix. The older surgical fixture
that first exercised the script is in `references/evidence-summary.md` §The capability matrix.
Label your own results the same way.

Two parts of this file have since been exercised against live hardened targets on a
rooted device. The **root-side memory route** (§Dumping when frida is refused) was run
end to end: 17 ART dex mappings exported from `/proc/<pid>/mem`, page-alignment trim
included, validated with `scripts/dex_dump_validate.py`; the evidence, the device-shell
traps and the throughput numbers are recorded in
`references/evidence-summary.md` §The capability matrix. The `frida-dexdump` refusal that
motivates that section is in `references/evidence-summary.md` §The capability matrix. A later
pass added the route's **negative boundary** — what it yields nothing against, and how
to tell before spending a process window — plus the reproducibility check between read
paths and the layered-descent table; those are measured on the clean MASTG targets and
on a hardened sample, with commands and hashes in
`references/evidence-summary.md` §The capability matrix. The
FART/active-invocation half of the file is still **inferred** — no extraction-shell
target has been spliced end to end here, and the two candidate samples shipped in
`repos/CyReverse` turned out not to be extraction shells at all (their two "shell"
assets differ by six bytes; row B3 in the bench evidence file).

## The four shapes a dump can be

Diagnose before choosing a route. Run `scripts/dex_dump_validate.py` over the dump
directory and read the `stub%` column — the four shapes separate on it.

| The dumped image | `stub%` | Diagnosis | Route |
|---|---|---|---|
| Parses, many classes, real bodies | near-baseline | First-generation landing shell; the whole-dex dump **is** the original | Done — filter (`recon.md` §Unpacking a dex-level packer) and proceed to patching |
| Parses, many classes, most bodies are `return-void` stubs or nop fills | high | **Extraction shell skeleton** — bodies are decrypted only on invocation | FART loop, this file |
| Whole classes appear as bare `native` declarations, and the matching `Java_*` export exists | n/a | **JNI sinking** — the code left the dex for the `.so` | `java2c-and-jni-sinking.md` — read the function in the library, **not** this file |
| Method bodies look like a thin forwarder to a native routine, or a single native island holds the app's own logic | n/a | **Java2C / native island** — the body is a compiled `J`/`.so` function, so re-reading the dex finds only the call | `java2c-and-jni-sinking.md` — the dex is the wrong instrument |
| Whole classes appear as bare `native` declarations, and **no** `Java_*` export exists | n/a | Dynamic-registration native sink — the binding table is built at runtime | `java2c-and-jni-sinking.md` §the symbol search fails structurally |
| Parses, bodies present but instruction streams are nonsense to a dalvik disassembler | baseline | **Real Dex VMP** — private opcodes behind a native interpreter | Last section of this file, and be honest about the cost |

The two `native`-looking rows are **not** one row. They are separated because the
correct next action differs: JNI sinking keeps the logic in a named, exported ARM64
function that you read from the library, while a dynamic-registration sink has no
symbol to find and needs the binding table read instead. Lumping them together sends an
analyst to dump memory for code that is sitting in an ordinary `.so` — the misdiagnosis
`java2c-and-jni-sinking.md` was written to stop.

Two supporting signals worth recording while you are here (the second is measured on
this repo's hardened sample): a shipped shell `classes.dex` can be megabytes in size
yet define only a handful of classes — the bytes are payload, not code, so class count
and file size move independently under a packer. And a dump whose signature field
disagrees with its own contents while the checksum agrees is not necessarily corrupt;
a shell that never verifies its own header can ship it that way, so treat
checksum/signature results from `verify_dex_header` as evidence about *who touched the
image*, not as a pass/fail gate on usability.

## Measuring extraction instead of guessing

The metric that separates shape 2 from shape 1 is the **trivial-body ratio**: among
methods that *have* a `code_item` (`code_off != 0`), the fraction whose instruction
stream, with plain `nop` units skipped, contains nothing but a single `return*`.
`code_off == 0` methods are abstract or native declarations — that absence is normal
and is excluded from the ratio. A method with a `code_item`, real `insns_size`, and a
lone `return-void` inside is what an extraction shell leaves behind.

```bash
python scripts/dex_dump_validate.py <dump_dir> --find 'Lcom/example/app/'
```

The script dedupes by sha256 (never by size — same-size dumps of one dex have been
measured to differ in ~73% of their bytes), rejects structurally impossible images
(bad magic, `file_size` mismatch, ids out of range), counts classes and stub bodies,
and ranks which surviving image is the most likely original.

**Calibration — measured, and it is not a threshold.** Do not look for a `stub%` number
to compare against. On a real 982 KB application dex (5,061 bodies) every emptying
shape the shell family uses was built into a fixture and measured against a
zero-change control (`references/evidence-summary.md` §The capability matrix,
which carries the commands and the full matrix):

| What the shell left behind | `stub%` | vs. control (1.9 %) |
|---|---|---|
| bare `return-void` in every body | 100.0 % | sighted |
| body cut to `const/4 v0,#0; return v0` | 93.2 % | sighted |
| nop fill, no return — **the slot-clearing shape** | 0.0 % | **blind, and scores below the untouched original** |
| `new RuntimeException; throw` stub — **the 360/legu shape** | 1.9 % | **blind, indistinguishable from the control** |
| 25 / 50 / 75 % of bodies emptied | 1.7 / 1.7 / 2.1 % | blind |

The distribution is **bimodal**: `stub%` lands either at the app's own baseline
(ordinary constructors and interface stubs, measured at 1.9 % here) or at ~100 %.
Nothing sits in between, so there is no band a threshold could live in, and **partial
extraction is invisible** — a dex with three quarters of its bodies removed reported
0.2 points above its untouched control.

Two consequences the metric's name hides:

- **`stub%` high is dispositive; `stub%` low is not evidence of anything.** A low
  reading is compatible with a genuine dex, a fully nop-wiped skeleton, and a
  `throw`-stubbed skeleton alike.
- **Read `emptied%`, not `stub%`, for the skeleton call.** `emptied%` unions the
  `return*`-stub and the nop-wiped classes, which is what lifts the nop-filled
  skeleton from 0.0 % to 100 %. A `throw`-stubbed skeleton still reads low; for that
  shape the ranking cannot help you and only per-body inspection can.

The trivial-body shapes `dex_dump_validate.py` counts, and which of them are skeleton
evidence, are documented in the script itself (`classify_body`); the split between
`stub` / `erased` / `minimal` exists because collapsing them produced a ranking that
named a fully-wiped image the most likely original.

### The ranking's failure conditions — read these before trusting its winner

The `ranking` block names a "best-supported candidate for the original", and it is
wrong in two measured situations. Both were reproduced, and both are the *opposite* of
the obvious reading:

- **A partially extracted image outranks a heavily stubbed one.** Ranking on the
  emptied share alone put a dex with 25 % of its bodies removed *ahead of* its own
  untouched control — 1.7 % against 1.9 %, because replacing a body with
  `const/4 + return` lowers the `return-void` count. Measured before it was fixed;
  the current key uses the count of skeleton-shaped bodies first, which is monotone,
  and evicts anything over 50 % emptied.
- **A `throw`-stub skeleton is invisible and ranks at the control's own baseline.**
  Every body replaced by `new RuntimeException; throw` measured 1.9 % — identical to
  the untouched image — and it still sorts third in the fixture set. No body statistic
  in this kit sees that shape. If the target family is 360/legu-like, **do not use the
  ranking to pick a baseline**; diff candidate images against each other by body hash
  instead.

The reason to state this in the reference file rather than only in the script: the
ranking's output is a *sentence with a winner in it*, and a wrong winner is worse than
no winner — an agent that adopts a modified image as its baseline builds every
subsequent diff on the wrong artifact. When `emptied%` is at the app's own baseline and
you cannot name a signal that separates the candidates, treat the ranking as
uninformative for that set. Commands and full matrix:
`references/evidence-summary.md` §The capability matrix.

## The FART loop: skeleton, invocation, splice

Extraction shells decrypt a method body only when that method first executes. A dump
taken at any fixed moment therefore holds whatever the app happened to invoke before
you dumped — mostly stubs. Waiting for the UI to wander into every method is not a
plan (thousands of methods, many on paths a user never triggers). The FART family of
tools closes the loop with three steps, **inferred** (not run by this repo against a
live extraction shell):

1. **Dump the whole image.** Class definitions, field and method signatures, string
   tables — the skeleton is complete even when every body is a stub. This is the
   ordinary `recon.md` dump; it gives you the address map for step 3.
2. **Actively invoke every method.** Walk the dumped class list reflectively and call
   each method (dummy arguments; most will throw, which is fine — the point is that
   the *shell* decrypts and installs the body as the method is entered). Hook inside
   ART at the interpreter's entry so that, as each method begins executing, the
   method's `code_item` — now holding the decrypted body — is written to disk,
   tagged with its `method_idx`. These per-method records are the "bin" files of a
   FART dump.
3. **Splice the bodies back into the skeleton.** For each record, overwrite the
   stub body in the whole-dex image at the offset the skeleton gives you, fix the
   header (`scripts/dexutil.py` `fix_dex_header` — signature first, checksum last),
   and **accept nothing until jadx or baksmali parses the result** and the method
   count matches the skeleton. "It assembled" is not "it repaired".

## The code_item length trap

Splicing fails in a specific place often enough to deserve its own section: the
computed length of a `code_item`. The full layout is

```
registers u16, ins u16, outs u16, tries u16,          -- 8 B
debug_info_off u32, insns_size u32,                   -- 8 B  (header = 16 B)
insns[insns_size] u2,                                 -- the instruction stream
[padding u2]        -- ONLY if tries_size > 0 AND insns_size is odd
try_item[tries_size]  { start_addr u32, insn_count u16, handler_off u16 },  -- 8 B each
encoded_catch_handler_list  { uleb size; per handler: sleb offs... }        -- variable
```

Two segments are routinely dropped: the odd-`insns_size` padding before `tries`, and
the whole `encoded_catch_handler_list`, which is LEB128-variable and sits *after* the
try table. Drop either and the splice boundary slides — the rebuilt method swallows
bytes from its neighbour or leaves the handler table pointing past the image, and the
failure surfaces later as a dex that half-parses. Walk the handler list with
`read_uleb` to its true end (`scripts/dexutil.py`); do not estimate it. This trap is
**inferred** from repair-tool post-mortems, and it is the first place to look when a
spliced dex parses worse than the skeleton did.

## Why the classic hooks die on Android 12-16

The original FART-era hooks assumed method entry flows through
`art::interpreter::Execute`. On Android 12-16 that assumption fails for five
independent reasons (**inferred**, from the Kanxue `thread-292312` analysis, 2026-08).
Any one of them produces the same symptom — the dumper runs, logs everything, and the
output directory stays thin:

1. **Invoke dispatch splits away from `Execute`.** A quick-entry call goes to Nterp,
   AOT or JIT code, or a bridge — none of them pass through the old `Execute` hook.
   Forcing the interpreter is not a fix either: the entry point then switches to
   Nterp, which *also* bypasses it. *Repair:* move the dump point up to
   `EnterInterpreterFromInvoke`, which sits ahead of the Nterp/interpreter split, and
   keep fallback points (special invoke branches, ClassLinker load paths, DexFile
   open, Frida ClassLoader enumeration) for the methods that still slip through.
2. **`ArtMethod` layout drift.** Field offsets and pointer-sized members changed
   across releases; a hardcoded offset reads the wrong field and the dump silently
   mislabels everything after it. *Repair:* derive offsets at runtime (probe
   `access_flags` / `quickCode` / `jniCode` on a known method) instead of compiling
   them in.
3. **Scoped Storage breaks the output quietly.** Writes to `/sdcard` fail, the log
   reads like a completed run, and the directory is empty. *Repair:* write under
   `/sdcard/Android/data/<pkg>/files/` (or app-private storage) and **check the
   `open()` return value** — the silent variant of this failure wastes a whole round.
4. **The shell fights back.** Junk classes that exit inside their initializer,
   detection of reflective enumeration, deliberate dex-header corruption in memory,
   decryption deferred to the true execution point, fingerprinting of known dumper
   thread names and paths. *Repair:* randomize your thread names and output paths,
   filter junk classes (few methods, throwaway names) before invoking, and expect the
   counter-measure list to differ per vendor.
5. **Compilation policy shifts the entry under you.** A just-installed app and one
   that has run for a while present different entry mixes (profile-guided
   compilation, Mainline module updates). *Repair:* re-probe the entry type every
   run; never cache yesterday's hook decision.

The debugging order that isolates all five in the fewest rounds: print the entry and
flags for a known method → force the interpreter → observe what the entry became →
place the dump point accordingly → force only the target package (`ignore` lists for
`androidx.*`, `com.google.*`, `kotlin.*` — forcing the framework too freezes or kills
the app) → compare a method's `code_item` before and after invocation → splice →
verify with jadx/baksmali.

## Youpk in one paragraph

Youpk is the ROM-level descendant of the same idea (**inferred**): a modified ART
performs the active invocation *inside* the runtime at class-link and interpret time,
so the reflective caller script, the entry-point guessing, and most shell
counter-measures against host-side tooling drop out — at the cost of building and
flashing a customized runtime per Android version. Choose it when the target's
anti-instrumentation defeats host-side loops entirely, and you control the device.

## The frida-dexdump route and where it stops

`frida-dexdump` walks the live ClassLoaders and writes every dex-shaped memory range.
Environment setup and its two time sinks (the `-o` directory must pre-exist, and
`-D` does not take remote devices) are recorded in `recon.md` §Unpacking a dex-level
packer; the Frida environment itself is `dynamic-frida.md`. What it hands you is a
pile of images of the four shapes above — dedupe, reject and rank them with
`scripts/dex_dump_validate.py` before touching any by hand. Its hard limit: against
an extraction shell it can only ever produce the **skeleton**, because the missing
bodies exist nowhere in memory until invoked. No amount of re-dumping fixes that;
only the invocation loop recovers them.

