> 本篇范围：root-side dump when frida is refused, layered descent, the real Dex VMP boundary, and the decision summary.
> 前后篇：part 2/2 · prev [advanced-unpacking-1-shapes-and-active-invocation.md](advanced-unpacking-1-shapes-and-active-invocation.md) · next — · index [advanced-unpacking.md](advanced-unpacking.md)

# Advanced Unpacking — part 2/2

## Dumping when frida is refused

A hardened target can refuse instrumentation outright: the dump tool dies with
`script has been destroyed` and the process is gone before the error can be read.
That is a *protocol* refusal, not a timeout, and re-running the same attach with a
different flag is the wrong response — twice-identical failure on one variable is a
stop signal, not a hint to try a third flag. What remains is the route that never
touches the process's instrumentation interface at all: **root reads the target's own
memory** through `/proc/<pid>/maps` and `/proc/<pid>/mem`. No agent, no ptrace
attach, no server process for the shell to find.

**Read the signals carefully, because one of them lies.** The refusal presents as
(a) the dump tool's attach failing with `script has been destroyed` while the app is
otherwise healthy, and (b) pid churn. But **pid churn alone is not evidence that
frida was detected.** A 360-jiagu sample on this repository's test device was
measured exiting every 7-18 s and being restarted by the platform, with *no*
instrumentation process anywhere on the device, logging
`Process <pkg> (pid N) has died: fg TOP` and no crash, tombstone or ANR record — a
clean self-exit, i.e. the packer's own environment check. Attribution needs the
control run, and the control run needs a window longer than one restart period: a
12-second observation lands inside a 17-second cycle and reports "stable" about a
process that is not. If the sample self-exits on that cadence, every step below must
fit inside a single lifetime.

### Read the map before choosing the bytes

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
adb shell 'su -c "pidof <PKG>"'                       # may return nothing mid-restart
adb shell 'su -c "ps -A -o PID,NAME | grep -w <PKG>"' # more robust: matches either way
adb shell 'su -c "cat /proc/<pid>/maps"' > maps.txt
```

ART names its in-memory dex mappings for you — this is the cheapest win on the whole
route, because a mapping called
`[anon:dalvik-classes*.dex extracted in memory from <src>]` *is* a dex image, already
located, already sized, no search required:

```
7129d8c000-712a60f000 r--p  [anon:dalvik-classes.dex extracted in memory from /data/app/~~…/base.apk]
```

Copy those ranges first. Everything else — anonymous `rw-p`, `libc_malloc`, `.bss` —
is a *search* target, and searching is the expensive half.

### Address arithmetic is where this route silently breaks

Three device-shell traps cost real time on the first run, and each one produces a
plausible-looking result rather than an error:

| Trap | Symptom | Fix |
|---|---|---|
| mksh arithmetic is 32-bit | `$((16#7129d9a000))` yields `702128128` (the low 32 bits) — `skip=` then seeks to the wrong address and the dump looks like zeros | convert hex to decimal with `awk` (double precision handles 48-bit addresses exactly) |
| A VMA is page aligned | the dump is 0..4095 bytes longer than the image; a validator rejects it with `file_size=8923752 actual=8925184` (17 of 17 files on the measured run) | trim to the `file_size` at dex header offset 32 before validating |
| `grep` is line oriented | the magic contains a `0A`, so no line-oriented pattern can ever match `dex\n035\0`; `-F` with a real newline in the pattern fails too | `grep -z -a -o -b -E 'dex.035'` — with `-z`, records are NUL separated and `.` matches the newline byte; the reported offset is stream-relative, add the segment start |

One more that only bites in scripts: **toybox `awk` cannot be trusted with
`/regex/ && $0 !~ /…/`** — a filter written that way selected all 808 map lines,
including `r--p` system libraries. Filter the map with `grep` and keep `awk` for
arithmetic only.

### Export, then prove it is a dex

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# inside one lifetime of the process: export a candidate range
dd if=/proc/<pid>/mem iflag=skip_bytes,count_bytes skip=<DEC_START> count=<SIZE> \
   of=/data/local/tmp/seg_<n>.bin bs=256k
adb pull /data/local/tmp/seg_<n>.bin <dumpdir>/<n>.bin      # trim first, see above

# or, without writing to the device at all: search a range in place
dd if=/proc/<pid>/mem iflag=skip_bytes,count_bytes skip=<DEC_START> count=<SIZE> bs=1M \
 | grep -z -a -o -b -E 'dex.035' | head -5
```

Then the same acceptance gate the frida route uses: `scripts/dex_dump_validate.py`
over the dump directory — sha256 dedupe, header and `file_size` validation, class
counts, `stub%`, ranking. Rename to `*.dex` first; the validator selects on extension.
Pass `--trim` when the captures come straight from VMAs: a page-aligned region is always
longer than the image it holds, so without it every file is rejected on
`file_size=… actual=…` — 17 of 17 on the measured run, all of them recoverable.

When you do **not** already know which region holds the payload —
`scripts/dex_mem_scan.py <region_dir> --dump <out_dir>` does the search and the cut in one
step: it scans the captures for the magic in bounded chunks, reads each hit's own header,
and writes exactly `file_size` bytes from there. That is the anonymous-mapping case, where
no `maps` entry names the buffer. The division of labour matches the rest of this kit:
that script **finds and cuts**, `dex_dump_validate.py` **judges**. On the measured device
the scan of 142 anonymous regions returned zero hits while the named ART mappings returned
17 images — a negative from a cheap scan is worth having before committing to a heap sweep.

Measured on the test device, this route **works**: 17 ART dex mappings exported in
one pass, all 17 parsing after the page-alignment trim, `stub%` 0.9-3.2 % (real
bodies, SDK plugins), and one of them — the mapping that came from the app's own
`base.apk` — defining exactly **4 classes** on 8.9 MB. That last image is the landing
shell skeleton, and the class count is what says so; the size says nothing. Note what
the route did *not* produce: no second application dex ever appeared in the map
across 22 s of sampling, so the packer's real payload was not sitting in memory as a
loaded ART dex while the observer watched — which is the honest boundary of every
`/proc/<pid>/mem` dump, not a defect of the tooling.

### Limits to budget for

- **The process must stay alive and keep the same pid.** A VMA map and a page table
  both belong to a live process, and every `dd` after the restart reads the wrong
  address space or nothing. On a sample that self-exits every 7-18 s, a dump routine
  must be atomic within one window and re-entrant (re-read `maps` after every
  restart) rather than a long batch.
- **Throughput is the binding constraint, not correctness.** Reading
  `/proc/<pid>/mem` through `grep -z -E` measured about **10 MB/s** on this device.
  A 1 GB ART heap is therefore a ~100 s scan — several lifetimes — so scanning the
  Java heap for a decrypted buffer is the *last* resort, not the first. Named ART dex
  mappings are free; a heap sweep is not.
- **`/proc/<pid>/map_files/` is not a shortcut on this ROM.** The directory exists
  and is root-owned, but its entries are absent/unreadable, so `dd
  if=/proc/<pid>/map_files/<start>-<end>` returns a few dozen bytes of error text.
  Use the `mem` + decimal-offset form.
- **Memcpy dumps of `.so` files are not the `.so` files.** A range lifted from
  `/proc/<pid>/mem` usually carries `PT_LOAD` contents and no section header table;
  a real ELF on disk has both. That difference is how to tell a *disk copy* of a
  library from a *memory-extracted* one — and it is why a leftover `.so` in a work
  directory must be matched against the APK it claims to come from before it is used
  as evidence.
- **In-memory dex bodies can be non-contiguous.** A decrypted image stitched across
  two VMAs (or a payload the packer splits) will not be recovered by dumping ranges
  independently; the `code_off` cross-check and the class-count sanity check in
  §Measuring extraction are what catch that, not the magic search.

### What this route cannot do, and how to tell before you spend the window

The sections above are the how. This is the boundary, and it is worth reading *before*
the first export, because the failure is silent: you export a region, it validates as
something else, and the conclusion "the payload is not resident" is drawn from a wrong
capture. Two measured obstacles and one measured non-obstacle.

**A dex that is still compressed never materialises as an image.** `dexopt` can only
map a dex directly when the archive stores it uncompressed, so for an APK whose
`classes.dex` is stored with **deflate** the method never applies — and nothing in
memory is a whole dex. Measured on the clean MASTG targets (`owasp.mstg.uncrackable1`,
`owasp.mstg.uncrackable3`, both with `classes.dex` at `compress_type=8` in the
*on-device* APK): **zero** `[anon:dalvik-classes.dex extracted in memory from …]`
mappings across ~2,400 map lines each, i.e. `named_dex=0`. There was nothing to
export, and the route's negative says nothing about those targets being protected.

**An `r--s` view of `base.apk` is not a source of dex bytes.** Both targets showed
exactly that shape — a read-only shared mapping of the APK — and it is the shape that
looks like an answer and is not one. Exported and compared byte-for-byte with the same
offset in the file:

| View | Compared with | Result |
|---|---|---|
| `76dfb14000-76dfb15000` (L1, file offset `0x11000`, 4 KiB) | the APK at `0x11000` | **identical** (sha256 `74846b8c…` both) — it is the APK's own bytes, and at that offset they are the ZIP *central directory* (`PK\x01\x02`), not a dex |
| `765a89c000-765a8de000` (L3, file offset `0x6000`, 264 KiB) | the APK at `0x6000` | **identical** (sha256 `2eafd7cc…` both) |
| `76dc28e000-76dc299000` (L3, file offset `0x15a000`, 44 KiB) | the APK at `0x15a000` | **different** — and the reason is not tampering: the mapping range runs *past the end of the file* (offset `0x15a000` > 1,460,555 B), so the file-side read is short and the two hashes describe different byte counts |

Two things follow, and the second one generalises. First, **the two read paths agree
exactly whenever they cover the same bytes** — `/proc/<pid>/mem` and a straight file
read returned identical sha256 on both full-length comparisons, which is the
reproducibility check worth running before treating any capture as evidence. Second,
**when they disagree, compute the length before suspecting the target**: a VMA can
legitimately extend beyond its backing file, and "the bytes differ" then means "you
compared different amounts of data", not "something rewrote the file".

**The non-obstacle, measured:** when the instrumentation route is refused, nothing here
needs fixing — root reads `/proc/<pid>/mem` with no `ptrace` and no agent, and on the
test device that produced 17 real, parseable dex images from a hardened process
(`references/evidence-summary.md` §The capability matrix). The correction this pass adds is
narrower than that claim: **the route's yield is a property of the target, not of the
route.** It yields everything the packer leaves as a whole image; it yields nothing
against a target whose dex never becomes one.

### Is this dex image real? Two independent readers, or a claim you have not earned

The route above produces candidate images; something else has to judge them, and the
judgement has to come from a reader you did not write. A single reading of a hard problem
is not evidence, and this file already carries the lesson in the opposite direction —
`§Establish "the bodies do not decode" with a decoder you did not write` is the case where
a hand-written decoder *invented* a finding.

Three checks, in increasing cost:

1. **Two read paths over the same bytes must agree byte-for-byte.** `/proc/<pid>/mem` at
   `(start, start+size)` versus the file or a second export. Measured above: identical
   sha256 on every comparison that covered the same length. Do this **before**
   interpretation — a capture that cannot be reproduced is not a capture.
2. **A producer you did not write must parse it.** `dexdump`
   (`E:\tools\android-14\dexdump.exe`), `baksmali` or `jadx` — and quote *its* failure
   count, not your own parser's. `scripts/dex_dump_validate.py` ranks and screens
   candidates; it does not decide whether a body is real dalvik.
3. **Only then interpret** `stub%` / `emptied%` / class counts, per
   §Measuring extraction instead of guessing.

**Cross-checking two dumpers is only meaningful when both produce the same artifact.** A
byte-identity comparison is a real check between two implementations reading the same
address space (`/proc/<pid>/mem` versus `process_vm_readv(2)`, or two independent export
tools); it is an empty check between a whole-image dump and a per-method `code_item`
harvest, because those are different artifacts and a byte difference says nothing about
either. State which kind of comparison you ran. A *cross-tool* agreement also does not
prove recovery: on a shell that stubs bodies, two agreeing dumps are two copies of the
same skeleton — which is why check 2's parse count and §Measuring extraction's ratios
both have to pass.

## Layered descent: Java → JNI → Native → libc → syscall

**Read this when an upper layer has gone silent.** "My hook produced no events" is not a
finding about the target until you know which layer is capable of seeing the code that
runs. The upper layers are cheaper and more informative, so the order is deliberate; the
mistake is skipping down for reassurance instead of on a signal.

| Layer | What it sees | What it cannot see | The signal to descend |
|---|---|---|---|
| **Java** (framework hooks) | methods, objects, arguments — the algorithm in its readable form | anything the app does in a library; anything the framework compiled out of reach | no invocation ever fires, or only the first call and then nothing |
| **JNI boundary** | argument and return values of a *named* export; the boundary itself | argument *meaning*; any logic past the call | outcomes are correct but you cannot see why |
| **Native, named exports** (`Module.findExportByName`) | entries of exported functions; the call site that reached them | the function body's control flow (that is `native-dbi-and-deobfuscation.md`) | correct answers, opaque body; a `.so` that never calls its own exports |
| **Native, internal** (module base + offset) | code with no symbol at all | how you found the offset in the first place | a library whose exports are a thin shell over internal work |
| **libc** (`open`, `read`, `mmap`, `strstr`, `pthread_create`, `exit`, …) | every call that *goes through* libc, with caller attribution | calls that do not; anything above libc | an event count that contradicts observed effects |
| **`svc #0` sites** | nothing at runtime until you patch the site — it is a *static* layer | kernel-side: unreachable here, see the gate below | libc shows no such syscall while the effect happens |

Three rules that keep the descent honest:

- **Descending is cheap to state and expensive to trust.** A lower layer has less
  context, so an event there needs *more* support to mean something: `open()` fired says
  nothing on its own, while `open()` with a caller of `libX.so+0x1cef8` names a detector.
  Always carry the caller offset down, or you have traded meaning for volume.
- **The bottom is static, not dynamic.** Below libc there is nothing to hook — a
  `svc #0` site is found by scanning the library (`scripts/svc_scan.py`) and changed by
  patching bytes. Measured: the ROM's `libc.so` carries exactly **4** termination sites
  (`exit`, `exit_group`, `kill`, `tgkill`) and those are libc's own exported
  implementations, which is *why* a libc hook sees callers at all; the same scan on a
  shell library returned 21 byte-scan "sites" that were all data (no syscall-number load
  near any of them). Read the neighbours before believing a count.
- **"Down" does not mean "more capable".** Measured on a real target, the decisive
  detection ran at the **libc** layer — `strstr("frida")` at ~300 ms of process life,
  followed within milliseconds by a clean self-exit with no tombstone — while the code
  that recovered the caller chain sat in **JIT-compiled** runtime output, i.e. a
  *higher* layer that has no file offset. The layers are not a ladder of access; they are
  different observation points, and the useful one is wherever the target's check
  happens to be.

**The kernel layer is not reachable on this device, and the gate is a kernel version.**
eBPF tracing (`stackplz`, kprobes, `seccomp` filters pushed from userspace) requires
kernel **5.10+**; the measured device is **4.14.186**, so that entire layer is closed
here regardless of tooling. `kernel-and-environment-hardening.md` maps the route and its
version gate; do not spend a session on the layer before checking `adb shell uname -r`.
The consequence for this file: the descent above stops at the `svc` boundary, and a check
that runs *inside* the kernel is out of reach of both dynamic and static userspace work.

## The honest boundary: real Dex VMP

The last shape is the one to say out loud: if the dump's method bodies are intact but
decode as private opcodes — rare-opcode density off the charts, unknown opcode slots,
and a large native interpreter loop behind them — the code has been virtualized, and
nothing in this repository will hand it back to you decompiled. Distinguish it from
the JNI sink first (`code-virtualization-and-custom-linkers.md`,
`java2c-and-jni-sinking.md`): there the methods are `native` stubs and the logic lives
as native code; here the bodies are present and *re-encoded*.

### Establish "the bodies do not decode" with a decoder you did not write

This is the one measurement in this file that has already been got wrong here, so it
gets its own rule. A hand-written opcode-width table silently desynchronises on large
dex files — one arm64 branch opcode missing from the table is enough — and the
desynchronisation is indistinguishable from the finding it fakes. Measured on the
`ezAndroid` sample: a workbench table reported **1,393 of 22,424 bodies as
non-decodable** and I read it as private opcodes; the platform decoder returned
**943,223 lines, 34,566 instruction decodes, and zero structural errors** on the same
file (`references/evidence-summary.md` §The capability matrix). The bodies
were ordinary dalvik the whole time, and one of the "desync" methods disassembles into
five clean instructions under `dexdump`.

So: **before any VMP verdict, decode the same file with `dexdump`,
`baksmali`/`smali`, or `jadx`, and quote the failure count that came from *it*.** A
rare-opcode histogram is a lead, not evidence. Never let a private table's desync
inform a classification — "my decoder stopped" is a fact about the decoder.

### What a static dex probe can and cannot decide

Two different questions live in the same dump, and only the first one is answerable
from the bytes on disk:

| Question | Statically decidable? | Why |
|---|---|---|
| Are the bodies real dalvik, or an encoded program? | **yes** | the platform decoder decodes them or reports a structural error |
| Did the code leave the dex for native? | **yes** | `native` access flags, then `Java_*` exports / `JNI_OnLoad` in the matching `.so` |
| Does a native island check signature, root or debugger? | **no** | the logic is ARM64 behind a vtable; the check may exist in no dex at all |
| Are unlabelled `assets/` blobs live payload? | **no** | an unreferenced blob is dead until a runtime path constructs its name — measured: six such files in `ezAndroid`'s `assets/`, **zero** dex strings referencing them |

The trap is the asymmetry. A clean static reading licenses exactly one sentence —
*"this is not dex-VMP"* — and it does **not** license *"this is not hardened"*. Those
are different claims: the second one is the misdiagnosis that sends an analyst looking
for an unpacker when the problem is a native island, or for a private disassembler when
the code is ordinary ARM64 in a 206 KB `.so`. A static probe's silence about hardening
is silence, not a clean bill of health.

What recovery looks like when someone does it, **all inferred**, no fixture exists in
this repo, treat as a research plan rather than a recipe:

1. **Differential hardening as a black-box oracle.** Build sample APKs containing
   every dalvik opcode in known, labeled sequences; submit them to the *same*
   hardening platform as the target; dump the returned dexes; align each original
   method with its hardened counterpart and read off the opcode substitution table.
2. **Handler map recovery.** Locate the native interpreter's dispatch table; each
   handler implements one virtual opcode; the differential table names them.
3. **A private disassembler.** Feed the substitution table into an existing dalvik
   decode layer (`scripts/dexutil.py`'s format table is the shape of the thing) and
   re-disassemble the bodies; decompilation is then ordinary tooling on the output.

Budget honestly: this is weeks, not an afternoon, and it redone per vendor per
version. The cheaper question is usually whether the behaviour you need survives
outside the virtualized island — a hook at the method's Java boundary
(`dynamic-frida.md`) or a server-side answer often reaches the goal without paying
for the island itself.

## Decision summary

| Observation | Action | Where |
|---|---|---|
| Dump parses, stub% near baseline | Filter, verify with jadx, move on to patching | `recon.md` |
| stub% high, image parses | FART loop: skeleton + active invocation + splice | this file |
| `emptied%` high but `stub%` low | nop-wiped skeleton; the old `stub%`-only reading called it the original | §Measuring extraction instead of guessing |
| The ranking names a winner but `emptied%` sits at the app's baseline | Treat the ranking as uninformative for this set; do not adopt that image as a patch baseline | §The ranking's failure conditions |
| Splice produces a half-parsing dex | Re-check code_item length (padding, handler list) | §The code_item length trap |
| Dumper runs, output dir empty | Storage path + `open()` check, then entry-type probe | §Why the classic hooks die on Android 12-16 |
| App dies under the invoker | Shell counter-measures; narrow the force list | §Why the classic hooks die on Android 12-16, and `detection-and-anti-analysis.md` |
| frida attach refused (`script has been destroyed`) | Root-side `/proc/<pid>/mem` dump, atomic inside one process lifetime | §Dumping when frida is refused |
| Target has no `[anon:dalvik-classes…]` mapping at all (`named_dex=0`) | Its dex is compressed and never becomes a whole image — the route has nothing to export here; this is not evidence of protection | §What this route cannot do, and how to tell before you spend the window |
| An `r--s` view of `base.apk` looks like a dex region | Compare it with the file at the same offset and check the length: it is the APK's own bytes (often the ZIP central directory), and a range may exceed the file | §What this route cannot do, and how to tell before you spend the window |
| Two captures of the same address differ | Compare byte *lengths* first; a VMA can extend past its backing file | §What this route cannot do, and how to tell before you spend the window |
| A hook on the upper layer stops firing | Descend one layer on a named signal, not for reassurance, and carry the caller offset down | §Layered descent: Java → JNI → Native → libc → syscall |
| The effect happens but libc shows no such syscall | Static: scan the library for an inline `svc` site before assuming evasion | §Layered descent: Java → JNI → Native → libc → syscall |
| Sample self-exits and restarts with no instrumenter present | The packer's own check, not your hook; shorten every step to one lifetime | §Dumping when frida is refused |
| Methods are `native` stubs with a `Java_*` export | JNI sinking — read the function in the `.so` | `java2c-and-jni-sinking.md` |
| Bodies present, decode as nonsense | Real VMP — **but confirm with `dexdump` first**, then differential oracle or walk away | §Establish "the bodies do not decode" with a decoder you did not write |

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
