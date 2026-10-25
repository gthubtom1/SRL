> 本篇范围：Pitfalls P31–P38 — terminate paths, ELF parsing, checksums, `resources.arsc` and install codes.
> 前后篇：part 4/5 · prev [pitfalls-3-patching-and-artifacts.md](pitfalls-3-patching-and-artifacts.md) · next [pitfalls-5-verification-and-decoding.md](pitfalls-5-verification-and-decoding.md) · index [pitfalls.md](pitfalls.md)

# Pitfalls — part 4/5

## P31. Neutralising a terminate path by making it "not return" freezes the whole process

**Symptom**

The app hangs with **no crash record at all**, then disappears. Or an external process kills it —
`Force stopping … from uid 0`, an app-restart loop — and nothing in the log says "crash".

**Root cause**

A terminate routine (a shell's `kill`/`exit`/`abort` stub, or a self-terminating function entry)
was replaced with something that **never returns**: a self-branch, an infinite loop, a spinning
stub. The caller was written expecting the process to be gone. Instead control never comes back,
whatever lock it held is never released, and unrelated threads wedge behind it.

**Why it is hard to see**

There is no exception, no signal, and no tombstone, because nothing failed — it stopped. Absence of
a crash record reads as "it is still fine", and the eventual death is attributed to whatever the
killer happened to be. The tell is a **uid-0 killer**: an app cannot spawn a root-owned executioner,
so the executioner is outside the app, which means the app froze rather than died.

**Do instead**

**Return. Always return.** A `ret`, or a stub that loads 0 and returns.

- Callers commonly inspect the return value, so make the suppressed call **succeed (0)** rather
  than fail (-1) — failure can push the caller into an error branch that tries a *different* way
  to terminate.
- Do not touch the ordinary-path symbols: `pthread_exit`, `exit`, `abort`, `snprintf`, `closedir`,
  `android_set_abort_message`. Freezing `pthread_exit` wedges every thread that finishes; freezing
  `snprintf` wedges the first log line. A five-stub patch intended for terminate symbols has hit
  exactly those symbols before.
- If the fix is a delay-loop watchdog, the *faulting store*, not the loop, is the thing to remove.

Full treatment, including how to tell which mechanism is actually firing:
`native-tamper-and-suicide.md`.

---

## P32. Rewiring a stub without resolving which symbol it belongs to

**Symptom**

A patch meant to suppress one check breaks something entirely unrelated — often before that check
would even have run.

**Root cause**

PLT stubs are laid out back to back. A patch recipe that names offsets, or that assumes a fixed
stub width, is one arithmetic slip away from rewriting its neighbour. Real outcome of one such set:
five stubs intended to be terminate symbols resolved to **five different symbols on each
architecture**, including a string formatter and a directory call — so the app froze on its first
log line instead of suppressing anything.

**Why it is hard to see**

The offsets and the symbol names usually come from different sources (a note, a previous round, a
generated table) and nothing cross-checks them. The damage then presents as an unrelated stability
problem, and the real cause is two rounds back.

**Do instead**

Resolve every stub to its symbol **before** writing the patch, from the **relocation table** —
never from a comment, a position, or an assumed width.

`scripts/elf_plt.py` prints `stub address -> symbol` for both x86_64 and aarch64, and
`--diff --name-regions` names the symbol each changed stub belongs to, which is the right way to
audit a patch set you inherited.

**The aarch64 stub is 16 bytes (four instructions), not four.** Assuming the short form pushes you
into borrowing the next slot, which belongs to a different symbol — and a 16-byte stub is exactly
what makes a clean two-instruction replacement (`mov x0, #0; ret`) possible without touching
anything else.

---

## P33. "The scan found no call sites" — from a decoder that stopped early

**Symptom**

A scan for call sites, stubs, or a byte pattern reports zero matches, and that zero becomes a
finding: "this library never calls `kill`", "there is no second site", "the payload is absent".

**Root cause**

A linear disassembler handed a buffer that does not start on an instruction boundary can return a
few instructions and then **stop, silently**. No error, no warning — and its partial output is
indistinguishable from a complete negative. On a fixed-width architecture, decoding from the wrong
offset also produces plausible garbage rather than failing.

**Why it is hard to see**

Zero is a comfortable answer. It usually agrees with what you were hoping ("the check is not
there"), so nothing prompts a second look. (See also P25 — same shape, different mechanism.)

**Do instead**

Never conclude absence from a scan whose coverage you cannot describe.

- Prefer **byte-pattern search** for a sequence you already know, taken from a crash or a known
  call site.
- For instruction classes with regular encoding, use a **bit-pattern scan** — branch instructions
  are the useful ones, and this finds every occurrence without depending on linear decoding.
- Otherwise use a **resynchronising** scan (advance one instruction unit — 4 bytes on aarch64,
  1 on x86_64 — and retry).
- State which method you used and what it can miss.

---

## P34. A deliberate crash read as an ordinary bug

**Symptom**

`SIGSEGV`, a real tombstone, `fault addr 0x4` (or `0x0`/`0x8`), `Cause: null pointer dereference`.
It looks like a plain null-dereference defect, so you go looking for the defect.

**Root cause**

There is no defect. A hardening layer that wants the process dead **without calling anything it
imports** arranges a fault — load a small constant, use it as a pointer:

```
mov  x0, #4
mov  w1, #1
str  w1, [x0]        ; fault addr = 0x4
```

**Why it is hard to see**

The tombstone is genuine, the signal is genuine, and `null pointer dereference` is the runtime's
honest description. Nothing distinguishes it from a real bug except the *shape* of the fault — and
"it crashes on a small address" reads like sloppy target code, which is exactly what it is
imitating.

**Do instead**

Read the fault address and the registers **together**:

- Is the fault address a small integer rather than a plausible pointer?
- Does some register hold exactly that value?
- Does the instruction at the faulting `pc` load that constant a few instructions earlier, in the
  same basic block?
- Is there a delay loop immediately above it (`sleep` repeated N times)? That is a watchdog, and it
  explains why the death always comes "a little while after launch" rather than at once.
- Does the block sit right before a normal epilogue (canary check + `ret`)? The intended exit is
  right there.

If all of that holds, **nop the faulting store** and leave the surrounding arithmetic alone — the
thread then falls through into the epilogue and returns normally.

`scripts/native_crash.py` extracts the frames, registers and faulting instruction, and flags this
shape explicitly.

---

## P35. Blocking one termination mechanism and calling the check suppressed

**Symptom**

The `kill` stub now returns success, the import table is clean, the patch is verifiably present —
and the app still dies, with the same signal at the same time.

**Root cause**

A hardening library terminates through **several independent mechanisms that share no choke
point**: an imported `kill`, an imported `exit`, `abort()`, and a **deliberate crash that calls
nothing at all** (P34). A PLT-level fix covers the first two and has literally no effect on the
last one, because no imported symbol is involved.

**Why it is hard to see**

"It imports `kill`, so `kill` is how it dies" is a satisfying and often correct-sounding story. A
*correct* patch to a *real* mechanism produces no visible change when a second mechanism fires
first — so the conclusion drawn is "the patch did not work / the approach is wrong", and a working
route gets discarded.

**Do instead**

Enumerate the mechanisms before patching, then **measure which one actually fires**. The signal
splits the space, and the tombstone confirms it:

| Observation | Mechanism |
|---|---|
| `SIGKILL`, no exit code, **no tombstone** | an imported terminate call |
| `SIGSEGV`, small fault address | arranged crash — no imported symbol involved |
| `SIGABRT` + tombstone | usually a genuine assertion |
| process survives a repack but the library is absent from `maps` | the patch never ran |

**Then verify against the observed time-to-death.** If it died ~40 s after launch before, a
30-second test proves nothing, and a run that survives 45 s has not yet passed.

---

## P36. Parsing a hardened ELF through its section headers

**Symptom**

A tool reports that a library imports one symbol, or has a 200-byte `.text`, or contains no
functions. You build a plan on that.

**Root cause**

Hardened libraries ship **forged section headers**: `.text` sized to a token value, `.dynsym`
truncated, sections overlapping. Anything that walks the section table returns confidently wrong
output — and because the output is well-formed, the wrongness is invisible.

**Why it is hard to see**

A truncated result and a genuinely minimal library look identical. The tool has no way to report
that it was lied to, so the failure is attributed to the target rather than the method.

**Do instead**

Work from the **program headers**, which the loader itself uses and which therefore cannot lie
about what gets mapped:

- `PT_LOAD` → the real segments, their file offsets and their permissions.
- `PT_DYNAMIC` → `DT_STRTAB` / `DT_SYMTAB` / `DT_STRSZ` / `DT_SYMENT` / `DT_JMPREL` /
  `DT_PLTRELSZ`, walked by hand.
- Translate any virtual address to a file offset through the containing `PT_LOAD`.

A library that yields a full import list this way is fine. One that still yields almost nothing
means the hardening is deeper than the section table — **say that**, rather than reporting the
truncated answer as a finding.

For **function boundaries**, use `PT_GNU_EH_FRAME` when it survived: it is authoritative and
complete, and it costs a few lines to parse. Do not reverse-decode backwards looking for a prologue
— on aarch64 almost any 4-byte window decodes as *something*, so a naive scanner reports hundreds
of fictional entry points — and prologue pattern-matching yields a plausible set with no
completeness guarantee.

---

## P37. A byte patch lands, and the app dies with `Bad checksum` and a missing normal class

**Symptom**

After editing a dex by a few bytes and repacking, the app fails to start, and logcat shows an
ordinary class failing to resolve — the Application class, or a small AndroidX component:

```
W/<pkg>: Failure to verify dex file '.../base.apk': Bad checksum (eacdc11c, expected 6456b6b5)
E/LoadedApk: java.lang.ClassNotFoundException: Didn't find class "<AppClass>" on path: ...
E/AndroidRuntime: FATAL EXCEPTION: main
    java.lang.RuntimeException: Unable to instantiate application <AppClass>: java.lang.ClassNotFoundException: ...
```

**Root cause**

Every dex header carries two integrity fields that cover the rest of the file, and **they must be
recomputed in a specific order**:

```
bytes 12..32 = sha1(data[32:])        # signature — computed FIRST
bytes  8..12 = adler32(data[12:])     # checksum — covers the signature, so LAST
```

Computing them in the reverse order leaves the adler32 taken while the signature field was still
zeroed, so the header never verifies. Note also that in the log line above the **real** adler32 is
printed as "expected" and the header's stale value as the computed one, which reads backwards and
sends you looking at the wrong number.

Two properties make this expensive:

- **Android may still start the process**, falling back to interpreting the dex instead of using a
  verified/optimized image. So the failure is not "rejected", it is a *different* failure, and it
  appears as a class-resolution problem in a component unrelated to your edit.
- **Some producers ship a dex whose signature field is all zeros.** On such a file the wrong order
  is self-consistent, so the bug stays invisible until the first edit — and then looks like your
  edit caused it.

**Do instead**

Recompute both fields on every dex you touch, in the order above, and assert the result:

```
adler32(data[12:]) == header_checksum   and   sha1(data[32:]) == header_signature
```

`scripts/dexutil.py` provides `fix_dex_header()` (correct order) and `verify_dex_header()`;
`scripts/dex_patch_bytes.py` runs both and refuses to write a header that does not self-verify.
When you see `Bad checksum`, check the header before investigating the class it named.

---

## P38. `[-124]` on install after a repack: `resources.arsc` must be STORED *and* aligned

**Symptom**

An APK that was previously installed fine, rebuilt with only a dex change, is refused:

```
Failure [-124: Failed parse during installPackageLI: Targeting R+ (version 30 and above)
requires the resources.arsc of installed APKs to be stored uncompressed and aligned
on a 4-byte boundary]
```

**Root cause**

Two independent requirements are compressed into that one sentence: the entry must be **STORED**,
and its **data offset** must be divisible by 4. A `zipfile`-based repack can satisfy the first and
still fail the second, because Python's zip writer gives you no control over entry offsets.

An aggravating factor: this is exactly the class of defect a *signing* step can introduce.
`jarsigner` recompresses entries as a side effect of adding the v1 JAR signature, so an archive that
was correctly aligned before signing is not aligned after — and `jarsigner -verify` still reports
success. If a build that installed a minute ago now returns `[-124]`, suspect the signer first.

**Do instead**

- Write the archive aligned **while writing it** (`scripts/repack.py` emits local headers itself and
  pads the local extra field), rather than repairing alignment afterwards.
- Know the padding arithmetic trap: a zip extra area is a sequence of `(id, size, payload)` records,
  so its minimum useful length is 4 bytes — **a required pad of 1-3 bytes cannot be expressed**.
  Insert a stored filler entry of exactly that size instead.
- Sign with **`apksigner`** (v1+v2+v3), which appends the signature block without reordering the zip.
- Verify by reading the archive, not the tool's exit code: for each gated entry, parse the local
  header, compute `header_offset + 30 + namelen + extralen`, and check `compress_type == 0` and
  `offset % 4 == 0`.

---

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
