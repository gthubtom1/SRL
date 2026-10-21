> 本篇范围：Pitfalls P39–P42 — install/UI verification and decoder desynchronisation.
> 前后篇：part 5/5 · prev [pitfalls-4-native-and-install.md](pitfalls-4-native-and-install.md) · next — · index [pitfalls.md](pitfalls.md)

# Pitfalls — part 5/5

## P39. Install fails with a bare numeric code and no `INSTALL_FAILED_*` constant

**Symptom**

```
Performing Streamed Install
adb.exe: failed to install app.apk: Failure [-99]
```

The APK installs fine through the device's own file manager, and the same build installs on another
device. There is no symbolic `INSTALL_FAILED_*` name, so there is nothing to look up.

**Root cause**

Some OEM ROMs route `adb install` through their own security/verification service. The failure is
**not about your APK**; a device process is declining to accept an ADB-initiated install. The device
log names the real actor:

```
ColorPackageInstallInterceptManager: <VENDOR>_ADB_INSTALL_CANCEL ... packageName=<pkg>
```

**Do instead**

Recognise the shape: numeric-only failure, no symbolic constant, installs fine via the device UI,
and a vendor package-installer/security process in logcat. Then bypass ADB's install path with root:

```bash
adb -s <serial> push app.apk /data/local/tmp/app.apk
adb -s <serial> shell "su -c 'pm install -r -g -d /data/local/tmp/app.apk'"
```

Do **not** start rebuilding the APK, and do not remove permissions or components to "make it
installable" — the artifact was never the problem. Search the device log for the install attempt
before touching the build again.

---

## P40. The screen you captured is not your app

**Symptom**

A launch capture sequence shows a consistent, plausible screen, and conclusions are drawn from it.
Later, the app is discovered never to have been in the foreground at all. The captured frames show,
for example, a vendor package-installer confirmation bearing a package name from an unrelated
earlier attempt.

**Root cause**

An install that went through a UI prompt or an OEM interception can leave the **installer window as
the foreground activity indefinitely**. From then on:

- `am start` on your app appears to do nothing; the other window owns the display.
- Screenshots of your supposed launch show the installer instead.
- `am start -W` — which waits for a first frame — can block past any reasonable timeout, because
  that frame never arrives. This presents as "the tool hung", not as "the wrong window is up".

The insidious part is that the frames are **mutually consistent**, which feels like corroboration.
Consistency is not corroboration when every frame shares the same blind spot.

**Do instead**

- Check the foreground before trusting any capture, and again at the end of the sequence:
  ```bash
  adb -s <serial> shell "dumpsys activity activities | grep -m1 ResumedActivity"
  ```
  If the component is not your package, the frames are evidence about something else.
- Clear the stray window (`am force-stop <installer pkg>`, or a HOME key event) and re-capture.
- Prefer a launcher-driven capture over `am start -W`: derive the time line from captures plus
  logcat instead of blocking on a first frame.
- Treat byte-identical consecutive frames as a **finding** (a hang, a dialog awaiting input), not as
  a capture artefact.

`scripts/coldstart.py` performs the foreground check and warns; see also
`long-task-discipline.md` §captures you never looked at are not evidence.

---

## P41. A patched branch does the opposite of what was intended, and starts cleanly

**Symptom**

The patch targets a boolean config gate. The build installs, launches, and never crashes — and the
behaviour is exactly inverted: the thing that was supposed to be suppressed now appears every time,
or vice versa. Nothing in the logs indicates a problem.

**Root cause**

The **polarity of the branch was read from the field name instead of from the control flow.**
Field names describe intent, not branch layout.

```
0x151304  iget-boolean v11, v0 -> Config.enabled
0x151308  if-nez v11, :far         ; enabled == false jumps AWAY
0x15130c  invoke ...startMain()    ; fall-through: straight into the app
0x151314  :far  iget v11, v0 -> Config.duration   ; the "show it" path
```

Here `enabled == true` is the value that **skips** the promo — the opposite of the literal reading.
A patch that "enables the skip" forces the promo to display on every launch.

The second, equally quiet variant: redirecting a conditional branch (`if-*` -> `goto`) to force one
side. That introduces a new control-flow edge, which can land on a `move-result*` and make the class
fail to load with `VerifyError` — a class-load failure that does not always surface as a crash
dialog.

**Do instead**

- **Decode both sides before editing**, and write one line naming what each one does. If you cannot
  describe the fall-through and the target, you are not ready to patch.
- Prefer **neutralising the branch** (`if-*` -> `nop` pair) over redirecting it. Removing an edge is
  safe; adding one is not.
- Pin the polarity in the patch specification itself: assert which instruction must immediately
  follow the branch. `scripts/dex_patch_bytes.py` fails the patch if `expect_next` does not hold,
  which makes this mistake impossible to commit silently.
- Audit verifier legality after the edit instead of trusting that it launched
  (`scripts/dex_check_verifier.py`).

---

## P42. A decode desynchronises, and every offset after that point is wrong

**Symptom**

An instruction you can see in a smali listing is not found by your own decoder, or is reported at an
offset that does not match the disassembler. Sometimes the decode still produces plausible-looking
instructions, just shifted, so "no match" is reported for something that is definitely present.

**Root cause**

**One wrong instruction width desynchronises everything after it.** Common offenders, each with its
own trap:

- `0x32`-`0x3D` (`if-test` 22t / `if-testz` 21t) are **2** code units, not 1. Treating them as 1
  unit invents a fake second instruction at every branch.
- `0x1A` (`const-string/jumbo`) appears in real toolchains as a **4-byte** form (op, register,
  uint16 string index), not the 6-byte 31c shape its format name suggests. Counting it as 3 units
  shifts the rest of the method by one unit per occurrence.
- `0x28` is `goto` (10t, **1** unit); `0x29` is `goto/16` and `0x2A` is `goto/32`.
- A `nop` payload is encoded `00 <ident> <size>` with `ident` in 1..3; a plain `00 00` is an ordinary
  one-unit `nop`. Treating every `00` as a payload swallows the following instruction.
- dalvik encodes a distant conditional jump as `if-*` **plus** a separate `goto`, not a single
  instruction.

**Why it is hard to see**

The decoder reports what it decoded. A shifted stream looks like a method that simply does not
contain the instruction you want, which reads as a finding about the target — the same failure shape
as P25/P26/P33, and it removes viable patch sites for free.

**Do instead**

- **Assert the walk ends exactly on `insns_off + insns_size*2`.** If it overshoots or undershoots,
  the width table is wrong somewhere and every offset derived from that method is suspect. One
  comparison catches all of the above.
- **Cross-check register numbers.** If the method's `registers` count is 12 and the listing mentions
  `v13`, the decode has drifted.
- **Cross-check one known instruction** against a disassembler before trusting offsets you derived.
- Build the width table from the format groups in `references/byte-level-patching.md` rather than
  from memory, and keep the width logic in one place so a fix applies everywhere.
