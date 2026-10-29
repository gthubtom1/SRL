---
name: apkseep
description: "初步分析这个 APP/看看这个应用/能不能去广告/去弹窗/改会员/解锁功能/重打包/重新签名/脱壳/抓包(.apk/.aab/.xapk/.dex/.so)。Android 逆向、客户端鉴权走查(CWE-602)、DEX/SO 微创补丁、Frida/RPC 插桩、Java2C 与 VMP 差分、重打包签名全链路。"
license: MIT — see LICENSE at the repository root
# ---------------------------------------------------------------------------
# ATTRIBUTION: This skill is derived from and tracks the upstream project
#   https://github.com/newliver666/apk-reverse  (MIT License,
#   Copyright (c) 2026 apk-reverse contributors)
#   The upstream repository carries the tool-verification evidence record
#   (Tool/upstream/apk-reverse/docs/tool-verification/), the offline test suite (tests/), and the
#   capability registry. A copy is bundled at share/upstream/apk-reverse/.
# ---------------------------------------------------------------------------
compatibility: "Python 3.9+。静态分析（DEX/ELF/Protobuf/LeakScan）离线可用；动态探测需 adb / frida-server；重打包签名需 zipalign + apksigner。运行 scripts/doctor.py --json 查看环境能力。"
metadata:
  version: "1.0"
  capability_registry: Tool/skill/apkseep/scripts/capabilities.py
  evidence_summary: Tool/skill/apkseep/references/evidence-summary.md
  last_reconstruction_pass: "2026-09-22"
  strength_labels: "observed | inferred | unverified"
---

# APK Reverse Engineering & Patching

For modification tasks, reach a **verified, installable, still-working artifact** — and avoid the whole class of
mistakes that destroy an APK while looking completely healthy.

## 操作坑（架构层，不是某个样本的问题）

1. **aapt 在 GBK 环境下打不开中文路径**：对含中文的路径直接 `aapt dump badging` 会报
   `Illegal byte sequence` / `no AndroidManifest.xml found`。**先复制到 ASCII 路径**再跑，
   否则会误判成「这个 APK 没有 manifest」。
2.5 **按 Android 路线处理加固**：需要读取或修改受保护代码时，先读 `references/packers.md`、`references/advanced-unpacking.md` 与 `Tool/playbooks/apk-unpack.md`；DEX/SO dump 须结构验证。JNI/native 算法可由 softseep 辅助并返回本项目。Windows PE 的 unpack-loop 不处理 APK；仅画像/静态元信息任务不强制脱壳。
2. **关键词命中 ≠ 加固**：`StubApp` 在普通应用里也可能是系统 launcher 的类名
   （实测上下文 `com.google.android.launcher/.StubApp`）。判加固要看**上下文 + 壳入口类 + so 名**，
   不能只数关键词；`libexec` / `libcompress` 这类名字也要落到具体 ABI 与导出符号再定性。
3. **判据要 dex 与 so 两边都搜**：root 检测/密钥线索可能只在 dex（`/system/xbin`），
   也可能只在 so（`ptrace`/`fork`）。只搜一边会得出「没有检测」的错误结论。

## 阶段契约（与 softseep 一致，**先判再做**）
> **域契约**（判型→裁定+M1–M4→按上限执行→停手问）：见 `Tool/skill/seep-router/SKILL.md`（唯一口径：判型→选域→上限 M1–M4→按当前路线核缺件）。本文件不复制。
- 项目登记、证据、验收与接续按 router 第 5 步；`case_state.py` 仅用于需要专业过闸的单案。
- 只执行当前目标需要的阶段；缺不可替代输入才问 A/B/C，已有授权不重复询问。参考与配方不能扩大用户目标；示例案例通过只证明工具自检，不能代替当前项目验收。
- 子技能可调用辅域；输入、派生文件、已证/未知与输出归同一 project/version/run。方法参考中的秘密采集与系统改动不作为当前执行指引：真实凭据/Token/Key/Salt/私钥由用户操作，不进入 Agent；不改系统网络、时钟或驱动。

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 去广告/去弹窗，开屏与插屏一起清 → `Tool/playbooks/apk-ad-removal.md`
- 加固 APK 脱壳（DexVMP / 内存 dump / 反调试）→ `Tool/playbooks/apk-unpack.md`
- APP 每日任务与签到做成可重放的定时脚本 → `Tool/playbooks/app-daily-task.md`
- 验证码/滑块/点选/人机验证接自动化 → `Tool/playbooks/captcha-handling.md`
- Unity 游戏 il2cpp / global-metadata / AssetBundle → `Tool/playbooks/game-client-il2cpp.md`
- 私有协议、蓝牙/BLE 报文重放与构造新帧 → `Tool/playbooks/protocol-replay.md`
- APK 内 UI 改版、换品牌与图标 → `Tool/playbooks/ui-rebrand.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`壳/加固是哪一类、关键校验落在哪个类哪个方法（dex 定位 + so 导出符号）都已给出，但动态面被壳挡住，没在设备上跑过`
- **能改到能用**：`重打包后能装、能起、目标功能真的变了（Rung 3–4），附反例对照与「原件未改」的哈希证明`
- **能完全自己接管**：`相邻功能逐项验过、机制被证明、发出去的产物就是验过的那个（hash 一致，Rung 5–7）`
- **卡点通常是**：`广告/会员由服务端下发，或碰上抽取壳与真 VMP——改客户端改不了权威，只能出带边界的报告`

> 依据：`Tool/skill/apkseep/references/01-criteria.md` §2 claim ladder（Rung 0–7）/ §4 四种结论形态 + 本文件 §Symptom index

## G-Auth — pointer only

**Single source of truth: `AGENTS.md` §六 + the injected boundary anchor. This section does not restate the rule.**

Apply existing authorization to necessary workspace outputs and available tools. Target execution and system changes follow current host rules; do not ask again for every file write.

## Immediate — scope these steps to the requested outcome

Static inventory/report tasks use relevant read-only classification and evidence only. Device baseline, patch, repack, signing and install gates below apply when delivering a modified runnable APK; they are not prerequisites for every Android question.

This file is a **procedure with gates**, not background reading, and it is long enough that its middle
gets skimmed. So the four moves come first; everything below is the explanation for them.

**1. Classify before choosing a route.** Answer the thirteen questions in §Start here. **R4** decides
whether you are editing the right layer at all, and a wrong branch does not fail loudly — it produces
an artifact that builds, runs, and does the wrong thing.

**2. Clear the four gates, in order, with their pass criteria** (§Gates). G1 names the deliverable form
in one testable sentence *before* any work; G2 establishes what this machine can really do; G3 locates
the code; G4 records the baseline and the control. "I understand the idea" is not clearing a gate.

**3. A symptom you cannot explain is a stop signal, not a puzzle.** Search §Symptom index for the shape
**before your next attempt** and load the file that row names. Those rows exist because each one cost
hours — and in several cases the answer was already written down while it was being re-derived.

**4. Two strikes on one shape of attempt sends you back to classification**, not to a third variant
(§Stop conditions). And **never report done without the six items in §What "done" means.**

**Two rules about this file itself.** When a failure does not fit your plan, the symptom index is the
a useful diagnostic aid. Current user requirements, host rules and reproducible evidence take precedence over this procedure. Check each symptom’s preconditions; a previous case is not proof about the current sample.

## Four rules for artifact modification

**R1 — Write the deliverable as a testable sentence before you touch the target.**
"It works" is not the goal; "it works under the stated constraint" is. Root-assisted, live-
instrumentation, host-proxy and patched-device results frequently do **not** satisfy a request for an
installable artifact that works on a normal phone — and it is easy to present such a result as
finished. Write the sentence, re-read it at every checkpoint, and if you cannot meet it, say so
plainly and label the privileged workaround a **fallback**, never the deliverable.
→ `references/long-task-discipline.md` §the most expensive drift

**R2 — Change one variable at a time, and keep a control build.**
An experiment that flips two things teaches nothing when it fails, and a failure you cannot attribute
will be attributed to the wrong cause. Every "the app rejects X" claim needs its own run, and every
patch needs a same-pipeline control that still fails the old way.
→ `references/long-task-discipline.md` §single-variable discipline

**R3 — Never ship or claim an unverified artifact.**
"It assembles" is not "it works"; "the process started" is not "the feature works"; "no error in the
log" is not "the check is gone". Install it, launch it, exercise the exact feature you changed, and
look at the screen. Prove the device is running the build you made — hash it, do not trust the
filename.
→ `references/verification.md`

**R4 — Identify the owning layer before patching, and re-classify when reality disagrees.**
Ads, paywalls, feature gates, integrity checks and update gates live in different layers (Java, dex,
native, Dart/Unity, server). Patching the wrong layer either does nothing or breaks the app. If a
patch "had no effect", the diagnosis was wrong — go back to classification instead of patching harder.
→ `references/recon.md`, then the layer-specific file the symptom index points at

## Tooling — reach for the right instrument, and check before declaring it absent

Most wasted rounds in this domain are not bad reasoning about the target. They are **the right question
asked of a tool too weak to answer it**: an hour of `grep` over a hand-exported smali tree where one
indexed query would do, a manual ELF walk where a decompiler was one `pip install` away. The failure is
invisible from the inside, because the weak route still produces output.

**Five obligations. These are instructions; a violation is a defect, not a preference.**

| Obligation | Do this | Cost of ignoring it |
|---|---|---|
| **Orient with an indexer, not an export** | Build the ability to *ask the artifact questions* before reading code: `droidasc findrefs` / `ddc findrefs` (string/type/method → every reference site, sub-second). Use indexed references when available; targeted JADX search/decompilation is also a valid entry. Resolve disagreements using DEX instructions and actual callers, not a fixed tool preference | hours of `grep` per question asked, over an export you paid for first |
| **Install the missing tool; it is part of the task** | Check existing equivalent channels, then acquire a necessary missing capability through the formal tool path. Platform, license or dependency failures may be real limits; ask only for indispensable human input | hours re-derived by hand for output a decompiler gives in minutes |
| **Name the gap before spending against it** | State the capability the blocker requires and whether this machine has it, **out loud**. This is a G2 item | designing around a tool that installs in ten minutes |
| **Reach for a shipped script before writing one** | Parsing, hashing, alignment and hot-plug probes are already written; a bespoke script in place of `scripts/dex_find_insn.py` is how offsets get **guessed instead of computed** | a wrong offset that decodes cleanly and behaves wrongly |
| **Pick the instrument for the layer the question lives on** | A dex in memory wants `dex_mem_scan.py` (find and cut) **plus** `dex_dump_validate.py` (judge), not a decompiler pointed at a fragment. An algorithm you only have to *call* wants `emulation-and-rpc.md`. "Does this class ever load at runtime" wants a hook that fires or does not | the heavier tool is not the safer one — it produces a *plausible* answer, which is worse than none |

**Run `python Tool/skill/apkseep/scripts/doctor.py --json` before concluding anything is unavailable.**
It reports per-capability closure — what is missing, what to install, and roughly how long that takes —
and a capability you have not checked for is not a capability you lack. **It is deliberately allowed to
report `BLOCKED`:** a machine with a JVM but no `zipalign`/`apksigner` cannot re-sign, and the report
says so rather than inferring capability from a tool that is merely present. Detail:
`references/toolchain-1-tiers-and-capability-gaps.md` and `references/toolchain-2-runtime-signing-and-trust.md`; the registry it reads is `scripts/capabilities.py`.

## Coverage — what this skill claims, and what it does not

The failure this section prevents is not ignorance. It is **a confident wrong answer produced by
applying the nearest available procedure to a target it was never written for.** A documented method
that almost fits is more dangerous than no method at all, because it arrives with a plan, a
vocabulary and a set of reassuring numbers.

**How strong these claims are — this is load-bearing, not cosmetic.** Every claim in this skill carries
one of three labels, and you must label your own results the same way:

| Label | Means | May it justify a decision? |
|---|---|---|
| `observed` | a command was run and its output exists | yes |
| `inferred` | follows from an observation, but the step is reasoned | provisionally |
| `unverified` | assumed, or reported elsewhere and never reproduced here | only as something to test |

**The inventory that replaces a guess:** the per-route list of what is covered and what is not — by
verified mechanism versus by documented-but-mostly-inferred route — is in
`references/coverage-and-limits.md`. Load it when the question is "can this skill actually do X".

**Partial coverage that is easy to over-read** — these are documented routes whose *dependency* this
skill does not ship, and each has a fence around it in the same file: Dart AOT analysis needs a
snapshot dump you must obtain elsewhere and naming the front end matters · extraction-shell recovery
stops at the VMP boundary · a Stalker trace is not guaranteed on every device · a kernel-side answer
requires a module this skill only scaffolds.

**Unity/IL2CPP 的条件式补充路线**：本域提供 `subskills/il2cpp-dump/SKILL.md` 进行同构建类型/地址映射，可调用 softseep 与 forensics-mobile 的深度参考；工具/设备与版本支持须逐案核实，不能从导航存在推断恢复原始 C# 逻辑或全平台已验证。下列旧覆盖记录描述既有工具包的验证范围，不排除按该子技能做有边界的分析。

**Not covered — say so rather than improvise:** automatic original Unity/IL2CPP method-body recovery · React Native / Hermes / Cordova ·
iOS · defeating a server-side authority · an off-the-shelf unpacker or an anti-detection arms race ·
building and shipping a kernel module. Reasons and evidence boundaries are in
`references/coverage-and-limits.md`; **silence in that record is not support.**

**The fallback, as an instruction — this is a rule, not advice.** If the target does not match the
covered list, or no symptom-index row matches, then **stop and classify before choosing a branch**:
answer the thirteen questions (§Start here). If the shape still does not fit — an unknown runtime, a
mechanism you cannot name — **say exactly that and propose the cheapest experiment that would
identify it.** Do not take the closest documented route and apply it anyway. A wrong branch here does
not fail loudly: it produces an artifact that builds, runs, and does the wrong thing.

## Hand-off points — where this skill ends and another view begins

Four boundaries that are easy to walk into without noticing. Each names what the other side owns
rather than restating it, because two copies of the same advice drift apart. The JNI form table and
the per-form verification table live in `references/handoff-boundaries.md`.

1. **JNI** — a Java `native` declaration and its implementation are two views of one function, and
   this skill reads each with a different tool. A symbol search fails **silently** on dynamic
   registration. Authoritative treatment: `java2c-and-jni-sinking.md` §The JNI boundary — why a
   symbol search fails silently.
2. **Hardening** — a dex-side packer observation is a native-side implementation question.
   `packers.md` owns the dex-side identification; the deep dive belongs on the other side.
3. **Native anomalies** — read them *from the APK side*, because the judgement is whether your patch
   caused the death. Restoring a symbol or reversing an OLLVM function is a different activity with a
   different toolchain: point across instead of extending `native-and-so.md` into it.
4. **Deliverable form** — when the artifact stops being an APK, the verification question changes with
   it. G1's other three forms each move the evidence somewhere else, and the failure is quiet: a
   privileged result reported in the language of a finished build.

## Symptom index — a matching row is a stop signal

You arrive at a symptom, not at a file name. Each row below is a failure that has already been paid
for. **If any row matches what you are observing, load the file before your next command** — not after
your next three attempts. Reasoning from first principles at this point is how the same hours get
spent twice; more than one entry here is a lesson that was re-derived by hand while the answer sat
unread in this repository.

| What you observe | Load first |
|---|---|
| A repackaged/re-signed build **dies before your code runs**; `SIGSEGV`, all registers zero, `pc=0`, `fault addr` near `0x0` | `native-tamper-and-suicide.md` (deliberate crash), then `code-virtualization-and-custom-linkers.md` |
| **No packer** (Application is the app's own, dex readable) **and it still dies** | `code-virtualization-and-custom-linkers.md` §a loader is still a possibility; but if the same build also dies on a *second, unrelated* device you are looking at an ordinary startup fault, not a hardened one |
| The app dies at startup on **every** device, packed or not, with **no tombstone** while `crash_dump` says `already traced` and logcat says `exited cleanly (0)` | a bundled crash reporter has taken the signal handlers, so the platform's own trail is gone. Frida spawn-gating is the recovery route |
| A `FORTIFY: pthread_mutex_lock called on a destroyed mutex` abort in a Flutter app, on the **main** thread, before the first frame completes | `dart-aot.md` — check `libapp.so` is actually being loaded; Flutter's engine bootstrap is the usual place a native lifecycle fault surfaces |
| Log says a **Java-layer** signature/integrity check **passed**, yet the process dies | `code-virtualization-and-custom-linkers.md` §a Java-layer "signature killer" is a decoy |
| Deleting a library fixes validation but yields `UnsatisfiedLinkError: dlopen failed: library "X" not found` | `code-virtualization-and-custom-linkers.md` §the deadlock that eats hours |
| Whole classes appear as bare `native` declarations with no body | `java2c-and-jni-sinking.md` — read it **before** dumping memory: if this is Java2C there is no DEX to find, at any point in the process lifetime. A handful of `native` methods in an otherwise ordinary dex is JNI sinking, not this |
| A `Java_*` search over a hardened library returns nothing at all | `java2c-and-jni-sinking.md` §The JNI boundary — why a symbol search fails silently — dynamic registration, or `-fvisibility=hidden`. The check that works is "exports `JNI_OnLoad` and zero `Java_*`" |
| You are about to publish an evidence file, a transcript or a README that quotes real work | `references/desensitization-and-leak-scans.md` — run `scripts/scan_leaks.py` **before** it is committed; the hit list is a set of lines to look at, and `--show-exempt` is where the wrong suppressions show |
| A hooking module appears to have run but its log tag is silent, and you are about to record "it never loaded" | `references/precedents/logd-broken-module-never-ran-case-3.md` — a broken `logd` delivers nothing on `logcat` while the module's whole run sits in LSPosed's file log; read both channels |
| A library's **SONAME does not match its filename** | `code-virtualization-and-custom-linkers.md`, `native-and-so.md` |
| Your edit had **no effect at all**, with no error | `server-config-and-updates.md` §3 (the value may be server-sent), then `packers.md` §map the validation boundary |
| Process **hangs** with no crash record, or dies to a `uid 0` killer | `native-tamper-and-suicide.md` §the rule (you probably made a terminate path *not return*) |
| Death looks like an ordinary null dereference in a hardened library | `native-tamper-and-suicide.md` §deliberate-crash stubs |
| The app dies **only while you are attached/rooted** | `detection-and-anti-analysis.md`; run the unmodified original under identical conditions first |
| **Install fails with `[-124]` and mentions `resources.arsc` / alignment** | `repack-and-sign.md` §2a — STORED **and** 4-byte aligned, both required |
| **Install fails with a bare numeric code (e.g. `[-99]`) and no `INSTALL_FAILED_*`** | `repack-and-sign.md` §vendor install interception — a device-side interceptor, not your build. Use the root `pm install` path |
| **After an install, `am start` does nothing / screenshots show another app / `am start -W` hangs** | `repack-and-sign.md` §the installer may still own the screen |
| Log shows `Failure to verify dex file ...: Bad checksum` and a startup `ClassNotFoundException` for an ordinary class | `byte-level-patching.md` §the dex header has two integrity fields — order matters |
| An install "succeeded" but nothing changed, or the version did not move | `long-task-discipline.md` §keep the observation window clean |
| Evidence contradicts itself, or a capture looks like two states mixed | `long-task-discipline.md` §keep the observation window clean |
| You took screenshots but drew the conclusion from logs or from the patch itself | `long-task-discipline.md` §captures you never looked at are not evidence |
| You are about to re-run an experiment whose result you already recorded | `long-task-discipline.md` §long-context decay |
| A script will not start, or a tool "is missing" | `scripts/doctor.py`, then `toolchain-2-runtime-signing-and-trust.md` §"not on PATH" is not "not installed" |
| A hook or probe reports **no events at all**, and you are about to call it detection | `scripts/anti_detect_probe.js` for the environment self-report first, then `detection-and-anti-analysis.md` §Step 3: locating the check — the order of search from Stage 0 |
| `attach` hangs and then fails **while the process is still in `ps`** | `detection-and-anti-analysis.md` §Step 3 Stage 0 — check for `D` in `/proc/<pid>/stat`, and attach a *different* pid as a one-line control before blaming the target |
| The app exits with no tombstone, no crash and no ANR record | `detection-and-anti-analysis.md` §Step 3 — a clean self-exit means the check ran before your hooks existed; the branch conditions there say which Stage |
| A dump region validates as the wrong thing, or an `r--s` view of `base.apk` looks like a dex | `advanced-unpacking-2-root-dump-and-vmp-boundary.md` §What this route cannot do, and how to tell before you spend the window |
| Feature-scoped network failure (login/register/pay) while the rest works | `tls-and-cert.md` — do not assume your patch caused it |
| Everything works but **every signed request fails** after repack | `signature-derived-keys.md` |
| A re-signed build **runs fine, renders its whole UI and logs no error — but one feature silently never loads**, and `dumpsys`/DNS/logcat show **no request for it at all** (not a rejected request: *no request*) | `code-virtualization-and-custom-linkers.md` §what the native check actually reads — refusing **before** the request is built. Not the row above: "sent and rejected" and "never sent" have different owners |
| You cannot tell whether a missing feature is **your patch's fault or the target's own behaviour** | `long-task-discipline.md` §single-variable discipline. Run the **zero-change control through the same pipeline**, and the decisive variant: the unmodified original with the patch applied **in memory only**, same device, same network |
| Under Frida `spawn`, the UI never appears — `mCurrentFocus` stays `null`, screenshots come back blank, the Activity stack never builds | `dynamic-frida-1-setup-and-probe.md` §spawn keeps the Activity stack down: write the patch into memory, **detach**, then start the Activity normally |
| `frida-server` keeps disappearing mid-experiment, or the device reboots itself while you are working | `dynamic-frida-2-failures-and-anti-instrumentation.md` §when the ROM hunts your instrumentation |
| Ads still appear after a patch that should have killed them | `server-config-and-updates.md` §6 (cached config / remote re-enable), then `ad-removal.md` §step 4 (count the SDK's own log lines; n -> 0, not "I did not see it") |
| A forced-update or "must update" gate blocks the build | `updates-and-forced-upgrade.md` §step 6 |
| The dialog is gone but the feature is still locked | `membership-and-limits.md` / `account-gates.md` — decide server vs client authority before patching again |
| You are about to discard a route as "blocked" | `packers.md` — re-read it before writing any route off; mis-attributed failures have removed viable routes for hours |
| The task has run long and you are unsure what is already proven | `long-task-discipline.md` §keep a live record |
| A dumped dex parses in full, the classes are all there, and most method bodies are `return-void` stubs or nop fills | `references/advanced-unpacking-1-shapes-and-active-invocation.md` — an extraction shell: measure the `stub%` with `scripts/dex_dump_validate.py` before trusting any of it, and know that recovering the bodies is a different route |
| 需要审计一次微创补丁是否合法（等长改字节 / 方法级重写 / header 校验） | `references/patch-audit.md` — 先跑 `scripts/dex_check_verifier.py` 再信 `dex_classdiff` |
| 要改本地状态（DataStore / SharedPreferences / SQLite）做离线验证 | `references/runtime-data.md` — 容器结构 + `scripts/datastore_inject.py` 回写验证 |
| Your `frida` dump dies mid-write (`script has been destroyed`), or the process you are dumping keeps changing pid | `advanced-unpacking-2-root-dump-and-vmp-boundary.md` §dumping when frida is refused — rule out memory pressure first; a reclaim-and-relaunch needs no instrumentation |
| A repack is refused by several independent checks, or the build has to keep working through store updates | `references/lsposed-and-modules.md` — deliver a module instead of an APK; G1's form table says when |
| A hook module is installed, enabled and scoped, yet its log tag never appears — and you are about to conclude it never ran | `lsposed-and-modules.md` §Deploy, enable, and verify — **a `logcat`-only verdict has already been wrong here**: on one ROM `logd` is broken and output reaches only `/data/adb/lspd/log/modules_<ts>.log` |
| A module's entry class is missing from its own dex (so it can never load), yet the package installs, enables and looks healthy | `references/lsposed-and-modules.md` — check `assets/xposed_init` against the dex's actual classes; installation is not evidence of anything |
| You only need to **call** the target's own routine (sign, token, encrypt) rather than change the app | `references/emulation-and-rpc.md` — emulate it, or service-ify the live function over Frida RPC |
| A native function is a many-thousand-line `switch` state machine, or the decompiler's output is meaningless | `references/native-dbi-and-deobfuscation.md` — OLLVM shapes, a Stalker trace, and how far a trace actually gets you |
| `Stalker.follow` installs but no events arrive, or following a hot libc export crashes the process | `references/native-dbi-and-deobfuscation.md` §6 failure modes — this repository measured both |
| The traffic is protobuf/gRPC/QUIC, or a proxy sees TLS but requests still fail on a Flutter app | `references/protocol-reverse.md` — schema-less protobuf, frame capture, and native-side pinning |
| Userspace hooks land and the app still dies: the check reads `/proc/self/status` through a raw `svc`, or runs before `JNI_OnLoad` | `references/kernel-and-environment-hardening.md` — what the next layer up and down can actually do, and when to stop |
| You must edit, repack, sign or inspect the APK **from the phone itself** | `references/on-device-tooling.md`, `scripts/mt_mcp_probe.py` |
| A captured body decodes to nothing readable, or you cannot tell whether a length-delimited field is a string, a nested message or a packed array | `protocol-reverse.md`. Protobuf on the wire (measured) — run `scripts/protobuf_decode_raw.py`; the candidate list and its `tie:` lines are the answer |
| Method bodies are present but decode as **private opcodes**, and you need the mapping rather than an explanation of why VMP is hard | `vmp-differential-analysis.md`, then `advanced-unpacking-1-shapes-and-active-invocation.md` and `advanced-unpacking-2-root-dump-and-vmp-boundary.md` for the shape diagnosis and boundary |
| A store build arrives as `base.apk` + `split_config.*.apk`, or a rebuilt build is refused **as a set** although every file verifies on its own | `split-apk.md` — one keystore across every member for `pm install-multiple`, and check that a merge is legal before trusting a merged single APK |

## Gates — clear these before you patch, in order

Each gate is an **action with a pass criterion**. Do not proceed past a gate you have not cleared, and
do not treat "I understand the idea" as clearing it. Skipping a gate is not a shortcut; it is how the
work gets redone.

**G1 · Deliverable form — and the cost ceiling on it.** State, in one sentence you could hand to
someone else, what artifact must exist at the end and under what constraints (rooted or not,
installable on a stock device or not, must survive updates or not, online or offline). *Pass:* the
sentence names a testable constraint, not an activity. *Fail:* you are solving a problem in an
environment the deliverable will never see.

Then name the **form** that sentence implies. "A rebuilt, self-contained APK" is only one of four, and
this is where the choice belongs — not after the repack has already failed:

| Form | Right answer when | What it costs you |
|---|---|---|
| **Rebuilt, installable APK** | The client owns the behaviour; no multi-point integrity check; no extraction shell | Repack, re-sign, and a device to verify on |
| **LSPosed / Xposed module** | The logic is client-side but the app fights repacks (multi-point signature checks, shell self-verification), or the result only has to work on rooted devices you control | A rooted device, module scaffolding, and an app that must not detect the hooking framework → `references/lsposed-and-modules.md` |
| **Local RPC / emulation service** | You do not need to change the app — you need to **call** it: a signing routine, a token, an encryption function | A live device or an emulated loader plus a call harness → `references/emulation-and-rpc.md` |
| **Analysis report with a stated boundary** | The authority is server-side, or the target is a real VMP / extraction shell whose recovery cost exceeds the value of the task | Nothing ships — and that is the honest answer, not a failure → `references/advanced-unpacking-2-root-dump-and-vmp-boundary.md`, `references/server-api.md` |

*Decision trigger for leaving the first column:* switch off "rebuilt APK" as soon as the evidence shows
Multiple integrity checks, extraction-shell evidence or private opcodes are reasons to test feasibility, not automatic proof that repacking is impossible. Run the cheapest discriminating control within scope. If required capability remains unavailable, record the specific block and recovery condition; change deliverable form only when it still meets the user's goal or the user chooses that alternative.

**G2 · Environment truth and capability inventory.** Run `scripts/doctor.py` (and `scripts/preflight.py`
if a device is in play). *Pass:* you know which toolchains and scripts can actually run here, you have
seen the environment warnings — clock skew, leftover `adb forward`/proxy, a device-side frida process
already running, a tool installed off-PATH — **and you have written down the capability this target will
demand against the capability this machine has.** Name the two or three layers the task will almost
certainly reach (for example "arm64 native decompilation", "Dart AOT snapshot dumping", "device-side
TLS inspection", "dex-wide cross-referencing") and mark each available / missing-but-installable /
genuinely out of reach. *Fail:* you are about to attribute to the target a failure caused by your own
setup — or to spend a day routing around a tool that installs in ten minutes. A layer whose tool is
missing is a **task item**, not a constraint to design around. → `references/toolchain-1-tiers-and-capability-gaps.md` §Closing a
capability gap

**G3 · Code location.** From the manifest and dex, answer: is there a packer, where does the app's own
code live (dex / native / Dart / Unity / server), and is any of it virtualized to native. *Pass:* you
can name the class that owns the behaviour you intend to change, or you have an explicit plan to find
it. *Fail:* you are about to patch a layer you have not located. If recon says "no packer", still
check the virtualization shape — see the index rows above.

**G4 · Baseline and control.** *Pass:* you have a control run — the unmodified original, or a
zero-change repack through the same pipeline — and you have recorded the observed failure (including
**time-to-death**, if it dies). *Fail:* when the patched build misbehaves you will have nothing to
compare against, and every later measurement is unfalsifiable.


## Start here: classify the target in thirteen questions

**Answer these before touching a tool — all thirteen, in order. Each one changes the whole plan, and
a wrong answer here does not fail loudly: it produces an artifact that builds, runs, and does the
wrong thing.** The answer column names both the action and the file that owns the detail; load that
file before acting on the question.

| # | Question | What the answer changes | Load |
|---|---|---|---|
| 1 | **Is the app packed/hardened?** Read the manifest's `application android:name` | A third-party Application is only a clue; confirm with DEX structure, loader/native evidence and context before choosing a protected-code route | `recon.md` |
| 2 | **Where does the behaviour actually live?** — ad SDK · **server-issued config for client-rendered UI** · membership/VIP · feature flag or debug switch · anything decided by an API response | Client-side and removable, versus server-supplied data the client decides with, versus server-authoritative where a client patch is cosmetic. **Decide this early**: hunting an ad SDK that does not exist costs hours, and the server-config shape has no SDK to find | `ad-removal.md`, `server-config-and-updates.md`, `membership-and-limits.md`, `server-api.md` |
| 3 | **Is the app's own code in plain dex, or moved to native / Flutter / Unity?** | Which toolchain the whole task uses. **Cheap runtime check before committing:** hook the obvious Java classes for the UI you care about and reproduce that UI. Hooks that fire mean Java owns it; hooks that fire **zero times** (only meaningful after positive control, timing and trigger coverage) while the UI is on screen are only a clue. Confirm the class loader, rendering call chain and actual implementation before assigning ownership to native/runtime code or abandoning DEX | `recon.md` §Where does the app's own code live, `framework-runtimes.md` |
| 4 | **What must the deliverable be able to do?** Write it as a testable sentence and re-read it at every checkpoint | The most expensive drift in this skill: a runtime-only result (data edit, live hook, blocked hostname, host proxy) looks like success while failing the requirement. The axes: **privilege** (unrooted?), **modification form** (rebuilt artifact vs live instrumentation), **ABI/device class**, **network**, **persistence**, **distribution** (self-contained?). If the evidence already shows a deep extraction shell, a VMP, or more than one independent integrity check, **re-answer against G1's four forms** — the repack column may be blocked, not expensive | `long-task-discipline.md` §the most expensive drift |
| 5 | **Does the app verify its own signature, or does the server?** | App-side means you must bypass it; server-side means re-signing silently breaks the app later | `repack-and-sign.md`, `server-api.md` |
| 6 | **What is your device situation?** — rooted real device, rooted emulator, or no device | Whether Frida is usable at all, and whether the deliverable can be tested where it will run. **Run `scripts/preflight.py` before your first experiment** and again whenever a failure surprises you — device state, a dead device server, a leftover proxy and clock drift all masquerade as a broken patch | `environment.md`, `pitfalls-2-environment-and-evidence.md` P9 |
| 7 | **Which architecture is actually executing?** | `getprop` reports what the device claims and `primaryCpuAbi` what the package manager chose — **neither is what runs**. Only the live mapping is ground truth. An unmapped library, a translator in play, or a different ABI than assumed changes the plan more than any patch will | `native-and-so.md` §Cross-architecture, `scripts/lib_map.py` |
| 8 | **Is one *specific* feature failing at runtime** (login, registration, payment, an API-backed screen) while the rest works? | A feature-scoped network failure is very often a **TLS/certificate problem on one code path**, not your patch. An app can carry two independent trust chains, so "other requests work" proves nothing. Rule this out in minutes before hunting a signature check | `tls-and-cert.md` |
| 9 | **Was the input a build you did not produce** (a circulating "cracked"/"modded" APK)? | Such builds are frequently re-protected — sometimes with *more* layers than the original — and may carry injected components or endpoints. **Never use one as a patching workbench** | `third-party-builds.md` |
| 10 | **Does the client sign its requests with its own signing certificate?** | Grep for `toCharsString()` / `signatures[0]` / `getPackageInfo(..., 64)` **before the first repack**. If that value feeds a native HMAC/DES routine, the rebuilt APK must hardcode the *original* certificate value at every read site, or every signed request fails while the app still launches and looks healthy. The single most expensive silent failure in a repack, and 15 minutes of grep prevents it | `signature-derived-keys.md` |
| 11 | **Does the app die on its own after a while** — no Java stack, or a native crash that looks like a bug? | A hardened library rarely calls `kill`; it more often **arranges a fault** (load a small constant, use it as a pointer) so the death looks like an ordinary defect. Two rules before touching anything: **enumerate which mechanism actually fires** (signal and tombstone split them apart), and **neutralise by returning, never by making it not return** — a spinning stub freezes the process and produces a symptom that looks nothing like the cause | `native-tamper-and-suicide.md` |
| 12 | **Will this build still be usable in a week?** | Any version check, upgrade prompt or self-update path means an unpatched build can be switched off or replaced remotely. This is one or two edits and it decides whether the work is durable — part of the build, not a follow-up. Also check for a **hot-update / remote-config** channel, which restores removed behaviour with no version change at all | `updates-and-forced-upgrade.md` |
| 13 | **Does the request touch sign-in or phone binding** ("no login required", "skip binding", "guest ok")? | Separating a **client-side gate** (patchable) from an **account-scoped resource** (the screen is empty because the server has no account to answer for — not patchable). Classify first; and **never fabricate a session** to satisfy a gate, which produces a state worse than being signed out | `account-gates.md` |

**Long-task rule (a condition, not advice):** if this is likely to run long, open
`references/long-task-discipline.md` **now** and keep its record updated as you go. Re-read its
refuted-conclusions and dead-routes sections before starting any experiment. Losing earlier findings
is the most expensive failure in this skill, and it is entirely preventable.

## The workflow, end to end

Steps are ordered. **Skip a step only when its stated skip condition is met** — "it seems
unnecessary" is not a condition, and it is the reason most of the failures in the `pitfalls.md` catalogue happened.

**Two-strike rule.** If the *same kind* of attempt fails twice, stop and go back to classification.
Do not run a third variation of a hypothesis that has already failed twice. Two failures of one shape
means the model is wrong, not that the parameters need tuning — and the third attempt is where an
entire round gets spent confirming what the first two already said. Re-read the symptom index at that
point; it exists for exactly this moment.

1. **Preflight, then Recon** — `scripts/doctor.py` is the cheapest possible first command: it reports which toolchains and scripts can actually run here, and surfaces the environment facts that poison experiments (clock skew, leftover `adb forward`/proxy, a device-side frida process already running, a tool installed off-PATH). Then `scripts/preflight.py` before anything else if a device is involved (it takes seconds and prevents a whole class of false conclusions), then `references/recon.md`. Manifest, package name, version, ABI, dex count, packer, embedded SDKs, where the app's own code lives. Ten minutes here saves hours. **If the requested code analysis/edit needs the protected payload, unpack first** (`references/recon.md` §unpacking): you cannot patch code you cannot read, the encrypted payload lengths tell you which dumped dex is the original, and a memory dump must be de-duplicated by hash and structurally validated before any of it is trusted.
   **If recon says there is no packer but a re-signed build still dies**, you are in the layer `references/code-virtualization-and-custom-linkers.md` covers — do not proceed on the assumption that "no packer" means "editable".
   **If the app already dies on its own** — especially at a roughly constant time after launch, or with a native crash — locate the mechanism *before* planning any patch (`references/native-tamper-and-suicide.md`, `scripts/native_crash.py`). Record the observed time-to-death: it is the baseline every later attempt is measured against, and without it a surviving run cannot be told from a changed schedule.
   *Skip condition:* never skipped. G2/G3 in §Gates are cleared here or not at all.
2. **Extract strings and endpoints** — build a picture of the app's API surface and SDK inventory from the dex string tables. No decompiler needed for this, and it is fast. Scripts: `scripts/dex_strings.py`.
3. **Trace to the owning class** — find the class that wraps the behavior (the app almost always wraps third-party SDKs in one helper). Reverse-lookup instructions: `references/dex-patching.md` §finding-the-call-site.
4. **Decide the patch layer** — client SDK call / client rendering / client data consumption / server contract. See the table in `references/ad-removal.md`.
5. **Patch surgically** — `references/dex-patching.md` and `references/byte-level-patching.md`.
   Two techniques, and picking the right one is a decision, not a preference:
   **equal-length byte edits** (`scripts/dex_patch_bytes.py`, located with
   `scripts/dex_find_insn.py`) when the change fits in an existing instruction slot
   or constant — nothing moves, so no offset, try/catch block or debug pointer can
   be invalidated. **dexlib2 method rewriting** (`scripts/dexpatch/`) only when the
   change genuinely needs new instructions. Whole-tree smali round-trip damages
   R8-optimized dex in ways that only show up at runtime; a method rebuild also
   inflates the file (measured: `debug_info` 924 B -> 22.8 KB, dex 4.32 MB ->
   7.73 MB on one sample). Whichever you use, recompute the dex header integrity
   fields (**signature first, checksum last**) — `references/byte-level-patching.md`
   §the dex header has two integrity fields.
6. **Repack and sign** — `references/repack-and-sign.md`. **Do not strip the whole `META-INF/`.** This single mistake destroys otherwise-correct builds.
6b. **Assess update/config interactions within scope.** Record whether an update or remote config affects the requested change. Modify those channels only when required by the agreed goal, then verify affected behavior and rollback; do not disable unrelated updates by default. See `references/updates-and-forced-upgrade.md` as a conditional technique.
6c. **Handle account gates only after classifying them** — if the request mentions sign-in or binding, apply `references/account-gates.md` and state plainly which guarded screens become usable and which stay empty because their content is account-scoped.
7. **Verify on device** — `references/environment.md` + `references/verification.md`. Check: launches, the changed behavior actually changed, nothing unrelated broke, and **the app reaches its normal UI with no blocking dialog**. First prove the artifact actually changed on the device -- a package manager reporting success does not prove an interposed confirmation was accepted (P18). Capture continuously for the first ~20 seconds after launch, **and look at the captures** — sampling gaps are how a blocking modal goes unseen (P20), and a burst of images that were never inspected is not evidence. If the accessibility tree is empty, the image is the primary evidence rather than a fallback.
8. **Log what you learned** — if a failure cost you more than thirty minutes, add it to the matching `references/pitfalls-*.md` part (index: `references/pitfalls.md`). That catalogue is the most valuable artifact in this skill.

## What "done" means — do not claim it earlier

For a modified runnable APK, every item below must be true before claiming that artifact is ready. A static report instead completes against its stated questions, source evidence and unknowns; it must not claim install/runtime success. Missing artifact checks are a **checkpoint** and must
be labelled as one, out loud, with what remains. Premature "done" is the most damaging thing you can
report, because it ends the investigation while the user believes the problem is solved.

1. **The artifact exists and its identity is recorded** — path plus hash, not a filename.
2. **It was installed and launched on the environment the deliverable sentence names** (G1/R1). If
   that environment was not available to you, say so and label the result accordingly.
3. **The behaviour you changed is verified changed** — by direct observation of the feature, not by
   the absence of an error message. "The log is clean" is not evidence; "the screen shows X" is.
4. **The features it touches still work.** You exercised them. A build that starts but whose affected
   feature is dead is not a result.
5. **The original limitation is stated if any survives** — with the coupling that causes it, so the
   next person can decide whether to accept it.
6. **Nothing you did leaves the target or the device in a broken state** unless that was the goal, and
   any privileged workaround is labelled a fallback rather than the deliverable.

If items 1–4 hold but the environment was wrong, you have a **prototype**, not a deliverable. Say
"prototype" and name the gap.

## Stop conditions — halt and re-classify, do not retry

These are moments where continuing to push forward is the wrong move. Each has cost hours somewhere.

- **The same shape of attempt failed twice.** See the two-strike rule above.
- **A patch had no effect and you were about to try a third variant of it.** No effect means the
  diagnosis was wrong, not that the patch was unlucky. Re-classify the layer.
- **A new failure has no place in your current model.** That is the symptom index's trigger condition.
- **You are about to write off a route as "blocked"** without a control build proving the block is
  the app's doing rather than your pipeline's. Mis-attributed blocks have removed viable routes.
- **You are about to claim success on absence of errors.** See §What "done" means.
- **A measurement disagrees with a conclusion you already recorded as settled.** Re-open the
  conclusion; do not explain the measurement away.

## Non-negotiable constraints

**These are defects when violated, not preferences.** Each row states the check that catches it, so
"did I comply" is a command you can run rather than a judgement you make about yourself.

| Constraint | Why it is absolute | The check |
|---|---|---|
| **Inputs are read-only.** Work on copies; keep a known-good baseline | an edited original destroys the only reference you can diff against | `git`/hash the original before the first edit; `scripts/apk_diff.py` for entry-level proof |
| **One variable at a time**, with a control build (same pipeline, **zero** patches) | a compound change that fails teaches nothing, and the failure will be attributed to the wrong cause | a control run exists and its result is recorded |
| **Verify structure after every dex edit** | a patch that assembles and dies at load looks like a patch that worked | `scripts/dex_classdiff.py`: zero differences in class set and access flags for classes you did not intend to change |
| **Never patch a widely shared method.** Count callers first | a `Long.valueOf`-shaped helper with 30 callers is not an ad-specific hook | `scripts/find_refs.py` on the method you are about to touch |
| **Never make an API fail to suppress a UI element** | a 404/400 an endpoint's other features depend on takes the whole screen with it — measured as a build that never leaves the launch screen | suppress at the data-consumption or render layer instead; if a request's path changes, that is the bug |
| **Neutralise a native terminate path by returning, never by making it not return** | a spin stub freezes the caller **holding its lock**; unrelated threads wedge and the symptom (hang, external kill, restart loop) looks nothing like the cause, with no crash record | return a benign value, prefer success (`0`) over failure (`-1`), never touch `pthread_exit`/`exit`/`abort`/`snprintf`/`closedir`. `native-tamper-and-suicide.md` |
| **Look before you conclude, and look while you wait** | a screen that is actually looked at answers in one step what coordinate-guessing cannot answer in five | capture **and inspect**; byte-identical samples mean nothing will change. `scripts/snap.py`, `environment.md` §look at the screen |
| **Bound every command, and calibrate the bound from a measurement** | an unbounded call turns a stall into "still working", which is indistinguishable from progress | time the operation once, record it, derive the deadline from it. `long-task-discipline.md` §Bound every wait |
| **Every claim carries a label — `observed`, `inferred` or `unverified`** | "probably", "should be" and "in theory" are not findings, and an unlabelled guess propagates as a fact | `observed` requires a command **and its output**; nothing else may be written as established |
| **"Done" means the user-visible outcome** | a blocking dialog still on screen means the task is not done, however clean the log is | §What "done" means, all six items; absence of a log line is never evidence of success |
| **Never discard a route on compound evidence** | if a failure followed two simultaneous changes, the attribution is a hypothesis — mis-attributed failures have removed viable routes for hours | re-run the abandonment single-variable before writing it down |
| **Prove the device changed before measuring anything** | install success describes the *request*, not the app on disk | hash the on-device artifact against your build; otherwise every later observation describes the previous build |
| **Attribute a failure to the right layer before patching again** | a feature-scoped network failure is frequently the app's own TLS/certificate problem, and chasing a signature check that does not exist burns hours | run the **unmodified original** on the same device and network first (`tls-and-cert.md`) |

## Reference index and script index

**Both tables live in `references/routing.md`** — one load gets you every reference file with when to
load it, and every script with what it does. They are deliberately not duplicated here: this file is
loaded in full every time the skill activates, and those two tables are about 140 rows of lookup data
that nobody needs until they have already decided what to do.

### Lossless split reference sets

The four long references are now directory pages; every split file is ≤400 lines and keeps its original `##` sections verbatim. Each file is listed here so the split cannot become an orphan set.

| Directory page | Split files |
|---|---|
| [references/pitfalls.md](references/pitfalls.md) | [1 packaging/dex](references/pitfalls-1-packaging-and-dex.md) · [2 environment/evidence](references/pitfalls-2-environment-and-evidence.md) · [3 patching/artifacts](references/pitfalls-3-patching-and-artifacts.md) · [4 native/install](references/pitfalls-4-native-and-install.md) · [5 verification/decoding](references/pitfalls-5-verification-and-decoding.md) |
| [references/advanced-unpacking.md](references/advanced-unpacking.md) | [1 shapes/active invocation](references/advanced-unpacking-1-shapes-and-active-invocation.md) · [2 root dump/VMP boundary](references/advanced-unpacking-2-root-dump-and-vmp-boundary.md) |
| [references/toolchain.md](references/toolchain.md) | [1 tiers/capability gaps](references/toolchain-1-tiers-and-capability-gaps.md) · [2 runtime/signing/trust](references/toolchain-2-runtime-signing-and-trust.md) |
| [references/dynamic-frida.md](references/dynamic-frida.md) | [1 setup/probe](references/dynamic-frida-1-setup-and-probe.md) · [2 failures/anti-instrumentation](references/dynamic-frida-2-failures-and-anti-instrumentation.md) |

The symptom index above stays, because **symptom to file has to be one hop**: when something fails you
are not choosing a file, you are recognising a failure, and a two-hop lookup at that moment is exactly
how a stop signal gets skipped.

`references/evidence-summary.md` is the one reference that answers the claim-strength question from
inside an installed copy: capability → one-line conclusion → `observed`/`inferred`/`unverified` → the
evidence that ships with the skill. Load it when a claim's strength decides whether you trust it and
the run record is not in front of you.

维护工作台时从仓库根运行 `python Tool/scripts/check.py --strict`，并核对 `references/routing.md` 的实际引用。工作台自检不代替客户 APK 的安装、功能或静态任务验收。

## 子技能（按需读，不常驻）

本域相关子技能放在 `subskills/` 目录中（按需读取，零预载）：

| 技能名称 | 核心功能与解决的问题 | 触发场景 / 适用特征 | 所属相对路径 |
| :--- | :--- | :--- | :--- |
| **frida-hook** | Android 移动端动态插桩、Java/Native 双层 Hook、SSL Pinning 绕过与反反调试对抗 | 需要动态观察内存参数、函数调用栈追踪、绕过客户端双向证书绑定或对抗反调试检测 | `subskills/frida-hook/SKILL.md` |
| **dex-unpack** | Android APK 加固识别、运行时内存 DEX 转储、抽取壳主动调用还原与 DEX 文件头对齐修复 | 遇到 360/腾讯乐固/爱加密/梆梆等加固保护、DEX 加密抽取、需要转储内存中已解密的纯净 DEX | `subskills/dex-unpack/SKILL.md` |
| **lsposed-modern** | Modern libxposed (API 100/101) 架构骨架生成、BaseDexClassLoader 动态 ClassLoader 挂钩 | Android 14/15+ 环境、Vector/LSPosed_mod、加壳或分包延迟加载类拦截 | `subskills/lsposed-modern/SKILL.md` |
| **il2cpp-dump** | Unity IL2CPP 逆向分析、内存 global-metadata 抓取、符号复原与 IDA/Ghidra 脚本生成 | 遇到 Unity IL2CPP 编译应用、C# 业务符号被剥离或 global-metadata 被加密保护 | `subskills/il2cpp-dump/SKILL.md` |

## 失败判据 — 停手条件与"改走哪一条"的入口

本节是**索引**，不复制判据表：完整表在 `references/02-failure-criteria.md`
（现象 → 可机检判据 → 不许得出的结论 → 改走哪条），表里每一行都指回本文件或某篇 reference 已有的一句话。

本文件里已经写死的三条总规则是它的入口，不要另立一套：

1. **§Stop conditions 的六条**：同形失败两次 · 补丁无效却要试第三变体 · 新失败在当前模型里没有位置 ·
   要写"blocked"却没有对照组 · 要拿"没有报错"当成功 · 测量与已定结论冲突。
2. **§The workflow 的 Two-strike rule**：两次同形失败说明模型错了，不是参数需要调。
3. **§Non-negotiable constraints 的最后两行**：向正确层归因、以单变量证据放弃路线。

最常触发的判据（各自的行号级来源写在 `references/02-failure-criteria.md` §1）：
`JNI_OnLoad` 返回 `JNI_ERR` 只证明初始化失败，需定位原因 · Java 层校验通过后仍退出不能单独证明 native 校验 · 整类裸 `native` 且无 `Java_*` 可能是 Java2C、动态注册或隐藏导出，先核实现/注册/运行证据，不能仅凭符号排除 DEX ·
`stub%` 落在高那一峰 ⇒ 抽取壳，不是"再 dump 一次" · attach 即死且报错提到 ptrace/tracer ⇒
这是**环境事实**，转全静态 · 每次签名请求都失败而 UI 正常 ⇒ 签名派生密钥。

边界必须写成一句可复核的话（模板与六行边界记录见 `references/02-failure-criteria.md` §3）。

## 模型常见失误 — 这一域最贵的"看起来对"

本节是**索引**：二十余条在 `references/03-model-pitfalls.md`（`M**` 是本篇索引号，检索以原 `P**` 为准），
完整的 42 条失败目录在 `references/pitfalls.md` 与 `pitfalls-1..5` 五个子篇。

按代价排序的前四条（来源：`references/pitfalls.md` §按代价排序，都是"当天基本报废"级，而且**污染后续证据**）：
一次改两个变量（P21）· 签名派生密钥（P27）· 改对了但执行的是旧产物（P24）· 整个 `META-INF/` 被删（P1）。

四条越界型失误（来源：`references/handoff-boundaries.md` §The four ways a boundary gets crossed wrongly）：
用对岸的工具回答这一岸的问题 · 把 JNI 接缝当成实现 · 悄悄换了交付形态（R1 点名的那次漂移）·
把边界当判决（native 代码仍是客户端代码）。

**"这条我读过"不等于"这次在此情形下失效"** —— 命中条目时要对着当前现象再确认一次条件；
目录里没有命中时，正确动作是回 §Stop conditions，而不是继续试。

## 范围边界 — 覆盖到哪、明确不覆盖什么

本节是**索引**，判据与证据在 `references/coverage-and-limits.md`（§Covered · §Dependencies this skill
does not ship · §Not covered），一句话口径在本文 §Coverage，逐条能力强度在
`references/evidence-summary.md` §The capability matrix。

- **覆盖**（`observed`）：dex 等长改字节与 header/verifier/对齐规则 · 重打包签名与安装拒绝 ·
  抽壳识别（平凡体占比是**双峰**，不是阈值）· Java2C 与 JNI sinking 的密度判据 · `resources.arsc`
  STORED+对齐 · Frida 运行时变量（attach 本身即变量）· 签名派生密钥的定位 · 客户端广告与服务器下发
  UI 配置 · 分片 APK 的统一签名与合并。
- **有依赖、不随本技能提供**：Dart AOT 需要你自己拿到 snapshot dump（`dart_pool_strings.py` 说**文件**偏移、
  `pp.txt`/`dart_pprefs.py` 说 **pool** 偏移，两者不是常量差）。
- **条件式方法，不冒充已验证覆盖**：IL2CPP 类型/地址路线见 `subskills/il2cpp-dump/SKILL.md`；原始 C# 方法体恢复不在默认承诺内。
- **不覆盖**：React Native / Hermes 与 Cordova 内部 · iOS 与 `.ipa` ·
  击穿服务端权威 · 开箱即用脱壳器与反检测军备竞赛 · 内核模块开发 · 每台设备都能跑的 Stalker trace。
- **判据表本身**在 `references/01-criteria.md`；**一次完整的判定链走法**在
  `references/04-walkthrough-dump-to-deliverable.md`。

这三节与上面两篇合起来是本域的"停止/归因/边界"闭环：`01-criteria.md` 说"算不算打下来了"，
`02-failure-criteria.md` 说"什么时候改走"，`03-model-pitfalls.md` 说"哪些做法看着对",
`04-walkthrough-dump-to-deliverable.md` 说"按什么顺序走、每一站拿什么数字"。
