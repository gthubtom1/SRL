# The Toolchain: What to Install, What It Cannot Do, and How to Invoke It Unattended

Goal: know which tool owns which question, what has to be installed before the question can be asked at all,
whether that tool can be driven from a script, and how to find out what this machine has instead of assuming
either a rich install or an empty one.

## When to load this

Load this when a documented command fails and the instinct is "the tool is missing", when a step needs a
capability whose tool you have not identified, when you are choosing between two static-analysis engines and
only one can run unattended, when a licence gate may decide the route, when a run returns more output than you
can read, or when you are about to substitute a weaker method for a tool that is interactive or GUI-only. The
symptom index routes "a tool returns more output than you can read, or the same run returns different amounts"
and "a documented command does not run, or a tool is missing" here.

## How the labels in this file are used

Every factual claim carries `observed`, `inferred` or `unverified`, and the two kinds of `observed` are kept apart
because they transfer differently (`observed (record)`: this repository's contribution rules).

| Label | What it means | What it transfers to |
|---|---|---|
| `observed (host)` | Measured on this machine in the session that wrote this file | A host with the same tool at the same version, and no further |
| `observed (source)` | Read in a primary source: the vendor's own documentation, or a file in the project's own repository | Any host running that tool |
| `observed (record)` | Read in this repository's own record: `docs/tool-verification/`, `skills/exe-reverse/evidence/`, or another reference here | The claim as that record grades it |
| `inferred` | Follows from an observed fact, with the step named | The chain, and no further |
| `unverified` | Reported and not confirmed | Nothing, until it is confirmed |

Where a fact could not be confirmed it is labelled rather than smoothed over, and **no flag, function, licence,
version or tool name here was invented to fill a gap**.

The `observed (source)` rows about products, interfaces, licences and maintenance state are collected in
`skills/exe-reverse/evidence/tool-sources.md`, which names the URL behind each one and labels it the same way.
Read it when you need to argue with a claim here, or when a claim has aged: licences change, repositories are
archived, and a project moves its active branch without moving its release tag.

**Provenance of the tool sections.** Every tool claim in the static-analysis-engine, radare2/rizin/Cutter and MCP
sections comes from the repository's research record `_research/F-agent-tooling.md`, unless the line says `observed
(host)` because it was re-measured here; the solver rows come the same way from `_research/F-solvers.md`. Both
records name the URL behind every claim and carry their own strength label, negative results included.

## The rule that decides every other question in this file

**A tool counts as installed when it runs and produces output — not when a file with its name exists on
`PATH`.** Three consequences, each of which has cost a session:

1. **A tool installed off `PATH` is not missing.** Installers place binaries in versioned directories, under a user
   profile, or inside an SDK tree, and nothing adds them to `PATH`, so a probe that only consults `PATH` reports a
   capable machine as bare. The host probe here resolves each name against `PATH` first, then against directories
   given through its own repeatable option and through an environment variable, and labels a hit found that way
   (`observed (host)`, `scripts/hwprobe.py`: `--tools-dir`, `EXEREV_TOOLS` / `EXE_REVERSE_TOOLS`).
2. **A runnable archive counts as installed.** A `.py` invoked through the interpreter, or a `.jar` invoked through
   the host's Java runtime or a vendor launcher, is a capability that exists. Give it an input and see that it
   produces output; only then is it absent.
3. **A capability you never probed for is not a capability you lack.** The probe answers with three states rather
   than two — available, needs-something-named, unavailable with the reason (`observed (host)`, its route rows:
   `available`, `needs-a-debugger`, `needs-privilege`, `needs-reboot-and-testsigning`, `no documented user-mode
   path on this platform`). "Needs a restart and test signing" and "the CPU does not report this" lead to
   different plans.

Two invocations, run in this order before any plan depends on a tool:

```
python scripts/hwprobe.py --tools      # which tools and Python modules this machine has
python scripts/hwprobe.py              # which routes those tools and this CPU can support
python scripts/hwprobe.py --json       # the same report, machine-readable
```

An empty category is a finding to state out loud with the search that produced it. This skill's own development
host is the standing example: Python, MinGW binutils, `go`, `dotnet`, `frida`, `wpr` and `java` present, and
**every static-analysis engine, debugger and signature tool absent** (`observed (record)`,
`docs/tool-verification/TOOL-VERDICTS.md`).

## Tiers: what must be added before anything can run

| Tier | Cost | Products in it | What it buys | The measurement that decides it |
|---|---|---|---|---|
| **0. Already on the machine** | nothing | The PE format as the platform implements it; the event-tracing pair `wpr` + `logman` and the parser `tracerpt`; the boot-configuration editor `bcdedit`; the .NET CLI `dotnet`; the in-box IPT driver `ipt.sys` | Everything offline: this skill's readers and patchers, ETW capture, managed-runtime enumeration, boot configuration. **No static-analysis engine is in this tier.** | `wpr`, `tracerpt` and `bcdedit` resolve from the system directory here (`observed (host)`); the repository records `wpr` 10.0.26100.4652 and `logman` 10.0.26100.8875, noting that capture needs elevation to be worth anything (`observed (record)`). `dotnet --list-runtimes` answers with **six runtimes at once** here, so a managed-code result must name the runtime that ran it (`observed (host)`) |
| **1. One download, no licence** | a fetch and an unpack | Ghidra plus PyGhidra; radare2; rizin; Cutter; the pip-installable solver and emulation layer; Frida; HyperDbg (see tier 3 for what else it costs); the Microsoft pieces — the debugger package carrying `cdb` and `TTD.exe`, the SDK carrying the header dumper and the signing tool | A working disassembler, decompiler, debugger engine and automation channel for ordinary tasks. A plan should normally live here. | Nothing beyond the download, but "free disassembler" is not one option: radare2 and rizin carry different licences, and Cutter's command line means something else again |
| **2. Needs a licence** | a purchase, or accepting a licence's scope | IDA Pro, `idalib`, and the separate IDA Pro Headless SKU; Binary Ninja Commercial / Ultimate / headless | The strongest decompiler output in the field, Binary Ninja's layered intermediate languages, and **the only route to unattended IDA or unattended Binary Ninja** | IDA Free costs nothing and removes the scripting capability entirely; Binary Ninja Free costs nothing and excludes the headless API. The answer to a licence gate is to buy the licence or change engines, never to script the unscriptable tier |
| **3. Needs hardware, privilege or a second machine** | a reconfiguration you may not be allowed to make | Intel Processor Trace capture; HyperDbg; kernel debugging; hardware breakpoints; TTD recording; ETW kernel providers | The observation routes that survive a target which detects or refuses software instrumentation. Each is conditional on the host, and the probe states the condition | `observed (host)`: the processor reports Intel Processor Trace, the record-and-replay debugger is not installed, a hypervisor is present, and reading last-branch-record or performance-monitoring registers needs privilege. "The CPU supports it" is never "you can capture it" |

## The static-analysis engines, one by one

All three answer "what does this code do"; they differ in what they expose to a script, which decides whether
a task can run unattended. Engine facts are `observed (source)` unless marked otherwise.

### IDA Pro, and `idalib`

**For.** The reference disassembler and decompiler. Two things share the name: the GUI binary `ida`, and the
headless library `idalib`.

**Headless entry point, route 1 — the GUI binary in batch mode** (`observed (source)`, the vendor's
command-line switch documentation for 9.5):

```
ida -A -S"myscript.py argument1 \"argument 2\" argument3" sample.exe
ida -B sample.exe
```

- **`-A` is not "run a script".** Its documented meaning is autonomous mode: "IDA will not display dialog boxes.
  Designed to be used together with `-S` switch." It suppresses interaction and executes nothing by itself — the
  most commonly misquoted switch in the domain, which is why the repository records it as a fact worth stating
  (`observed (record)`, `docs/tool-verification/TOOL-VERDICTS.md`).
- **`-S###` runs a script**, when the database is opened. The interpreter follows the extension (`.idc`, `.py`),
  parameters may follow the script name, and they arrive in the IDC global `ARGV` (`ARGV.count` / `ARGV[0]`, and
  in Python after `import idc`, `idc.ARGV`).
- **`-B` is a wrapper, not a third mechanism**: `ida -B input-file` is documented as equivalent to
  `ida -c -A -Sanalysis.idc input-file`, writing a database and an assembly listing beside the input.
- Switches for a repeatable run: `-a` disables automatic analysis (`-a-` enables it), `-c` creates a new database
  and deletes an existing one, `-o####` names the output database and implies `-c`, `-L####` the log file,
  `-T###` the file type or archive member (suppressing the load-file dialog), `-p####` the processor.
- **Two batch caveats.** Ordinary plugins are **not** loaded automatically in batch mode, because the analysis
  script exits before the kernel reaches the plugin-loading point; and the vendor's batch guidance recommends
  `idalib` instead, because it uses fewer system resources.

**Headless entry point, route 2 — `idalib`**, "IDA as a library", usable from standalone applications so that
analysis runs headlessly:

- **`import idapro` must be the first import in the script**, before any other IDA module; IDAPython modules such
  as `ida_funcs` and `ida_auto` come after it. Two API routes sit on top: IDAPython and the higher-level Domain
  API. C++ links against `idalib.hpp` and the IDA C++ SDK.
- The Python-side lifecycle function names are **`unverified`**: the documentation read describes the sequence as
  "initialize, open a database, analyze, close" without naming the functions.
- **Registration is one-time and per-installation**: `idalib` finds the installation through `ida.config.json`,
  and activation happens during installation (9.4 and later), through HCLI, or by running the installation's
  `py-activate-idalib.py` helper in its `idalib/python/` directory.
- **One vCPU per process**: "IDA is single-threaded. Allocate one vCPU per container." Plan processes, not threads.

**The licence gate, and it is the hard part** (`observed (source)`): `idalib` is included in IDA Home, IDA Pro
(Essential, Expert, Ultimate) and IDA Classroom. Embedding `idalib` in your own software, using it as a SaaS
engine or running it on a shared server needs an **IDA Pro OEM** licence, free during development and beta phases.
The separate **IDA Pro Headless** SKU is the same disassembler, decompiler and analysis delivered as a library
with no interface, licensed per person, machine or seat.

**What it cannot do**, which decides more plans than any missing feature:

- **IDA Free has no scripting path at all** — no IDAPython, no C++ SDK, no `idalib` (`observed (source)`: the
  vendor's FAQ answers "No, you don't have access to IDA C++ SDK or IDAPython API with IDA Free."). It is
  x86-32/x86-64 only, non-commercial only, and its decompiler is cloud-only.
- **IDA Home, the paid personal edition, does not restore `-S`**: "The `-S` switch is not available in the IDA
  Home edition", and `-O` is unavailable there too (`observed (source)`). Free and Home are different products.

**Unattended?** Yes on IDA Pro, through either route, with route 2 the vendor's own recommendation. No on IDA
Free or IDA Home. Neither route produces a conclusion: a batch job yields a database and a listing, not an
answer.

### Ghidra, headless

**For.** A free, Apache-2.0 (repository `LICENSE`) analysis suite with a decompiler, and the engine most likely
to be present because it runs anywhere a JVM runs (`observed (source)`; the main branch was last committed
2026-10-15, so it is alive).

```
support/analyzeHeadless <project_location> <project_name> [options]
```

| Argument | What it does |
|---|---|
| first and second positional | The project location, then `project_name[/folder_path]` with backslashes normalised to `/`. A location starting with `ghidra:` is a Ghidra Server URL, and then there is no second positional |
| `-import <directory\|file>` / `-process [<project_file>]` | Mutually exclusive; the launcher refuses both at once |
| `-preScript` / `-postScript <ScriptName>`, `-scriptPath "<path1>[;<path2>...]"` | Scripts are supplied by name, with their search path |
| `-log <path>` / `-scriptlog <path>` | Where application messages and script messages go — see below |
| `-noanalysis`, `-processor <languageID>`, `-cspec <compilerSpecID>`, `-analysisTimeoutPerFile <seconds>`, `-max-cpu <count>`, `-librarySearchPaths`, `-loader <name>` (spelled `-loader-<parameter>`) | Whether analysis runs, what reads the file, and how the run is bounded |
| `-readOnly`, `-overwrite`, `-deleteProject`, `-mirror`, `-recursive [<depth>]`, `-allowAllAccess`, `-propertiesPath` | Whether the project may be written back, and how existing state is handled |
| `-connect [<userID>]`, `-p`, `-commit ["<comment>"]`, `-okToDelete`, `-keystore` | Server projects and what gets committed |

- **Output is captured as a log, not stdout.** This costs an hour when it is not known. The launcher's own
  source states that it does not write script output directly to stdout or stderr and that the headless
  analyzer uses only its logging mechanism to deliver output to the user; a script exception becomes a
  `REPORT SCRIPT ERROR:` entry. A pipeline that greps standard output for script results gets nothing, and that
  emptiness is not a finding about the target.
- **`-noanalysis` and `-readOnly` are different decisions.** The first controls whether automatic analysis runs
  after import; the second whether the project may be written back. `-readOnly` is **required** inside a
  read-only project or repository, conflicts with `-commit` and `-okToDelete` (the launcher's own error text
  refuses the combination), and processing a Ghidra URL enables `-commit` automatically unless `-readOnly` is
  given. `-overwrite` does not apply in `-process` mode.
- **Concurrency is per-project**: a failure to obtain the project's write lock surfaces as an exception caused
  by a lock exception (`observed (source)`). Whether the documentation says "one process per project" in words
  is **`unverified`**; plan one process per project and do not add a lock protocol of your own.

**PyGhidra, the Python route that ships with Ghidra itself.** A feature module in the project's own repository,
developed originally as "Pyhidra" by a government cyber-crime centre, driving the Ghidra API from native
CPython through a Java bridge (`observed (source)`). It runs Ghidra scripts written in CPython 3 in **both the
GUI and headless Ghidra**. Entry points from the module's own README: `pyghidra.start(verbose=False, *,
install_dir=None)`, then `started()`, `open_project()`, `open_filesystem()`, `consume_program()`,
`program_context()`, `analyze()`. Installed with `pip install pyghidra`, stubs as `pip install
ghidra-stubs==<version>`; the installation is located through `GHIDRA_INSTALL_DIR` or the `install_dir`
argument. The Windows launcher's filename is **`unverified`**; the one confirmed in the repository is bash.

**What it cannot do.** It is the slowest of the three engines on a large binary; it has no official MCP
component, a negative that is itself **`unverified`** because the README and recent release notes contain no
mention but a code search that would settle it needs authentication; and two headless processes on one project
is a conflict, not a queue.

**Unattended?** Yes, and it is the free engine that actually supports it.

### Binary Ninja

**For.** A decompiler and analysis platform whose distinguishing feature for this skill is not its UI but its
**layered intermediate languages**: the layers below source-like reading are queryable structures rather than
rendered text, which is what makes it the best engine to drive from a machine.

**There is no batch mode, and that is the vendor's position, not an omission** (`observed (source)`, the
vendor's batch-analysis page): asked "How do I enable batch-processing mode?", the answer is that there is not
one, and "the good news is because it doesn't need it! ... BN is simply a library that is trivial to include in
your own scripts for batch analysis." The interface is therefore Python:

```python
import binaryninja
with binaryninja.load("/path/to/sample.exe") as bv:
    ...
```

The operational details that decide whether a run is usable, all `observed (source)`:

- **Licence gate.** "As long as you have a Commercial or Ultimate license (or a headless license), it's
  possible to invoke the core analysis library with all of its APIs without even launching the UI." The headless
  MCP server is documented as **not** available in Free or Personal either, and the Free Edition licence forbids
  reverse engineering Binary Ninja itself. `inferred`: the headless API is unavailable in Free and Personal,
  since both statements restrict headless use to the paid tiers.
- **Setup, teardown and parallelism.** The SDK ships a helper (`install_api.py`) inside the product's own
  `scripts` directory that writes a `.pth` so Python can find the library; the vendor warns against the
  store-distributed Python. `load()` with `with` closes the view; without it, closing the file is the caller's
  job and memory leaks until the process ends. Multiprocessing must use the `spawn` or `forkserver` start
  method, because forking "WILL CRASH OR HANG" in the vendor's own wording.
- **Two ways to make loading cheap or lazy.** `load(path, update_analysis=False)` skips the linear sweep and the
  recursive descent. `load(path, options={'analysis.initialAnalysisHold': True})` holds analysis, and reading a
  function's high-level IL then forces analysis on demand for that function only. Registered plugin commands
  are reachable from the library: build a `PluginCommandContext(bv)` and execute a named command from
  `PluginCommand.get_valid_list(cxt)`.
- **Licence and user state are injectable, which makes a clean container possible.** The licence normally sits
  in a file under the user profile and can also be set through the API, which the vendor states does not
  obfuscate the serial number. User settings, user plugins and repository plugins can each be disabled through
  environment variables that must be set **before** the library is imported.

**The intermediate-language levels, and what each is for** (`observed (source)`, the vendor's IL overview):

| Level | What it is | What to use it for |
|---|---|---|
| **LLIL** (Low Level IL) | From the lifted form; removes no-op instructions and folds flag computation into conditional instructions, otherwise the same operations. An SSA form exists | Machine-shaped questions: exact operand flow, flag semantics, one instruction's effect |
| **Mapped Medium Level IL** | A translation layer, documented as rarely needed for analysis but useful for the translation process | Almost never a target; it explains a discrepancy between LLIL and MLIL |
| **MLIL** (Medium Level IL) | Registers and memory accesses become variables, types are associated with those variables, and platform information is used to generate calls. An SSA form exists | The level to query from a script: typed variables and real call structure without source-level guesswork |
| **HLIL** (High Level IL) | The highest layer, meant for reading close to source | Reading by eye, and confirming in human terms what a script found at MLIL |

**Read at HLIL, query at MLIL, drop to LLIL only when MLIL has absorbed the detail.** Note that the vendor's
function-identification feature, which generates GUIDs from function bytes, is a signature-library mechanism and
not a model-driven one.

**What it cannot do.** No batch switch exists to be found; the Free Edition forbids reverse engineering the
product itself; and without a paid seat the route cannot run at all, however well the library is documented.

**Unattended?** Yes as a library, on a Commercial, Ultimate or headless licence.

## radare2, rizin and Cutter are three different things

They are related, they are frequently spoken of as interchangeable, and treating them as one has cost a
session's work. `observed (source)` throughout, from each project's own files.

**The relationship.** rizin is a **fork of radare2**, described in its own README as "born as a fork of the
radare2, with a focus on usability, features and cleanliness"; its FAQ gives the reasons as a divergence of
direction, technical disagreements and interpersonal ones, and records that Cutter and its team moved to rizin
as the backend. So **Cutter is powered by rizin**, and rizin is a fork of radare2 — a Cutter plugin's Python
API is built on rizin's bindings, not on r2pipe.

**Their licences differ, and the difference is not cosmetic.** rizin's repository root licence is the GNU GPL
v3 and Cutter's is too (`observed (source)`: both read at the repository root). radare2's README self-reports
LGPLv3 (`observed (source)`), and whether its `COPYING` says the same is **`unverified`** — that file was not
read line by line. Whether rizin's library carries additional permissive terms is also **`unverified`**. The
consequence: **do not carry radare2's licence description over to rizin or Cutter**, and do not reuse a
permissive-licence argument from one project in a plan that uses another.

**The flag differences that make a copied command mean something else.** Every one of these produces a run
rather than an error:

| Flag | radare2 | rizin | Cutter |
|---|---|---|---|
| `-j` | Two meanings, both implemented: JSON output, and entry to an embedded JavaScript engine when no file argument is given | **Does not exist**; JSON comes from long options and command-level JSON modes | not this flag |
| `-E` | Opens an editor on the user's rc file | **Endianness** | `-e` is endianness |
| `-P` | Exists (patch mode) | **Does not exist** | a different option |
| `-c` | A command string to execute | A command string to execute | **The CPU**, not a command |
| `-e` | A configuration assignment | A configuration assignment | **Endianness**, not a configuration assignment |
| `-a` / `-b` | Force architecture / bits | Force architecture / bits, and the **only** accepted route for them | architecture / bits |
| `-q` | Quiet, no prompt, exits after the scripted commands | Same idea, with its own documented wording scoping the exit to the scripted commands | n/a |

**rizin refuses `-e` for architecture, bits, OS and endianness** and requires the dedicated flags, so a radare2
invocation that configures the target through `-e` is rejected rather than reinterpreted. And **the claim that
rizin renamed the core command and configuration surface does not hold**: `e` still means "get or set a
configuration variable", and `asm.arch`, `asm.bits`, `cfg.debug` and `cfg.bigendian` keep their names. What
changed is the shell underneath (a new parser and a generated command registry), the project file format, the
package manager (`r2pm` against `rz-pm`), the binding (`r2pipe` against `rzpipe`), the tool family names (`r2`
with the `ra*2` family against `rizin` with the `rz-*` family: `rz-bin`, `rz-asm`, `rz-diff`, `rz-hash`,
`rz-gg`, `rz-find`, `rz-sign`, `rz-ax`, `rz-run`), and some removals — the embedded web interface, the `m` and
`T` commands and the old project format among them. A recipe that says "r2 tools" and then invokes `rz-*` names
was written by someone who did not check.

**Scripting entry points.** radare2's `-A` runs the analysis command before the prompt (`-AA` the deeper one),
`-c '<command>'` executes a command before the prompt, `-i <file>` runs a script **after** loading a file
(`-I` before), `-w` is write mode, and its main programmable interface is a pipe to the process (r2pipe), with a
socket-style mode driven by environment variables and an internal interpreter dispatch (`#!`) for script
languages. Cutter's Python plugin API binds to rizin's own bindings and exposes a singleton core object.

**Cutter's headless status is `unverified`**: the absence of any such option in the development branch's
documentation and application entry point was checked, but no vendor statement denying it was found. Do not
call Cutter "GUI-only" as though that were cited, and do not plan on driving it unattended. Maintenance at the
verification pass (`observed (source)`, each project's main-branch feed): radare2 2026-10-16, rizin
2026-10-15, Cutter 2026-09-11 — all alive, none a dead dependency, none the same project.

## The solver and emulation layer

Method belongs to `references/symbolic-execution.md`; this carries what is needed to install and drive it, which
is the promise that reference makes. Rows are `observed (source)` from `_research/F-solvers.md`, which names
each project's repository, licence file and package metadata.

| Tool | Install name | Licence | Entry point | The packaging trap |
|---|---|---|---|---|
| Z3 | `z3-solver`, imported as `z3` | MIT | Constructor and solver classes, a check call, a model call, plus SMT-LIB export; bit-vector, integer, array, real, floating-point and string theories | It can answer `unknown`, which is not an error and not an answer; mixing bit-vectors with integers or reals carries significant overhead by its own guidance |
| Bitwuzla | `bitwuzla` | MIT | Bit-vectors, floating point, arrays, uninterpreted functions and combinations | The intended successor to Boolector, whose README states that active development has stopped and that Bitwuzla succeeded it — recommending Boolector as a current bit-vector solver is out of date |
| CVC5, Yices 2 | `cvc5`; `yices` | modified BSD (BSD-3-Clause); GPLv3 | A first-order combination solver with several language bindings; SMT-LIB and its own format | CVC5 needs MSYS2 or a MinGW cross-compilation on Windows; the Yices Python binding is a separate repository, classified Beta, last uploaded 2024-12-18 |
| Triton | `triton-library` (note the name, not `triton`) | Apache-2.0 | Symbolisation, tainting, path constraints, slicing, solver calls, lifting to SMT and to LLVM | **The active branch is not the release**: newest tag 2022-02, master 2026-05, development branch 2026-10, package index 2024-05 — four answers to "how old is Triton" |
| angr | `angr` | BSD-2-Clause | Project, state, simulation manager, explore with find and avoid, then a solver query on the found state | Needs a recent Python; its own documentation is candid about path explosion, imperfect library summaries, and symbolic write indices being concretised |
| Miasm | `miasm` (native Python package) | GPLv2 | Its own disassembler, intermediate representation, JIT and symbolic-execution engine | Pins an exact version of the solver and of the JIT support library, which collides with other tools in one environment; a missing native JIT component degrades functionality silently; the package index trails the source by years |
| Unicorn | `unicorn` | GPLv2 in the repository, BSD in the package metadata | A CPU emulator: map memory, write code, register hooks, run | The licence statement disagrees between repository and package index; take the repository. A pure CPU model with no operating system: it caches translated blocks so patched code needs the cache invalidated, and it cannot be interrupted from the keyboard while emulation runs |
| Qiling | `qiling` | GPLv2 | Emulation with an operating-system layer over Unicorn, driven by a rootfs | The rootfs is a separate repository, so the documented install is not sufficient; the package index trails the source; an unimplemented system call or API stops the emulation, which the project's own FAQ calls not a bug |
| VTIL, Titan, TritonDSE, QSynth | pip for TritonDSE and QSynth; source for VTIL and Titan | Apache-2.0 (TritonDSE), AGPL-3.0 (QSynth), not stated (VTIL, Titan) | De-virtualisation-oriented optimisation; de-virtualisation and expression synthesis on top of Triton | VTIL has no Python bindings and its README states the initial release is not done; Titan covers one protector generation and says the output is not ideal; TritonDSE supports one operating system's binaries only; QSynth calls itself experimental |

**A release tag is not a maintenance signal, and the package index is not the source.** Three of these publish a
version years behind their active branch, so the installed behaviour may not be the documented behaviour. Record
the installed version beside every result.

## MCP bridges: official, community, and the ones that are not what they claim

A bridge is a convenience over a tool's own scripting interface: worth using when that interface is awkward and
the bridge is real, worse than useless when it is abandoned, overclaimed or fictional, because the plan then
rests on a capability that does not exist.

| Bridge | Ownership | Exposes | Claim against code |
|---|---|---|---|
| IDA bridge | The vendor's own repository | **6 tools** in the project's own test snapshot: open a database, execute Python, read reference material, list databases, save, close. Every call carries an explicit database session argument | Small, and it matches its code (`observed (host)`: snapshot re-read here) |
| WinDbg bridge | The vendor, shipped with the debugger | Session tools plus in-session debugger tools, plus built-in prompts | Requires a specific minimum debugger build, supports one client, and the session's secure mode is on by default and cannot be turned off for that run |
| LLDB bridge | The LLVM project, shipped with the debugger | **4 tools** plus resources; a running debugger can be exposed through a command | The smallest surface here, and the most clearly maintained |
| `ida-pro-mcp` | Community | **97 tools**, including a debugger group gated by a query parameter | Still maintained, and the tools are visible in the source (`observed (host)`: 97 counted here). Its README now carries a banner recommending the official bridge, and the commit that added it says so — a **hand-over**, not an abandonment |
| `GhidraMCP` | Community | **30 tools** (`observed (host)`: recounted here) | The README understates rather than overstates. Note its two ports: the Ghidra-side HTTP server and the MCP-side port are different numbers |
| `mcp-windbg` | Community | **11 tools** (`observed (host)`: recounted here) | README and source agree exactly, and the README points users at the vendor's official bridge |
| `x64dbg-mcp-server` | Community | **84 tool definitions** in the source | **The README contradicts itself**: one section says 84, another 72. The code is the authority, and the transport carries a bearer token over plaintext HTTP |
| `ghidra-mcp` (a different community project) | Community | Claims a very large tool count | Its tools are generated dynamically from an endpoint catalogue, and a static count of the source finds a single-digit number of declarations, so **the advertised count cannot be reproduced from visible code** |
| `x64dbg-mcp` | **Nobody** | — | **Does not exist** (`observed (host)`: the repository URL returns HTTP 404). It is widely referenced. The name is wrong and the capability behind it is imaginary |

The consequences, in the order they change a plan: **an official bridge is small and supported**, because its
job is to hand a model the tool's own escape hatch rather than a rich surface; **a community bridge may expose
far more and be intermittently maintained** — one row above has a most recent commit and a previous one roughly
sixteen months apart, and a bridge whose last commit predates the tool it wraps has almost certainly stopped
tracking its interface; **one widely referenced debugger bridge does not exist at all**; and **at least one
README overstates its own tool count**, in a table where another README understates.

**The pattern to apply before using any bridge**, which is the point of this section rather than the list:

1. **Read the last commit date on the branch the instructions use.** Not the release page, not the banner.
2. **Count the capability in the code, not in the README.** A tool count is cheap to check and has been wrong in
   both directions above.
3. **Check whether the README defers to an official replacement** — that converts "abandoned" into "handed over" —
   **and what it leaves unsaid.** A vendor bridge documents its constraints (client count, secure mode, minimum
   build); a community bridge often documents nothing about its transport, and a bearer token on a plaintext
   loopback port is a real exposure on a shared host.
4. **Keep the underlying interface in the plan.** If the bridge breaks, the tool's own CLI or Python API is the
   fallback, and a plan that only knows the bridge has none. Official-versus-community is also not good-versus-bad:
   two official bridges are deliberately tiny, and one widely used community bridge is both larger and accurate.

The record-and-replay debugger has no MCP server of its own: its automation entry point is its own command line,
and the MCP-side workflow for it rides the debugger's official bridge through a built-in prompt.

## What "agent-native fast analysis" actually is

The phrase names a shape, not a vendor, and the shape is worth stating because this repository already
implements it without waiting on any product. Three properties, read off the fastest tools on the
companion platform's side (a SQL interface over the DEX; a whole-app decompiler whose output is verified
to compile):

1. **Query over a prebuilt index, not a re-run per question.** The expensive pass happens once and its
   result is a record; every later question is a bounded lookup into that record. Here, that is the
