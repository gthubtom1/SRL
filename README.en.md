# Seep Reverse Lab

Seep Reverse Lab supplies an AI agent with skills, tools, knowledge, project state and evidence records for reverse-engineering work. Describe the goal and provide the material; the main model chooses a route, combines capabilities across domains and checks its results against observed evidence.

The workbench provides capabilities, contracts and execution interfaces. The model decides when to use a skill, how to combine domains and whether a conclusion is supported. For example, an Android task can combine binary and SO analysis, while a web task can combine HTTP, protocol and JavaScript methods.

## Let your agent install it

Give your agent the repository URL or local directory and say:

> Install and verify this workbench. Start with `Tool/docs/BOOTSTRAP.md`. Treat the current source, script parameters, command output and exit codes as facts about this machine; do not treat historical documents or another machine's completion record as current status. Inspect the system and Agent host, reuse available components, install what is missing and verify with the same AgentRoot. Report what passed, what remains unavailable, and which sign-in, license, device or external-service actions require me.

[BOOTSTRAP](Tool/docs/BOOTSTRAP.md) is the agent-facing installation entry. It documents prerequisites, Windows and Linux/macOS commands, custom AgentRoots, the exact scope of `SkipPackages`, and post-install checks. Users do not need to select internal skill names or fill planning fields by hand.

## Prerequisites

- The Windows installer requires Python 3.11+ runnable as `python`. The Linux/macOS installer tries executable `python3` and then `python`, with the same Python version requirement.
- A normal Pi deployment also requires Node.js and the Pi host. The current environment check requires Node.js 22.19.0+; the chosen Pi host and its dependencies may impose additional version requirements.
- `-SkipPackages` on Windows and `--skip-packages` on Linux/macOS skip bundled offline dependency extraction and package/host-dependent checks or installation. This can prepare configuration first. It does not relax the Python 3.11+ requirement or prove overall readiness; the full installer's final environment check can still fail because Node.js, Pi or sign-in is missing.
- AgentRoot resolution is explicit argument, then `PI_CODING_AGENT_DIR`, then `PI_AGENT_DIR`, then `.pi/agent` under the user directory. Use the same AgentRoot for installation, update, uninstallation and later checks.

From the repository root, the default Windows installation is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive
```

For an isolated AgentRoot with spaces:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup\install.ps1 -NonInteractive -AgentRoot "D:\Agent Root\Pi"
```

Linux/macOS uses:

```bash
bash setup/install.sh
bash setup/install.sh --agent-root "/srv/agent root/pi"
```

Exit code `0` from a full installer means the managed deployment steps and final environment check passed for this run; nonzero means work remains. Windows `setup/install-pi.ps1 -SkipPackages -AgentRoot <AgentRoot>` deploys Pi configuration only, so exit code `0` does not prove later sign-in or external-service availability. Update and uninstallation entry points are `setup/update.ps1`, `setup/uninstall.ps1`, `setup/update.sh` and `setup/uninstall.sh`; inspect their current parameters before use.

Repeat installation updates an existing task or agent only when its content hash matches the managed record in the installation ownership manifest; a matching file is backed up and atomically replaced. User-modified and pre-existing entries are not overwritten and are excluded from managed ownership. Do not interpret repeat installation as replacing every file in an AgentRoot.

## Verify after installation

From the repository root, with the same AgentRoot selected:

```powershell
python Tool/scripts/env-check.py
python Tool/scripts/check.py --runtime --json
```

`env-check.py` returns JSON by default and checks deployed files, Pi configuration, and the Seep MCP initialize/tools-list identity. `check.py --runtime --json` validates the current runtime implementation and regressions. For a custom AgentRoot, set `PI_CODING_AGENT_DIR` or use an explicitly supported script argument.

After install or update, use the host's `/reload` command or restart the host completely, then confirm that skills, extensions and MCP entries actually load. A long-running host can reuse old modules across new sessions, so opening a new session alone does not establish that updated code was loaded. Model sign-in happens inside the host and remains a user action. A present configuration, a successful handshake, host loading, a real tool call and an accepted customer task are separate observations; success at one level does not imply the next.

## Daily use

Describe the outcome and provide files, directories or URLs. The agent identifies missing material, selects primary and supporting domains, and reads only the skills, recipes and knowledge needed for the task. Project, version, run, typed input, raw output, evidence, acceptance and report records connect through the existing interfaces, so work can continue from project state in a later session.

When an account, device, commercial license or other user action is required, the agent explains the reason, impact and available alternatives. `lab:` is an optional interaction in some Pi setups; it is not required to complete installation or use every route.

## Capabilities and limits

- The current formal domains are defined by `Tool/skill/*/pack.json`. `seep-router` helps select and combine them, and cross-domain work shares project assets, routes, evidence and acceptance records.
- The project supports files, directory snapshots, URL descriptions, primary and supporting assets, plus project export, verification, import and relocation recovery.
- Tools can be discovered, planned for installation and verified after installation. Python libraries are imported with the actual service interpreter, and command-line tools are checked as executable entry points. A newly requested tool still has to be adapted to its installer, permissions and the current machine.
- External MCP servers, commercial software, browser automation, hardware and specialist actions are verified separately. A configuration entry or registered tool does not prove that a service is connected, or that every domain and tool has passed end-to-end acceptance.
- `_pending` is a reference area read by source path, not a deployed top-level skill name.

Keep the source checkout available because the installed runtime registration points to it. If the repository moves, redeploy, refresh the configuration and `seep-runtime.json`, and reload or restart the host before verification.

For MCP failures, [MCP-SETUP](Tool/docs/MCP-SETUP.md) distinguishes a quick port or executable check from a full handshake and a real tool call. `mcp-doctor.py --quick` does not establish a JSON-RPC session; the default full diagnostic does, and may start configured programs. Future skills, tools and domains are documented in the [extension guide](Tool/docs/EXTEND.md).

Maintenance and issue reporting: [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [manual index](MANUAL/README.md). Read [current state](docs/CURRENT-STATE.md) for the baseline and verification limits, and [REQUIREMENTS](REQUIREMENTS.md) for scope.

GitHub CI verifies the explicit [public source scope](.github/public-suites.json). Complete domain acceptance also requires a user-supplied APK that is not distributed with a clone. Authorized maintainers must prepare the original by its recorded hash locally and run the unchanged complete checks; public CI success does not establish complete domain acceptance.

The root [LICENSE](LICENSE) contains GNU GPL version 3. Third-party components retain their own licenses and copyright notices; the root license does not relicense every bundled component. Source attribution and component licensing: [PROVENANCE](Tool/docs/PROVENANCE.md), [UPSTREAM](docs/UPSTREAM.md). The [Chinese entry](README.zh.md) and [Chinese README](README.md) are also available.
