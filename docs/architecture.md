# How agent-white-hat is built

Standard library only, Python 3.10 or newer. Nothing in a scanned target is executed: every module reads files.

## What a scan does

```
collect()      read the folder, file or archive; open archive members (scan.py)
   |
dispatch       each file to the handlers that understand it (surfaces/, packages.py):
   |           hooks, settings, MCP servers, skills, instruction files, editor tasks, workflows, git, manifests
   |           -> surfaces (what runs, and what starts it) and files marked "autoexec"
toxic_flows    the repository's agent setup as a whole (surfaces/agent_setup.py, flows.py)
   |
propagate      what autoexec code imports or starts through a runtime also runs on its own (scan.py)
   |
scan_text      content rules on every text file, in its context: autoexec, code, doc, config (patterns.py)
   |           with decoding first (deobfuscate.py), campaign shapes (campaigns.py), hidden text (text.py)
   |
adjust         where a file sits changes what a finding means: fixtures, CI, containers (policy.py)
   |
Report         findings, surfaces, verdict (model.py, report.py)
```

`pah diff` runs this twice and keeps what is new (diff.py, capabilities.py). `pah checkup` looks at the computer
instead of a target (checkup.py, incidents.py, flows.py). The guard runs the command analysis on what an agent is
about to do (guard.py, hooks.py).

## Modules

| Module | What it holds |
| --- | --- |
| `scan.py` | `collect()` and the scan pipeline above |
| `surfaces/` | One module per kind of file that runs without being read: `agent_configs.py` (Claude Code, Cursor, Codex, Gemini CLI, Copilot, OpenCode, Crush, Aider, OpenClaw), `instructions.py` (AGENTS.md, CLAUDE.md, rules files, setup documents, skills), `mcp.py`, `ide.py` (tasks, settings, dev containers, direnv), `workflows.py`, `git.py`, `env.py`; `base.py` holds File, State and command parsing, `dispatch.py` decides which handler reads a file, `agent_setup.py` reads a repository's agent setup as a whole, `rules.py` the rules they report |
| `packages.py` | Package manifests and build files: npm, pnpm, Yarn, Bun, PyPI, Cargo, RubyGems, Gradle, Maven, MSBuild, Make, CMake, Xcode |
| `patterns.py` | Content rules and command analysis (`scan_text`, `analyze_command`) |
| `content_rules.py` | The rules `patterns.py`, `campaigns.py` and `deobfuscate.py` report |
| `campaigns.py` | Shapes of named campaigns that need two pieces of evidence near each other |
| `deobfuscate.py` | Decoding before the rules: pieces joined, character codes, escapes, ROT13, brackets, getattr, shell variables |
| `codectx.py` | Where a match sits: string, comment, regular expression, test data |
| `hosts.py` | Where a URL points: official installer or registry, reference host, user content, look-alike |
| `indicators.py`, `text.py` | Shared regular expressions; invisible characters, padding, encoded blobs |
| `policy.py` | How a file's location changes a finding's severity |
| `capabilities.py` | What a file can do: network, sending data, processes, dynamic code, credentials, persistence, install hooks |
| `diff.py` | `pah diff`: two versions, or a source checkout and the package built from it |
| `flows.py` | Toxic flows (PAH-A021) and pre-approved commands that run any program (PAH-A020) |
| `incidents.py`, `data/incidents.json` | The incident catalog: what happened, what checks it, traces, the response in order |
| `checkup.py`, `watch.py`, `protect.py`, `av.py` | The computer: exposures and traces, configuration baseline, real-time protection and quarantine, the local antivirus engine |
| `guard.py`, `hooks.py`, `install.py`, `agents.py` | The guard in each agent's hook protocol, and installing it |
| `intel.py`, `names.py`, `lockfiles.py`, `review.py` | Registry and OSV lookups (opt-in), look-alike names, pinned versions, the model review (opt-in) |
| `report.py`, `ci.py`, `mcp_server.py`, `cli.py` | Text, JSON and SARIF; GitHub Actions; the MCP server; the command line |
| `model.py`, `collector.py` | Findings, rules registry, reports; one file's findings, deduplicated |

## Where a change goes

- **A rule about what a file contains:** define it in `content_rules.py` with the incident or study behind it, add
  the pattern to `patterns.py` (or a shape to `campaigns.py`), and a malicious TrapRepo case with a benign twin in
  `bench/fixtures/_build_cases.py`.
- **A new kind of file that runs on its own:** a handler in the matching `surfaces/` module (or `packages.py` for a
  build or package manifest) that records the surface and marks what it runs as autoexec; the content rules then judge
  that code as code that runs on its own. Route it in `surfaces/dispatch.py` or `dispatch_packages`.
- **A way to hide code:** an operator in `bench/fuzz.py` first, then the decoding in `deobfuscate.py`.
- **A real incident:** an entry in `pah/data/incidents.json`, then `pah incident list --markdown > docs/incidents.md`.
- **A new agent:** its configuration files in `surfaces/agent_configs.py`, its hook protocol in `hooks.py` and
  `agents.py`, its user-level files in `watch.locations()`.

Every change keeps the benchmark at 0 benign flagged, the fuzzer at 0 got past, and the 30 popular repositories
unblocked ([CONTRIBUTING.md](../CONTRIBUTING.md)).
