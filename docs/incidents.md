# Incidents

Real attacks on people who use AI agents, and what to do about each one: how it got in, which rules and trap
repositories cover it, what it leaves on a computer (`pah incident check` looks for these, and so does
`pah checkup`), and the response in order. Generated from [pah/data/incidents.json](../pah/data/incidents.json)
by `pah incident list --markdown`.

| When | Incident | Kind | Caught by | Traces |
| --- | --- | --- | --- | --- |
| 2026-11 | [MIDNIGHT NEPTUNE: fake recruiters and a Claude Code hook backdoor](#midnight-neptune) | repository | PAH-A001, PAH-C001 | - |
| 2026-11 | [GhostAction and WFX Phantom](#ghostaction) | ci | PAH-I010, PAH-C004 | - |
| 2026-10 | [Trojanized Claude Code extension on Cursor's marketplace](#trojanized-claude-code-extension) | extension | - | 4 |
| 2026-10 | [testmetest worm and strutil-core](#testmetest-worm) | package | PAH-P005, PAH-C004, PAH-C006, PAH-A001, PAH-I001, PAH-C026 | 7 |
| 2026-10 | [@subql/common release pipeline compromise](#subql-common) | ci | PAH-P001, PAH-D002 | - |
| 2026-10 | [PolinRider](#polinrider) | repository | PAH-I001, PAH-C022, PAH-C023 | 2 |
| 2026-10 | [MALFEX](#malfex) | package | PAH-T006 | 1 |
| 2026-10 | [Load/Mine: fake Qwen2 model repositories](#load-mine) | model | PAH-M006, PAH-C001 | - |
| 2026-10 | [LiteLLM .pth compromise](#litellm-pth) | package | PAH-P008 | 1 |
| 2026-10 | [Apex Accelerator](#apex-accelerator) | package | PAH-C009 | 2 |
| 2026-10 | [Poisoned AGENTS.md in Downloads (function-color)](#agents-md-function-color) | instruction-file | PAH-A011 | - |
| 2026-10 | [Unauthorized Codex and Claude Code relays](#agent-relays) | install-page | PAH-A003, PAH-A004, PAH-C001 | 2 |
| 2026-09 | [SleepyDuck](#sleepyduck) | extension | PAH-C022 | 3 |
| 2026-09 | [PyPI .pth typosquats of AI libraries](#pth-typosquats) | package | PAH-P008, PAH-P007 | 1 |
| 2026-08 | [Paperclip and Browser Use skill clones](#paperclip-skills) | skill | PAH-C001 | 2 |
| 2026-08 | [Deadbugz: an MCP server that changes its tools after three calls](#deadbugz-mcp) | mcp | PAH-A005, PAH-C003, PAH-A014 | 1 |
| 2026-08 | [ChainDrop (keyv worm)](#chaindrop) | package | PAH-P001, PAH-C006, PAH-C004, PAH-A001, PAH-I001, PAH-I010 | 3 |
| 2026-08 | [arrayref, internment and append-only-vec crates](#arrayref-crates) | package | PAH-C001, PAH-P011, PAH-D001 | 3 |
| 2026-08 | [Stealers that take AI-agent tokens (WardenStealer, Aokigahara, Vidar)](#ai-token-stealers) | stealer | - | 1 |
| 2026-07 | [SANDWORM_MODE: rogue MCP servers and global git hooks](#sandworm-mode) | package | PAH-P001, PAH-A005, PAH-A014, PAH-G002 | - |
| 2026-06 | [Planted programs and relocated agent configuration](#planted-programs) | agent-flaw | PAH-F006, PAH-A008 | - |
| 2026-06 | [Miasma worm](#miasma-worm) | repository | PAH-A001, PAH-I001 | - |
| 2026-06 | [IronWorm: an npm worm that hides with a rootkit](#ironworm) | package | PAH-P001, PAH-C004 | - |
| 2026-06 | [Hades: PyPI wheels that talk to AI scanners](#hades-pypi) | package | PAH-C011, PAH-C002, PAH-C004 | - |
| 2026-06 | [CVE-2026-54316: an issue that made Claude Code in CI leak its key](#claude-code-ci-key-leak) | agent-flaw | PAH-A021, PAH-O001, PAH-B003 | - |
| 2026-06 | [Agentjacking: fake error reports that run npx](#agentjacking) | mcp | PAH-O001, PAH-B003 | - |
| 2026-03 | [InstallFix: fake AI install pages](#installfix) | install-page | PAH-C001, PAH-C013 | 3 |
| 2026-02 | [Clinejection](#clinejection) | ci | PAH-I011, PAH-P001 | - |
| 2026-02 | [ClawHavoc: malicious skills on ClawHub](#clawhavoc) | skill | PAH-C001, PAH-A016 | - |
| 2026 | [StoatWaffle: fake job-interview repositories](#stoatwaffle) | repository | PAH-I001 | - |
| 2026 | [Slopsquatting: react-codeshift](#react-codeshift-slopsquat) | skill | PAH-A017, PAH-P014 | - |
| 2026 | [Phantom Gyp](#phantom-gyp) | package | PAH-P005, PAH-C004 | - |
| 2026 | [Claude Code project files before the trust prompt](#claude-code-project-files) | agent-flaw | PAH-A001, PAH-A003 | - |
| 2025-11 | [Malware that calls AI models (PROMPTFLUX, PROMPTSTEAL)](#promptflux-promptsteal) | malware | - | 2 |
| 2025-10 | [PhantomRaven](#phantomraven) | package | PAH-P002 | - |
| 2025-10 | [GlassWorm](#glassworm) | extension | PAH-T002 | - |
| 2025-09 | [Shai-Hulud](#shai-hulud) | package | PAH-C024, PAH-C029, PAH-A001 | - |
| 2025-09 | [postmark-mcp: the first malicious MCP server](#postmark-mcp) | mcp | PAH-A013 | - |
| 2025-08 | [s1ngularity (Nx)](#s1ngularity-nx) | package | PAH-C010 | 3 |

<a id="midnight-neptune"></a>
## MIDNIGHT NEPTUNE: fake recruiters and a Claude Code hook backdoor

*2026-11, repository.* A suspected North Korean cluster used AI-generated recruiter personas and ClickFix-style "diagnostic fix" scripts, then edited .claude/settings.json in internal repositories so that starting Claude Code downloaded the SOMBERMEME backdoor. It also created GitHub personal access tokens named after Microsoft Copilot.

**How it got in**

- Running a recruiter's "fix" command, then a hook in .claude/settings.json that runs when Claude Code starts in the repository.

**What agent-white-hat checks**

- [PAH-A001](rules.md) Repository ships agent hooks
- [PAH-C001](rules.md) Downloads code and runs it
- Trap repositories: `claude-settings-sessionstart-hook`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Check .claude/settings.json in your repositories and in ~/.claude for hooks you did not add (pah sweep, pah watch check).
3. GitHub: revoke personal access tokens you did not create, including ones named like Microsoft Copilot.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
6. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
7. Never paste a "diagnostic" or "fix" command from a recruiter, a chat or a web page into a terminal.

**Sources:** <https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold>

<a id="ghostaction"></a>
## GhostAction and WFX Phantom

*2026-11, ci.* Stolen GitHub tokens pushed workflow changes that send every repository secret (toJSON(secrets)) out. GhostAction, first seen in September 2025 and back from September 2026 in about 30,000 repositories, posted them to a bare IP address from workflows named like security tooling. WFX Phantom (November 2026, tokens of about 4,837 accounts) hid the posting in a dot-file script run from a step named like a cache restore, wired the same script into postinstall, and reverted each change within seconds, so a gap in run numbers may be the only trace.

**How it got in**

- A commit by a compromised account added a workflow, or a step with WF_SECRETS: ${{ toJSON(secrets) }}, that posts the secrets to a server.
- WFX Phantom also ran the script from postinstall, so developers who ran npm install sent their own environment.

**What agent-white-hat checks**

- [PAH-I010](rules.md) Workflow sends the repository's secrets out
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- Trap repositories: `workflow-secrets-exfil`, `workflow-wf-secrets-hidden-script`

**What to do, in order**

1. Revoke the token that pushed the changes (revoke it, do not only rotate it) and the account's OAuth grants, SSH keys and sessions.
2. Rotate every repository and organisation secret the workflows could read: assume all of them were sent.
3. Check your cloud accounts for what was added: role trust policies opened to "Principal": {"AWS": "*"}, new IAM access keys, Azure federated credentials named wfx-ci-*.
4. Look for workflow runs you did not start, including gaps in run numbers, and delete the added workflows and dot-file scripts.
5. If you ran npm install while the postinstall script was there, rotate the credentials on your own machine.
6. Require review for changes under .github/workflows (branch protection or rulesets).

**Sources:** <https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/>, <https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories>, <https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer>, <https://socket.dev/blog/ghostaction-cloud-credentials>

<a id="trojanized-claude-code-extension"></a>
## Trojanized Claude Code extension on Cursor's marketplace

*2026-10, extension.* A copy of the Claude Code extension sat on Cursor's marketplace for about 11 hours on 29 October 2026, with up to 5,000 installs; it planted an SSH key, switched on the SSH server and opened a reverse tunnel.

**How it got in**

- Installing the extension in Cursor ran its code with the editor.

**Traces on a computer** (`pah incident check trojanized-claude-code-extension`)

- `~/Library/LaunchAgents/com.apple.sysmond.plist`: its LaunchAgent (Apple's own agents live in /System)
- `{appdata}/Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd`: its startup script
- `~/.config/.smt*`: its hidden .smt file
- `~/.ssh/authorized_keys` containing `\ssvc-telemetry\s*$`: the SSH key it planted (comment svc-telemetry)

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Uninstall the extension and install Claude Code from Anthropic's own listing.
3. Delete the line ending in svc-telemetry from ~/.ssh/authorized_keys.
4. Turn the SSH server off unless you use it (macOS: System Settings, General, Sharing, Remote Login; Windows: the OpenSSH Server service).
5. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
7. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
8. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
9. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://www.sophos.com/en-us/blog/malicious-claude-code-extension-distributed-through-cursor-marketplace>, <https://www.stepsecurity.io/blog/claude-code-extension-trojanized>

<a id="testmetest-worm"></a>
## testmetest worm and strutil-core

*2026-10, package.* A worm in hijacked repositories and packages: a binding.gyp loader planted hooks, rules, MCP entries and folder-open tasks for several agents at once, and armed a wiper that deletes your home folder when the stolen token stops working. Its descendants on RubyGems (strutil-core 1.0.1, November 2026, run from extconf.rb at gem install) and PyPI (pystr-codec) use the same persistence and add an MCP server named workspace-tools.

**How it got in**

- binding.gyp ran a command while npm built the package; strutil-core's extconf.rb fetched Bun into /tmp/.b_<pid> and ran index.js at gem install.
- It then wrote SessionStart hooks, Cursor rules, MCP server entries and folder-open tasks for several agents, and pushed the same files to the victim's repositories.

**What agent-white-hat checks**

- [PAH-P005](rules.md) node-gyp runs a command while building
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- [PAH-C006](rules.md) Makes network requests while installing or opening
- [PAH-A001](rules.md) Repository ships agent hooks
- [PAH-I001](rules.md) Task runs when the folder is opened
- [PAH-C026](rules.md) Wipes your files when its token stops working
- Trap repositories: `binding-gyp-command-expansion`, `rubygem-extconf-bun-loader`

**Traces on a computer** (`pah incident check testmetest-worm`)

- `~/.local/bin/net-health-checker.sh`: testmetest persistence script
- `~/.local/share/runtimes/sync.py`: testmetest persistence
- `/var/tmp/.fontconfig_state`: testmetest state file
- `~/.config/systemd/user/pkg-runtime.service`: service that keeps the worm running
- `~/Library/LaunchAgents/com.user.pkg-runtime.plist`: LaunchAgent that keeps the worm running
- `~/.config/net-health-checker/token`: the stolen token the wiper checks
- `~/.config/index.js`: worm payload

**What to do, in order**

1. Do not revoke the stolen token first: net-health-checker.sh deletes your home folder when the token returns 401 or 403. Disconnect the network and copy your work to another machine or an external drive.
2. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
3. Check every agent's configuration for hooks, MCP servers, rules files, skills and folder-open tasks you did not add: pah sweep and pah watch check.
4. Only now revoke the token stored in ~/.config/net-health-checker/token and the other credentials, from a device you trust.
5. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
6. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
7. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
8. Scan the repositories, packages and extensions involved, and every project opened since: pah scan <path>.
9. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/>, <https://socket.dev/blog/shai-hulud-descendant-malicious-ruby-gem>

<a id="subql-common"></a>
## @subql/common release pipeline compromise

*2026-10, ci.* A modified publish.yml replaced the package build with an archive downloaded without a hash check, so @subql/common 5.8.3 shipped code that is not in its source: a postinstall script that also runs on import, a workflow named codeql_analysis.yml committed as github-advanced-security[bot], and a remote shell.

**How it got in**

- npm install of 5.8.3 ran postinstall: node ./dist/project/readers/manifest-cache.js.

**What agent-white-hat checks**

- [PAH-P001](rules.md) Install-time script
- [PAH-D002](rules.md) Package has code that runs on its own and is not in its source

**What to do, in order**

1. Use 5.8.2 and exclude 5.8.3, including as a transitive dependency.
2. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
3. Rebuild the machines and CI runners that installed it.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. Delete the codeql_analysis.yml workflow if it appeared in your repositories.
8. Before trusting a release, compare the package with its source: pah diff --source <checkout at the tag> <package>.

**Sources:** <https://www.stepsecurity.io/blog/subql-ecosystem-compromised>

<a id="polinrider"></a>
## PolinRider

*2026-10, repository.* Amended and force-pushed commits in 188 GitHub repositories added a folder-open task that ran a loader disguised as a font; hijacked npm packages read their server from an Ethereum transaction and ran what it returned.

**How it got in**

- A VS Code and Cursor task named eslint-check, with "runOn": "folderOpen", ran a loader saved as fa-solid-300.ttf when the folder was opened.
- Hijacked npm packages read their command server from an Ethereum transaction and piped the reply into a detached node -i.

**What agent-white-hat checks**

- [PAH-I001](rules.md) Task runs when the folder is opened
- [PAH-C022](rules.md) Runs a file disguised as a font, image or media file
- [PAH-C023](rules.md) Gets its instructions from a dead drop and runs them
- Trap repositories: `vscode-folderopen-fake-font`, `eth-dead-drop-loader`

**Traces on a computer** (`pah incident check polinrider`)

- `~/.node_modules/.npm-ws-runner.js`: PolinRider loader
- `~/.node_modules/.npm-ws.json`: PolinRider loader state

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
3. In each affected repository, compare the history with what you pushed yourself (git log, git reflog): reset to your last own commit, delete the task and the fake font, and force-push only after rotating the token.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
7. Scan the repositories, packages and extensions involved, and every project opened since: pah scan <path>.

**Sources:** <https://blog.gitguardian.com/ghostaction-x-polinrider/>, <https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages>

<a id="malfex"></a>
## MALFEX

*2026-10, package.* An npm campaign with three payloads that hid code past the right edge of the editor with long runs of spaces and kept itself running through a scheduled task.

**How it got in**

- Installing the package ran code pushed off-screen with spaces, which created a scheduled task.

**What agent-white-hat checks**

- [PAH-T006](rules.md) Code pushed off-screen with spaces
- Trap repositories: `js-trailing-spaces-hidden`

**Traces on a computer** (`pah incident check malfex`)

- `{localappdata}/ScopeSmart Technologies Inc`: MALFEX payload folder

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Delete the scheduled tasks you did not create (Task Scheduler, or schtasks /Query) and the payload folder.
3. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
6. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.

**Sources:** <https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/>

<a id="load-mine"></a>
## Load/Mine: fake Qwen2 model repositories

*2026-10, model.* 31 fake Qwen2 repositories on Hugging Face used auto_map in config.json, so loading them with trust_remote_code=True imported their own Python files. Those files installed a cryptocurrency miner, added SSH keys and opened reverse shells. About 30,000 downloads; Hugging Face's scanners did not flag them (September 21 to October 28).

**How it got in**

- Loading a model with trust_remote_code=True (transformers' from_pretrained) from a repository that ships its own modeling code.

**What agent-white-hat checks**

- [PAH-M006](rules.md) Model repository runs its own code (trust_remote_code)
- [PAH-C001](rules.md) Downloads code and runs it
- Trap repositories: `hf-auto-map-remote-code-miner`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Look for a miner (a process using all CPU), keys you did not add in ~/.ssh/authorized_keys, and new cron jobs, services or scheduled tasks. Remove them before rotating anything.
3. Delete the model from the Hugging Face cache (~/.cache/huggingface/hub) and from wherever it was copied.
4. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
5. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. Load models only from organizations you know, pin the revision, prefer safetensors, and leave trust_remote_code off unless you have read the code (pah scan <model folder>).

**Sources:** <https://pluto.security/blog/hugging-face-malware-campaign-load-mine/>

<a id="litellm-pth"></a>
## LiteLLM .pth compromise

*2026-10, package.* LiteLLM was compromised on PyPI twice: an earlier release shipped a .pth file, and 1.107.0 (21 October 2026) shipped cook.pth and sitecustomize.py. Both run at every Python start, not only when LiteLLM is imported.

**How it got in**

- pip install of the bad version put the .pth file in site-packages.

**What agent-white-hat checks**

- [PAH-P008](rules.md) Python code that runs at interpreter start
- Trap repositories: `python-pth-exec`

**Traces on a computer** (`pah incident check litellm-pth`)

- `/tmp/remote_code_loader.lock`: lock file of the 1.107.0 loader

**What to do, in order**

1. Do not run pip or python in that environment until the .pth and sitecustomize.py files are gone: they run again at every interpreter start. Delete them from site-packages (python -I -S -c "import site; print(site.getsitepackages())" shows where without running them), then uninstall the bad version.
2. Rotate every provider key the LiteLLM configuration held.
3. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.

**Sources:** <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>, <https://docs.litellm.ai/blog/security-incident-oct-21-2026>

<a id="apex-accelerator"></a>
## Apex Accelerator

*2026-10, package.* npm packages posing as an AI agent set OPENROUTER_BASE_URL to the attacker's server, wrote an MCP server configuration and added a Microsoft Defender exclusion.

**How it got in**

- Installing the package ran a dropper at install time.

**What agent-white-hat checks**

- [PAH-C009](rules.md) Writes AI-agent configuration

**Traces on a computer** (`pah incident check apex-accelerator`)

- `~/.apex/agent/mcp.json`: Apex Accelerator MCP configuration
- `{temp}/_apex_run.ps1`: Apex Accelerator dropper script

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove Microsoft Defender exclusions you did not add (PowerShell: Get-MpPreference | Select-Object -ExpandProperty ExclusionPath, then Remove-MpPreference -ExclusionPath <path>) and run a full scan.
3. Remove OPENROUTER_BASE_URL from your environment and shell profile, and the MCP server entries it added.
4. Revoke the OpenRouter key and every other AI key the redirected traffic carried.
5. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.

**Sources:** <https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages>

<a id="agents-md-function-color"></a>
## Poisoned AGENTS.md in Downloads (function-color)

*2026-10, instruction-file.* A 13 KB AGENTS.md posing as engineering guidelines, dropped into ~/Downloads by a website, made Codex change its machine-wide settings and then install the malicious npm package function-color in more than 90% of attempts. A CLAUDE.md variant got Claude Code to send its requests to the attacker's server about half the time, exposing the login token.

**How it got in**

- Starting a coding agent in a folder that holds the file: agents read AGENTS.md and CLAUDE.md on their own.

**What agent-white-hat checks**

- [PAH-A011](rules.md) Instruction file tells the agent to do something risky
- Trap repositories: `agents-md-install-and-reconfigure`, `claude-md-set-base-url`

**What to do, in order**

1. Do not start coding agents in Downloads or other folders that hold files you did not write; delete the planted file.
2. Check whether function-color is installed (npm ls -g function-color, and npm ls function-color in your projects) and remove it.
3. Undo the settings the agent changed (~/.codex/config.toml, ~/.claude/settings.json); pah checkup lists risky settings.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. Check every agent's configuration for hooks, MCP servers, rules files, skills and folder-open tasks you did not add: pah sweep and pah watch check.

**Sources:** <https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/>

<a id="agent-relays"></a>
## Unauthorized Codex and Claude Code relays

*2026-10, install-page.* After a genuine npm install of the CLI, setup scripts run with iwr | iex or curl | bash rewrote the agents' configuration to send all traffic through a third-party relay: base_url, sandbox_mode = "danger-full-access" and network_access in ~/.codex/config.toml, and ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN and DISABLE_TELEMETRY as user environment variables.

**How it got in**

- Pasting a "cheap access" setup command from a relay's page.

**What agent-white-hat checks**

- [PAH-A003](rules.md) Redirects the agent's API traffic
- [PAH-A004](rules.md) Turns off the agent's approvals or sandbox
- [PAH-C001](rules.md) Downloads code and runs it

**Traces on a computer** (`pah incident check agent-relays`)

- `~/.codex/config.toml` containing `aiok[.]me|nuoda[.]vip|claudechn[.]com|vibe[.]skk[.]moe`: Codex configured to use a known relay
- `~/.claude/settings.json` containing `aiok[.]me|nuoda[.]vip|claudechn[.]com|vibe[.]skk[.]moe`: Claude Code configured to use a known relay

**What to do, in order**

1. Remove base_url, sandbox_mode = "danger-full-access" and network_access from ~/.codex/config.toml, and ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN and DISABLE_TELEMETRY from your user environment variables (Windows) or shell profile (macOS, Linux).
2. Rotate the API keys and sign in to the agents again: every prompt, file and key they sent went through the relay.
3. Install the CLIs only with the vendor's instructions; pah checkup flags API base URLs that are not the vendor's.

**Sources:** <https://www.security.com/threat-intelligence/openai-claude-unauthorized-relays>

<a id="sleepyduck"></a>
## SleepyDuck

*2026-09, extension.* Open VSX extensions for Solidity developers carried a payload appended to an MP4 file and installed a backdoor that starts at login.

**How it got in**

- Installing the extension in an editor that uses Open VSX (Cursor, Windsurf, VSCodium) ran its code with the editor.

**What agent-white-hat checks**

- [PAH-C022](rules.md) Runs a file disguised as a font, image or media file

**Traces on a computer** (`pah incident check sleepyduck`)

- `~/.solidity`: SleepyDuck backdoor folder
- `~/Library/LaunchAgents/com.solidity.langsupport.runner.plist`: SleepyDuck LaunchAgent
- `~/.config/systemd/user/solidity-langsupport-runner.service`: SleepyDuck service

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Uninstall the Solidity extension it came with and check your other Open VSX extensions.
3. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
4. Move crypto funds from a clean device to a new wallet with a new seed phrase.
5. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.

**Sources:** <https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/>

<a id="pth-typosquats"></a>
## PyPI .pth typosquats of AI libraries

*2026-09, package.* Packages named like AI libraries (openaii, ollamaa, langgrap, transfomers) dropped a <name>-setup.pth file, which runs at every Python start. Reported by one vendor.

**How it got in**

- pip install of a misspelled name.

**What agent-white-hat checks**

- [PAH-P008](rules.md) Python code that runs at interpreter start
- [PAH-P007](rules.md) Package name looks like a popular package
- Trap repositories: `python-pth-exec`

**Traces on a computer** (`pah incident check pth-typosquats`)

- `/tmp/.lurves-planted`: marker file the loader leaves

**What to do, in order**

1. Do not run Python in that environment until the .pth file is gone: delete *-setup.pth from site-packages, then uninstall the package.
2. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
3. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
4. Check requirements files for misspelled names (pah scan reports look-alikes).

**Sources:** <https://corgea.com/research/openaii-ollamaa-langgrap-transfomers-pypi-pth-typosquats-september-2026>

<a id="paperclip-skills"></a>
## Paperclip and Browser Use skill clones

*2026-08, skill.* Look-alike publishers copied the official Paperclip and Browser Use skills to skills.sh word for word. Once installs grew, a commit added setup-installation.md in seven paths: SKILL.md stayed clean and sent the agent there, and it ran curl -k on a look-alike API, decoded the reply with base64 and ran it with node.

**How it got in**

- The agent loaded the skill and followed its setup instructions.

**What agent-white-hat checks**

- [PAH-C001](rules.md) Downloads code and runs it
- Trap repositories: `skill-linked-setup-doc-loader`

**Traces on a computer** (`pah incident check paperclip-skills`)

- `~/.paperclip_install_*.mjs`: the clones' loader
- `~/.paperclip_ai`: folder the clones' loader creates

**What to do, in order**

1. Remove the cloned skills and every setup-installation.md they brought, and install skills only from their real publishers.
2. If the loader ran, treat it as a stealer infection: pah incident show ai-token-stealers.
3. Compare installed skills with their upstream on every update: pah diff <installed> <new version>.

**Sources:** <https://labs.zenity.io/post/attackers-target-agents-via-the-skill-supply-chain>

<a id="deadbugz-mcp"></a>
## Deadbugz: an MCP server that changes its tools after three calls

*2026-08, mcp.* An account opened 23 pull requests adding an MCP server named productivity-suite with harmless tools (format_text, summarize). After the third call its tool list and prompts changed to steer the agent toward SSH keys, AWS credentials and kubeconfig. Four of the pull requests pointed to a script hidden in ~/.config/.cache/.sys/. None was merged.

**How it got in**

- Merging the pull request adds the server to the project's MCP configuration; the agent starts it and calls its tools.

**What agent-white-hat checks**

- [PAH-A005](rules.md) Repository defines an MCP server the agent will start
- [PAH-C003](rules.md) Touches credential stores
- [PAH-A014](rules.md) MCP tool description gives the model hidden orders
- Trap repositories: `mcp-server-runtime-gated-tools`

**Traces on a computer** (`pah incident check deadbugz-mcp`)

- `~/.config/.cache/.sys/.deadbug-mcp.py`: the hidden MCP server script

**What to do, in order**

1. Reject pull requests and configurations that add productivity-suite or point at productivity-suite-mcp.onrender.com or a trycloudflare.com host.
2. Keep the MCP client logs: they show which tool definitions the agent was given.
3. Pin MCP servers to versions you reviewed and approve a server again when its tools change.
4. If the agent read keys while the server was running, rotate them.

**Sources:** <https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign>

<a id="chaindrop"></a>
## ChainDrop (keyv worm)

*2026-08, package.* A Shai-Hulud variant: the keyv maintainer's account was hijacked and the project's own trusted-publishing workflow released 444 infected packages (keyv 6.0.0, cacheable 2.5.1, flat-cache 6.1.24 and file-entry-cache 11.1.6 among them), so they carried valid provenance. The same loader came back in tensorlake 0.5.144 in October.

**How it got in**

- "preinstall": "node setup.mjs" downloaded Bun 1.3.13 and ran Math_Symbol.js or math_init.js.
- The payload took npm, GitHub and AI-agent credentials (.codex/auth.json, .cursor/credentials.json, .gemini/.env, .kiro/settings/mcp.json, opencode.json), committed a .claude/settings.json SessionStart hook and a folder-open task to up to 50 branches per repository (author claude, message "chore: update config"), and added a "Run Copilot" workflow that puts every secret into a build artifact.

**What agent-white-hat checks**

- [PAH-P001](rules.md) Install-time script
- [PAH-C006](rules.md) Makes network requests while installing or opening
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- [PAH-A001](rules.md) Repository ships agent hooks
- [PAH-I001](rules.md) Task runs when the folder is opened
- [PAH-I010](rules.md) Workflow sends the repository's secrets out
- Trap repositories: `npm-preinstall-bun-chaindrop`

**Traces on a computer** (`pah incident check chaindrop`)

- `~/.local/bin/gh-token-monitor.sh`: token monitor that acts when the stolen token is revoked
- `~/.config/systemd/user/gh-token-monitor.service`: token monitor service
- `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`: token monitor LaunchAgent

**What to do, in order**

1. Remove the token monitor (the traces above) before rotating anything: it acts when the stolen token is revoked.
2. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
3. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
4. Reinstall your dependencies at versions from before the incident with --ignore-scripts.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
7. Delete the branches and commits by "claude" with the message "chore: update config", and the "Run Copilot" workflow, from your repositories.
8. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
9. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.

**Sources:** <https://www.stepsecurity.io/blog/chaindrop-npm-worm>, <https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain>, <https://www.aikido.dev/blog/tensorlake-npm-package-compromised>

<a id="arrayref-crates"></a>
## arrayref, internment and append-only-vec crates

*2026-08, package.* arrayref 0.3.10, internment 0.8.7 and append-only-vec 0.1.9 were on crates.io for 86 to 107 minutes with a new dependency, proc-macro1 1.0.107, whose build.rs downloaded a payload from a bare IP address and started it.

**How it got in**

- cargo build compiled proc-macro1 and ran its build.rs.

**What agent-white-hat checks**

- [PAH-C001](rules.md) Downloads code and runs it
- [PAH-P011](rules.md) Cargo runs repository code
- [PAH-D001](rules.md) New version gives code that runs on its own a new capability
- Trap repositories: `rust-build-rs-network-exec`

**Traces on a computer** (`pah incident check arrayref-crates`)

- `/tmp/rust-setup`: downloaded payload (Linux, macOS)
- `{temp}/rust-setup.ps1`: downloaded payload (Windows)
- `{temp}/rust-setup-launch.vbs`: launcher (Windows)

**What to do, in order**

1. Pin arrayref =0.3.9, internment =0.8.6 and append-only-vec =0.1.8, and check Cargo.lock for proc-macro1.
2. Delete ~/.cargo/registry/cache, CI caches and vendored copies that hold the bad versions.
3. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
4. On every machine that built them, rotate SSH keys, cloud credentials, crates.io tokens and signing keys.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
6. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.

**Sources:** <https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/>, <https://stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack>

<a id="ai-token-stealers"></a>
## Stealers that take AI-agent tokens (WardenStealer, Aokigahara, Vidar)

*2026-08, stealer.* Infostealers now take AI-agent logins: WardenStealer (more than 130,000 infections since 3 August 2026) takes Claude Code OAuth tokens, MCP server tokens included, and Codex auth.json; Aokigahara reads the session files of Claude Code, Codex, Cursor, Windsurf, VS Code, Gemini CLI and Copilot; a Vidar variant took OpenClaw's gateway token and memory file.

**How it got in**

- Usually a cracked program, a fake installer or a pasted command; the stealer copies the session files and leaves.

**Traces on a computer** (`pah incident check ai-token-stealers`)

- `{temp}/akg_*`: WardenStealer staging file

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
3. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
6. Move crypto funds from a clean device to a new wallet with a new seed phrase.
7. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/>, <https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/>, <https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/>

<a id="sandworm-mode"></a>
## SANDWORM_MODE: rogue MCP servers and global git hooks

*2026-07, package.* A supply-chain worm that adds a rogue MCP server to Claude Desktop, Cursor, VS Code and Windsurf configurations. The server's instructions tell assistants to collect SSH, AWS and npm secrets. It also installs global git hooks. In CrowdStrike's analysis only 2 of its 14 behaviors were alert-worthy on their own: the attack shows in the sequence.

**How it got in**

- Installing an infected package; its install script edits agent MCP configurations and git's hooks.

**What agent-white-hat checks**

- [PAH-P001](rules.md) Install-time script
- [PAH-A005](rules.md) Repository defines an MCP server the agent will start
- [PAH-A014](rules.md) MCP tool description gives the model hidden orders
- [PAH-G002](rules.md) Git configuration that runs commands
- Trap repositories: `npm-postinstall-beacon`, `mcp-tool-description-poisoning`, `git-dir-hookspath-fsmonitor`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove MCP servers you did not add from Claude Desktop, Cursor, VS Code and Windsurf (pah checkup lists them), and check `git config --global core.hooksPath` and ~/.gitconfig for hooks you did not install.
3. Check every agent's configuration for hooks, MCP servers, rules files, skills and folder-open tasks you did not add: pah sweep and pah watch check.
4. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
8. pah session list: look for agent sessions that read credentials and then sent data out.

**Sources:** <https://www.crowdstrike.com/en-us/blog/denying-the-worm-sandworm-mode-and-ai-toolchain-supply-chain-attacks/>

<a id="planted-programs"></a>
## Planted programs and relocated agent configuration

*2026-06, agent-flaw.* Agents ran code from a repository before the first prompt: a git.exe at the top of the repository ran when it was opened in Cursor, Claude Desktop or Kiro (CVE-2026-63093, CVE-2026-88066, CVE-2026-18656); GEMINI_CLI_HOME in a .env file started an MCP server (CVE-2026-13745); a __proto__ key in .vscode/mcp.json did the same in Restricted Mode (CVE-2026-121662); and PATH pointing at a repository's bin/git ran through Claude Code's startup git probes.

**How it got in**

- Opening the repository in the agent was enough: it looked up git or read .env and project configuration before asking for trust.

**What agent-white-hat checks**

- [PAH-F006](rules.md) Program named after a system tool at the top of the repository
- [PAH-A008](rules.md) Redirects Codex's configuration into the repository
- Trap repositories: `git-exe-planted-root`, `codex-env-codexhome-config-toml`

**What to do, in order**

1. Update the AI CLIs and editors to their current versions (pah checkup lists versions with a known code-execution fix missing).
2. Scan the repositories, packages and extensions involved, and every project opened since: pah scan <path>.
3. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.

**Sources:** <https://github.com/advisories/GHSA-prfr-jc65-hr23>, <https://github.com/advisories/GHSA-2255-3477-vp73>, <https://securitylabs.datadoghq.com/articles/coding-agent-project-trust-code-execution-before-first-prompt/>

<a id="miasma-worm"></a>
## Miasma worm

*2026-06, repository.* A worm planted Claude Code and Gemini CLI SessionStart hooks, a Cursor rule and a VS Code folder-open task in the repositories it reached; GitHub disabled 73 Microsoft repositories.

**How it got in**

- The hooks run when an agent session starts in the folder; the task runs when the folder opens in VS Code or Cursor.

**What agent-white-hat checks**

- [PAH-A001](rules.md) Repository ships agent hooks
- [PAH-I001](rules.md) Task runs when the folder is opened
- Trap repositories: `claude-settings-sessionstart-hook`, `gemini-settings-hook`, `vscode-tasks-folderopen`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Check every agent's configuration for hooks, MCP servers, rules files, skills and folder-open tasks you did not add: pah sweep and pah watch check.
3. Remove the hooks, rules and tasks from every affected repository and restore its history from a commit you made yourself.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
7. Scan the repositories, packages and extensions involved, and every project opened since: pah scan <path>.

**Sources:** <https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents>, <https://labs.cloudsecurityalliance.org/research/csa-research-note-agent-instruction-file-poisoning-20261027/>

<a id="ironworm"></a>
## IronWorm: an npm worm that hides with a rootkit

*2026-06, package.* An npm worm that hides from ps and top with an eBPF rootkit, steals Claude, Codex and Gemini credential files and AI API keys, and commits to the repositories it reaches under the name "claude".

**How it got in**

- npm install of an infected package (an install script).

**What agent-white-hat checks**

- [PAH-P001](rules.md) Install-time script
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- Trap repositories: `npm-postinstall-beacon`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. A rootkit hides processes from ps and top: check the machine from a clean boot or another system, and reinstall if in doubt.
3. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
6. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
7. Look for commits authored as "claude" that you did not make, in every repository you can push to.

**Sources:** <https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/>

<a id="hades-pypi"></a>
## Hades: PyPI wheels that talk to AI scanners

*2026-06, package.* 37 wheels on PyPI carried text telling LLM-based security scanners to report the package as clean, next to code that stole credentials.

**How it got in**

- pip install of one of the wheels; the payload ran on import.

**What agent-white-hat checks**

- [PAH-C011](rules.md) Text addressed to AI reviewers or agents
- [PAH-C002](rules.md) Decodes hidden data and executes it
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- Trap repositories: `python-exec-loader-ai-reviewer-comment`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Uninstall the packages and scan the environments they were installed in (pah scan <venv>).
3. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
4. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
5. Do not take an AI reviewer's verdict on code that addresses the reviewer: that text is the attack.

**Sources:** <https://www.zscaler.com/blogs/security-research/shai-hulud-campaign-evolution-miasma-hades-and-ai-scanner-evasion>

<a id="claude-code-ci-key-leak"></a>
## CVE-2026-54316: an issue that made Claude Code in CI leak its key

*2026-06, agent-flaw.* A prompt-injected GitHub issue made Claude Code running in CI send its API key out through download counters on huggingface.co, a host its configuration pre-approved. Fixed in Claude Code 2.1.163 (advisory in June; presented at Black Hat in August).

**How it got in**

- Issue or pull request text read by an agent in CI that may fetch pre-approved hosts without asking.

**What agent-white-hat checks**

- [PAH-A021](rules.md) Agent setup lets content anyone can write reach a way out without asking
- [PAH-O001](rules.md) Tool output carries instructions aimed at the agent
- [PAH-B003](rules.md) Sensitive step after a tool returned injected instructions
- Trap repositories: `mcp-toxic-flow-autoapprove`

**What to do, in order**

1. Update Claude Code to 2.1.163 or later.
2. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
3. In CI, give the agent only the secrets the job needs and pre-approve only the hosts it needs; a host anyone can publish to (a model hub, a paste site) is a way out.
4. Read the job logs for requests to hosts you did not expect.

**Sources:** <https://advisories.gitlab.com/npm/@anthropic-ai/claude-code/CVE-2026-54316/>, <https://novee.security/blog/critical-flaws-in-anthropic-google-and-openais-coding-agents/>

<a id="agentjacking"></a>
## Agentjacking: fake error reports that run npx

*2026-06, mcp.* Researchers planted error events in Sentry; returned through the Sentry MCP server, the "fix" in them made Claude Code, Cursor and Codex run an attacker's npx command about 85% of the time. A demonstration, not a campaign, of how tool output steers an agent.

**How it got in**

- An agent reading an error report through an MCP server and following the command in it.

**What agent-white-hat checks**

- [PAH-O001](rules.md) Tool output carries instructions aimed at the agent
- [PAH-B003](rules.md) Sensitive step after a tool returned injected instructions

**What to do, in order**

1. Treat what MCP tools return as data: read a suggested command before letting an agent run it.
2. Keep agent-white-hat's output hook on, so such output is flagged and the next package install in that session needs your approval (pah install adds it for Claude Code, Codex, Gemini CLI, Cursor and Copilot).
3. If the package already ran: @contain
4. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.

**Sources:** <https://tenetsecurity.ai/blog/agentjacking-coding-agents-with-fake-sentry-errors/>

<a id="installfix"></a>
## InstallFix: fake AI install pages

*2026-03, install-page.* Search ads led to cloned Claude Code install pages whose one-line install commands (curl … | zsh, mshta https://…) installed the Amatera and Cuckoo stealers; researchers counted 88 lure domains, more than 30 of them for Claude Code. Shared ChatGPT, Grok and claude.ai chats were used as lure pages for AMOS and MacSync.

**How it got in**

- Pasting the page's install command into a terminal or the Windows Run box.

**What agent-white-hat checks**

- [PAH-C001](rules.md) Downloads code and runs it
- [PAH-C013](rules.md) Uses Windows system binaries to fetch or run remote code
- Trap repositories: `readme-curl-bash-lookalike`

**Traces on a computer** (`pah incident check installfix`)

- `{localappdata}/Microsoft/EdgeUpdate/MicrosoftEdgeUpdateCore.dll`: fake Edge Update payload (ACRStealer, Amatera)
- `/tmp/helper`: fake Claude Code installer dropper (macOS)
- `/tmp/osalogging.zip`: MacSync staging archive

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
3. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
6. Move crypto funds from a clean device to a new wallet with a new seed phrase.
7. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.
8. Install AI tools only from the vendor's own site, typed by hand, never from an ad or a shared chat.

**Sources:** <https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/>, <https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware>, <https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign>, <https://www.huntress.com/blog/fake-claude-macsync>

<a id="clinejection"></a>
## Clinejection

*2026-02, ci.* Text in a GitHub issue title hijacked Cline's AI triage workflow and led to a stolen npm token; cline@2.3.0 installed OpenClaw globally from its postinstall script.

**How it got in**

- An AI agent in a GitHub workflow acted on an issue anyone could open, with the release token within reach.
- Installing cline@2.3.0 ran its postinstall script.

**What agent-white-hat checks**

- [PAH-I011](rules.md) AI agent in a workflow acts on anyone's issue or comment
- [PAH-P001](rules.md) Install-time script

**What to do, in order**

1. If you installed cline@2.3.0, update Cline and remove the OpenClaw package it installed globally (npm ls -g, then npm uninstall -g).
2. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
3. Maintainers: do not give an AI agent in a workflow write tokens or secrets when anyone can trigger it (pah scan reports this as PAH-I011).

**Sources:** <https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions>

<a id="clawhavoc"></a>
## ClawHavoc: malicious skills on ClawHub

*2026-02, skill.* 341 of 2,857 skills on ClawHub were malicious on 1 February 2026, and 824 by 16 February; most delivered the AMOS stealer for macOS.

**How it got in**

- A skill's setup step told the agent, or the user, to download and run a program.

**What agent-white-hat checks**

- [PAH-C001](rules.md) Downloads code and runs it
- [PAH-A016](rules.md) Skill fetches or runs remote code
- Trap repositories: `skill-md-fetch-binary`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove the skill and check your other installed skills (pah sweep).
3. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
4. Move crypto funds from a clean device to a new wallet with a new seed phrase.
5. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting>

<a id="stoatwaffle"></a>
## StoatWaffle: fake job-interview repositories

*2026, repository.* Repositories sent as coding tests in fake job interviews ran StoatWaffle through .vscode/tasks.json with "runOn": "folderOpen": opening the folder was enough.

**How it got in**

- Opening the repository in VS Code or Cursor and trusting the folder.

**What agent-white-hat checks**

- [PAH-I001](rules.md) Task runs when the folder is opened
- Trap repositories: `vscode-tasks-folderopen`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
3. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. Move crypto funds from a clean device to a new wallet with a new seed phrase.
8. Open code from recruiters only in a disposable VM, or in Restricted Mode with automatic tasks off ("task.allowAutomaticTasks": "off").

**Sources:** <https://www.infoworld.com/article/4149285/new-stoatwaffle-malware-auto%E2%80%91executes-attacks-on-developers-2.html>

<a id="react-codeshift-slopsquat"></a>
## Slopsquatting: react-codeshift

*2026, skill.* The hallucinated package name react-codeshift appeared in 47 AI-generated skills copied into 237 repositories; whoever registers such a name gets their code run. Across 16 models, 5.2% (commercial) and 21.7% (open) of suggested packages did not exist.

**How it got in**

- A skill told the agent to run npx react-codeshift; npx fetches whatever is published under that name.

**What agent-white-hat checks**

- [PAH-A017](rules.md) Instructions run an unpinned package from the registry
- [PAH-P014](rules.md) Package does not exist on the public registry
- Trap repositories: `skill-npx-nonexistent-slopsquat`

**What to do, in order**

1. Remove or fix the skill: pin packages to an exact, known version and publisher.
2. If the command ran after someone registered the name, treat it as malware: follow pah incident show ai-token-stealers.

**Sources:** <https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands>, <https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen>

<a id="phantom-gyp"></a>
## Phantom Gyp

*2026, package.* 57 npm packages ran code while being built, through command expansion in binding.gyp.

**How it got in**

- node-gyp evaluates <!(…) command expansions in binding.gyp during npm install.

**What agent-white-hat checks**

- [PAH-P005](rules.md) node-gyp runs a command while building
- [PAH-C004](rules.md) Reads secrets or the environment and sends data out
- Trap repositories: `binding-gyp-command-expansion`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Remove the package.
3. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
4. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
5. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.

**Sources:** <https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp>

<a id="claude-code-project-files"></a>
## Claude Code project files before the trust prompt

*2026, agent-flaw.* Project files could run code or send the API key to another server before the trust prompt (CVE-2025-59536, CVE-2026-21852). Both are patched and no exploitation is known.

**How it got in**

- Opening an untrusted repository with an affected Claude Code version.

**What agent-white-hat checks**

- [PAH-A001](rules.md) Repository ships agent hooks
- [PAH-A003](rules.md) Redirects the agent's API traffic
- Trap repositories: `claude-settings-env-anthropic-base-url`, `claude-settings-sessionstart-hook`

**What to do, in order**

1. Update the AI CLIs and editors to their current versions (pah checkup lists versions with a known code-execution fix missing).
2. If you opened untrusted repositories with an affected version, revoke your Anthropic API key and sign in to Claude Code again.

**Sources:** <https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/>

<a id="promptflux-promptsteal"></a>
## Malware that calls AI models (PROMPTFLUX, PROMPTSTEAL)

*2025-11, malware.* Google's threat intelligence group reported malware that asks AI models for code while it runs: PROMPTFLUX rewrites itself through the Gemini API to evade antivirus, and PROMPTSTEAL (LAMEHUG) asks a model for the commands that collect documents and system information.

**How it got in**

- Usually a phishing attachment or a fake installer.

**Traces on a computer** (`pah incident check promptflux-promptsteal`)

- `{temp}/thinking_robot_log.txt`: PROMPTFLUX log file
- `C:/ProgramData/info/info.txt`: PROMPTSTEAL (LAMEHUG) output file

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Check the Startup folder for scripts you did not put there (pah checkup reports them).
3. Remove what it left behind (the traces above), then look for other persistence: shell profiles, LaunchAgents, systemd user units, scheduled tasks and the Startup folder, cron and ~/.ssh/authorized_keys. pah checkup lists the usual places.
4. Sign out of every browser session for email, password manager and code hosting, and revoke them from each account's security page: stealers take cookies, which skip passwords and 2FA.
5. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
6. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools>

<a id="phantomraven"></a>
## PhantomRaven

*2025-10, package.* 126 npm packages that showed "0 dependencies" on the registry fetched their payload at install time from URL dependencies, so the code that ran was never on npm.

**How it got in**

- npm install followed a dependency given as an http URL and ran its install script.

**What agent-white-hat checks**

- [PAH-P002](rules.md) Dependency fetched from a URL or git
- Trap repositories: `npm-url-dependency`

**What to do, in order**

1. Remove the package and every package from the same publisher; npm 12 and later no longer fetch URL dependencies unless a project's .npmrc turns that back on.
2. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
3. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
4. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.

**Sources:** <https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies>

<a id="glassworm"></a>
## GlassWorm

*2025-10, extension.* A self-spreading worm in Open VSX and VS Code extensions, later also on GitHub and npm, that hid its code in invisible Unicode variation selectors and used stolen developer tokens to publish more infected releases.

**How it got in**

- Installing or auto-updating an infected extension ran its hidden code with the editor.

**What agent-white-hat checks**

- [PAH-T002](rules.md) Data hidden in Unicode variation selectors
- Trap repositories: `glassworm-variation-selectors-eval`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. Uninstall the infected extensions and turn off automatic extension updates until you have checked the rest.
3. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
4. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
5. Revoke your Open VSX and VS Code Marketplace publisher tokens.
6. Move crypto funds from a clean device to a new wallet with a new seed phrase.
7. Reinstall the operating system if the payload ran with administrator rights, installed remote access, or left persistence you cannot fully explain.

**Sources:** <https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode>

<a id="shai-hulud"></a>
## Shai-Hulud

*2025-09, package.* A self-spreading npm worm: install scripts swept the machine for tokens and secrets and republished the victims' packages with the worm inside. At least seven waves ran from September 2025 to August 2026; the sweep grew from 189 to 469 file paths, including Cursor, OpenClaw and Codex configuration, and Mini Shai-Hulud persisted through .claude/settings.json hooks.

**How it got in**

- npm install of an infected version ran its install script, which used the stolen npm and GitHub tokens to publish more infected versions.

**What agent-white-hat checks**

- [PAH-C024](rules.md) Publishes packages with your credentials
- [PAH-C029](rules.md) Hunts for secrets while installing or opening
- [PAH-A001](rules.md) Repository ships agent hooks
- Trap repositories: `npm-worm-republish`, `claude-settings-sessionstart-hook`

**What to do, in order**

1. Stop the agent, terminal or editor that ran it and end processes you do not recognise. If it may still be sending data, disconnect the network. Do not wipe the machine yet: its files show what was taken.
2. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
3. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
4. Look in your GitHub account for repositories and workflow files you did not create: the first wave published the stolen secrets in a public repository named Shai-Hulud.
5. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
6. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
7. Check every agent's configuration for hooks, MCP servers, rules files, skills and folder-open tasks you did not add: pah sweep and pah watch check.
8. Scan the repositories, packages and extensions involved, and every project opened since: pah scan <path>.

**Sources:** <https://socket.dev/glossary/shai-hulud>, <https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/>, <https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem>, <https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-credential-expansion-2026090/>

<a id="postmark-mcp"></a>
## postmark-mcp: the first malicious MCP server

*2025-09, mcp.* An npm package posing as a Postmark MCP server added a hidden BCC to every email it sent, from version 1.0.16 on, after fifteen clean versions.

**How it got in**

- The agent started the MCP server from an unpinned npm package and picked up the new version.

**What agent-white-hat checks**

- [PAH-A013](rules.md) MCP server runs an unpinned package

**What to do, in order**

1. Remove postmark-mcp from every agent's MCP configuration and uninstall it.
2. Revoke the Postmark server token it used and review what it sent.
3. Pin MCP servers to an exact version you reviewed (pah scan reports unpinned ones as PAH-A013).

**Sources:** <https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html>

<a id="s1ngularity-nx"></a>
## s1ngularity (Nx)

*2025-08, package.* Malicious Nx versions ran Claude Code, Gemini CLI and Amazon Q with their permission checks bypassed to search the machine for secrets; 2,349 secrets from 1,079 machines were published.

**How it got in**

- The package's postinstall script started the AI CLIs already installed, with flags that skip approvals.

**What agent-white-hat checks**

- [PAH-C010](rules.md) Runs an AI agent with approvals switched off
- Trap repositories: `agent-cli-yolo-secret-hunt`

**Traces on a computer** (`pah incident check s1ngularity-nx`)

- `~/.bashrc` containing `sudo shutdown -h 0`: line it added to shut the machine down in every new shell
- `~/.zshrc` containing `sudo shutdown -h 0`: line it added to shut the machine down in every new shell
- `/tmp/inventory.txt`: list of files it collected

**What to do, in order**

1. Remove the line sudo shutdown -h 0 from ~/.bashrc and ~/.zshrc.
2. Delete the repositories named s1ngularity-repository (and -0, -1, …) from your GitHub account: they hold your stolen secrets.
3. GitHub: revoke personal access tokens, OAuth app grants, SSH and deploy keys you do not recognise, then review the security log and recent pushes, workflows, repositories and gists for ones you did not make.
4. npm and PyPI: revoke your tokens (npm token list, npm token revoke) and check whether any of your packages got a version you did not publish; deprecate or yank it and tell its users.
5. From a device you trust, revoke and reissue AI credentials: API keys in each provider's console, and agent logins (sign out of Claude Code, Codex, Gemini CLI, Copilot and Cursor, then sign in again). A new password does not end a stolen session.
6. Cloud: rotate the access keys in ~/.aws, the gcloud and Azure folders and .env files, and review the audit log for new users, keys and resources.
7. Update Nx and its plugins to versions published after the incident.

**Sources:** <https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/>, <https://nx.dev/blog/s1ngularity-postmortem>
