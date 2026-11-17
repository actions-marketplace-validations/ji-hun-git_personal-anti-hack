# Research behind agent-white-hat

The evidence this tool is designed from, current to 2026-11-12: how malware reaches people who use AI coding agents (Claude Code, Codex, Cursor, Gemini CLI, OpenClaw, MCP servers, Agent Skills), why language-model review misses it, what existing defenses cover, and what the strongest security projects have in common. Every rule in [rules.md](rules.md) cites the incident or study it comes from; this page collects them.

**Legend.** **[V]** checked against the primary source. **[R]** as reported by the linked source, not independently re-checked. **[?]** unverified or conflicting.

## 1. How malware reaches people who use AI tools

| Door | What happened | Source |
|---|---|---|
| Opening a repo with an agent or IDE | Miasma worm (Jun 2026) planted Claude/Gemini `SessionStart` hooks, a Cursor rule and a VS Code `folderOpen` task; GitHub disabled 73 Microsoft repos [R] | [StepSecurity](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-agent-instruction-file-poisoning-20261027/) |
| | Fake job-interview repos deliver StoatWaffle through `.vscode/tasks.json` with `"runOn": "folderOpen"` [R] | [InfoWorld](https://www.infoworld.com/article/4149285/new-stoatwaffle-malware-auto%E2%80%91executes-attacks-on-developers-2.html) |
| | Claude Code project files could run code or leak the API key before the trust prompt (CVE-2025-59536, CVE-2026-21852; both patched, no known exploitation) [R] | [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/) |
| Following instructions in files | A 13 KB `AGENTS.md` posing as engineering guidelines, dropped in `~/Downloads` by a website: Codex first changed its machine-wide settings, then installed the malicious npm package `function-color`, in more than 90% of attempts. A `CLAUDE.md` variant got Claude Code to route its requests to an attacker server about 50% of the time, exposing the login token. The researchers say there is nothing for the vendors to patch, so users must defend themselves. About half of the firm's customers run a coding agent in Downloads [V] | [Help Net Security, 2026-10-26](https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/) |
| | Agents install whatever setup docs list. Registry redirection is missed almost everywhere, near-miss names (azurecore for azure-core) slip through, and whether an attack is caught depends on the harness-model pair. A deterministic pre-install check of names, sources and versions closes most of the gap [V, abstract only; per-agent numbers R] | [Bagmar & Saraf, arXiv 2607.15143](https://arxiv.org/abs/2607.15143) |
| | Clinejection (Feb 2026): text in a GitHub issue title hijacked Cline's triage bot, leading to a stolen npm token; `cline@2.3.0` installed OpenClaw globally from its postinstall script [R] | [Snyk](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions) |
| Installing packages | PhantomRaven: 126 npm packages showing "0 dependencies" that fetch the payload from URL dependencies at install [R]. Phantom Gyp: 57 packages running code through `binding.gyp` [R]. LiteLLM compromise through a `.pth` file [R]. Shai-Hulud: at least seven waves Sep 2025 to Aug 2026; the credential sweep grew from 189 to 469 file paths including Cursor, OpenClaw and Codex configs; Mini Shai-Hulud persisted through `.claude/settings.json` hooks [R] | [Koi](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies), [Snyk](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp), [FutureSearch](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/), [Socket](https://socket.dev/glossary/shai-hulud), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-credential-expansion-2026090/) |
| | Slopsquatting: the hallucinated name `react-codeshift` appeared in 47 AI-generated skills copied into 237 repos [R]. Across 16 LLMs, 5.2% (commercial) and 21.7% (open) of suggested packages were hallucinated [R] | [Aikido](https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands), [USENIX Security '25](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen) |
| Adding skills, MCP servers, extensions | ClawHavoc: 341 malicious skills among 2,857 on ClawHub (1 Feb 2026), 824 by 16 Feb, mostly delivering the AMOS stealer [R]. A trojanized Claude Code extension sat on Cursor's marketplace for about 11 hours on 29 Oct 2026, up to 5,000 installs, planting an SSH key [R]. `postmark-mcp` (Sep 2025) BCC'd every email it sent [R] | [Koi](https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting), [Sophos](https://www.sophos.com/en-us/blog/malicious-claude-code-extension-distributed-through-cursor-marketplace), [THN](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) |
| Pasting install commands | "InstallFix" (Mar 2026): Google ads led to cloned Claude Code install pages whose one-liners (`curl … \| zsh`, `mshta https://…`) installed the Amatera and Cuckoo stealers [R]. Straiker counted 88 lure domains, 30+ for Claude Code [R]. Shared ChatGPT, Grok and claude.ai chats were used as lure pages (AMOS, MacSync) [R]. Fake-CAPTCHA (ClickFix) incidents rose 563% in 2025 [R]. Sophos: of 38 malicious-AI cases (Jul 2025 to Jun 2026), 30 were fake AI software and Claude was the lure in 26 [R] | [Help Net Security](https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/), [Bitdefender](https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware), [Straiker](https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign), [Huntress](https://www.huntress.com/blog/fake-claude-macsync), [CrowdStrike](https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/), [Sophos](https://www.sophos.com/en-us/blog/fake-ai-real-malware-attackers-impersonating-ai-brands) |
| Turning your own AI CLIs against you | s1ngularity/Nx (Aug 2025) ran Claude Code, Gemini CLI and Amazon Q with their permission checks bypassed; 2,349 secrets from 1,079 machines [R]. QUIETVAULT uses AI CLIs already on the machine to hunt for secrets [R]. Amazon Q v1.84.0 shipped a wiper prompt [R] | [GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/), [Google GTIG](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), [The Register](https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/) |

### After infection: AI-token theft

- WardenStealer: more than 130,000 infections since 2026-08-03. It takes Claude Code OAuth tokens (including MCP server tokens) and Codex `auth.json` [R] ([SpyCloud](https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/)).
- Aokigahara's `aisessions` module reads `.claude.json`, `.codex/auth.json`, Cursor/Windsurf/VS Code `state.vscdb`, `.gemini/.env`, `.copilot/hosts.json` and the Claude/ChatGPT Store-app caches [R] ([Check Point](https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/)).
- A Vidar variant took `openclaw.json` (with the gateway token), `device.json` and `MEMORY.md` [R] ([Hudson Rock](https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/)). ACRStealer takes Cline and Continue keys [R].
- A password change does not cancel stolen tokens; sessions must be revoked and tokens rotated [R] (SpyCloud, above).

### September to November 2026 (rules added in 0.2.0) [R]

| Campaign or flaw | What it did | Source |
|---|---|---|
| PolinRider (Oct to Nov) | Amended and force-pushed commits in 188 GitHub repositories: a folder-open task named `eslint-check` ran a loader saved as `fa-solid-300.ttf`. Hijacked npm packages read their server from an Ethereum transaction and piped it into a detached `node -i` | [GitGuardian](https://blog.gitguardian.com/ghostaction-x-polinrider/), [Sonatype](https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages) |
| GhostAction and "wfx" (Sep to Nov) | Stolen tokens pushed workflows named like security tooling that sent `toJSON(secrets)` to a bare IP; about 30,000 repositories | [GitGuardian](https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/), [Aikido](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories) |
| testmetest worm (Oct) | `binding.gyp` loader, then SessionStart hooks, Cursor rules, MCP entries and folder-open tasks for several agents at once, and a wiper that fires when the stolen token is revoked | [JFrog](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/) |
| MALFEX, Apex Accelerator, SleepyDuck (Sep to Oct) | Padding past the editor edge and a scheduled task; a fake AI agent that set `OPENROUTER_BASE_URL`, wrote an MCP server and added a Defender exclusion; Open VSX extensions with a payload appended to an MP4 | [Checkmarx](https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/), [Elastic](https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages), [Pluto](https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/) |
| Planted programs and relocated configs (Jun to Nov) | A repository's `git.exe` ran on open in Cursor, Claude Desktop and Kiro (CVE-2026-63093, CVE-2026-88066, CVE-2026-18656); `GEMINI_CLI_HOME` in `.env` started an MCP server (CVE-2026-13745); a `__proto__` key in `.vscode/mcp.json` did the same in Restricted Mode (CVE-2026-121662); `PATH` pointing at a repository `bin/git` ran through Claude Code's startup git probes | [GHSA-prfr-jc65-hr23](https://github.com/advisories/GHSA-prfr-jc65-hr23), [GHSA-2255-3477-vp73](https://github.com/advisories/GHSA-2255-3477-vp73), [Datadog](https://securitylabs.datadoghq.com/articles/coding-agent-project-trust-code-execution-before-first-prompt/) |
| Install protections (Jul) | npm 12 stopped running dependencies' install scripts and fetching git or URL dependencies by default; a project's `.npmrc` can switch both back on | [GitHub](https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation) |

Heuristics adopted from other scanners in 0.2.0: template injection and over-shared secrets in workflows (zizmor), worm self-propagation and silent processes (GuardDog), bin-name shadowing (Socket), AI agent actions on untrusted triggers (Trail of Bits' agentic-actions-auditor), skill shell lines and pre-approved tools (Snyk agent-scan, Cisco skill-scanner), terminal escape codes (Trail of Bits).

## 2. Why conventional LLMs miss it

- **Size and dilution.** Cloudflare (2026-04-29), 7 models, 18,400 calls, 100 malicious Workers: 67.3% baseline detection. Files over 3 MB: 17.6% (12.3–13.6% with injected comments). Deceptive comments making up under 1% of a file cut detection to 53.3%; very dense comments raised it instead. Their conclusion: structural obfuscation beats linguistic deception. Their advice: strip comments before analysis, keep functional code when truncating, anonymise names, ask attack-specific questions, check safety claims against behavior [V] ([Cloudflare](https://www.cloudflare.com/cloudforce-one/research/adversarial-deception-a-study-of-indirect-prompt-code-injection/)).
- **Scanners bypassed in under an hour.** Trail of Bits (2026-06-03) beat five products (ClawHub's pipeline, Cisco skill-scanner, and Gen, Socket and Snyk on skills.sh) with four skills: about 100,000 leading newlines (the harness truncates large files), a payload in shipped `.pyc` bytecode, scripts hidden inside a DOCX, and a registry-redirecting config framed as a compliance policy that talked the LLM scanner into approving. Three of four took under an hour. Their message: don't outsource trust to a scanner; pin versions, limit permissions, monitor at runtime [V] ([CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/)).
- **LLM-only recall is low.** On 6,420 malicious npm packages, SocketAI (LLM) had 98.2% precision but 44.4% recall; GuardDog (rules) 89.9% recall [R] ([arXiv 2603.27549](https://arxiv.org/html/2603.27549v2)). 13 LLMs on 4,070 PyPI packages located the malicious lines at F1 0.48; code length was the only significant factor [R] ([arXiv 2602.16304](https://arxiv.org/abs/2602.16304)). LLM scanners analysed only 69–86% of large npm files before preprocessing [R] ([CASHEWS, arXiv 2609.18862](https://arxiv.org/abs/2609.18862)). Miasma's payload was a single 4.6 MB line [R].
- **Invisible characters.** GlassWorm hid payloads in Unicode variation selectors decoded into `eval()`, hitting 151+ GitHub repos 3–9 Mar 2026 [R] ([Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)). GPT-4o's code comprehension fell from 100% to 0–2.3% with invisible, bidi or backspace characters [R] ([arXiv 2412.08098](https://arxiv.org/html/2412.08098v3)). Hidden Unicode in rules files made Copilot and Cursor insert scripts silently [R] ([Pillar](https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)).
- **Malware now talks to the scanner.** Hades PyPI (Jun 2026) put a prompt injection before its payload asking LLMs to report it clean [R] ([StepSecurity](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages)). A Shai-Hulud wave opened with refusal bait: a scanner must report a refusal as "not scanned", never "clean" [R] ([JFrog](https://research.jfrog.com/post/prompt-injection-vs-scanners/)).
- **Code that isn't there yet or isn't active yet.** URL dependencies (PhantomRaven), NuGet logic bombs set for 2027–28 inside ~99% benign code, xz-utils' payload in test fixtures activated only in specific builds [R]. Environment-checking npm malware is caught 39.5–51.7% of the time [R].
- **Even the winner's models.** Gatekeeper's Muse models block 55–57% of malware on its time-split test [V] (§3).

## 3. Existing defenses and their gaps

### The winning repo: Gatekeeper [V]

Second place, Indie track, Meta Global AI Developer Hackathon 2026 (finals 2026-11-09), and the only security project among the 14 winners, per a third-party recap of the closing announcements; the official gallery had not shown placements yet [R]. Built 26 Oct to 4 Nov 2026.

- **What it does.** npm malware detection on Meta models; never runs package code. An investigator agent reads the package step by step with code tools (read, search, decode, strings, diff against the previous version or the original of a fork). Every claim is checked by code: cited lines must exist, and `reach.py` checks that an install hook can actually reach the cited file. Flags "phantom" dependencies the public registry doesn't have (the fake job-interview Tailwind campaign) and URL dependencies. Campaign memory of endpoints and accounts. Install guard: shims for `npm`/`npx`, live OSV lookup plus an offline list of 222k malicious npm names, a 24-hour cooldown via `--before`, and a local Muse Glimmer judge. Live monitor of every npm release with flag times committed to an OpenTimestamps ledger.
- **Results.** 48 confirmed malicious packages (117 versions) flagged about a minute after publication, a median 14 hours before any public report and 25 hours before the OSV/GitHub/npm listing; 48% of the malware published while it ran.
- **Its own stated gaps.** npm and npx only (pnpm, yarn, bun or a full-path npm bypass the shims). Dependencies are not read by the model. `npm install` with no arguments, which is what you run in a cloned repo, gets no model check. The local classifier is public, so attackers can test against it offline. Models block 55–57%.
- **Out of scope entirely.** Repo auto-execution files, agent configs, README/AGENTS.md lures, skills, MCP servers, extensions, other ecosystems, paste-to-run installers, post-infection checks.
- Sources: [README](https://github.com/lb2002/gatekeeper), [guard threat model](https://github.com/lb2002/gatekeeper/blob/main/docs/guard-threat-model.md), [winners recap](https://dev.to/moruku36/the-meta-ai-hackathon-is-over-what-the-winners-of-5367-projects-built-and-what-i-learned-by-glc).

### Agent, skill and MCP defenses [R]

| Tool | Mechanism | Gap |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) (ex mcp-scan) | Rules plus Snyk-hosted models across 14 clients | Needs `SNYK_TOKEN` and uploads tool descriptions and skill content; starts stdio servers during scans; bypassed by Trail of Bits |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) / mcp-scanner | YARA-X, Python AST dataflow, LLM judge | Rules alone catch 7.7% at HIGH (vendor figure); bypassed by Trail of Bits |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | 71 patterns: regex, AST, taint, YARA, optional LLM | Flagged 48.7% of 67,453 ClawHub skill versions yet caught 6.8% of 206 rated malicious ([arXiv 2606.01494](https://arxiv.org/abs/2606.01494)); cannot analyse binary code |
| [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | LLM-driven scans | Needs an LLM key; web UI without authentication |
| LlamaFirewall + Prompt Guard 2 | Classifier plus LLM alignment check | AgentDojo attack success 1.75% (vendor); 512-token window reportedly split-bypassed [?] |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | Local MCP/HTTP proxy, schema hashing for rug pulls | No published rates; misses poisoning present at the first `tools/list` |
| Hook packs: [dcg](https://github.com/Dicklesworthstone/destructive_command_guard), [cc-safety-net](https://github.com/kenryu42/claude-code-safety-net), [lasso claude-hooks](https://github.com/lasso-security/claude-hooks) | Command patterns per agent | No content analysis; one agent each; "not a sandbox" |
| [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime), Codex and Cursor sandboxes | OS sandbox | Escaped by writing config that an unsandboxed tool runs later (7 findings, Jul 2026); Windows support in alpha |
| [ClawSec](https://github.com/prompt-security/clawsec) | Config drift detection | OpenClaw only. No tool watches agent config files across all agents |

### Package-level detectors [R]

| Tool | Notes |
|---|---|
| [GuardDog](https://github.com/DataDog/guarddog) | YARA rules plus metadata, 7 ecosystems, local. npm precision 97.0%, recall 89.9% |
| [malcontent](https://github.com/chainguard-dev/malcontent) | 14,500+ YARA capability rules, diff between versions; many false positives |
| [OpenSSF package-analysis](https://github.com/ossf/package-analysis) | Runs packages in gVisor, records strace and network |
| [Packj](https://github.com/ossillate-inc/packj) | Static plus install tracing; precision about 50–57% |
| [SafeDep vet / pmg](https://github.com/safedep/pmg), [Aikido safe-chain](https://github.com/AikidoSec/safe-chain), [Datadog scfw](https://github.com/DataDog/supply-chain-firewall), Socket Firewall | Package-manager wrappers on vendor feeds; unknown new versions pass |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Offline MAL- records; most malware is classified within 3 days |
| [YARA-X](https://github.com/VirusTotal/yara-x), [capa](https://github.com/mandiant/capa) | Rule engines; quality depends on the rules |

npm 12 (Jul 2026) blocks dependency install scripts, `binding.gyp` and URL/git dependencies by default, but a repo's own scripts still run; pnpm 10 blocks dependency scripts [R].

## 4. What a pre-flight repo scan must map (things that run without being read) [R]

| Surface | Paths | Trigger | Incidents and CVEs |
|---|---|---|---|
| Agent configs | `.claude/settings*.json` (hooks, `env`, `defaultMode`), `.mcp.json`, `.cursor/{mcp.json,hooks.json,rules/}`, `.codex/config.toml` plus a `.env` setting `CODEX_HOME`, `.gemini/settings.json`, `.openclaw/extensions/` | Session start or folder open | Claude Code CVE-2025-59536, CVE-2026-21852, CVE-2026-33068, CVE-2026-40068; Cursor CVE-2025-54135/54136, CVE-2026-48124; Codex CVE-2025-61260; Gemini CLI CVE-2026-12537; OpenClaw CVE-2026-32920; Miasma |
| Instruction files | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, README setup steps | The agent reads them | Forever Security, Bagmar & Saraf, Miasma |
| Redirects | `*_BASE_URL`, `CODEX_HOME`, `.npmrc`/`pip.conf` registries, lockfile `resolved` URLs | First request or install | CVE-2026-21852; Trail of Bits' LLM-scanner bypass |
| IDE | `.vscode/tasks.json` with `runOn: folderOpen`; settings naming executables or auto-approval | Folder open (Cursor shipped with Workspace Trust off [?]) | StoatWaffle; CVE-2025-53773; IDEsaster (30+ flaws) |
| Dev containers | `devcontainer.json` `initializeCommand` (runs on the host) | Container setup | |
| Shell env | `.envrc` | After `direnv allow` | |
| npm | Own lifecycle scripts, husky `prepare`, `binding.gyp` with `<!(`, URL/git dependencies | Install | Phantom Gyp, PhantomRaven |
| Python | `*.pth`, `conftest.py`, `setup.py`, import-time code | Interpreter start, pytest, `pip install` or even `pip download` | LiteLLM, Hades |
| Rust | `build.rs`, proc macros, `.cargo/config*`, `rust-toolchain.toml` | Build, or rust-analyzer on open | proc-macro1 typosquat |
| Make | `$(shell …)` | When the Makefile is read | Bagmar & Saraf |
| Git | Submodule plus symlink, worktree `commondir` | `clone --recursive`, agent start | CVE-2024-32002, CVE-2025-48384, CVE-2026-40068 |
| Symlinks out of the repo | Any file | Agent reads or writes it under a harmless name | GhostApproval (6 assistants) |
| Content tricks | Invisible/bidi/tag Unicode; single lines over 1 MB; padding; decode-then-execute; high-entropy literals; binaries in fixtures; date-, CI- or environment-conditional code; text addressed to AI scanners; scripts launching agent CLIs with permission-bypass flags | Review or scan | GlassWorm, Miasma, xz-utils, Hades, Nx |
| CI | `pull_request_target` checking out PR code or sharing caches | Fork pull request | TanStack / Mini Shai-Hulud |

## 5. Benchmarks and datasets [R]

- **Malicious packages.**
  - [ossf/malicious-packages](https://github.com/ossf/malicious-packages): about 240k OSV reports including spam (Apache-2.0).
  - [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset): 29,847 samples including IDE extensions and AI skills (Apache-2.0 with attribution; zips use the password "infected"; mostly found by GuardDog, so selection bias).
  - [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry): 9,503 packages.
  - Backstabber's Knife Collection: 174 packages, available on request.
- **Skills.**
  - MalSkillBench: 3,944 malicious skills verified by execution, plus 4,000 benign ([arXiv 2606.07131](https://arxiv.org/abs/2606.07131)).
  - MaliciousSkillBench: 9,740 skills; the best detector reached 95.6% recall at a 62.4% false-positive rate ([arXiv 2608.19901](https://arxiv.org/abs/2608.19901)).
- **Agent injection.**
  - AgentDojo, AgentDyn, InjecAgent.
  - MCPTox: 1,312 tool-poisoning cases.
  - LLMail-Inject: 208k attacks.
  - b3 and BrowseSafe-Bench.
- **Gap.** No public benchmark measures the end-to-end case: an agent sets up a malicious repo, and is the person compromised? There is also none for MCP rug pulls or for persistence through hooks.

## 6. What winning security repos share [R]

1. **They prove findings instead of raising alerts.** AIxCC's Atlantis re-ran the exploit on every patch, Shannon says "no exploit, no report", and Gatekeeper's lines are checked by code.
2. **They publish a number against a named baseline.**
3. **One command gets a first result.**
4. **They ship inside the agent people already run** (skill, plugin, MCP server).
5. **They pair the LLM with plain code.** The AIxCC review found that LLMs add to fuzzing rather than replace it.
6. **They favor robustness over cleverness.** Stability explained most of AIxCC's score gap.
7. **Their costs are low and stated.**
8. **They plug into CI with machine-readable output** (SARIF, JSON).
9. **They run locally and sandboxed by default.**
10. **They ride a fresh threat with a credible statistic.**

**Two more findings:**
- Open-source personal security is an empty field: the top scam-detection repo created since 2025 has 44 stars.
- Winning a competition does not by itself bring stars: AIxCC repos have 11–1,744; Buttercup, which runs on a laptop, out-starred the winner.

Sources: [AIxCC SoK](https://arxiv.org/html/2602.07666), [Team Atlanta](https://team-atlanta.github.io/blog/post-afc), [Trail of Bits](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/), [ROSS index](https://runacap.com/ross-index/q3-2026/).

## 7. Implications for agent-white-hat

- Guard every door an AI-tool user opens, not one ecosystem; leave deep npm detection to OSV and tools like Gatekeeper.
- Code decides, the LLM investigates. A model can raise suspicion but cannot clear a rule-based block, and its claims count only when they cite lines that code has verified. A refusal or a truncation is reported as "not scanned".
- Normalize before any model reads: reveal invisible Unicode, cut padding, split minified lines, strip comments for a second pass, decode in code, look inside `.pyc` files and archives.
- Get behavior evidence by running installs in isolation with canary secrets (optional).
- Watch agent config and instruction files across all agents, not one.
- Measure end-to-end with real agents and publish numbers against bare LLMs and named tools, including an adaptive round.

## 8. Code to reuse from the author's repos

- `ai-agent-building-kit/template/kit/guard.py`: tag characters, invisible characters, variation selectors, hidden HTML, secret patterns, exfiltration URLs in images and links.
- `ethical-research/skills/ethical-research/scripts/integrity_scan.py`: zero-width and bidi detection, hidden text in PDF and DOCX.
- `ethical-research/skills/ethical-research/scripts/mcp_server.py`: standard-library MCP server supporting current protocol revisions.
- The `.claude-plugin/` packaging and the benchmark harness pattern (pass^3, multiple vendors, result files tied to the code version).

## 9. Methods adopted in 0.4.0 (November 2026)

| Method | Where it comes from | What agent-white-hat does with it |
| --- | --- | --- |
| Capability diff between releases | Chainguard's [malcontent](https://github.com/chainguard-dev/malcontent) `diff`: report only behaviours that are new in the next version | `pah diff OLD NEW` tags every file with capabilities (network, sending data, processes, dynamic code, credentials, persistence, decoding, install hooks) and reports what code that runs on its own gained (PAH-D001), new dependencies and new findings. ChainDrop, arrayref 0.3.10 and strutil-core 1.0.1 all fit this shape |
| Published package against its source | [LastPyMile](https://2021.esec-fse.org/details/fse-2021-papers/61/LastPyMile-identifying-the-discrepancy-between-sources-and-packages) (ESEC/FSE 2021), Google's [OSS Rebuild](https://blog.google/security/introducing-oss-rebuild-open-source/) (2025) | `pah diff --source <checkout at the tag> <package>` blocks on code that runs on its own and is only in the package (PAH-D002): the xz-utils build file, LiteLLM's `.pth` files, the swapped @subql/common archive. Packaging metadata (RECORD, PKG-INFO, dist-info) is ignored, and rewritten manifests count only when their install hooks change |
| Toxic flows, the lethal trifecta | [Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) (2025), Invariant Labs' [toxic flow analysis](https://invariantlabs.ai/blog/toxic-flow-analysis), [CaMeL](https://arxiv.org/abs/2503.18813) (2025) | Each MCP server and built-in tool is labelled with what it reaches (content anyone can write, private data, a way out). When a tool that brings in untrusted content and a tool that sends data out both run without asking, the agent's own access to your files completes the trifecta (PAH-A021), in a repository's settings and in the user's own setup (`pah checkup`) |
| Argument injection in pre-approved commands | [Trail of Bits](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/) (2025) | Allow-list entries for programs that run other programs through an option or the repository's files (`find -exec`, `go test -exec`, `rg --pre`, `git -c`, `npm test`, `make`) are reported; interpreters and package runners (`node`, `python`, `npx`, `uvx`) more strongly (PAH-A020). Exact commands with fixed arguments stay quiet |
| Following the chain at install time | Behaviour-sequence detection ([Cerebro](https://arxiv.org/abs/2309.02637), TOSEM) | Install-time code that starts a file through a runtime (`bun Math_Symbol.js`, `system('bun index.js')`, `spawn(bun, ['x.js'])`) makes that file install-time code too, so the payload is judged where it runs. A download decoded on its way to an interpreter (`curl … \| base64 -d > /tmp/t.mjs && node /tmp/t.mjs`) is high wherever it is written |
| Incident response in the right order | Vendors' advisories for ChainDrop, strutil-core and the testmetest worm; [SpyCloud](https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/); [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) | 33 incidents with their traces and responses in [incidents.md](incidents.md). Several current worms wipe the home folder when their stolen token is revoked, so their responses remove the persistence before any token is revoked, and stolen sessions are revoked rather than only changing passwords |

Not adopted yet: pinning MCP tool descriptions to detect rug pulls ([mcp-scan](https://invariantlabs.ai/blog/introducing-mcp-scan), [ETDI](https://arxiv.org/abs/2506.01333)). `pah watch` already pins the configuration that starts each server; the descriptions a server returns at run time need the server to be started, which `pah` never does.

### August to November 2026 (incidents added in 0.4.0) [R]

ChainDrop (keyv and 443 more packages released through the project's own trusted publishing), WFX Phantom (CI secret stealer reverted within seconds), MIDNIGHT NEPTUNE (fake recruiters, a Claude Code hook backdoor), strutil-core (a gem extension with the testmetest wiper), the Paperclip and Browser Use skill clones (a loader in a linked setup document), @subql/common (a release archive swapped in the publish workflow), the arrayref crates (a build script behind a new dependency), Deadbugz (an MCP server whose tools change after three calls), unauthorized Codex and Claude Code relays, and `.pth` typosquats of AI libraries. Each one, with sources, traces and the response: [incidents.md](incidents.md).

## 10. Methods adopted in 0.5.0 (November 2026)

Endpoint security vendors now sell agent protection built on their endpoint methods: CrowdStrike's Falcon Guardian
(formerly Falcon AIDR) plugs into the agents' own hooks and inspects tool calls and outputs, and its Agent Graph links
prompt, tool call and process activity; Palo Alto Networks' Cortex Agentic Endpoint Security (from Koi) applies block or
ask policies to shell, file, MCP and network actions, and Prisma AIRS Model Security (from Protect AI) scans model
files. The methods below are the ones that work on one machine without a vendor's cloud.

| Method | Where it comes from | What agent-white-hat does with it |
| --- | --- | --- |
| Indicators of attack: sequences, not single events | CrowdStrike, [IOA vs IOC](https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/) | Every hook call becomes a tagged step in a per-session record (`session.py`); seven rules look for the orders attacks take (`behavior.py`, PAH-B001 to B007). In CrowdStrike's analysis of SANDWORM_MODE only 2 of 14 behaviors were alert-worthy alone, which is the case for judging sequences |
| Causality chains | Palo Alto Networks, Cortex XDR [causality analysis](https://cortex-docs.paloaltonetworks.com/cortex-xdr/detect-investigate-and-respond-to-threats/investigate-and-respond-to-cases/case-concepts/what-is-causality) and [BIOC rules](https://cortex-docs.paloaltonetworks.com/cortex-xdr/detect-investigate-and-respond-to-threats/threat-management/detection-rules/whats-a-bioc/create-a-bioc-rule) | The agent session is the root of the chain; each alert names the earlier step that completes it, and `pah session show` prints the chain. Like a BIOC rule, each chain rule is checked against recorded history before it fires, and steps the guard denied never count as having happened |
| Inspecting tool output, not only tool input | CrowdStrike [Falcon Guardian](https://www.crowdstrike.com/en-us/blog/falcon-guardian-defines-next-generation-of-ai-security/); Unit 42's [22 web prompt-injection techniques](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) (2026) | `outputs.py` reads what WebFetch, web search, MCP tools, shell commands and file reads return, through post-tool hooks in Claude Code, Codex, Gemini CLI, Cursor and Copilot (PAH-O001 to O004) |
| Untrusted data kept away from actions | [CaMeL](https://arxiv.org/abs/2503.18813) (2025), Microsoft [FIDES](https://arxiv.org/abs/2505.23643) (2025) | Not their full design (that needs control of the agent loop), but the same separation where a hook can enforce it: once an output carries injected instructions, the session's later sends, setting changes, guard changes and runs of downloaded files need the user (PAH-B003) |
| Model files read without loading them | Protect AI [ModelScan](https://github.com/protectai/modelscan), Trail of Bits [fickling](https://github.com/trailofbits/fickling), Prisma AIRS [model security rules](https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security/model-security-to-secure-your-ai-models/understanding-ai-model-security-rules) | `models.py`: pickle opcodes listed with `pickletools` (ModelScan's critical modules, plus loaders of nested code), Keras configs and Lambda layers, GGUF chat templates, nullifAI's 7z packing and broken streams, `auto_map` code (PAH-M001 to M006) |
| Tamper protection | Standard in endpoint agents | Writes that turn off hooks, permission prompts or the guard are denied; doing it after untrusted content is a chain (PAH-B005) |

Not adopted, because they need what a local tool does not have: fleet-wide prevalence and cloud models (Threat
Graph), detonation in a sandbox (WildFire), process and kernel telemetry (a rootkit such as IronWorm's hides from user
space; agent-white-hat has no kernel driver), and managed hunting.

### June to November 2026 (incidents added in 0.5.0) [R]

IronWorm (an npm worm with an eBPF rootkit that steals AI-agent credentials), the Hades PyPI wave (wheels that tell AI
scanners they are clean), Agentjacking (fake Sentry errors that made agents run npx; a demonstration), CVE-2026-54316
(an issue that made Claude Code in CI leak its key through a pre-approved host), SANDWORM_MODE (rogue MCP servers and
global git hooks) and Load/Mine (31 fake Qwen2 repositories that ran a miner through `trust_remote_code`). Each one,
with sources and the response: [incidents.md](incidents.md).
