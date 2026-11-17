"""Rules for execution surfaces: agent hooks and settings, MCP servers, skills, instruction files, editor tasks,
CI workflows and git configuration. The handlers that report them live in the sibling modules.
"""
from __future__ import annotations


from ..model import rule


R_HOOKS = rule(
    "PAH-A001", "Repository ships agent hooks",
    "Hooks in a repository's .claude/settings.json (or Gemini/Cursor equivalents) run shell commands with your "
    "permissions: after you trust the folder in an interactive session, and with no prompt at all under `claude -p` or "
    "the Agent SDK. The Miasma worm (June 2026) spread through SessionStart hooks; 73 repositories were disabled.",
    "Read every hook command and the files it runs before trusting the folder. Run headless agents on repos you did "
    "not write with hooks disabled.", attack=("T1546", "T1059"), owasp=("ASI04", "ASI05"),
    refs=("https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents",
          "https://code.claude.com/docs/en/hooks"))


R_CMD_SETTING = rule(
    "PAH-A002", "Agent setting that runs a command",
    "apiKeyHelper, statusLine, awsAuthRefresh, awsCredentialExport, otelHeadersHelper (Claude Code) and Codex's notify "
    "run programs; a repository has no reason to supply the program that produces your API key.",
    "Remove the setting or point it at a program you installed yourself.", attack=("T1059", "T1552"), owasp=("ASI03",),
    refs=("https://code.claude.com/docs/en/settings",))


R_BASE_URL = rule(
    "PAH-A003", "Redirects the agent's API traffic",
    "A repository that sets ANTHROPIC_BASE_URL, OPENAI_BASE_URL, a proxy, NODE_OPTIONS or extra CA certificates routes "
    "your prompts, code and API key through someone else's server (CVE-2026-21852 leaked API keys this way; a planted "
    "CLAUDE.md captured login tokens in about half of attempts).",
    "Delete the setting. If an agent already ran here, rotate the API key or log out and back in.",
    attack=("T1557", "T1552"), owasp=("ASI03", "LLM02"),
    refs=("https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/",
          "https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/"))


R_APPROVALS = rule(
    "PAH-A004", "Turns off the agent's approvals or sandbox",
    "Project settings that set bypassPermissions, allow every shell command, approval_policy=never or full disk "
    "access let any instruction the agent reads run without asking you.",
    "Remove the setting from the repository; decide approval modes yourself.", owasp=("ASI02",),
    refs=("https://code.claude.com/docs/en/permissions",))


R_MCP_SERVER = rule(
    "PAH-A005", "Repository defines an MCP server the agent will start",
    "A project MCP server is a program the agent launches with your permissions (CurXecute, MCPoison, CVE-2025-59536). "
    "Interactive Claude Code asks first; `claude -p` and the SDK connect without asking.",
    "Check the command and pin the package version before approving the server.", attack=("T1059",), owasp=("ASI04",),
    refs=("https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison",))


R_MCP_AUTO = rule(
    "PAH-A006", "Approves the repository's MCP servers automatically",
    "enableAllProjectMcpServers / enabledMcpjsonServers in a repository's own settings pre-approve its servers, so "
    "they start without the prompt that would have shown you the command (CVE-2025-59536).",
    "Remove the setting and approve servers one by one.", owasp=("ASI04",),
    refs=("https://www.wiz.io/vulnerability-database/cve/cve-2025-59536",))


R_CURSOR_HOOKS = rule(
    "PAH-A007", "Repository ships Cursor hooks",
    "Commands in .cursor/hooks.json run on agent events; workspace hooks ran before trust until Cursor 3.0.0 "
    "(CVE-2026-48124).", "Read the commands; update Cursor.", attack=("T1546",),
    refs=("https://www.pillar.security/blog/the-hook-was-already-in-the-workspace",))


R_CODEX_HOME = rule(
    "PAH-A008", "Redirects Codex's configuration into the repository",
    "A .env that sets CODEX_HOME makes Codex load config.toml from the repository, whose MCP servers then run "
    "(CVE-2025-61260, fixed in 0.23.0).", "Delete the variable; update Codex.", attack=("T1574",),
    refs=("https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/",))


R_SKILL_SHELL = rule(
    "PAH-A019", "Skill runs shell commands when it is invoked",
    "A line written !`command` in a skill or a slash command runs as soon as it is invoked, before the model has read "
    "anything, and its output goes into the prompt; `allowed-tools: Bash` in the frontmatter lets every shell command "
    "through without asking while the skill is active.",
    "Read every !` line and narrow allowed-tools to the commands the skill needs (Bash(git status:*)). "
    "disableSkillShellExecution turns the shell lines off.", attack=("T1059",), owasp=("ASI02", "ASI04"),
    refs=("https://code.claude.com/docs/en/skills",))


R_PLUGIN_REQUEST = rule(
    "PAH-A018", "Repository asks the agent to install plugins",
    "A repository's .claude/settings.json can name plugin marketplaces (extraKnownMarketplaces) and plugins to enable "
    "(enabledPlugins). Once you trust the folder, Claude Code offers to install them, and a plugin brings its own hooks, "
    "MCP servers, skills and commands, none of which are in the repository you scanned. A marketplace on someone's "
    "GitHub account can change what it serves at any time.",
    "Decline the install prompt unless you know the marketplace; scan the plugin's repository first "
    "(pah scan https://github.com/owner/repo).", attack=("T1195.002", "T1546"), owasp=("ASI04",),
    refs=("https://code.claude.com/docs/en/plugin-marketplaces",))


OFFICIAL_MARKETPLACES = ("claude-plugins-official", "anthropic-agent-skills", "claude-code-plugins")


R_AGENT_EXTENSION = rule(
    "PAH-A010", "Agent extension loaded with the workspace",
    "OpenClaw loaded .openclaw/extensions from an opened workspace before trust (CVE-2026-32920, fixed 2026.3.12).",
    "Remove the extension or review its code; update OpenClaw.", attack=("T1546",),
    refs=("https://advisories.gitlab.com/npm/openclaw/GHSA-99qw-6mr3-36qr/",))


R_INSTRUCTION = rule(
    "PAH-A011", "Instruction file tells the agent to do something risky",
    "Agents load AGENTS.md, CLAUDE.md, GEMINI.md, rules and skills automatically and follow them. A 13 KB AGENTS.md "
    "disguised as engineering guidelines made Codex install malware in over 90% of attempts; the researchers' "
    "conclusion was that users have to defend themselves.",
    "Read the instruction. Agents should not change their own settings, hide actions from you or install packages "
    "an instruction file names.", attack=("T1204",), owasp=("ASI01", "LLM01"),
    refs=("https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/",
          "https://arxiv.org/abs/2607.15143"))


R_UNPINNED_MCP = rule(
    "PAH-A013", "MCP server runs an unpinned package",
    "`npx -y package` or `@latest` fetches whatever version is newest at each start, so a later malicious release "
    "(a rug pull, like postmark-mcp) runs without any change in the repository.",
    "Pin an exact version.", attack=("T1195.002",), owasp=("ASI04",),
    refs=("https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html",))


R_TOOL_POISON = rule(
    "PAH-A014", "MCP tool description gives the model hidden orders",
    "Tool descriptions go straight into the model's context. Poisoned descriptions tell it to read ~/.ssh or config "
    "files and pass them as arguments; no model in MCPTox refused more than 3% of the time.",
    "Do not connect the server. Report it.", attack=("T1059",), owasp=("LLM01", "ASI04"),
    refs=("https://arxiv.org/abs/2508.14925",))


R_OTHER_AGENT = rule(
    "PAH-A015", "Other agent configuration that runs commands",
    "Aider test/lint commands, Zed context servers and tasks, Continue and Cline MCP servers in a repository run "
    "programs on the agent's behalf.", "Read the commands before using the agent here.", attack=("T1059",))


R_UNPINNED_RUN = rule(
    "PAH-A017", "Instructions run an unpinned package from the registry",
    "`npx pkg@latest`, `uvx pkg` or `pipx run pkg` in instructions an agent follows runs whatever the registry serves "
    "under that name today. LLM-written skills spread invented names (react-codeshift was copied into 237 repositories), "
    "and whoever registers such a name gets code execution.",
    "Pin an exact version of a package you have checked; run `pah scan --online` to confirm the package exists.",
    attack=("T1195.002",), owasp=("LLM03", "ASI04"),
    refs=("https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands",))


R_SKILL_FETCH = rule(
    "PAH-A016", "Skill fetches or runs remote code",
    "Skills are instructions plus scripts the agent runs. ClawHavoc's 341+ malicious ClawHub skills told the agent to "
    "run a setup step that downloaded the AMOS stealer.", "Do not install the skill.", attack=("T1204", "T1105"),
    refs=("https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting",))


R_FOLDER_OPEN = rule(
    "PAH-I001", "Task runs when the folder is opened",
    "VS Code and Cursor tasks with runOn: folderOpen run a command as soon as the folder opens (Cursor shipped with "
    "Workspace Trust off). Fake job-interview repositories deliver StoatWaffle this way.",
    "Do not open the folder in an editor that trusts it until you have read the task.", attack=("T1204.002", "T1059"),
    refs=("https://www.infoworld.com/article/4149285/new-stoatwaffle-malware-auto%E2%80%91executes-attacks-on-developers-2.html",
          "https://www.oasis.security/blog/cursor-security-flaw"))


R_WEAK_SETTINGS = rule(
    "PAH-I002", "Workspace settings weaken the editor's protections",
    "chat.tools.autoApprove, task.allowAutomaticTasks and turning Workspace Trust off in a repository let tasks and "
    "agent tools run without asking (CVE-2025-53773).", "Remove the settings from the repository.",
    attack=("T1562",), refs=("https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection",))


R_EXEC_SETTING = rule(
    "PAH-I003", "Workspace settings point an executable into the repository",
    "Settings like git.path, terminal profiles or language-server paths that name a file in the repository make the "
    "editor run it.", "Remove the setting.", attack=("T1574",))


R_DEVCONTAINER_HOST = rule(
    "PAH-I004", "Dev container runs a command on your machine",
    "initializeCommand runs on the host, not in the container, before the container exists.",
    "Read the command before opening the folder in a container.", attack=("T1059",),
    refs=("https://containers.dev/implementors/json_reference/",))


R_DEVCONTAINER_MOUNT = rule(
    "PAH-I005", "Dev container exposes host secrets or privileges",
    "Mounting ~/.ssh, ~/.aws, the Docker socket or the host root, or running privileged, gives code in the "
    "container your credentials or the host.", "Remove the mount or flag.", attack=("T1611", "T1552"))


R_ENVRC = rule(
    "PAH-I006", "Shell code runs when you enter the directory",
    "direnv runs .envrc on cd once it is allowed.", "Read it before `direnv allow`.", attack=("T1546",))


R_CI_PRT = rule(
    "PAH-I008", "Workflow runs pull-request code with repository secrets",
    "pull_request_target with a checkout of the pull request's head lets a fork run code with the repository's "
    "secrets and caches (TanStack / Mini Shai-Hulud).", "Do not check out untrusted code in pull_request_target.",
    attack=("T1195",), refs=("https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",))


R_CI_INJECTION = rule(
    "PAH-I009", "Workflow puts untrusted text into a shell command",
    "${{ github.event.issue.title }}, a comment body, a branch name or a commit message pasted into `run:` or a "
    "github-script `script:` becomes shell or JavaScript that anyone who can open an issue or a pull request writes. "
    "In September 2026, 83 issues and comments across 61 repositories hid commands in HTML comments for workflows like "
    "these; Nx's s1ngularity compromise began the same way. A risk to the repository's CI secrets, not to the machine "
    "of someone who clones it.", "Pass the value through `env:` and quote the variable in the script.",
    attack=("T1059", "T1195"),
    refs=("https://docs.zizmor.sh/audits/#template-injection", "https://nx.dev/blog/s1ngularity-postmortem"))


R_CI_SECRETS = rule(
    "PAH-I010", "Workflow sends the repository's secrets out",
    "toJSON(secrets) hands every secret of the repository to one step; GhostAction (Sep to Oct 2026, about 30,000 "
    "repositories) and the November 'wfx' wave pushed workflows that did this and posted the result to a bare IP "
    "address. Reading the runner's memory for secrets is how the tj-actions/changed-files compromise worked. A "
    "repository whose workflows do this has been compromised, and the same campaigns planted agent hooks and "
    "folder-open tasks.", "Treat the repository as compromised: rotate its secrets and check its recent commits.",
    attack=("T1552.004", "T1041"),
    refs=("https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/",
          "https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories"))


R_CI_AGENT = rule(
    "PAH-I011", "AI agent in a workflow acts on anyone's issue or comment",
    "An AI agent action (Claude Code, Codex, Gemini CLI and others) started by issues, comments or pull_request_target "
    "reads text an outsider wrote. When it also gets that text in its prompt, accepts any user or has its approvals "
    "off, the outsider is giving the instructions: Clinejection turned an issue title into a stolen npm token "
    "(Feb 2026), and PromptPwnd found the pattern across many repositories.",
    "Restrict who can trigger it, keep untrusted text out of the prompt, and do not give it write tools or secrets.",
    attack=("T1059", "T1195"), owasp=("LLM01", "ASI01"),
    refs=("https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm",
          "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents"))


R_GITMODULES = rule(
    "PAH-G001", "Dangerous submodule definition",
    "ext:: transports, option-like URLs, custom update commands and paths with control characters or pointing into "
    ".git have been used for code execution on `git clone --recursive` (CVE-2024-32002, CVE-2025-48384).",
    "Clone without --recursive and update git.", attack=("T1203",),
    refs=("https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/",))


R_GIT_CONFIG = rule(
    "PAH-G002", "Git configuration that runs commands",
    "core.fsmonitor, core.hooksPath, sshCommand, pager, credential helpers, diff/filter drivers and ! aliases run "
    "programs on everyday git commands, which agents run constantly. A cloned repository never ships these; an archive "
    "or a tampered checkout can.", "Remove the setting from .git/config.", attack=("T1546",))


R_GIT_HOOKS = rule(
    "PAH-G003", "Git hooks are already installed",
    "A fresh clone has only *.sample hooks. Real hook files mean the repository came as an archive or something "
    "installed them; they run on commit, checkout or push.", "Read them; delete what you did not install.",
    attack=("T1546",))


R_WORKTREE = rule(
    "PAH-G004", "Git directory indirection",
    "commondir/gitdir files that point elsewhere can make tools trust or run things from another location "
    "(Claude Code CVE-2026-40068).", "Inspect where they point.", attack=("T1574",),
    refs=("https://advisories.gitlab.com/npm/@anthropic-ai/claude-code/CVE-2026-40068/",))
