"""Rules for what code and documents contain: downloads that run, secrets sent out, obfuscation, hidden text
and the shapes of named campaigns. Each rule names the incident or study behind it. The checks that report
them live in patterns.py (commands and content), campaigns.py (campaign shapes) and deobfuscate.py.
"""
from __future__ import annotations

from .model import rule


R_DOWNLOAD_EXEC = rule(
    "PAH-C001", "Downloads code and runs it",
    "Piping a remote script into a shell (or iex, mshta, an interpreter) runs whatever the server sends at that "
    "moment, with your permissions, and leaves nothing to review. It is the delivery step of InstallFix/ClickFix "
    "campaigns and of most install-time malware.",
    "Download the file, read it, verify its checksum or signature, then run it. Prefer the vendor's signed installer.",
    attack=("T1105", "T1059"), owasp=("LLM05",),
    refs=("https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/",
          "https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/"))
R_DECODE_EXEC = rule(
    "PAH-C002", "Decodes hidden data and executes it",
    "Code that base64/zlib/marshal/char-code decodes a string and passes it to eval/exec/Function hides its real "
    "behavior from people and from LLM reviewers; Hades (PyPI, 2026) and obfuscated npm stealers use this shape.",
    "Treat as malicious unless you can decode the payload and explain why it must be hidden.",
    attack=("T1027", "T1140", "T1059"),
    refs=("https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages",))
R_SECRETS = rule(
    "PAH-C003", "Touches credential stores",
    "Paths such as ~/.ssh, ~/.aws/credentials, browser login databases, crypto wallets and AI-tool tokens "
    "(~/.claude/.credentials.json, ~/.codex/auth.json, openclaw.json) are what infostealers collect.",
    "Code that runs at install or open time has no reason to read these. Inspect what it does with them.",
    attack=("T1552.001", "T1555", "T1539"), owasp=("LLM02",),
    refs=("https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/",
          "https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/"))
R_EXFIL = rule(
    "PAH-C004", "Reads secrets or the environment and sends data out",
    "Reading credentials or the whole environment and making a network request in the same file is the shape of "
    "dependency-confusion beacons and credential stealers (Shai-Hulud, s1ngularity).",
    "Do not run it. Rotate any credential the code could have reached if it already ran.",
    attack=("T1041", "T1552"), owasp=("LLM02",),
    refs=("https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/",))
R_ENV_DUMP = rule(
    "PAH-C005", "Collects the whole environment",
    "Serializing every environment variable collects API keys and tokens that live there.",
    "Read only the variables the code needs.", attack=("T1082", "T1552"))
R_NET_AUTO = rule(
    "PAH-C006", "Makes network requests while installing or opening",
    "Code that runs at install or open time and talks to the network can fetch a second stage that no scanner saw.",
    "Check the destination. Prefer packages that ship what they need, or install with scripts disabled.",
    attack=("T1105",))
R_EXFIL_HOST = rule(
    "PAH-C007", "Sends to a request-capture, tunnel or raw-IP endpoint",
    "webhook.site, pipedream, interactsh/oast, ngrok, trycloudflare, Discord/Telegram webhooks and raw IP addresses "
    "are where install-time beacons and stealers deliver data.",
    "Find out what is sent there and why.", attack=("T1567", "T1071"))
R_PERSIST = rule(
    "PAH-C008", "Sets up persistence",
    "Writing to shell profiles, LaunchAgents, scheduled tasks, Run keys, cron or the Startup folder makes code run "
    "again on every login or shell.", "Remove the entry and find out what installed it.",
    attack=("T1547", "T1546.004", "T1053"))
R_AGENT_CFG_WRITE = rule(
    "PAH-C009", "Writes AI-agent configuration",
    "Changing an agent's settings, hooks, MCP servers or instruction files makes the change persist into every later "
    "session; Shai-Hulud variants persisted through .claude/settings.json hooks, and a planted AGENTS.md made Codex "
    "rewrite its own machine-wide settings.",
    "Agent configuration should change only by your hand. Review the diff with `pah watch`.",
    attack=("T1546", "T1098"), owasp=("ASI06",),
    refs=("https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/",
          "https://socket.dev/glossary/shai-hulud"))
R_AGENT_BYPASS = rule(
    "PAH-C010", "Runs an AI agent with approvals switched off",
    "Malware has driven the agents already installed on a machine with their permission prompts disabled to search "
    "for secrets (Nx/s1ngularity, August 2025; 2,349 secrets from 1,079 machines).",
    "Never let a script start an agent with approvals disabled.",
    attack=("T1059", "T1552"), owasp=("ASI02", "ASI03"),
    refs=("https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package",))
R_AI_ADDRESSED = rule(
    "PAH-C011", "Text addressed to AI reviewers or agents",
    "Code has no reason to tell an AI scanner it is safe or to give an agent orders. Malicious packages now do both "
    "(Hades, Koi's 'gaslighting' npm package); a model reading them can be talked into a clean verdict.",
    "Treat the claim as a red flag, not as information. Review what the code does, with comments removed.",
    attack=("T1036",), owasp=("LLM01", "ASI01"),
    refs=("https://koi.ai/blog/two-years-17k-downloads-the-npm-malware-that-tried-to-gaslight-security-scanners",
          "https://research.jfrog.com/post/prompt-injection-vs-scanners/"))
R_OBFUSCATED = rule(
    "PAH-C012", "Obfuscated code",
    "Obfuscator-style identifiers, packers and long encoded arrays hide what code does from people and models; "
    "LLM detection drops sharply under encryption and heavy obfuscation.",
    "Do not run obfuscated code from a source you cannot verify.",
    attack=("T1027",), refs=("https://arxiv.org/abs/2605.06910",))
R_LOLBIN = rule(
    "PAH-C013", "Uses Windows system binaries to fetch or run remote code",
    "mshta, rundll32 over WebDAV, regsvr32 /i:http, certutil -urlcache and bitsadmin are the run-and-fetch steps of "
    "fake Claude Code installers and ClickFix lures (Amatera, ACRStealer).",
    "Do not run it.", attack=("T1218", "T1105"),
    refs=("https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware",
          "https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign"))
R_QUARANTINE = rule(
    "PAH-C014", "Removes macOS quarantine or runs a dropped binary",
    "xattr -c / removing com.apple.quarantine and running a file just written to /tmp is how fake installers get "
    "past Gatekeeper (AMOS, MacSync).", "Install signed, notarized software from the vendor instead.",
    attack=("T1553.001", "T1204"),
    refs=("https://www.huntress.com/blog/fake-claude-macsync",))
R_INLINE_NET = rule(
    "PAH-C015", "Inline interpreter code with network access",
    "python -c / node -e / powershell -c one-liners that open network connections hide a downloader in a command.",
    "Move the logic into a reviewed file, or remove it.", attack=("T1059", "T1105"))
R_CONDITIONAL = rule(
    "PAH-C016", "Malicious-looking code runs only under certain conditions",
    "Payloads that wait for CI, a date or one operating system stay quiet while reviewers look (NuGet logic bombs set "
    "for 2027-28, xz-utils).", "Read the conditional branch as if the condition were true.",
    attack=("T1480",), refs=("https://www.theregister.com/2025/11/07/cybercriminals_plant_destructive_time_bomb/",))
R_FAKE_PROMPT = rule(
    "PAH-C017", "Fake password prompt",
    "AppleScript dialogs asking for your password with hidden answers are how macOS stealers (AMOS) get your login "
    "password and keychain.", "Never type your password into a dialog a script opened.",
    attack=("T1056.002",))
R_REGISTRY = rule(
    "PAH-C018", "Points a package manager at a non-default registry or index",
    "Changing where packages come from is missed by almost every coding agent (Bagmar & Saraf, 2026), and lets an "
    "attacker serve any code under familiar names.",
    "Install from the default registry unless you know and trust the alternative.",
    attack=("T1195.001",), owasp=("LLM03", "ASI04"),
    refs=("https://arxiv.org/abs/2607.15143",))
R_URL_INSTALL = rule(
    "PAH-C019", "Installs from a URL, git repo or tarball",
    "Packages from a URL or git have no registry metadata, no integrity record and can change at any time "
    "(PhantomRaven hid its payloads this way).", "Install a published, pinned version instead.",
    attack=("T1195.001",), refs=("https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies",))
R_DESTRUCTIVE = rule(
    "PAH-C020", "Destructive command",
    "Deleting home directories, whole drives or disks is what wiper payloads do (Amazon Q v1.84.0 shipped a prompt "
    "asking the agent to do it).", "Do not run it.", attack=("T1485",),
    refs=("https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/",))
R_REVERSE_SHELL = rule(
    "PAH-C021", "Reverse shell", "Connecting a shell to a remote host gives an attacker interactive control.",
    "Do not run it.", attack=("T1059.004", "T1071"))
R_TAGS = rule(
    "PAH-T001", "Hidden text in Unicode tag characters",
    "Tag characters (U+E0000-E007F) render as nothing but models read them: ASCII smuggling and the rules-file "
    "backdoor hid text that coding agents follow this way.", "Delete the characters; read the decoded text shown here.",
    attack=("T1027",), owasp=("LLM01",),
    refs=("https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents",))
R_SELECTORS = rule(
    "PAH-T002", "Data hidden in Unicode variation selectors",
    "Runs of variation selectors encode bytes that editors do not show; GlassWorm decoded them into eval() in 151+ "
    "GitHub repositories in March 2026.", "Treat as malicious; the decoded bytes are shown in the evidence.",
    attack=("T1027",), refs=("https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode",))
R_BIDI = rule(
    "PAH-T003", "Bidirectional control characters in code",
    "Bidi controls make code display in a different order from how it runs (Trojan Source); invisible and bidi "
    "characters dropped GPT-4o's code comprehension from 100% to 0-2.3%.",
    "Remove them from code; they belong only in localized text.",
    attack=("T1027",), refs=("https://arxiv.org/html/2412.08098v3",))
R_ZERO_WIDTH = rule(
    "PAH-T004", "Zero-width or filler characters",
    "Zero-width and Hangul filler characters create look-alike identifiers and hide content.",
    "Remove them unless the file is localized text that needs them.", attack=("T1027",))
R_PAD_LINES = rule(
    "PAH-T005", "Content hidden after a long run of blank lines",
    "Trail of Bits got malicious skills past five scanners by putting ~100,000 newlines before the payload, because "
    "the scanners truncated large files.", "Read the end of the file; it is shown in the evidence.",
    attack=("T1027.001",),
    refs=("https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/",))
R_PAD_SPACES = rule(
    "PAH-T006", "Code pushed off-screen with spaces",
    "Hundreds of spaces before code put it beyond the right edge of editors, diffs and approval prompts "
    "(Gemini CLI approval-prompt bypass, 2025).", "Scroll right or view the file with whitespace shown.",
    attack=("T1027.001",), refs=("https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack",))
R_LONG_LINE = rule(
    "PAH-T007", "Very long line",
    "A single multi-megabyte line defeats reading and many LLM scanners (Miasma's payload was one 4.6 MB line; "
    "Cloudflare measured 17.6% LLM detection on files over 3 MB).", "Inspect it with a formatter before trusting it.",
    attack=("T1027",), refs=("https://www.cloudflare.com/cloudforce-one/research/adversarial-deception-a-study-of-indirect-prompt-code-injection/",))
R_HIDDEN_COMMENT = rule(
    "PAH-T008", "Instructions hidden in an HTML comment",
    "Markdown comments do not render, so a person reviewing the page does not see what an agent reads.",
    "Read the comment; remove instructions you did not write.", attack=("T1027",), owasp=("LLM01",))
R_TERMINAL = rule(
    "PAH-T009", "Terminal escape codes that hide text",
    "Escape sequences can conceal text, erase a line or move the cursor back over it, so a terminal shows a person "
    "something other than what an agent reads. Trail of Bits hid instructions in MCP tool descriptions this way.",
    "View the file with escape codes shown (cat -v) and remove what you did not write.", attack=("T1027", "T1036"),
    owasp=("LLM01",), refs=("https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/",))
R_DISGUISED_RUN = rule(
    "PAH-C022", "Runs a file disguised as a font, image or media file",
    "An interpreter has no reason to run a .ttf, .woff2, .png or .mp4. PolinRider (Oct 2026) amended and force-pushed "
    "commits in 188 GitHub repositories; their folder-open task ran a loader saved as fa-solid-300.ttf.",
    "Do not run it. A real font or image starts with its format's signature; open it in a hex viewer.",
    attack=("T1036.008", "T1059"), refs=("https://blog.gitguardian.com/ghostaction-x-polinrider/",))
R_DEAD_DROP = rule(
    "PAH-C023", "Gets its instructions from a dead drop and runs them",
    "Reading a blockchain transaction, a JSON-storage site, a calendar invite or a GitHub search result and executing "
    "what comes back lets an attacker swap the payload or the server address without publishing anything new. "
    "PolinRider took its server from an Ethereum transaction (Nov 2026); GlassWorm and SleepyDuck used contracts and "
    "Solana memos; Contagious Interview used JSON-storage sites.",
    "Treat it as malicious: legitimate code does not execute what it reads from a blockchain or a paste site.",
    attack=("T1102.001", "T1059"),
    refs=("https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages",
          "https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/"))
R_WORM = rule(
    "PAH-C024", "Publishes packages with your credentials",
    "Code that reads your npm or PyPI token, finds the packages you maintain and publishes new versions of them is how "
    "Shai-Hulud spread to hundreds of packages within hours.",
    "Do not install it. If it ran, revoke your registry tokens and check the latest versions of your packages.",
    attack=("T1195.002", "T1078"), refs=("https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",))
R_CI_BACKDOOR = rule(
    "PAH-C025", "Plants a CI backdoor",
    "Writing a workflow into .github/workflows or registering a self-hosted GitHub runner from code that runs on your "
    "machine gives the attacker a foothold in every repository your credentials reach (Shai-Hulud; Miasma).",
    "Do not run it; look for workflows and runners you did not add.", attack=("T1053", "T1098"),
    refs=("https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",))
R_DEADMAN = rule(
    "PAH-C026", "Wipes your files when its token stops working",
    "A loop that checks a stolen GitHub or npm token and deletes your home folder once the check fails punishes "
    "rotating credentials (gh-token-monitor in Mini Shai-Hulud and Miasma; the testmetest worm, Oct 2026).",
    "Remove its persistence first, then revoke the tokens.", attack=("T1485",),
    refs=("https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/",))
R_WALLET = rule(
    "PAH-C027", "Swaps crypto wallet addresses",
    "Replacing fetch, XMLHttpRequest or the wallet's request function and matching wallet-address formats is how the "
    "September 2025 chalk/debug compromise redirected payments in every page that bundled those packages.",
    "Do not ship or install it.", attack=("T1565.002",),
    refs=("https://cycode.com/blog/npm-debug-chalk-supply-chain-attack-the-complete-guide/",))
R_HIDDEN_PROC = rule(
    "PAH-C028", "Starts a hidden process while installing or opening",
    "A detached child with its output discarded, a process with no window, or `node -i` fed through a pipe keeps "
    "running after the install has finished and shows nothing (MALFEX and PolinRider, Oct to Nov 2026).",
    "Find out what the process runs before installing.", attack=("T1564.003", "T1059"),
    refs=("https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/",))
R_SWEEP = rule(
    "PAH-C029", "Hunts for secrets while installing or opening",
    "Running TruffleHog or Gitleaks over your files, asking the cloud metadata service for credentials or listing a "
    "secrets manager from an install script is credential harvesting (Shai-Hulud ran TruffleHog on the home folder).",
    "Do not install it; rotate cloud and CI credentials if it ran.", attack=("T1552", "T1552.005"),
    refs=("https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",))
R_LOG_WIPE = rule(
    "PAH-C030", "Deletes or silences logs",
    "Removing audit logs, system logs or shell history, or stopping the services that write them, hides what was "
    "done; it is the clean-up step after a break-in, and an agent has no reason to do it.",
    "Do not run it. If it already ran, assume the logs that would show what happened are gone.",
    attack=("T1070.002", "T1070.003", "T1562.002"))
R_SELF_PUBLISH = rule(
    "PAH-C031", "Publishes packages from its own code",
    "Code that rewrites package.json and runs npm publish spreads through the registry under your npm login: the "
    "IndonesianFoods spam worm (Nov 2025) published tens of thousands of packages that way, renaming itself each "
    "time, and Shai-Hulud republished infected versions of its victims' own packages.",
    "Do not run it where npm credentials are available; check `npm whoami` and your recent publishes.",
    attack=("T1195.002", "T1584"))
R_ATTACK_TOOL = rule(
    "PAH-C032", "Fetches or runs an attack tool",
    "Credential dumpers and privilege-escalation scanners (mimikatz, LaZagne, linpeas, pspy, Rubeus, SharpHound) "
    "have no place in a package's install step or among the commands an agent is asked to run.",
    "Do not run it. If it already ran, treat the machine's credentials as exposed.", attack=("T1003", "T1068", "T1087"))
