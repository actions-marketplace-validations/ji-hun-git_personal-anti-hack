"""Where a URL points: official installers and registries, reference hosts, look-alikes of AI brands and
user-content hosts. Downloads, registries and destinations of data are judged by it."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .indicators import EXFIL_HOSTS, is_private_ip


OFFICIAL_INSTALLERS = {
    "sh.rustup.rs", "static.rust-lang.org", "astral.sh", "bun.sh", "deno.land", "install.python-poetry.org",
    "get.docker.com", "claude.ai", "downloads.claude.ai", "sdk.cloud.google.com", "ollama.com", "get.pnpm.io",
    "fnm.vercel.app", "starship.rs", "pyenv.run", "install.determinate.systems", "nixos.org", "get.volta.sh",
    "tailscale.com", "get.k3s.io", "bootstrap.pypa.io", "cli.github.com", "foundry.paradigm.xyz", "sh.flox.dev",
    "opencode.ai", "cursor.com", "app.warp.dev", "mise.run", "pkgx.sh", "install.duckdb.org", "get.helm.sh",
    "dot.net", "dotnet.microsoft.com", "aka.ms", "community.chocolatey.org", "get.scoop.sh", "chocolatey.org",
    "getcomposer.org", "install.ohmyz.sh", "get.sdkman.io", "get.rvm.io", "deno.com", "bun.com", "deb.nodesource.com",
    "cpanmin.us", "install.perlbrew.pl", "get.haskellstack.org", "get-ghcup.haskell.org",
    "rpm.nodesource.com", "packages.microsoft.com", "download.docker.com", "apt.releases.hashicorp.com", "dl.google.com",
    "install.julialang.org", "sh.vector.dev", "get.jetify.com", "install.lunarvim.org", "repo.yarnpkg.com", "yarnpkg.com",
    "nodejs.org", "go.dev", "golang.org", "www.python.org", "rustup.rs", "brew.sh",
}


# Hosts that appear in license headers, schemas and documentation links. They are not destinations for data and not
# sources of install scripts anyone pipes into a shell, so they neither raise nor lower a finding.
REFERENCE_HOSTS = {
    "apache.org", "opensource.org", "gnu.org", "fsf.org", "creativecommons.org", "w3.org", "json-schema.org",
    "schema.org", "spdx.org", "ietf.org", "rfc-editor.org", "unicode.org", "semver.org", "keepachangelog.com",
    "conventionalcommits.org", "wikipedia.org", "shields.io", "example.com", "example.org", "example.net",
    "readthedocs.io", "readthedocs.org", "mit-license.org", "choosealicense.com", "contributor-covenant.org",
    "editorconfig.org", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "stackoverflow.com", "mozilla.org",
    "osv.dev", "deps.dev", "nvd.nist.gov", "cve.org", "mitre.org", "owasp.org", "first.org", "sigstore.dev",
}


OFFICIAL_RAW_PREFIXES = ("/Homebrew/", "/nvm-sh/nvm/", "/ohmyzsh/ohmyzsh/", "/pyenv/pyenv-installer/",
                         "/rbenv/rbenv-installer/", "/creationix/nvm/", "/helm/helm/", "/golangci/golangci-lint/",
                         "/cli/cli/", "/oven-sh/bun/", "/denoland/", "/astral-sh/", "/nodejs/", "/python/", "/rust-lang/",
                         "/golang/", "/microsoft/", "/anthropics/", "/openai/", "/google-gemini/", "/docker/",
                         "/kubernetes/", "/hashicorp/", "/aws/", "/Azure/", "/github/", "/actions/", "/pnpm/", "/yarnpkg/",
                         "/npm/", "/pypa/", "/volta-cli/", "/Schniz/fnm/", "/jdx/mise/", "/starship/starship/")


OFFICIAL_REGISTRIES = {
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "npm.pkg.github.com", "pypi.org",
    "files.pythonhosted.org", "pypi.python.org", "upload.pypi.org", "download.pytorch.org", "pypi.nvidia.com",
    "crates.io", "index.crates.io", "static.crates.io", "rubygems.org", "proxy.golang.org", "repo.maven.apache.org",
    "repo1.maven.org", "plugins.gradle.org", "services.gradle.org", "nuget.org", "api.nuget.org", "jsr.io",
}


BRANDS = ("claude", "anthropic", "openai", "chatgpt", "codex", "cursor", "gemini", "copilot", "github", "ollama", "npmjs",
          "pypi", "python", "rustup", "docker", "homebrew", "nodejs", "microsoft", "apple", "deepseek", "llama", "huggingface",
          "windsurf", "openclaw", "vscode")


BRAND_DOMAINS = {
    "claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com", "cursor.com", "cursor.sh", "google.com",
    "googleapis.com", "github.com", "githubusercontent.com", "githubassets.com", "ollama.com", "ollama.ai", "npmjs.org",
    "npmjs.com", "pypi.org", "pythonhosted.org", "python.org", "rust-lang.org", "rustup.rs", "docker.com", "docker.io",
    "brew.sh", "nodejs.org", "microsoft.com", "visualstudio.com", "apple.com", "deepseek.com", "llama.com", "meta.com",
    "huggingface.co", "windsurf.com", "codeium.com", "openclaw.ai", "x.ai", "mozilla.org", "gemini.google.com",
    "meta.ai", "groq.com", "mistral.ai", "openrouter.ai", "cohere.com", "together.ai", "perplexity.ai",
}


URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`)\]}|]+", re.I)


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "go") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def urls(text: str) -> list[str]:
    return URL.findall(text)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


BRAND_TLDS = (".google", ".microsoft", ".apple", ".aws", ".amazon", ".azure", ".android", ".chrome", ".youtube",
              ".gle", ".goog", ".bing", ".xbox", ".windows", ".office")


USER_CONTENT_HOSTS = {"github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com",
                      "objects.githubusercontent.com", "codeload.github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}


def classify_host(url: str) -> str:
    """official | reference | lookalike | raw-ip | plain-http | unknown

    Anyone can publish under github.com/<user> or raw.githubusercontent.com, so those count as official only under
    the vendors' own paths (Homebrew/install, nvm-sh/nvm, ...)."""
    host = host_of(url)
    if not host:
        return "unknown"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return "official" if is_private_ip(host) and host.startswith("127.") else "raw-ip"
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host, re.I):
        return "raw-ip"  # an IPv4 address written as one number or in hex or octal: only used to disguise it
    if host in ("localhost", "::1") or host.endswith(".localhost"):
        return "official"
    path = urlsplit(url).path
    if host in OFFICIAL_INSTALLERS or host in OFFICIAL_REGISTRIES:
        return "official"
    if host in USER_CONTENT_HOSTS:
        return "official" if path.startswith(OFFICIAL_RAW_PREFIXES) else "unknown"
    reg = registrable(host)
    if reg in REFERENCE_HOSTS or host in REFERENCE_HOSTS:
        return "reference"
    if host.endswith(BRAND_TLDS):
        return "official"  # top-level domains that only their owner can register under (antigravity.google)
    if reg in BRAND_DOMAINS or host in BRAND_DOMAINS:
        return "official" if not host.endswith("github.io") else "unknown"
    if any(b in host for b in BRANDS):
        return "lookalike"
    if url.lower().startswith("http://"):
        return "plain-http"
    return "unknown"


def host_kind(window: str) -> str:
    """none | official | unknown | plain-http | risky, for the URLs in a command or line."""
    found = urls(window)
    if not found:
        return "none"
    kinds = {classify_host(u) for u in found}
    if kinds & {"lookalike", "raw-ip"} or EXFIL_HOSTS.search(window):
        return "risky"
    if "plain-http" in kinds:
        return "plain-http"
    if kinds <= {"official", "reference"}:
        return "official"
    return "unknown"
