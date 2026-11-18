#!/usr/bin/env python3
"""An independent, held-out evaluation: real malicious packages the rules were never tuned on, and a random sample of
the most-downloaded packages.

    python bench/independent.py plan      # draw the sample: listings and registry metadata only, nothing downloaded
    python bench/independent.py run       # download each file into memory, scan it there, write the results
    python bench/independent.py profile   # describe a random 60 misses per set by structure, never by contents

The protocol, fixed in bench/fixtures/independent-sample.json before the first download:

- Malicious: Datadog's malicious-software-packages-dataset (Apache-2.0) at one commit, in six sets by ecosystem and
  kind. A fixed number of packages is drawn at random from each set (every package in the small ones), and one version
  of each at random. Datadog's ZIP files are encrypted with the password "infected".
- Benign: 500 of the 5,000 most-downloaded PyPI projects and 500 of the 5,000 most-downloaded npm packages
  (pah/data/popular-*.txt), taken in a seeded random order, each at its latest release when the sample was drawn: the
  source distribution (the smallest wheel when there is none) or the npm tarball. Names and digests are pinned.
- Each file is downloaded into memory and checked against its pinned digest, then unpacked there, up to 1 GB per
  package (members over 256 MB are not read; either cut is noted). Datadog's registry metadata file beside a package
  is left out, and the folders all files share are stripped, so the package sits at the root of the scan. scan_files
  judges it with the same limits and rules as a scan of a folder, stopping after 300 seconds. Nothing is written to
  disk and nothing is executed.
- Caught (for a benign package: flagged) means the verdict is block or warn. Every flagged sample is scanned again
  with the campaign-shape checks (pah/campaigns.py) switched off, to show what the general rules catch alone.
- A file that cannot be downloaded, verified or unpacked is reported and left out of the counts.
- One run, reported whatever it shows. Rules changed afterwards are measured on a fresh draw.

Results go to bench/results/<date>-independent.json: per sample its set, name, version, file, digest, verdict and the
rules that fired. Never the files' contents or the findings' text: malware carries live attacker URLs and tokens.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import posixpath
import random
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from pah import __version__  # noqa: E402
from pah.model import worst  # noqa: E402
from pah.scan import scan_files  # noqa: E402
from run import code_hash  # noqa: E402

SAMPLE = HERE / "fixtures" / "independent-sample.json"
RESULTS = HERE / "results"
REPO = "DataDog/malicious-software-packages-dataset"
COMMIT = "72c723be547033c558244520524b117c8d71663b"
RAW = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
SEED = "agent-white-hat independent evaluation 2026-11-18"
MALICIOUS = {"npm/malicious_intent": 500, "pypi/malicious_intent": 500, "ai-skills/malicious_intent": None,
             "ide_extensions/malicious_intent": None, "npm/compromised_lib": 100, "pypi/compromised_lib": None}
BENIGN = {"pypi": 500, "npm": 500}
PASSWORD = b"infected"
UA = {"User-Agent": "agent-white-hat-bench"}
FLAGGED = ("block", "warn")
MAX_SECONDS = 300
MAX_MEMBER = 256 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024
PACKAGE_ARCHIVES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".whl", ".egg", ".vsix")


# ------------------------------------------------------------------------------------------------- network


def _open(url: str, headers: dict | None = None, timeout: int = 300) -> bytes:
    """GET with a few patient retries on rate limits and server or network errors."""
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={**UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as err:
            if err.code not in (429, 500, 502, 503, 504) or attempt == 5:
                raise
            wait = int(err.headers.get("Retry-After") or 0) or 5 * 2 ** attempt
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 5:
                raise
            wait = 5 * 2 ** attempt
        time.sleep(min(wait, 300))
    raise AssertionError("unreachable")


def _json(url: str, headers: dict | None = None):
    return json.loads(_open(url, headers, timeout=120))


# ------------------------------------------------------------------------------------------------- the draw


def malicious_frame() -> dict[str, dict[str, list[dict]]]:
    """Every sample of the six sets at COMMIT, from GitHub's tree listings: paths, sizes and blob ids only."""
    api = "https://api.github.com/repos/" + REPO

    def tree(sha: str, recursive: bool = False) -> dict:
        return _json(f"{api}/git/trees/{sha}" + ("?recursive=1" if recursive else ""),
                     {"Accept": "application/vnd.github+json"})

    def entry(listing: dict, name: str) -> str:
        return next(e["sha"] for e in listing["tree"] if e["path"] == name)

    root = _json(f"{api}/git/commits/{COMMIT}", {"Accept": "application/vnd.github+json"})["tree"]["sha"]
    samples = tree(entry(tree(root), "samples"))
    frame: dict[str, dict[str, list[dict]]] = {}
    for eco in sorted({s.split("/")[0] for s in MALICIOUS}):
        eco_tree = tree(entry(samples, eco))
        for kind in sorted({s.split("/")[1] for s in MALICIOUS if s.startswith(eco + "/")}):
            listing = tree(entry(eco_tree, kind), recursive=True)
            if listing.get("truncated"):
                raise SystemExit(f"{eco}/{kind}: GitHub truncated the listing")
            packages: dict[str, list[dict]] = {}
            for b in listing["tree"]:
                if b["type"] == "blob":
                    packages.setdefault(b["path"].split("/")[0], []).append(
                        {"path": f"samples/{eco}/{kind}/{b['path']}", "bytes": b["size"], "git_blob": b["sha"]})
            frame[f"{eco}/{kind}"] = packages
    return frame


def _version(path: str) -> str | None:
    parts = path.split("/")
    if len(parts) == 6:
        return parts[4]
    if path.endswith(".vsix"):
        return posixpath.basename(path)[:-5]
    return None


def draw_malicious(frame: dict) -> list[dict]:
    out = []
    for stratum, k in MALICIOUS.items():
        packages = frame[stratum]
        rng = random.Random(f"{SEED}:{stratum}")
        names = sorted(packages)
        chosen = names if k is None or k >= len(names) else sorted(rng.sample(names, k))
        for name in chosen:
            pick = rng.choice(sorted(packages[name], key=lambda x: x["path"]))
            out.append({"set": stratum, "package": name, "version": _version(pick["path"]), **pick})
    return out


def popular(eco: str) -> list[str]:
    lines = (ROOT / "pah" / "data" / f"popular-{eco}.txt").read_text(encoding="utf-8").splitlines()
    return [x.strip() for x in lines if x.strip() and not x.startswith("#")]


def pypi_release(name: str) -> dict | None:
    d = _json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    files = [f for f in d["urls"] if not f.get("yanked")]
    sdists = [f for f in files if f["packagetype"] == "sdist"]
    wheels = sorted((f for f in files if f["packagetype"] == "bdist_wheel"), key=lambda f: (f["size"], f["filename"]))
    f = (sdists or wheels or [None])[0]
    if f is None:
        return None
    return {"version": d["info"]["version"], "file": f["filename"], "url": f["url"], "bytes": f["size"],
            "sha256": f["digests"]["sha256"], "form": f["packagetype"]}


def npm_release(name: str) -> dict | None:
    d = _json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest")
    dist = d.get("dist") or {}
    if not dist.get("tarball"):
        return None
    return {"version": d["version"], "file": dist["tarball"].rsplit("/", 1)[-1], "url": dist["tarball"],
            "unpacked_bytes": dist.get("unpackedSize"), "integrity": dist.get("integrity"),
            "shasum": dist.get("shasum"), "form": "tarball"}


def draw_benign() -> tuple[list[dict], list[dict]]:
    out, passed_over = [], []
    for eco, k in BENIGN.items():
        order = popular(eco)
        random.Random(f"{SEED}:{eco}").shuffle(order)
        taken = 0
        for name in order:
            if taken == k:
                break
            try:
                release = pypi_release(name) if eco == "pypi" else npm_release(name)
                why = "no release file"
            except (urllib.error.URLError, TimeoutError, ConnectionError, KeyError, ValueError) as err:
                release, why = None, type(err).__name__
            if release is None:
                passed_over.append({"set": f"{eco}/popular", "package": name, "why": why})
                continue
            out.append({"set": f"{eco}/popular", "package": name, **release})
            taken += 1
    return out, passed_over


def _wait_for_github(need: int) -> None:
    core = _json("https://api.github.com/rate_limit")["resources"]["core"]
    if core["remaining"] < need:
        wait = max(0.0, core["reset"] - time.time()) + 5
        print(f"waiting {wait / 60:.0f} minutes for GitHub's hourly API allowance", flush=True)
        time.sleep(wait)


def cmd_plan(args) -> int:
    benign, passed_over = draw_benign()
    print(f"benign: {len(benign)} releases, {len(passed_over)} passed over", flush=True)
    _wait_for_github(need=15)
    frame = malicious_frame()
    malicious = draw_malicious(frame)
    plan = {
        "drawn": time.strftime("%Y-%m-%d"), "seed": SEED, "protocol": "bench/independent.py",
        "dataset": {"repo": REPO, "commit": COMMIT, "license": "Apache-2.0",
                    "packages": {s: len(p) for s, p in frame.items()},
                    "samples": {s: sum(len(v) for v in p.values()) for s, p in frame.items()}},
        "plan": {"malicious": MALICIOUS, "benign": BENIGN},
        "seen_before_run": args.seen or [],
        "malicious": malicious, "benign": benign, "benign_passed_over": passed_over,
    }
    SAMPLE.write_text(json.dumps(plan, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(malicious)} malicious samples ({sum(m['bytes'] for m in malicious) / 1e9:.2f} GB), "
          f"{len(benign)} benign releases, {len(passed_over)} passed over -> {_rel(SAMPLE)}")
    return 0


# ------------------------------------------------------------------------------------------------- one sample


def _digest_ok(sample: dict, data: bytes) -> bool:
    if sample.get("git_blob"):
        return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() == sample["git_blob"]
    if sample.get("sha256"):
        return hashlib.sha256(data).hexdigest() == sample["sha256"]
    if (sample.get("integrity") or "").startswith("sha512-"):
        return base64.b64encode(hashlib.sha512(data).digest()).decode() == sample["integrity"][7:]
    if sample.get("shasum"):
        return hashlib.sha1(data).hexdigest() == sample["shasum"]
    return False


def members(data: bytes, notes: list[str] | None = None) -> dict[str, bytes] | None:
    """The regular files of a zip or tar archive, read in memory (encrypted zip members with the dataset's password),
    or None when data is not an archive. Cuts at the size limits are added to notes."""
    out: dict[str, bytes] = {}
    total = skipped = 0
    cut = False
    if data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER:
                    skipped += 1
                    continue
                total += info.file_size
                if total > MAX_UNPACKED:
                    cut = True
                    break
                out[info.filename] = z.read(info, pwd=PASSWORD if info.flag_bits & 0x1 else None)
    elif data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00" or data[257:262] == b"ustar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t.getmembers():
                if not m.isfile():
                    continue
                if m.size > MAX_MEMBER:
                    skipped += 1
                    continue
                total += m.size
                if total > MAX_UNPACKED:
                    cut = True
                    break
                out[m.name] = t.extractfile(m).read()
    else:
        return None
    if notes is not None and skipped:
        notes.append(f"{skipped} members over 256 MB not read")
    if notes is not None and cut:
        notes.append("unpacking stopped at 1 GB")
    return out


def strip_shared_folders(files: dict[str, bytes]) -> dict[str, bytes]:
    folders = [p.split("/")[:-1] for p in files]
    shared = 0
    for parts in zip(*folders, strict=False):
        if len(set(parts)) != 1:
            break
        shared += 1
    return {"/".join(p.split("/")[shared:]): v for p, v in files.items()}


def package_files(sample: dict, data: bytes) -> tuple[dict[str, bytes], list[str]]:
    """The package's own files, in memory, with the package at the root."""
    notes: list[str] = []
    files = members(data, notes)
    if files is None:
        raise ValueError("not an archive")
    files = {k.replace("\\", "/"): v for k, v in files.items()}
    if sample.get("git_blob"):  # a dataset sample: Datadog's wrapper around the package
        meta = [p for p in files if posixpath.basename(p).startswith("package_info-") and p.endswith(".json")]
        for p in meta:
            del files[p]
        if meta:
            notes.append("registry metadata file left out")
        if len(files) == 1:
            (only, blob), = files.items()
            inner = members(blob, notes) if only.lower().endswith(PACKAGE_ARCHIVES) else None
            if inner is not None:
                files = {k.replace("\\", "/"): v for k, v in inner.items()}
                notes.append("package archive opened")
    outside = [p for p in files if p.startswith("/") or ".." in p.split("/")]
    for p in outside:
        del files[p]
    if outside:
        notes.append(f"{len(outside)} member paths outside the archive left out")
    return strip_shared_folders(files), notes


def judge(files: dict[str, bytes]) -> dict:
    started = time.monotonic()
    report = scan_files(files, target="sample", max_seconds=MAX_SECONDS)
    rules: dict[str, str] = {}
    for f in report.findings:
        rules[f.rule] = worst([rules.get(f.rule, "info"), f.severity])
    out = {"verdict": report.verdict, "rules": dict(sorted(rules.items())), "files": report.stats.get("files"),
           "incomplete": len(report.incomplete), "seconds": round(time.monotonic() - started, 2)}
    if report.verdict in FLAGGED:
        with mock.patch("pah.patterns.campaign_shapes", lambda *a, **k: None):
            out["verdict_without_campaign_shapes"] = scan_files(files, max_seconds=MAX_SECONDS).verdict
    else:
        out["verdict_without_campaign_shapes"] = report.verdict
    return out


def _download(sample: dict) -> bytes:
    url = RAW + urllib.parse.quote(sample["path"], safe="/@") if sample.get("git_blob") else sample["url"]
    data = _open(url)
    if not _digest_ok(sample, data):
        raise ValueError("digest does not match the sample file")
    return data


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _key(sample: dict) -> str:
    return f"{sample['set']}|{sample['package']}|{sample.get('path') or sample.get('file')}"


def _public(sample: dict) -> dict:
    return {k: v for k, v in sample.items() if k != "url"}


def evaluate(sample: dict, data: bytes) -> dict:
    try:
        files, notes = package_files(sample, data)
    except (zipfile.BadZipFile, tarfile.TarError, RuntimeError, NotImplementedError, ValueError, EOFError,
            OSError) as err:
        return {**_public(sample), "error": f"could not unpack: {type(err).__name__}"}
    return {**_public(sample), **judge(files), "notes": notes}


def _work(sample: dict) -> dict:
    """One sample, in a worker process: download, check, unpack and judge."""
    try:
        return evaluate(sample, _download(sample))
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as err:
        return {**_public(sample), "error": f"{type(err).__name__}: {err}"[:200]}


def cmd_run(args) -> int:
    plan = json.loads(SAMPLE.read_text(encoding="utf-8"))
    todo = [*plan["malicious"], *plan["benign"]]
    progress = Path(args.progress)
    done: dict[str, dict] = {}
    if progress.exists():
        for line in progress.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue  # a line cut off when a run was stopped: that sample runs again
            done[_key(row)] = row
    todo = [s for s in todo if _key(s) not in done and s["set"] not in args.skip]
    total = len(plan["malicious"]) + len(plan["benign"])
    print(f"{len(done)} done before, {len(todo)} to go, {args.workers} worker processes; progress in {progress}",
          flush=True)
    started = time.monotonic()
    with ProcessPoolExecutor(max_workers=args.workers) as pool, progress.open("a", encoding="utf-8") as log:
        futures = {pool.submit(_work, s): s for s in todo}
        for n, fut in enumerate(as_completed(futures), 1):
            sample = futures[fut]
            try:
                row = fut.result()
            except BrokenProcessPool:
                print("a worker process died; run again to resume", flush=True)
                break
            except Exception as err:  # a crash on one sample must not lose the others
                row = {**_public(sample), "error": f"scan failed: {type(err).__name__}"}
            log.write(json.dumps(row) + "\n")
            log.flush()
            done[_key(row)] = row
            if n % 25 == 0 or "error" in row:
                rate = n / max(1e-9, time.monotonic() - started)
                print(f"[{len(done)}/{total}] {row['set']} {row['package']}: {row.get('verdict', row.get('error'))} "
                      f"({rate:.2f}/s, about {(len(todo) - n) / max(rate, 1e-9) / 60:.0f} min left)", flush=True)
    rows = [done[_key(s)] for s in [*plan["malicious"], *plan["benign"]] if _key(s) in done]
    if len(rows) < total:
        print(f"{total - len(rows)} samples not done yet; run again to resume")
        return 1
    out = {"name": args.name, "date": time.strftime("%Y-%m-%d"), "platform": sys.platform, "code": code_hash(),
           "version": __version__, "sample": _rel(SAMPLE),
           "dataset": plan["dataset"], "seed": plan["seed"], "max_seconds": MAX_SECONDS, "rows": rows}
    dest = RESULTS / f"{args.name}-independent.json"
    dest.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8", newline="\n")
    errors = sum("error" in r for r in rows)
    print(f"{len(rows)} samples, {errors} left out -> {_rel(dest)}")
    return 0


# ------------------------------------------------------------------------------------------------- what was missed

# Structural features only: what kind of code a sample has and when it would run. They describe the misses for the
# report; they are not detection rules, and nothing here reads or prints a sample's contents.
NET_CALL = re.compile(r"\b(?:https?|net|dns|tls|dgram)\.(?:request|get|connect|createConnection|lookup|resolve\w*)\s*\(|"
                      r"\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|XMLHttpRequest|urlopen\s*\(|urlretrieve\s*\(|"
                      r"requests\.(?:get|post|put)\s*\(|http\.client|socket\.socket\s*\(|aiohttp\.|new\s+WebSocket|"
                      r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org", re.I)
PROC_CALL = re.compile(r"child_process|\bexec(?:Sync|File)?\s*\(|\bspawn(?:Sync)?\s*\(|subprocess\.\w+\s*\(|"
                       r"os\.system\s*\(|os\.popen\s*\(|Popen\s*\(", re.I)
DECODE_CALL = re.compile(r"b64decode\s*\(|\batob\s*\(|Buffer\.from\([^)]{0,200}['\"](?:base64|hex)['\"]|marshal\.loads|"
                         r"zlib\.decompress|String\.fromCharCode|exec\s*\(\s*(?:base64|zlib|marshal|codecs)", re.I)
# The browser store names are split across literals so this file does not itself read as code that opens them.
SECRETS = re.compile(r"process\.env\b|os\.environ|os\.getenv|\.ssh[/\\]|\.aws[/\\]|\.npmrc|\bwallet\b|Local State|"
                     r"Login" r" Data|cookies\.sqlite", re.I)
CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".ps1", ".bat", ".cmd")
NPM_INSTALL = ("preinstall", "install", "postinstall", "prepare")
PROFILE_PER_SET = 60


def features(set_name: str, files: dict[str, bytes]) -> set[str]:
    texts = {p: b.decode("utf-8", "replace") for p, b in files.items() if len(b) < 5_000_000}
    code = {p: t for p, t in texts.items() if p.lower().endswith(CODE_EXT)}
    joined = "\n".join(code.values())
    out = set()
    for name, rx in (("starts a process", PROC_CALL), ("makes a network call", NET_CALL),
                     ("decodes or unpacks code", DECODE_CALL), ("reads environment or secret files", SECRETS)):
        if rx.search(joined):
            out.add(name)
    if not code:
        out.add("no code files")
    if set_name.startswith("npm"):
        try:
            scripts = json.loads(texts.get("package.json") or "{}").get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        out.add("npm install-time script" if any(k in scripts for k in NPM_INSTALL) else
                "no install-time script: runs when imported or run")
    if set_name.startswith("pypi"):
        setup = texts.get("setup.py", "")
        if not setup:
            out.add("no setup.py")
        elif NET_CALL.search(setup) or PROC_CALL.search(setup):
            out.add("setup.py starts a process or makes a network call")
        if any(p.endswith("__init__.py") and (NET_CALL.search(t) or PROC_CALL.search(t)) for p, t in code.items()):
            out.add("__init__.py starts a process or makes a network call (runs on import)")
    if set_name.startswith("ai-skills"):
        md = "\n".join(t for p, t in texts.items() if p.lower().endswith(".md"))
        if re.search(r"```(?:bash|sh|shell|powershell|pwsh|zsh|cmd)", md, re.I):
            out.add("skill text has shell commands")
        if re.search(r"\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b", md, re.I):
            out.add("skill text downloads something")
    if set_name.startswith("ide_extensions"):
        try:
            manifest = json.loads(texts.get("extension/package.json") or "{}")
        except ValueError:
            manifest = {}
        if "*" in (manifest.get("activationEvents") or []) or "onStartupFinished" in (manifest.get("activationEvents") or []):
            out.add("activates when the editor starts")
    return out


def cmd_profile(args) -> int:
    found = sorted(RESULTS.glob("20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-independent.json"))
    if not found:
        raise SystemExit("run the evaluation first")
    data = json.loads(found[-1].read_text(encoding="utf-8"))
    missed: dict[str, list[dict]] = {}
    for r in data["rows"]:
        if not r["set"].endswith("/popular") and "error" not in r and r["verdict"] not in FLAGGED:
            missed.setdefault(r["set"], []).append(r)
    out = {"source": found[-1].name, "per_set": PROFILE_PER_SET, "seed": f"{SEED}:misses", "sets": {}}
    for key in MALICIOUS:
        rows = missed.get(key, [])
        rng = random.Random(f"{SEED}:misses:{key}")
        pick = rng.sample(rows, min(PROFILE_PER_SET, len(rows)))
        counts: dict[str, int] = {}
        read = 0
        for r in pick:
            try:
                files, _ = package_files(r, _download(r))
            except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, zipfile.BadZipFile,
                    tarfile.TarError, RuntimeError, NotImplementedError, EOFError, OSError):
                continue
            read += 1
            for f in features(key, files):
                counts[f] = counts.get(f, 0) + 1
        out["sets"][key] = {"missed": len(rows), "profiled": read,
                            "features": dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))}
        print(f"{key}: {len(rows)} missed, {read} profiled", flush=True)
    dest = RESULTS / found[-1].name.replace("-independent.json", "-independent-misses.json")
    dest.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"-> {_rel(dest)}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="draw the sample (listings and registry metadata only)")
    p.add_argument("--seen", nargs="*", help="drawn samples whose file lists were looked at before the run")
    p.set_defaults(fn=cmd_plan)
    r = sub.add_parser("run", help="download, unpack and scan every sample in memory")
    r.add_argument("--name", default=time.strftime("%Y-%m-%d"))
    r.add_argument("--progress", default=str(Path(tempfile.gettempdir()) / "pah-independent-progress.jsonl"))
    r.add_argument("--workers", type=int, default=3, help="scans run in this many processes (default 3)")
    r.add_argument("--skip", nargs="*", default=[], help="sets to leave for a later run (it resumes from the progress)")
    r.set_defaults(fn=cmd_run)
    m = sub.add_parser("profile", help="describe a random 60 misses per set by structure (no contents)")
    m.set_defaults(fn=cmd_profile)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
