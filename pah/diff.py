"""Compare two versions of a package, repository, extension or skill, and report what the newer one does that the older
one did not.

Two research methods meet here. Chainguard's malcontent compares the capabilities of two releases: a compromised update
shows up as network, credential or process access in code that did not have it, or as a new install hook or a new
dependency in a patch release. LastPyMile (Vu et al., ESEC/FSE 2021), and Google's OSS Rebuild after it, compare a
published package with its source repository: code that exists only in the package, or differs from the source, is
where build-time backdoors such as xz-utils' hid.

OLD and NEW can each be a folder or an archive (.tgz, .whl, .zip, .vsix, .crate, .gem), so `pah diff` covers two
releases, and with --source a checkout of the source at a tag against the package published from it. The verdict counts
only what is new: findings the old version did not have (by rule, file and line content, so moved lines stay quiet),
capabilities gained by code that runs on its own (PAH-D001), and with --source, code that runs on its own and is not
in the source (PAH-D002).
"""
from __future__ import annotations

import hashlib
import posixpath
import re
import time
from pathlib import Path

from .capabilities import CAPABILITIES, RISKY, dependencies, of_file
from .model import Finding, Report, rule
from .scan import _analyze, collect

REFS = ("https://github.com/chainguard-dev/malcontent",
        "https://2021.esec-fse.org/details/fse-2021-papers/61/LastPyMile-identifying-the-discrepancy-between-sources-"
        "and-packages", "https://blog.google/security/introducing-oss-rebuild-open-source/")
R_GAINED = rule(
    "PAH-D001", "New version gives code that runs on its own a new capability",
    "Code that runs at install, at build or when a folder opens gained something the previous version could not do: "
    "an install hook, network access, credential reads, starting programs, decoding hidden data. Compromised releases "
    "look like this: ChainDrop and Shai-Hulud added a preinstall script that downloads a runtime and steals tokens, and "
    "arrayref 0.3.10 added a dependency whose build script fetched a payload.",
    "Read the new code before installing the update, and compare the package with its source at the same tag "
    "(pah diff --source <checkout> <package>). Stay on the previous version until the change is explained.",
    attack=("T1195.002",), owasp=("LLM03",), refs=REFS)
R_NOT_IN_SOURCE = rule(
    "PAH-D002", "Package has code that runs on its own and is not in its source",
    "The published package contains, or changes, a file that runs at install, at build or at every interpreter start, "
    "and the source repository at the same tag does not have it. Backdoors added at release time live there: the "
    "xz-utils build script, LiteLLM's .pth files, the swapped @subql/common archive.",
    "Do not install this version. Report it to the maintainers and the registry; use the previous release.",
    attack=("T1195.002",), owasp=("LLM03",), refs=REFS)

# Files packaging tools write, which never exist in a source tree and change with every release.
GENERATED = re.compile(r"(?:^|/)(?:[^/]+\.dist-info|[^/]+\.egg-info|__pycache__|\.git)/|(?:^|/)(?:PKG-INFO|RECORD|WHEEL|"
                       r"METADATA|INSTALLER|REQUESTED|\.cargo_vcs_info\.json|Cargo\.toml\.orig|\.npmignore)$")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _names(rels: list[str], target_is_file: bool) -> dict[str, str]:
    """Each path as the other side would name it: without the archive given as the target and without a single top
    folder (package/ in npm tarballs, name-1.2.3/ in sdists), so a folder and an archive of it line up."""
    names = {}
    for rel in rels:
        if target_is_file:
            if "!/" not in rel:
                continue  # the archive itself
            names[rel] = rel.split("!/", 1)[1]
        else:
            names[rel] = rel
    firsts = {p.split("/", 1)[0] for p in names.values()}
    if len(firsts) == 1 and names and all("/" in p for p in names.values()):
        names = {rel: p.split("/", 1)[1] for rel, p in names.items()}
    return names


def _key(f: Finding, name: dict[str, str]) -> tuple[str, str, str]:
    evidence = " ".join((f.evidence or "").split()) or "".join(c for c in f.message if not c.isdigit())
    return f.rule, name.get(f.path, f.path), evidence


def diff(old: str, new: str, *, source: bool = False, max_seconds: float | None = None) -> Report:
    """What NEW does that OLD did not. With source=True, OLD is the source and NEW the package built from it.
    Nothing in either is executed."""
    started = time.monotonic()
    sides = []
    for target in (old, new):
        state = collect(target, started=started, max_seconds=max_seconds)
        report = _analyze(state, str(target), started, max_seconds)
        names = _names(list(state.files), Path(str(target)).expanduser().is_file())
        files = {names[rel]: f for rel, f in state.files.items() if rel in names}
        auto = {names[rel] for rel in state.autoexec if rel in names}
        sides.append((report, names, files, auto))
    (old_rep, old_names, old_files, _), (new_rep, new_names, new_files, new_auto) = sides
    rel_of = {p: rel for rel, p in new_names.items()}

    comparable = lambda paths: sorted(p for p in paths if not GENERATED.search(p))  # noqa: E731
    added = comparable(set(new_files) - set(old_files))
    removed = comparable(set(old_files) - set(new_files))
    changed = comparable(p for p in set(new_files) & set(old_files)
                         if _sha(new_files[p].data) != _sha(old_files[p].data))

    known = {_key(f, old_names) for f in old_rep.findings}
    findings = [f for f in new_rep.findings if _key(f, new_names) not in known]
    caps, new_deps = [], {}
    for path in added + changed:
        f = new_files[path]
        before = of_file(path, old_files[path].data, old_files[path].text) if path in old_files else {}
        after = of_file(path, f.data, f.text)
        runs = path in new_auto or "install-time" in after
        rel = rel_of.get(path, path)
        manifest = posixpath.basename(path.lower()) == "package.json" or path.lower().endswith(".gemspec")
        if source and runs and f.text is not None and (not manifest or after.get("install-time") !=
                                                       before.get("install-time")):
            # Publishing tools rewrite manifests (versions, workspace ranges): only their install hooks count.
            what = "is not in the source" if path not in old_files else "differs from the source"
            findings.append(Finding(R_NOT_IN_SOURCE, "high", rel, 0, f"{path} runs on its own and {what}",
                                    after.get("install-time", ""), "autoexec"))
        deps = dependencies(path, f.text) - dependencies(path, old_files[path].text if path in old_files else None)
        if deps and path in old_files:
            new_deps[path] = sorted(deps)
        gained = {c: ev for c, ev in after.items() if c not in before or (c == "install-time" and ev != before.get(c))}
        lost = sorted(set(before) - set(after))
        if not gained and not lost:
            continue
        caps.append({"path": path, "status": "added" if path not in old_files else "changed", "runs_on_its_own": runs,
                     "gained": gained, "lost": lost})
        if source:
            continue  # a package always adds to its source; D002 above judges what matters
        if "install-time" in gained:
            findings.append(Finding(R_GAINED, "medium", rel, 0, f"now runs when installed or built: "
                                    f"{gained['install-time']}", gained["install-time"], "autoexec"))
        risky = sorted(set(gained) & RISKY)
        if runs and risky:
            findings.append(Finding(R_GAINED, "medium", rel, 0, "code that runs on its own now "
                                    + ", ".join(CAPABILITIES[c] for c in risky), gained[risky[0]], "autoexec"))

    old_surfaces = {(s.kind, old_names.get(s.path, s.path), s.trigger) for s in old_rep.surfaces}
    report = Report(target=f"{old} -> {new}", findings=findings,
                    surfaces=[s for s in new_rep.surfaces
                              if (s.kind, new_names.get(s.path, s.path), s.trigger) not in old_surfaces],
                    incomplete=old_rep.incomplete + new_rep.incomplete)
    report.stats = {
        "diff": {"old": str(old), "new": str(new), "mode": "source" if source else "versions",
                 "old_verdict": old_rep.verdict, "new_verdict": new_rep.verdict,
                 "files": {"added": len(added), "removed": len(removed), "changed": len(changed),
                           "same": len(comparable(set(new_files) & set(old_files))) - len(changed)},
                 "added": added, "removed": removed, "changed": changed, "capabilities": caps,
                 "new_dependencies": new_deps},
        "files": len(new_files), "seconds": round(time.monotonic() - started, 2),
    }
    return report


def summary(report: Report) -> str:
    """The changes behind the verdict, for people."""
    d = report.stats["diff"]
    n = d["files"]
    first, second = ("source", "package") if d["mode"] == "source" else ("old version", "new version")
    out = [f"Compared {d['old']}  ->  {d['new']}",
           f"  files: {n['added']} added, {n['changed']} changed, {n['removed']} removed, {n['same']} the same "
           f"({first} alone: {d['old_verdict']}, {second} alone: {d['new_verdict']})"]
    caps = d["capabilities"]
    if caps:
        out.append("  capabilities gained (* runs on its own)")
        width = min(48, max(len(c["path"]) for c in caps))
        for c in caps:
            gained = ", ".join(c["gained"]) or "-"
            lost = f"   (lost: {', '.join(c['lost'])})" if c["lost"] else ""
            out.append(f"   {'*' if c['runs_on_its_own'] else ' '} {c['path'].ljust(width)}  {c['status']:7}  {gained}{lost}")
    elif n["added"] or n["changed"]:
        out.append("  no capability gained")
    for path, deps in d["new_dependencies"].items():
        out.append(f"  new dependencies in {path}: {', '.join(deps)}")
    if d["added"]:
        shown = d["added"][:15]
        out.append("  added: " + ", ".join(shown) + (f" and {len(d['added']) - 15} more" if len(d["added"]) > 15 else ""))
    return "\n".join(out)
