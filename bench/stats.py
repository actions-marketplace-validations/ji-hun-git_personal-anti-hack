#!/usr/bin/env python3
"""Statistics for the benchmark results: what the counts in bench/results/ can and cannot rule out.

    python bench/stats.py [--name NAME]      # bench/results/<NAME>-stats.json and docs/statistics.md

Every rate gets an exact 95% confidence interval (Clopper-Pearson, from the binomial distribution itself, so it is
right for small samples and for 0 or n out of n, where normal approximations fail). Paired comparisons on the same
cases use the exact McNemar test: only the cases where the two disagree carry information, and under "no difference"
each disagreement is a fair coin. Standard library only.

The intervals treat cases as independent draws. TrapRepo's cases were written to cover techniques from real
incidents, not sampled at random from all attacks, so an interval says what this corpus can rule out, not what every
attack in the wild would show.
"""
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = HERE / "results"
ALPHA = 0.05


# ------------------------------------------------------------------------------------------------- the statistics


def _log_pmf(k: int, n: int, p: float) -> float:
    if p <= 0.0:
        return 0.0 if k == 0 else -math.inf
    if p >= 1.0:
        return 0.0 if k == n else -math.inf
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
            + k * math.log(p) + (n - k) * math.log1p(-p))


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed exactly in log space."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    logs = [_log_pmf(i, n, p) for i in range(k + 1)]
    top = max(logs)
    if top == -math.inf:
        return 0.0
    return min(1.0, math.exp(top) * sum(math.exp(v - top) for v in logs))


def _solve(f, target: float) -> float:
    """The p in [0, 1] where the decreasing function f(p) crosses target, by bisection to 1e-10."""
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if f(mid) > target:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def exact_ci(k: int, n: int, alpha: float = ALPHA) -> tuple[float, float]:
    """Clopper-Pearson interval for a proportion k/n."""
    if n == 0:
        return 0.0, 1.0
    lower = _lower(k, n, alpha)
    upper = 1.0 if k == n else _solve(lambda p: binom_cdf(k, n, p), alpha / 2)  # P(X <= k | p) = alpha/2
    return lower, upper


def _lower(k: int, n: int, alpha: float) -> float:
    """The p where P(X >= k | p) = alpha/2; P(X >= k) increases with p."""
    if k == 0:
        return 0.0
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if 1 - binom_cdf(k - 1, n, mid) < alpha / 2:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def mcnemar(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value: b and c are the two kinds of disagreement between paired outcomes."""
    m = b + c
    if m == 0:
        return 1.0
    return min(1.0, 2 * binom_cdf(min(b, c), m, 0.5))


def rate(k: int, n: int) -> dict:
    lo, hi = exact_ci(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [round(lo, 4), round(hi, 4)]}


# ------------------------------------------------------------------------------------------------- the results


def load(kind: str) -> tuple[str, dict]:
    found = sorted(RESULTS.glob(f"20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-{kind}.json"))
    if not found:
        raise SystemExit(f"no dated {kind} result in {RESULTS}")
    return found[-1].name, json.loads(found[-1].read_text(encoding="utf-8"))


FLAGGED = ("block", "warn")
MODELS = {"openai:gpt-6-astra": "GPT-6 Astra", "meta:muse-spark-1.3": "Muse Spark 1.3",
          "anthropic:claude-opus-5-5": "Claude Opus 5.5"}


def analyse() -> dict:
    out: dict = {"sources": {}, "date": time.strftime("%Y-%m-%d")}

    name, rules = load("rules")
    out["sources"]["rules"] = name
    mal = [r for r in rules["rows"] if r["kind"] == "malicious" and not r.get("skipped")]
    ben = [r for r in rules["rows"] if r["kind"] == "benign" and not r.get("skipped")]
    out["traprepo"] = {
        "malicious_flagged": rate(sum(r["pah"] in FLAGGED for r in mal), len(mal)),
        "malicious_blocked": rate(sum(r["pah"] == "block" for r in mal), len(mal)),
        "benign_flagged": rate(sum(r["pah"] in FLAGGED for r in ben), len(ben)),
        "by_category": {},
    }
    for cat in sorted({r["category"] for r in mal}):
        rows = [r for r in mal if r["category"] == cat]
        out["traprepo"]["by_category"][cat] = rate(sum(r["pah"] in FLAGGED for r in rows), len(rows))

    name, models = load("models")
    out["sources"]["models"] = name
    seen = {r["id"]: r for r in models["rows"]}
    ours = {r["id"]: r["pah"] in FLAGGED for r in rules["rows"] if r["id"] in seen and not r.get("skipped")}
    cmp = {}
    for spec, label in MODELS.items():
        for kind in ("malicious", "benign"):
            ids = [i for i, r in seen.items() if r["kind"] == kind and i in ours]
            every = {i: all(t["verdict"] == "unsafe" for t in seen[i]["models"][spec]) for i in ids}
            anyrun = {i: any(t["verdict"] == "unsafe" for t in seen[i]["models"][spec]) for i in ids}
            if kind == "malicious":
                # caught = flagged; agent-white-hat's single deterministic run against the model's every run / any run
                b = sum(ours[i] and not every[i] for i in ids)
                c = sum(every[i] and not ours[i] for i in ids)
                b_any = sum(ours[i] and not anyrun[i] for i in ids)
                c_any = sum(anyrun[i] and not ours[i] for i in ids)
                cmp.setdefault(label, {})["malicious"] = {
                    "n": len(ids), "ours": rate(sum(ours[i] for i in ids), len(ids)),
                    "model_every_run": rate(sum(every.values()), len(ids)),
                    "model_any_run": rate(sum(anyrun.values()), len(ids)),
                    "only_ours_vs_every": b, "only_model_vs_every": c, "p_vs_every": mcnemar(b, c),
                    "only_ours_vs_any": b_any, "only_model_vs_any": c_any, "p_vs_any": mcnemar(b_any, c_any),
                    "runs": sum(len(seen[i]["models"][spec]) for i in ids),
                    "refused_runs": sum(t["status"] == "refusal" for i in ids for t in seen[i]["models"][spec])}
            else:
                # false alarms: a flag on a benign case is the mistake, so "only ours" means we flagged and it did not
                b = sum(ours[i] and not anyrun[i] for i in ids)
                c = sum(anyrun[i] and not ours[i] for i in ids)
                cmp.setdefault(label, {})["benign"] = {
                    "n": len(ids), "ours_flagged": rate(sum(ours[i] for i in ids), len(ids)),
                    "model_flagged_any_run": rate(sum(anyrun.values()), len(ids)),
                    "only_ours": b, "only_model": c, "p": mcnemar(b, c)}
    out["models"] = cmp
    out["models_trials"] = models.get("trials", 3)

    name, drill = load("drill")
    out["sources"]["drill"] = name
    unexpected = len(drill.get("failures", []))
    per_agent = {a: {"malicious_stopped": rate(s["malicious_stopped"], s["malicious"]),
                     "benign_untouched": rate(s["benign_untouched"], s["benign"])}
                 for a, s in drill["summary"].items()}
    mal_runs = sum(s["malicious"] for s in drill["summary"].values())
    mal_stopped = sum(s["malicious_stopped"] for s in drill["summary"].values())
    ben_runs = sum(s["benign"] for s in drill["summary"].values())
    ben_touched = ben_runs - sum(s["benign_untouched"] for s in drill["summary"].values())
    out["drill"] = {"decisions": len(drill["rows"]), "unexpected": rate(unexpected, len(drill["rows"])),
                    "malicious_stopped": rate(mal_stopped, mal_runs), "benign_touched": rate(ben_touched, ben_runs),
                    "per_agent": per_agent}

    name, chains = load("chains")
    out["sources"]["chains"] = name
    s = chains["summary"]
    attacks = [r for r in chains["rows"] if r["kind"] == "attack" and r["applicable"]]
    # paired per attack run: stopped in the session, against stopped with every key step judged alone
    alone_stopped = sum(all(st["alone"] in ("deny", "ask") for st in r["steps"] if st["key"]) for r in attacks)
    both = sum(r["caught"] and all(st["alone"] in ("deny", "ask") for st in r["steps"] if st["key"]) for r in attacks)
    b = sum(r["caught"] for r in attacks) - both          # stopped in session only
    c = alone_stopped - both                               # stopped alone only
    # the independent units are the attack scripts (each runs once per agent): a script counts as stopped when every
    # agent it applies to stopped it
    scripts: dict = {}
    for r in attacks:
        key_alone = all(st["alone"] in ("deny", "ask") for st in r["steps"] if st["key"])
        entry = scripts.setdefault(r["chain"], {"session": True, "alone": True})
        entry["session"] &= bool(r["caught"])
        entry["alone"] &= key_alone
    sb = sum(v["session"] and not v["alone"] for v in scripts.values())
    sc = sum(v["alone"] and not v["session"] for v in scripts.values())
    out["chains"] = {"attack_runs_stopped": rate(s["attack_runs_caught"], s["attack_runs"]),
                     "stopped_by_steps_alone": rate(alone_stopped, len(attacks)),
                     "only_as_chain": b, "only_alone": c, "p_session_vs_alone": mcnemar(b, c),
                     "scripts": len(scripts), "scripts_stopped": sum(v["session"] for v in scripts.values()),
                     "scripts_only_as_chain": sb, "scripts_only_alone": sc, "p_scripts": mcnemar(sb, sc),
                     "ordinary_runs_with_extra_prompt": rate(s["benign_runs_with_added_prompts"], s["benign_runs"])}

    name, fuzz = load("fuzz")
    out["sources"]["fuzz"] = name
    mutants = [r for r in fuzz["rows"] if r["kind"] == "malicious"]
    rewrites = [r for r in fuzz["rows"] if r["kind"] == "benign"]
    out["fuzz"] = {"rewrites_caught": rate(sum(not r["bypass"] for r in mutants), len(mutants)),
                   "harmless_rewrites_flagged": rate(sum(r["verdict"] in FLAGGED for r in rewrites), len(rewrites)),
                   "operators": len(fuzz.get("operators", []))}

    name, repos = load("real-repos")
    out["sources"]["real_repos"] = name
    verdicts = [r["verdict"] for r in repos["repos"]]
    out["real_repos"] = {"blocked": rate(verdicts.count("block"), len(verdicts)),
                         "warned": rate(verdicts.count("warn"), len(verdicts)),
                         "flagged": rate(sum(v in FLAGGED for v in verdicts), len(verdicts)),
                         "files": sum(r.get("files", 0) for r in repos["repos"])}
    independent = _independent()
    if independent:
        out["sources"]["independent"] = independent.pop("source")
        out["independent"] = independent
    shell = _shellgate()
    if shell:
        out["sources"]["shellgate"] = shell.pop("source")
        out["shellgate"] = shell
    return out


def _shellgate() -> dict | None:
    """ViKernel's shell benchmark (bench/shellgate.py): the first, untuned run against the latest, paired by command."""
    dated = "20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
    if not (sorted(RESULTS.glob(f"{dated}-shellgate.json")) and sorted(RESULTS.glob(f"{dated}-shellgate-baseline.json"))):
        return None
    name, after = load("shellgate")
    _, before = load("shellgate-baseline")
    right = {}
    for label, run in (("before", before), ("after", after)):
        right[label] = {r["id"]: (r["verdict"] in ("deny", "ask")) == r["is_risky"] for r in run["rows"]}
    halves = {r["id"]: r["half"] for r in after["rows"]}
    paired = {}
    for half in ("tune", "test", "all"):
        ids = [i for i in right["after"] if half == "all" or halves[i] == half]
        b = sum(right["after"][i] and not right["before"][i] for i in ids)   # fixed by the change
        c = sum(right["before"][i] and not right["after"][i] for i in ids)   # broken by the change
        paired[half] = {"n": len(ids), "fixed": b, "broken": c, "p": mcnemar(b, c)}
    rows = {r["id"]: r for r in after["rows"]}

    def families(ids) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in ids:
            key = f"{rows[i]['family']} ({'risky' if rows[i]['is_risky'] else 'harmless'})"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    test_ids = [i for i in rows if halves[i] == "test"]
    return {"source": name, "dataset": after["dataset"], "code_before": before["code"], "code_after": after["code"],
            "before": before["summary"], "after": after["summary"], "paired": paired,
            "test_still_wrong": families(i for i in test_ids if not right["after"][i]),
            "broken": families(i for i in rows if right["before"][i] and not right["after"][i]),
            "test_still_wrong_seeds": len({rows[i]["seed_id"] for i in test_ids if not right["after"][i]})}


def _independent() -> dict | None:
    """The held-out evaluation (bench/independent.py), when it has been run."""
    if not sorted(RESULTS.glob("20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-independent.json")):
        return None
    name, data = load("independent")
    sample = json.loads((ROOT / data["sample"]).read_text(encoding="utf-8"))
    by_set: dict[str, list[dict]] = {}
    for r in data["rows"]:
        by_set.setdefault(r["set"], []).append(r)
    sets = {}
    for key, rows in by_set.items():
        ok = [r for r in rows if "error" not in r]
        sets[key] = {
            "kind": "benign" if key.endswith("/popular") else "malicious",
            "drawn": len(rows), "left_out": len(rows) - len(ok),
            "population": data["dataset"]["packages"].get(key, 5000 if key.endswith("/popular") else None),
            "flagged": rate(sum(r["verdict"] in FLAGGED for r in ok), len(ok)),
            "blocked": rate(sum(r["verdict"] == "block" for r in ok), len(ok)),
            "flagged_general_rules": rate(sum(r["verdict_without_campaign_shapes"] in FLAGGED for r in ok), len(ok)),
        }
    benign = [r for r in data["rows"] if r["set"].endswith("/popular") and "error" not in r]
    caught = [r for r in data["rows"] if not r["set"].endswith("/popular") and r.get("verdict") in FLAGGED]
    rule_counts: dict[str, int] = {}
    for r in caught:
        for rid, sev in r["rules"].items():
            if sev in ("medium", "high", "critical"):
                rule_counts[rid] = rule_counts.get(rid, 0) + 1
    false_alarms = [r for r in benign if r["verdict"] in FLAGGED]
    fa_rules: dict[str, int] = {}
    for r in false_alarms:
        for rid, sev in r["rules"].items():
            if sev in ("medium", "high", "critical"):
                fa_rules[rid] = fa_rules.get(rid, 0) + 1
    errors: dict[str, int] = {}
    for r in data["rows"]:
        if "error" in r:
            why = r["error"].split(":")[0]
            errors[why] = errors.get(why, 0) + 1
    misses = RESULTS / name.replace("-independent.json", "-independent-misses.json")
    profile = json.loads(misses.read_text(encoding="utf-8")) if misses.exists() else None
    return {"source": name, "code": data["code"], "dataset": data["dataset"], "seed": data["seed"],
            "misses": profile["sets"] if profile else None, "misses_per_set": profile["per_set"] if profile else None,
            "drawn_on": sample["drawn"], "seen_before_run": len(sample.get("seen_before_run", [])),
            "benign_passed_over": len(sample.get("benign_passed_over", [])),
            "sets": dict(sorted(sets.items(), key=lambda kv: (kv[1]["kind"] == "benign", _SET_ORDER.get(kv[0], 9)))),
            "benign_all": {"flagged": rate(sum(r["verdict"] in FLAGGED for r in benign), len(benign)),
                           "blocked": rate(sum(r["verdict"] == "block" for r in benign), len(benign))},
            "rules_behind_catches": dict(sorted(rule_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
            "rules_behind_false_alarms": dict(sorted(fa_rules.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
            "false_alarms": sorted((r["set"].split("/")[0], r["package"], r["version"], r["verdict"])
                                   for r in false_alarms),
            "left_out_why": dict(sorted(errors.items()))}


_SET_ORDER = {"npm/malicious_intent": 0, "pypi/malicious_intent": 1, "ai-skills/malicious_intent": 2,
              "ide_extensions/malicious_intent": 3, "npm/compromised_lib": 4, "pypi/compromised_lib": 5,
              "pypi/popular": 0, "npm/popular": 1}
SET_NAMES = {"npm/malicious_intent": "npm packages published to attack",
             "pypi/malicious_intent": "PyPI packages published to attack",
             "ai-skills/malicious_intent": "Agent skills published to attack",
             "ide_extensions/malicious_intent": "IDE extensions published to attack",
             "npm/compromised_lib": "Hijacked releases of real npm packages",
             "pypi/compromised_lib": "Hijacked releases of real PyPI packages",
             "pypi/popular": "Popular PyPI projects", "npm/popular": "Popular npm packages"}


# ------------------------------------------------------------------------------------------------- the report


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _shellgate_section(s: dict) -> list[str]:
    sg = s.get("shellgate")
    if not sg:
        return []
    ds = sg["dataset"]

    def cells(summary: dict) -> str:
        rr, bp = summary["risky_recall"], summary["benign_pass"]
        return (f"{100 * summary['balanced_accuracy']:.1f} | {rr['k']} of {rr['n']} ({ci(rr)}) | "
                f"{bp['k']} of {bp['n']} ({ci(bp)})")

    lines = [
        "## ViKernel's shell benchmark",
        "",
        f"[`bench/shellgate.py`](../bench/shellgate.py) scores the guard on the public dev split of "
        f"[{ds['name']}](https://huggingface.co/datasets/{ds['name']}) ({ds['license']}, {ds['rows']} bash commands, "
        "each risky one paired with a harmless one in the same disguise), the way the "
        "[Obfuscated-Shell Safety Leaderboard](https://huggingface.co/spaces/FINAL-Bench/obfuscated-shell-leaderboard) "
        "scores a gate: risky recall, benign pass and their mean, balanced accuracy. A deny or an ask stops a command. "
        "The leaderboard scores models on a private held-out split, so its numbers compare in method, not command for "
        "command.",
        "",
        f"The first run, on code `{sg['code_before']}`, had never seen the set. The seed commands were then split in "
        "two halves by a fixed seed; the shell-unfolding change (`pah/shellfold.py`, code "
        f"`{sg['code_after']}`) was written by looking only at the tune half, so the test half measures it on commands "
        "it was not built against.",
        "",
        "| Run | Half | Balanced accuracy | Risky stopped (95% interval) | Harmless let through (95% interval) |",
        "| --- | --- | --- | --- | --- |",
    ]
    for half in ("test", "tune"):
        lines.append(f"| Before | {half} | {cells(sg['before']['halves'][half])} |")
        lines.append(f"| After | {half} | {cells(sg['after']['halves'][half])} |")
    lines.append(f"| Before | all | {cells(sg['before']['all'])} |")
    lines.append(f"| After | all | {cells(sg['after']['all'])} |")
    t, a, rb = sg["paired"]["test"], sg["after"], sg["after"]["robustness"]
    lines += [
        "",
        f"On the test half, {t['fixed']} of its {t['n']} commands were judged right after the change and wrong before, "
        f"and {t['broken']} the other way round: exact McNemar p = {pval(t['p'])}. Still wrong on the test half after the "
        f"change: {sum(sg['test_still_wrong'].values())} commands from {sg['test_still_wrong_seeds']} seed "
        f"command{'s' if sg['test_still_wrong_seeds'] != 1 else ''}, by family "
        + ", ".join(f"{k} {v}" for k, v in sg["test_still_wrong"].items())
        + "; the commands the change broke: " + ", ".join(f"{k} {v}" for k, v in sg["broken"].items())
        + ". Over the whole set, balanced accuracy "
        f"after the change is {100 * a['all']['balanced_accuracy']:.1f} (bootstrap 95% interval "
        f"{100 * a['all']['balanced_accuracy_ci95'][0]:.1f} to {100 * a['all']['balanced_accuracy_ci95'][1]:.1f}), and "
        f"the obfuscation gap, plain minus disguised, is {100 * a.get('obfuscation_gap', 0):+.1f} points.",
        "",
        "Robustness, built from the plain commands as the leaderboard builds it:",
        "",
        "| Holds under persuasion | Calm under alarm | Wrapped, risky stopped | Wrapped, harmless let through | Talked into ALLOW | Robustness |",
        "| --- | --- | --- | --- | --- | --- |",
        f"| {pct(rb['holds_under_persuasion']['rate'])} | {pct(rb['calm_under_alarm']['rate'])} "
        f"| {pct(rb['wrapped_risky_denied']['rate'])} | {pct(rb['wrapped_benign_allowed']['rate'])} "
        f"| {pct(rb['talked_into_allow']['rate'] or 0)} | {pct(rb['robustness'])} |",
        "",
    ]
    return lines


def _independent_section(s: dict) -> list[str]:
    ind = s.get("independent")
    if not ind:
        return []
    ds = ind["dataset"]
    lines = [
        "## A held-out test: real malware and popular packages",
        "",
        f"[`bench/independent.py`](../bench/independent.py) drew this sample on {ind['drawn_on']}, before downloading "
        f"anything, and ran once on code `{ind['code']}`; the protocol is in its docstring and the sample, with every "
        f"file's digest, in [`bench/fixtures/independent-sample.json`](../bench/fixtures/independent-sample.json). "
        f"Malicious packages come from Datadog's [malicious software packages dataset]"
        f"(https://github.com/{ds['repo']}) (Apache-2.0) at commit `{ds['commit'][:12]}`: a random draw from each set, "
        "one version per package. Benign packages are a random 500 of the 5,000 most-downloaded PyPI projects and 500 "
        "of the 5,000 most-downloaded npm packages, at their latest release. Every file was unpacked and scanned in "
        "memory; nothing was written to disk or run. Caught or flagged means a block or warn verdict.",
        "",
        "| Set | Population | Scanned | Caught or flagged | 95% interval | Blocked | General rules alone |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for key, v in ind["sets"].items():
        f, b, g = v["flagged"], v["blocked"], v["flagged_general_rules"]
        pop = f"{v['population']:,}" if v.get("population") else ""
        lines.append(f"| {SET_NAMES.get(key, key)} | {pop} | {f['n']} | {f['k']} ({pct(f['rate'])}) | {ci(f)} "
                     f"| {b['k']} ({pct(b['rate'])}) | {g['k']} ({pct(g['rate'])}) |")
    ba = ind["benign_all"]
    lines += [
        f"| All popular packages | 10,000 | {ba['flagged']['n']:,} | {ba['flagged']['k']} ({pct(ba['flagged']['rate'])}) "
        f"| {ci(ba['flagged'])} | {ba['blocked']['k']} ({pct(ba['blocked']['rate'])}) | |",
        "",
        "\"General rules alone\" scans each caught sample again with the checks written for named campaigns "
        "(`pah/campaigns.py`) switched off. The rules behind the catches, by the number of malicious samples each "
        "fired on at medium severity or above: "
        + ", ".join(f"`{rid}` {n}" for rid, n in ind["rules_behind_catches"].items()) + ".",
        "",
    ]
    if ind["false_alarms"]:
        lines += [
            "Popular packages flagged: "
            + ", ".join(f"{name} {version} ({eco}, {verdict})" for eco, name, version, verdict in ind["false_alarms"])
            + ". The rules behind them: "
            + ", ".join(f"`{rid}` {n}" for rid, n in ind["rules_behind_false_alarms"].items()) + ".",
            "",
        ]
    notes = []
    if ind["left_out_why"]:
        notes.append("Left out because they could not be downloaded, verified or unpacked: "
                     + ", ".join(f"{n} ({why})" for why, n in ind["left_out_why"].items()) + ".")
    if ind["benign_passed_over"]:
        notes.append(f"{ind['benign_passed_over']} popular packages were passed over in the draw because their "
                     "latest release had no file to download.")
    if ind["seen_before_run"]:
        notes.append(f"While the unpacking code was written, the file lists (names and sizes, not contents) of "
                     f"{ind['seen_before_run']} drawn samples were looked at; no rule was changed.")
    notes.append("Datadog notes that most of its samples were found by one rule set (GuardDog), so read these rates "
                 "as rates on malware Datadog caught, not on all malware. Each set is its own population: the rates "
                 "are not pooled across sets.")
    lines += [" ".join(notes), ""]
    if ind.get("misses"):
        lines += [
            "### What the misses look like",
            "",
            f"`python bench/independent.py profile` describes a random {ind['misses_per_set']} of the misses in each "
            "set (all of them where there are fewer) by structure only: what kind of code a sample has and when it "
            "would run, never its contents. The features are descriptions for this report, not detection rules.",
            "",
            "| Set | Missed | Described | What they have, by number of samples described |",
            "| --- | --- | --- | --- |",
        ]
        for key, v in ind["misses"].items():
            if not v["missed"]:
                continue
            feats = "; ".join(f"{f} {n}" for f, n in list(v["features"].items())[:6])
            lines.append(f"| {SET_NAMES.get(key, key)} | {v['missed']} | {v['profiled']} | {feats} |")
        lines.append("")
    return lines


def ci(r: dict) -> str:
    lo, hi = r["ci95"]
    return f"{pct(lo)} to {pct(hi)}"


def pval(p: float) -> str:
    if p < 1e-6:
        return f"{p:.1e}"
    return f"{p:.2g}" if p < 0.01 else f"{p:.3f}"


def markdown(s: dict) -> str:
    t = s["traprepo"]
    lines = [
        "# What the numbers can and cannot rule out",
        "",
        "Generated by [`bench/stats.py`](../bench/stats.py) from "
        + ", ".join(f"`bench/results/{v}`" for v in s["sources"].values()) + ". Rerun it after any benchmark.",
        "",
        "Every rate below comes with an **exact 95% confidence interval** (Clopper-Pearson): the range of true rates "
        "that would make the observed count unsurprising. When a count is 0 or all of the cases, the interval still has "
        "width, and that width is the honest answer to \"how sure are we\": 76 of 76 caught means the true rate is at "
        "least 95.3%, not 100%. Comparisons on the same cases use the **exact McNemar test**, which looks only at the "
        "cases where the two disagree.",
        "",
        "**What the intervals assume.** They treat each case as an independent draw. TrapRepo's cases were written to "
        "cover techniques from real incidents, not sampled at random from all attacks, so read an interval as what this "
        "corpus can rule out, not as a rate for every attack in the wild. The popular repositories are a sample of 30 "
        "chosen by hand, not drawn at random either.",
        "",
        "**What the rules have seen.** Whenever a case got through, the rules were fixed until it did not: four of the "
        "cases added in 0.4.0 needed new detection, and the fuzzer's first run got eight rewrites past 0.2.1. So the "
        "TrapRepo and fuzzer rows say how well the rules cover the techniques they were built against. How they do on "
        "attacks they have never seen takes a corpus they were never tuned on"
        + (": the held-out test below." if "independent" in s else "."),
        "",
        *_independent_section(s),
        *_shellgate_section(s),
        "## Detection and false alarms",
        "",
        "| Measure | Observed | 95% interval |",
        "| --- | --- | --- |",
        f"| TrapRepo malicious repositories caught (block or warn) | {t['malicious_flagged']['k']} of {t['malicious_flagged']['n']} | {ci(t['malicious_flagged'])} |",
        f"| TrapRepo malicious repositories blocked | {t['malicious_blocked']['k']} of {t['malicious_blocked']['n']} | {ci(t['malicious_blocked'])} |",
        f"| TrapRepo benign repositories flagged | {t['benign_flagged']['k']} of {t['benign_flagged']['n']} | {ci(t['benign_flagged'])} |",
        f"| Evasion fuzzer: rewritten traps still caught | {s['fuzz']['rewrites_caught']['k']} of {s['fuzz']['rewrites_caught']['n']} | {ci(s['fuzz']['rewrites_caught'])} |",
        f"| Evasion fuzzer: harmless rewrites flagged | {s['fuzz']['harmless_rewrites_flagged']['k']} of {s['fuzz']['harmless_rewrites_flagged']['n']} | {ci(s['fuzz']['harmless_rewrites_flagged'])} |",
        f"| Attack drill: malicious setups stopped, nine agents | {s['drill']['malicious_stopped']['k']} of {s['drill']['malicious_stopped']['n']} | {ci(s['drill']['malicious_stopped'])} |",
        f"| Attack drill: benign setups interrupted | {s['drill']['benign_touched']['k']} of {s['drill']['benign_touched']['n']} | {ci(s['drill']['benign_touched'])} |",
        f"| Chain drill: attack runs stopped | {s['chains']['attack_runs_stopped']['k']} of {s['chains']['attack_runs_stopped']['n']} | {ci(s['chains']['attack_runs_stopped'])} |",
        f"| Chain drill: ordinary runs given an extra prompt | {s['chains']['ordinary_runs_with_extra_prompt']['k']} of {s['chains']['ordinary_runs_with_extra_prompt']['n']} | {ci(s['chains']['ordinary_runs_with_extra_prompt'])} |",
        f"| Popular repositories blocked | {s['real_repos']['blocked']['k']} of {s['real_repos']['blocked']['n']} | {ci(s['real_repos']['blocked'])} |",
        "",
        "The fuzzer, drill and chain rows count one case several times (as each of its rewrites, or once per agent), so "
        "their runs are not independent of each other and their intervals are narrower than the cases alone justify. "
        "The TrapRepo and popular-repository rows are the ones to quote.",
        "",
        "## Compared with models reading the repository",
        "",
        f"On the {next(iter(s['models'].values()))['malicious']['n']} malicious and "
        f"{next(iter(s['models'].values()))['benign']['n']} benign cases the models were given, {s['models_trials']} runs "
        "each. agent-white-hat runs once, because it is deterministic. \"Only ours\" counts the cases agent-white-hat "
        "caught and the model did not; \"only the model\" the reverse.",
        "",
        "| Model | Model caught, every run | Only ours | Only the model | McNemar p | Model caught, any run | Only ours | Only the model | McNemar p |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, c in s["models"].items():
        m = c["malicious"]
        lines.append(f"| {label} | {m['model_every_run']['k']} ({ci(m['model_every_run'])}) | {m['only_ours_vs_every']} "
                     f"| {m['only_model_vs_every']} | {pval(m['p_vs_every'])} | {m['model_any_run']['k']} "
                     f"({ci(m['model_any_run'])}) | {m['only_ours_vs_any']} | {m['only_model_vs_any']} | {pval(m['p_vs_any'])} |")
    first = next(iter(s["models"].values()))["malicious"]
    one_sided = all(c["malicious"]["only_model_vs_every"] == 0 and c["malicious"]["only_model_vs_any"] == 0
                    for c in s["models"].values())
    refusals = "".join(
        f" {label} refused {c['malicious']['refused_runs']} of its {c['malicious']['runs']} runs on these cases. A "
        "refusal counts as not caught, because the person asking is left without an answer, so that row measures "
        "refusals more than judgment."
        for label, c in s["models"].items() if c["malicious"]["refused_runs"])
    lines += [
        "",
        f"agent-white-hat caught {first['ours']['k']} of {first['n']} ({ci(first['ours'])})."
        + (" Every difference above is one-sided: there is no case a model caught and agent-white-hat missed."
           if one_sided else "")
        + refusals + " False alarms on the benign cases are too few to tell apart:",
        "",
        "| Model | Benign flagged by the model, any run | Only ours | Only the model | McNemar p |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label, c in s["models"].items():
        b = c["benign"]
        lines.append(f"| {label} | {b['model_flagged_any_run']['k']} of {b['n']} | {b['only_ours']} | {b['only_model']} "
                     f"| {pval(b['p'])} |")
    ch = s["chains"]
    lines += [
        "",
        "## Judging steps as a chain",
        "",
        f"Each attack run of the chain drill is paired with the same steps sent alone. Stopped as a chain: "
        f"{ch['attack_runs_stopped']['k']} of {ch['attack_runs_stopped']['n']}; stopped with every key step judged "
        f"alone: {ch['stopped_by_steps_alone']['k']} ({ci(ch['stopped_by_steps_alone'])}). {ch['only_as_chain']} runs "
        f"were stopped only as a chain and {ch['only_alone']} only alone, McNemar p = {pval(ch['p_session_vs_alone'])}. "
        f"That p-value treats the runs as independent, and they are not: the {ch['scripts']} attack scripts each run "
        f"once per agent. Counted by script, which is the independent unit, {ch['scripts_stopped']} of "
        f"{ch['scripts']} are stopped in every agent they apply to; {ch['scripts_only_as_chain']} are stopped only when "
        f"judged as a chain and {ch['scripts_only_alone']} only alone, McNemar p = {pval(ch['p_scripts'])}. That is "
        "the figure to quote.",
        "",
        "## By kind of attack",
        "",
        "| TrapRepo category | Caught | 95% interval |",
        "| --- | --- | --- |",
    ]
    for cat, r in t["by_category"].items():
        lines.append(f"| {cat} | {r['k']} of {r['n']} | {ci(r)} |")
    lines += [
        "",
        "Categories with a handful of cases have wide intervals: a perfect score on four cases still allows a true "
        "rate around 40%. Narrowing them takes more cases, which is what an independent, larger corpus is for.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--name", default=time.strftime("%Y-%m-%d"))
    ap.add_argument("--no-doc", action="store_true", help="only print the summary")
    args = ap.parse_args(argv)
    s = analyse()
    (RESULTS / f"{args.name}-stats.json").write_text(json.dumps(s, indent=1) + "\n", encoding="utf-8", newline="\n")
    if not args.no_doc:
        (ROOT / "docs" / "statistics.md").write_text(markdown(s), encoding="utf-8", newline="\n")
    t = s["traprepo"]
    print(f"TrapRepo caught {t['malicious_flagged']['k']}/{t['malicious_flagged']['n']} (95% {ci(t['malicious_flagged'])}); "
          f"benign flagged {t['benign_flagged']['k']}/{t['benign_flagged']['n']} (95% {ci(t['benign_flagged'])})")
    for label, c in s["models"].items():
        m = c["malicious"]
        print(f"vs {label}: only ours {m['only_ours_vs_every']}, only the model {m['only_model_vs_every']}, "
              f"p = {pval(m['p_vs_every'])} (every run); p = {pval(m['p_vs_any'])} (any run)")
    ch = s["chains"]
    print(f"chains: {ch['only_as_chain']} runs stopped only as a chain, {ch['only_alone']} only alone, "
          f"p = {pval(ch['p_session_vs_alone'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
