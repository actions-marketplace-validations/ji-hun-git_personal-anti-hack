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
    round_two = _round_two()
    if round_two:
        out["sources"]["round_two"] = round_two.pop("source")
        out["round_two"] = round_two
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


def holm(ps: dict[str, float]) -> dict[str, float]:
    """Holm's step-down adjustment: with these, the chance of any false finding among the tests stays under 5%."""
    out, running = {}, 0.0
    for i, key in enumerate(sorted(ps, key=lambda k: (ps[k], k))):
        running = max(running, min(1.0, (len(ps) - i) * ps[key]))
        out[key] = running
    return out


def paired_rounds(rows: list[dict]) -> dict:
    """Two versions of the rules on the same samples (bench/independent.py run --baseline), fixed before round two's
    download: per set, the rate each version catches (malicious) or flags (popular) and an exact McNemar test on the
    samples only one of them does, Holm-adjusted across the sets; overall, the same test on the discordant samples of
    all malicious sets together and of all popular packages together, Holm-adjusted across the two. Each sample is
    its own stratum, so summing the discordant pairs across sets is the stratified matched-pairs test."""
    sets: dict[str, dict] = {}
    pairs: dict[str, list[tuple[dict, bool, bool]]] = {}
    for key in sorted({r["set"] for r in rows}, key=lambda k: (k.endswith("/popular"), _SET_ORDER.get(k, 9), k)):
        drawn = [r for r in rows if r["set"] == key]
        ok = [r for r in drawn if "error" not in r and "verdict_baseline" in r]
        pairs[key] = [(r, r["verdict"] in FLAGGED, r["verdict_baseline"] in FLAGGED) for r in ok]
        only_now = sum(a and not b for _, a, b in pairs[key])
        only_before = sum(b and not a for _, a, b in pairs[key])
        sets[key] = {"kind": "benign" if key.endswith("/popular") else "malicious", "drawn": len(drawn),
                     "left_out": len(drawn) - len(ok),
                     "now": rate(sum(a for _, a, _ in pairs[key]), len(ok)),
                     "before": rate(sum(b for _, _, b in pairs[key]), len(ok)),
                     "blocked_now": rate(sum(r["verdict"] == "block" for r in ok), len(ok)),
                     "blocked_before": rate(sum(r["verdict_baseline"] == "block" for r in ok), len(ok)),
                     "only_now": only_now, "only_before": only_before, "p": mcnemar(only_now, only_before)}
    for key, p in holm({k: v["p"] for k, v in sets.items()}).items():
        sets[key]["p_holm"] = p
    overall = {}
    for kind in ("malicious", "benign"):
        group = [v for v in sets.values() if v["kind"] == kind]
        if group:
            b, c = sum(v["only_now"] for v in group), sum(v["only_before"] for v in group)
            overall[kind] = {"n": sum(v["now"]["n"] for v in group), "only_now": b, "only_before": c,
                             "p": mcnemar(b, c)}
    for kind, p in holm({k: v["p"] for k, v in overall.items()}).items():
        overall[kind]["p_holm"] = p
    lost = sorted((k, r["package"], r["version"]) for k, ps in pairs.items() if not k.endswith("/popular")
                  for r, a, b in ps if b and not a)
    flagged = sorted((k.split("/")[0], r["package"], r["version"], r["verdict"]) for k, ps in pairs.items()
                     if k.endswith("/popular") for r, a, _ in ps if a)
    return {"sets": sets, "overall": overall, "lost": lost, "false_alarms": flagged}


def _round_two() -> dict | None:
    """Round two of the held-out test (kind independent-round2), when it has been run."""
    if not sorted(RESULTS.glob("20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]-independent-round2.json")):
        return None
    name, data = load("independent-round2")
    sample_path = data["sample"].replace("\\", "/")  # the run recorded it with Windows separators
    sample = json.loads((ROOT / sample_path).read_text(encoding="utf-8"))
    errors: dict[str, int] = {}
    for r in data["rows"]:
        if "error" in r or "baseline_error" in r:
            why = r["error"].split(":")[0] if "error" in r else f"round one's rules failed: {r['baseline_error']}"
            errors[why] = errors.get(why, 0) + 1
    fa_rules: dict[str, int] = {}
    for r in data["rows"]:
        if r["set"].endswith("/popular") and r.get("verdict") in FLAGGED:
            for rid, sev in r["rules"].items():
                if sev in ("medium", "high", "critical"):
                    fa_rules[rid] = fa_rules.get(rid, 0) + 1
    misses = RESULTS / name.replace("-independent-round2.json", "-independent-round2-misses.json")
    profile = json.loads(misses.read_text(encoding="utf-8")) if misses.exists() else None
    return {"source": name, "code": data["code"], "baseline": data.get("baseline", {}).get("commit"),
            "dataset": data["dataset"], "drawn_on": sample["drawn"], "sample": sample_path,
            "misses": profile["sets"] if profile else None, "misses_per_set": profile["per_set"] if profile else None,
            **paired_rounds(data["rows"]), "changes": what_changed(data["rows"]),
            "rules_behind_false_alarms": dict(sorted(fa_rules.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
            "left_out_why": dict(sorted(errors.items()))}


_STRONG = ("medium", "high", "critical")


def what_changed(rows: list[dict]) -> dict:
    """Described after round two's results came in, not part of the analysis fixed before them: the rule each
    newly caught or flagged sample rests on (its only finding at medium severity or above), the findings that fell
    below medium on the samples only round one's rules caught, and each set's rate with the campaign checks
    (pah/campaigns.py) switched off."""
    resting: dict[str, dict[str, int]] = {}
    general: dict[str, dict] = {}
    lost, new_flags = [], []
    for key in sorted({r["set"] for r in rows}, key=lambda k: (k.endswith("/popular"), _SET_ORDER.get(k, 9), k)):
        ok = [r for r in rows if r["set"] == key and "error" not in r and "verdict_baseline" in r]
        general[key] = rate(sum(r["verdict_without_campaign_shapes"] in FLAGGED for r in ok), len(ok))
        counts: dict[str, int] = {}
        for r in ok:
            now, before = r["verdict"] in FLAGGED, r["verdict_baseline"] in FLAGGED
            strong = sorted(rid for rid, sev in r["rules"].items() if sev in _STRONG)
            if now and not before:
                why = strong[0] if len(strong) == 1 else "two or more rules" if strong else "no rule above low"
                counts[why] = counts.get(why, 0) + 1
                if key.endswith("/popular"):
                    new_flags.append((key.split("/")[0], r["package"], r["version"], r["verdict"],
                                      {rid: r["rules"][rid] for rid in strong}))
            elif before and not now and not key.endswith("/popular"):
                fell = {rid: [sev, r["rules"].get(rid, "none")] for rid, sev in sorted(r["rules_baseline"].items())
                        if sev in _STRONG and r["rules"].get(rid) not in _STRONG}
                lost.append((key, r["package"], r["version"], fell))
        resting[key] = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    return {"new_resting_on": resting, "general_rules": general, "lost": lost, "new_false_alarms": new_flags}


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


def _round_two_section(s: dict) -> list[str]:
    r2 = s.get("round_two")
    if not r2:
        return []
    lines = [
        "## Round two: the fixes on a fresh draw",
        "",
        f"Round one's misses and false alarms were studied, so they cannot measure a fix. Round two was drawn on "
        f"{r2['drawn_on']} ([`{r2['sample']}`](../{r2['sample']})), committed before any rule changed and before "
        "anything was downloaded: new samples that leave out every package of round one and, for the sets round one "
        "took whole, the half that was not studied. Every sample was judged by the current rules (code "
        f"`{r2['code']}`) and by round one's (commit `{(r2['baseline'] or '')[:12]}`), on the same bytes in the same "
        "process. The analysis was fixed before the download: for each set, an exact McNemar test on the samples only "
        "one version catches or flags, with Holm's adjustment across the sets; overall, the same test on the "
        "discordant samples of all malicious sets together and of all popular packages together, adjusted across the "
        "two. The halves under test were scanned in round one as well, and its report describes a random 60 misses "
        "per set by structure only; none of their contents was looked at while the rules were changed.",
        "",
        "| Set | Scanned | Round one's rules | Current rules | Current, 95% interval | Only current "
        "| Only round one's | p | Holm |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for key, v in r2["sets"].items():
        now, before = v["now"], v["before"]
        lines.append(f"| {SET_NAMES.get(key, key)} | {now['n']} | {before['k']} ({pct(before['rate'])}) "
                     f"| {now['k']} ({pct(now['rate'])}) | {ci(now)} | {v['only_now']} | {v['only_before']} "
                     f"| {pval(v['p'])} | {pval(v['p_holm'])} |")
    lines.append("")
    words = {"malicious": ("malicious samples", "caught"), "benign": ("popular packages", "flagged")}
    for kind, v in r2["overall"].items():
        what, did = words[kind]
        lines.append(f"- All {what} ({v['n']:,}): {v['only_now']} {did} only by the current rules, "
                     f"{v['only_before']} only by round one's; exact McNemar p = {pval(v['p'])} "
                     f"(Holm, two tests: {pval(v['p_holm'])}).")
    lines.append("")
    if r2["lost"]:
        lines += ["Malicious samples round one's rules caught and the current ones miss: "
                  + ", ".join(f"{p} {ver} ({SET_NAMES.get(k, k)})" for k, p, ver in r2["lost"]) + ".", ""]
    if r2["false_alarms"]:
        lines += ["Popular packages the current rules flag: "
                  + ", ".join(f"{p} {ver} ({eco}, {verdict})" for eco, p, ver, verdict in r2["false_alarms"])
                  + ". The rules behind them: "
                  + ", ".join(f"`{rid}` {n}" for rid, n in r2["rules_behind_false_alarms"].items()) + ".", ""]
    if r2["left_out_why"]:
        lines += ["Left out because they could not be downloaded, verified or unpacked: "
                  + ", ".join(f"{n} ({why})" for why, n in r2["left_out_why"].items()) + ".", ""]
    ch = r2.get("changes")
    if ch:
        def rule(why: str) -> str:
            return f"`{why}`" if why.startswith("PAH-") else why

        resting = [f"{SET_NAMES.get(k, k)}, {sum(v.values())}: " + ", ".join(f"{rule(w)} {n}" for w, n in v.items())
                   for k, v in ch["new_resting_on"].items() if v]
        lines += [
            "### What changed, described after the results",
            "",
            "Not part of the analysis fixed before the download. The samples only the current rules catch or flag, "
            "by the rule each rests on (its only finding at medium severity or above): " + "; ".join(resting) + ".",
            "",
        ]
        if ch["lost"]:
            lines += ["The findings that fell below medium on the samples only round one's rules caught: "
                      + "; ".join(f"{p} {ver} ({SET_NAMES.get(k, k)}): "
                                  + ", ".join(f"`{rid}` {a} before, {b} now" for rid, (a, b) in fell.items())
                                  for k, p, ver, fell in ch["lost"]) + ".", ""]
        if ch["new_false_alarms"]:
            lines += ["Popular packages only the current rules flag: "
                      + "; ".join(f"{p} {ver} ({eco}, {verdict}: "
                                  + ", ".join(f"`{rid}` {sev}" for rid, sev in strong.items()) + ")"
                                  for eco, p, ver, verdict, strong in ch["new_false_alarms"]) + ".", ""]
        lines += ["With the checks written for named campaigns (`pah/campaigns.py`) switched off, the current rules "
                  "catch or flag: " + "; ".join(f"{SET_NAMES.get(k, k)} {g['k']} (with them, {r2['sets'][k]['now']['k']})"
                                               for k, g in ch["general_rules"].items()) + ".", ""]
    if r2.get("misses"):
        lines += [
            "### What the current rules still miss",
            "",
            f"`python bench/independent.py profile --kind independent-round2` describes a random "
            f"{r2['misses_per_set']} of the current rules' misses in each set (all of them where there are fewer) by "
            "structure only, as for round one.",
            "",
            "| Set | Missed | Described | What they have, by number of samples described |",
            "| --- | --- | --- | --- |",
        ]
        for key, v in r2["misses"].items():
            if v["missed"]:
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
        *_round_two_section(s),
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
    for kind, v in (s.get("round_two") or {}).get("overall", {}).items():
        print(f"round two, {kind}: {v['only_now']} only by the current rules, {v['only_before']} only by round one's, "
              f"p = {pval(v['p'])} (Holm {pval(v['p_holm'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
