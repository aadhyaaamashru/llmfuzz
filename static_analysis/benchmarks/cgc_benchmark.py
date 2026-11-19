#!/usr/bin/env python3
"""Real-bug benchmark #3: DARPA Cyber Grand Challenge programs (trailofbits/cb-multios).

Each CGC challenge is a small C program (plus its own mini libc in lib/) written by security
experts with deliberately planted, realistic vulnerabilities; the fix for each one sits under
`#ifdef PATCHED` / `#ifdef PATCHED_<n>` (or `#ifndef`, `#if`). This script:

  1. builds the VULNERABLE program with `unifdef -l` (every PATCHED* macro undefined; removed
     lines become blank so line numbers stay put) and the patched one (all defined)
  2. ground truth = lines where the two differ (the fix, or the spot the missing check belongs),
     and the functions containing them
  3. scans all vulnerable programs in one Semgrep pass with both tiers of the stage
     (rules/memory_safety.yaml = precise, rules/wide_net.yaml = wide net); poller/ and pov_*/
     (test traffic, exploits) are not scanned
  4. scores per challenge, exactly as for Magma/ARVO:
       line      a finding within --window lines of a differing line
       function  precise: a finding inside a bug function; wide: a bug function is on the list
       rank      wide: position of the first bug function in the challenge's ranked list, as a %
                 of all its functions; reported next to a random-ranking baseline

  python3 benchmarks/cgc_benchmark.py --src cb-multios/challenges --work work --out cgc.json
"""
import argparse
import collections
import glob
import hashlib
import difflib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the static_analysis/ folder
sys.path.insert(0, HERE)
import preprocess  # noqa: E402
import wide_net  # noqa: E402
from static_analyzer import (DEFAULT_EXCLUDES, DEFAULT_RULES, function_spans,  # noqa: E402
                             innermost, run_semgrep, source_files)

WIDE_RULES = sorted(glob.glob(os.path.join(HERE, "rules", "wide_net*.yaml")))
SRC_EXT = (".c", ".h", ".cc", ".cpp")
SKIP_DIRS = {"poller", "support"}
PATCH_SYM = re.compile(r"\bPATCHED\w*")


def skip_dir(name):
    return name in SKIP_DIRS or name.startswith("pov") or name in DEFAULT_EXCLUDES


def unifdef(path, syms, define):
    flags = [("-D" if define else "-U") + s for s in syms]
    p = subprocess.run(["unifdef", "-l", "-x", "2", *flags, path], capture_output=True,
                       text=True, errors="replace")
    return p.stdout


def prepare(src, work):
    """Vulnerable copies of every challenge under work/; returns {challenge: [regions]}."""
    bugs = {}
    for name in sorted(os.listdir(src)):
        cdir = os.path.join(src, name)
        if not os.path.isdir(cdir):
            continue
        regions = []
        for d, sub, files in os.walk(cdir):
            sub[:] = sorted(s for s in sub if not skip_dir(s))
            for f in sorted(files):
                if not f.endswith(SRC_EXT):
                    continue
                path = os.path.join(d, f)
                rel = os.path.relpath(path, src)
                text = open(path, errors="replace").read()
                dest = os.path.join(work, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                syms = sorted(set(PATCH_SYM.findall(text)))
                if not syms:
                    shutil.copyfile(path, dest)
                    continue
                vul, fixed = unifdef(path, syms, False), unifdef(path, syms, True)
                with open(dest, "w") as out:
                    out.write(vul)
                a, b = vul.splitlines(), fixed.splitlines()
                for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b,
                                                                  autojunk=False).get_opcodes():
                    if tag == "equal":
                        continue
                    lo, hi = i1 + 1, max(i1 + 1, i2)
                    # blank-only differences (lines that exist only in the fix) mark the spot
                    regions.append({"file": os.path.relpath(dest, work), "lo": lo, "hi": hi})
        if regions:
            bugs[name] = regions
    return bugs


def scan(work, rules):
    raw = run_semgrep([work], rules, sorted(DEFAULT_EXCLUDES))
    extra, _ = preprocess.recover(raw, lambda p: run_semgrep(p, rules), work,
                                  excludes=DEFAULT_EXCLUDES)
    hits = collections.defaultdict(set)
    for r in raw.get("results", []) + extra:
        rel = os.path.relpath(os.path.abspath(r["path"]), work)
        hits[rel].add((r["start"]["line"], r["check_id"].rsplit(".", 1)[-1]))
    return hits


def random_hit(n, k, frac):
    """P(a uniformly random ordering of n functions puts at least one of k bug functions in
    the first ceil(frac*n))."""
    m = min(n, max(0, int(round(frac * n + 0.4999))))
    if k <= 0 or n <= 0:
        return 0.0
    if n - k < m:
        return 1.0
    p_none = 1.0
    for i in range(m):
        p_none *= (n - k - i) / (n - i)
    return 1.0 - p_none


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="cb-multios/challenges")
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--window", type=int, default=5)
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    if os.path.isdir(work):
        shutil.rmtree(work)
    bugs = prepare(os.path.abspath(args.src), work)
    print(f"[*] {len(bugs)} challenges with PATCHED-marked vulnerabilities", file=sys.stderr)
    hits = collections.defaultdict(set)
    for rules in [DEFAULT_RULES] + WIDE_RULES:          # cached per rules file
        h = hashlib.sha1(open(rules, "rb").read()).hexdigest()[:10]
        cache = f"{args.out}.{os.path.basename(rules)}.{h}.hits.json"
        if os.path.exists(cache):
            got = {f: {tuple(x) for x in v} for f, v in json.load(open(cache)).items()}
        else:
            got = scan(work, [rules])
            json.dump({f: sorted(v) for f, v in got.items()}, open(cache, "w"))
        for f, v in got.items():
            hits[f] |= v
    precise = {f: {h for h in v if not h[1].startswith(wide_net.RULE_PREFIX)}
               for f, v in hits.items()}
    wide = {f: {h for h in v if h[1].startswith(wide_net.RULE_PREFIX)} for f, v in hits.items()}
    files = [os.path.relpath(p, work) for p in source_files(work, sorted(DEFAULT_EXCLUDES))]
    sp = function_spans(work, [os.path.join(work, f) for f in files], excludes=DEFAULT_EXCLUDES)
    spans = {os.path.relpath(k, work): sorted(v) for k, v in sp.items()}
    wide = {f: set(v) for f, v in wide_net.fill_unparsed(
        {f: sorted(v) for f, v in wide.items()}, work, files).items()}

    def read_lines(rel):
        try:
            return open(os.path.join(work, rel), errors="replace").read().splitlines()
        except OSError:
            return []

    rows = []
    for name, regions in sorted(bugs.items()):
        cfiles = [f for f in files if f.split("/")[0] == name]
        cspans = {f: spans.get(f, []) for f in cfiles}
        nfn = sum(len(v) for v in cspans.values())
        whits = [(f, ln, rule) for f in cfiles for ln, rule in wide.get(f, ())]
        aug = wide_net.add_orphan_groups(whits, cspans)

        def targets_in(sp):
            t = set()
            for r in regions:
                for ln in range(r["lo"], r["hi"] + 1):
                    got = innermost(sp.get(r["file"]), ln)
                    if got:
                        t.add((r["file"], got[0], got[1]))
            return t
        targets, w_targets = targets_in(cspans), targets_in(aug)
        ranked = wide_net.score_functions(whits, cspans, read_lines)
        pos = {d["key"]: (i, bool(d["own"])) for i, d in enumerate(ranked)}
        best = min((pos[t] for t in w_targets if t in pos), default=None)

        def line_hit(found):
            return any(r["lo"] - args.window <= ln <= r["hi"] + args.window
                       for r in regions for ln, _ in found.get(r["file"], ()))

        def fn_hit(found):
            return any(lo <= ln <= hi for f, lo, hi in targets for ln, _ in found.get(f, ()))

        rows.append({
            "challenge": name, "regions": regions,
            "targets": sorted(f"{f}:{lo}-{hi}" for f, lo, hi in targets | w_targets),
            "functions": nfn, "functions_flagged": len(ranked),
            "functions_flagged_own": sum(1 for d in ranked if d["own"]),
            "precise": {"line": line_hit(precise), "function": fn_hit(precise) or line_hit(precise)},
            "wide": {"line": line_hit(wide), "function": best is not None,
                     "via": None if best is None else ("own" if best[1] else "calls"),
                     "rank_pct": None if best is None or not nfn else round(100 * best[0] / nfn, 1)},
        })
    scored = rows                      # every challenge counts; no bug function = a miss
    summ = {"challenges": len(rows), "scorable": len(scored),
            "precise_function": sum(r["precise"]["function"] for r in scored),
            "precise_line": sum(r["precise"]["line"] for r in scored),
            "wide_function": sum(r["wide"]["function"] for r in scored),
            "wide_line": sum(r["wide"]["line"] for r in scored),
            "wide_via_calls": sum(r["wide"]["via"] == "calls" for r in scored)}
    for p in (10, 25, 50):
        summ[f"wide_top{p}pct"] = sum(1 for r in scored if r["wide"]["rank_pct"] is not None
                                      and r["wide"]["rank_pct"] < p)
        # what a random ordering of the same functions would give (expected count)
        summ[f"random_top{p}pct"] = round(sum(random_hit(r["functions"], len(r["targets"]),
                                                         p / 100) for r in scored), 1)
    summ["functions_flagged_share"] = round(
        sum(r["functions_flagged"] for r in scored) / max(1, sum(r["functions"] for r in scored)), 3)
    json.dump({"summary": summ, "challenges": rows}, open(args.out, "w"), indent=1)
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
