#!/usr/bin/env python3
"""Wide-net tier on Magma: is each bug's function on the ranked list, and how high?

Needs what magma_benchmark.py leaves behind when run with --keep-work: the vulnerable library
copies in --work (patched, fixes stripped) and its output JSON (each bug's changed lines).

  python3 benchmarks/magma_wide_eval.py --work work --magma-results magma.json \
      --libs openssl php poppler sqlite3                      # held-out (the clean test)
  python3 benchmarks/magma_wide_eval.py --work work --magma-results magma.json \
      --libs libpng libsndfile libtiff libxml2 lua            # tuning libraries (not a test)

Scored exactly the way the stage ranks: the same Semgrep rules (rules/wide_net*.yaml), the same
function spans (static_analyzer.function_spans, heuristic recovery included), the same ranking
(wide_net.score_functions), orphan groups for code outside any function, and the line-pattern
fallback for files Semgrep can't read.

A bug is "flagged" when a function its patch changed is on the list; "exact spot" when a risky
operation is within --window lines of a changed line; topN% = the bug's best function is in the
first N% of the library's functions.
"""
import argparse
import collections
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the static_analysis/ folder
sys.path.insert(0, HERE)
import preprocess  # noqa: E402
import wide_net  # noqa: E402
from static_analyzer import (DEFAULT_EXCLUDES, WIDE_RULES, function_spans, innermost,  # noqa: E402
                             run_semgrep, source_files)


def rules_hash():
    h = hashlib.sha1()
    for r in WIDE_RULES:
        h.update(open(r, "rb").read())
    return h.hexdigest()[:10]


def cached(path, make):
    if path and os.path.exists(path):
        return json.load(open(path))
    val = make()
    if path:
        json.dump(val, open(path, "w"))
    return val


def wide_hits(root):
    raw = run_semgrep([root], WIDE_RULES, DEFAULT_EXCLUDES)
    extra, _ = preprocess.recover(raw, lambda p: run_semgrep(p, WIDE_RULES), root,
                                  excludes=DEFAULT_EXCLUDES)
    return sorted({(os.path.relpath(r["path"], root), r["start"]["line"],
                    r["check_id"].rsplit(".", 1)[-1])
                   for r in raw.get("results", []) + extra if wide_net.is_wide(r)})


def spans_of(root):
    sp = function_spans(root, source_files(root, DEFAULT_EXCLUDES), excludes=DEFAULT_EXCLUDES)
    return {os.path.relpath(k, root): sorted(v) for k, v in sp.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--work", required=True, help="magma_benchmark.py --work dir (--keep-work)")
    ap.add_argument("--magma-results", required=True, help="magma_benchmark.py output JSON")
    ap.add_argument("--libs", nargs="+", required=True)
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--cache", help="dir to cache scans in (keyed by the rules' hash)")
    ap.add_argument("--out", help="per-bug rows as JSON")
    args = ap.parse_args()
    if args.cache:
        os.makedirs(args.cache, exist_ok=True)
    rh = rules_hash()
    bugs = {t["target"]: t["bugs"] for t in json.load(open(args.magma_results))["targets"]}

    rows, agg = [], collections.Counter()
    for lib in args.libs:
        root = os.path.abspath(os.path.join(args.work, lib))
        c = (lambda name: os.path.join(args.cache, f"{lib}.{name}.json")) if args.cache \
            else (lambda name: None)
        hits = [tuple(h) for h in cached(c(f"hits.{rh}"), lambda: wide_hits(root))]
        spans = {k: [tuple(x) for x in v] for k, v in cached(c("spans"),
                                                              lambda: spans_of(root)).items()}
        byf = collections.defaultdict(list)
        for f, ln, r in hits:
            byf[f].append((ln, r))
        srcs = [os.path.relpath(p, root) for p in source_files(root, DEFAULT_EXCLUDES)]
        filled = wide_net.fill_unparsed(byf, root, srcs)
        hits = [(f, ln, r) for f, v in filled.items() for ln, r in v]
        nfn = sum(len(v) for v in spans.values())

        def read_lines(rel, root=root):
            try:
                return open(os.path.join(root, rel), errors="replace").read().splitlines()
            except OSError:
                return []
        ranked = wide_net.score_functions(hits, spans, read_lines)
        pos = {d["key"]: i for i, d in enumerate(ranked)}
        aug = wide_net.add_orphan_groups(hits, spans)
        n = collections.Counter()
        for b in bugs.get(lib, []):
            if b["status"] != "ok":
                continue
            targets = set()
            for r in b["regions"]:
                for ln in range(r["lo"], r["hi"] + 1):
                    fn = innermost(aug.get(r["file"]), ln)
                    if fn:
                        targets.add((r["file"], fn[0], fn[1]))
            exact = any(f == r["file"] and r["lo"] - args.window <= ln <= r["hi"] + args.window
                        for f, ln, _ in hits for r in b["regions"])
            best = min([pos[k] for k in targets if k in pos], default=None)
            via = None if best is None else ("own" if ranked[best]["own"] else "calls")
            rows.append({"lib": lib, "bug": b["bug"], "flagged": best is not None, "via": via,
                         "rank": None if best is None else best + 1,
                         "rank_pct": None if best is None else round(100 * best / nfn, 1),
                         "exact_spot": exact,
                         "targets": sorted(f"{f}:{lo}-{hi}" for f, lo, hi in targets)})
            n["bugs"] += 1
            n["flagged"] += best is not None
            n["exact"] += exact
            n["via_calls"] += via == "calls"
            for p in (10, 25, 50):
                n[f"top{p}"] += best is not None and best < p / 100 * nfn
        n["functions"] += nfn
        n["listed"] += len(ranked)
        print(f"{lib:<11} bugs {n['bugs']:>3} flagged {n['flagged']:>3} (via calls "
              f"{n['via_calls']}) exact-spot {n['exact']:>3} | top10% {n['top10']:>3} top25% "
              f"{n['top25']:>3} top50% {n['top50']:>3} | listed {len(ranked)}/{nfn} functions",
              flush=True)
        agg.update(n)
    print(f"{'TOTAL':<11} bugs {agg['bugs']:>3} flagged {agg['flagged']:>3} (via calls "
          f"{agg['via_calls']}) exact-spot {agg['exact']:>3} | top10% {agg['top10']:>3} top25% "
          f"{agg['top25']:>3} top50% {agg['top50']:>3} | listed {agg['listed']}/{agg['functions']}"
          " functions")
    if args.out:
        json.dump(rows, open(args.out, "w"), indent=1)


if __name__ == "__main__":
    main()
