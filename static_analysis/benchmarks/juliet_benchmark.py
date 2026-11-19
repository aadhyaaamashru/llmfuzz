#!/usr/bin/env python3
"""
Benchmark the static analyzer against the Juliet test suite (labeled ground truth).

Ground truth
------------
Juliet's manifest.xml lists the exact flaw line(s) of every test case. A finding is:
  - TP        if its span [start, end] contains a flaw line of the test case's CWE
              (spans longer than MAX_SPAN lines don't count, so a rule can't "win"
              by matching a whole function)
  - FP        if it lands inside a `#ifndef OMITGOOD` region (code Juliet labels safe)
  - off-target otherwise (inside bad() but not on the flaw line, or in main/helpers).
              Reported, but neither TP nor FP.

Recall    = test cases with >=1 TP finding / test cases
Precision = TP findings / (TP + FP findings)
The old metric ("any finding anywhere inside OMITBAD") is still reported as
recall_lenient so earlier numbers stay comparable.

Splits (so we don't tune rules and report on the same files)
------
  dev   = baseline variants (_01). Iterate rules against this.
  test  = every other flow variant (_02.._84).
  tune  = half of `test`: every other functional variant (bug shape, e.g. "malloc_free_char")
          of each CWE, all flow variants. Tune rules against this.
  final = the other half of `test`. Never tune on it; it measures whether fixes generalize
          to bug shapes the rules were not tuned on.
  all   = dev + test.
Juliet flow variants 01-34 keep source and sink in ONE function; 41+ split them across
functions/files. Recall is reported for both groups ("intra" / "inter"): pattern rules can
only be expected to do well on intra, so inter is the gap the CodeQL backend has to close.

Noise
-----
--noise PATH... scans real code (no ground truth) and reports findings/KLOC per rule:
the triage cost the LLM stage pays. Juliet can't show that a rule floods real code;
this can.

Parse coverage
--------------
Files Semgrep can't parse are re-scanned through a line-aligned preprocessed copy, exactly as
static_analyzer.py does (see preprocess.py), and the run reports how many files didn't parse.
--preprocess off   disables the fallback (to compare)
--preprocess force preprocesses EVERY file: if recall/precision match `auto`, preprocessing
                   doesn't change what the rules find.

Usage:
  python3 benchmarks/juliet_benchmark.py --juliet juliet-test-suite-c --split dev \
      --noise ~/corpus/libspng ~/corpus/zlib --misses misses.txt --out benchmark.json
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the static_analysis/ folder
sys.path.insert(0, HERE)
import preprocess  # noqa: E402
import codeql_backend  # noqa: E402
from static_analyzer import DEFAULT_EXCLUDES  # noqa: E402

DEFAULT_RULES = os.path.join(HERE, "rules", "memory_safety.yaml")
MAX_SPAN = 15

# Memory-safety CWEs whose bugs AddressSanitizer (the pipeline's oracle) can confirm.
MEMORY_CWES = [
    "CWE121", "CWE122", "CWE124", "CWE126", "CWE127",   # spatial: over/under write/read
    "CWE134",                                           # format string
    "CWE415", "CWE416",                                 # temporal: double free, UAF
    "CWE476", "CWE690",                                 # NULL deref
    "CWE590", "CWE761",                                 # invalid free
    "CWE680", "CWE789",                                 # bad allocation size
    "CWE194", "CWE195",                                 # negative length -> huge size_t
]
ORIGINAL_CWES = ["CWE121", "CWE122", "CWE134", "CWE416", "CWE476"]

VARIANT_RE = re.compile(r"_(\d\d)(?:[a-z]|_bad|_good\w*)?\.(c|cpp)$")


def functional_variant(name):
    """CWE415_Double_Free__malloc_free_char_02.c -> CWE415_Double_Free__malloc_free_char"""
    m = VARIANT_RE.search(name)
    return name[:m.start()] if m else name


def split_of(juliet, tree):
    """tune/final assignment: alternate functional variants (sorted) within each CWE."""
    fvs = collections.defaultdict(set)
    for tc in tree.getroot():
        f = tc.find("file")
        if f is not None:
            name = f.get("path")
            fvs[name.split("_", 1)[0]].add(functional_variant(name))
    return {fv: ("tune" if i % 2 == 0 else "final")
            for names in fvs.values() for i, fv in enumerate(sorted(names))}


# --------------------------------------------------------------------------- ground truth
def load_manifest(juliet, cwes, langs, split):
    """Return {testcase_id: {"cwe", "variant", "files": {path: [flaw lines]}}}."""
    index = {}
    for root, _, files in os.walk(os.path.join(juliet, "testcases")):
        for f in files:
            index[f] = os.path.join(root, f)

    cases = {}
    tree = ET.parse(os.path.join(juliet, "manifest.xml"))
    half = split_of(juliet, tree)
    for n, tc in enumerate(tree.getroot()):
        files = tc.findall("file")
        if not files:
            continue
        first = files[0].get("path")
        cwe = first.split("_", 1)[0]
        if cwe not in cwes:
            continue
        ext = first.rsplit(".", 1)[-1]
        if ext not in langs:
            continue
        m = VARIANT_RE.search(first)
        variant = m.group(1) if m else "??"
        if split == "dev" and variant != "01":
            continue
        if split in ("test", "tune", "final") and variant == "01":
            continue
        if split in ("tune", "final") and half.get(functional_variant(first)) != split:
            continue
        want = "CWE-" + cwe[3:] + ":"
        entry = {"cwe": cwe, "variant": variant, "files": {}}
        for f in files:
            path = index.get(f.get("path"))
            if not path:
                continue
            flaws = [int(fl.get("line")) for fl in f.findall("flaw")
                     if fl.get("name", "").startswith(want)]
            entry["files"][path] = flaws
        if any(entry["files"].values()):
            cases[n] = entry
    return cases


def regions(path):
    """Return (bad_ranges, good_ranges): line spans of OMITBAD / OMITGOOD guards."""
    bad, good = [], []
    cur_bad = cur_good = None
    with open(path, errors="replace") as f:
        for idx, line in enumerate(f, 1):
            if "#ifndef OMITBAD" in line:
                cur_bad = idx
            elif "#endif" in line and "OMITBAD" in line and cur_bad:
                bad.append((cur_bad, idx)); cur_bad = None
            elif "#ifndef OMITGOOD" in line:
                cur_good = idx
            elif "#endif" in line and "OMITGOOD" in line and cur_good:
                good.append((cur_good, idx)); cur_good = None
    return bad, good


def flow_group(variant):
    return "intra" if variant.isdigit() and int(variant) <= 34 else "inter"


def in_ranges(line, ranges):
    return any(a <= line <= b for a, b in ranges)


# --------------------------------------------------------------------------- semgrep
def run_semgrep(paths, configs, includes=None):
    cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore", "--disable-version-check",
           "--metrics", "off", "--timeout", "30", "--max-target-bytes", "5000000",
           "--timeout-threshold", "0"]
    for c in configs:
        cmd += ["--config", c]
    for inc in includes or []:
        cmd += ["--include", inc]
    p = subprocess.run(cmd + list(paths), capture_output=True, text=True)
    if p.returncode not in (0, 1):
        sys.stderr.write(p.stderr[-4000:])
        raise RuntimeError(f"semgrep failed (exit {p.returncode})")
    out = json.loads(p.stdout or "{}")
    errs = [e for e in out.get("errors", []) if e.get("level") == "error"]
    if errs:
        print(f"[!] semgrep reported {len(errs)} errors (first: "
              f"{errs[0].get('message', '')[:200]})", file=sys.stderr)
    return out


def scan_with_fallback(paths, configs, root, mode, includes=None, only=None, label=""):
    """Semgrep pass + preprocessing fallback for unparseable files. -> (results, coverage)"""
    raw = run_semgrep(paths, configs, includes)
    scan = None if mode == "off" else (lambda files: run_semgrep(files, configs))
    extra, cov = preprocess.recover(raw, scan, root, only=only, force=(mode == "force"))
    print(f"[*] {label}{preprocess.summary_line(cov)}", file=sys.stderr)
    base = raw.get("results", [])
    if mode == "force":
        # faithfulness test: for every file that was preprocessed, score ONLY the copy's findings
        done = {os.path.abspath(os.path.join(root, rel)) for rel, f in cov["files"].items()
                if f.get("preprocess") == "ok"}
        base = [r for r in base if os.path.abspath(r["path"]) not in done]
    return base + extra, cov


def dedupe(results):
    seen, out = set(), []
    for r in results:
        k = (r["check_id"], os.path.abspath(r["path"]), r["start"]["line"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def short_rule(check_id):
    return check_id.rsplit(".", 1)[-1]


# --------------------------------------------------------------------------- codeql
def _queries_hash(queries):
    """Hash of the query files' contents, so cached results are reused only for the same queries."""
    h = hashlib.sha1()
    paths = set()
    for q in queries:
        if os.path.isfile(q):
            paths.add(os.path.abspath(q))
            paths.update(glob.glob(os.path.join(os.path.dirname(os.path.abspath(q)), "**", "*.ql*"),
                                   recursive=True))
        else:
            h.update(q.encode())
    for p in sorted(paths):
        h.update(p.encode())
        with open(p, "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:16]


def codeql_results(root, name, args, include_flags=None, excludes=()):
    """CodeQL results for a tree, from the cached database <codeql-db-dir>/<name>. The SARIF is
    cached next to it per query version: the database covers every split, so tune / final /
    both-backend runs reuse one analysis."""
    db = os.path.join(args.codeql_db_dir, name)
    if not os.path.exists(os.path.join(db, ".done")):
        codeql_backend.create_db(root, db, excludes=excludes, include_flags=include_flags)
        open(os.path.join(db, ".done"), "w").close()
    cache = os.path.join(db, f"results-{_queries_hash(args.codeql_queries)}.sarif")
    if os.path.exists(cache):
        with open(cache) as f:
            sarif = json.load(f)
    else:
        sarif = codeql_backend.analyze(db, args.codeql_queries, out=cache,
                                       threads=args.codeql_threads)
    res = codeql_backend.results(sarif, os.path.abspath(root))
    print(f"[*] codeql {name}: {len(res)} results", file=sys.stderr)
    return res


# --------------------------------------------------------------------------- misses
def sink_key(src):
    """Cluster a flaw line by its first call name, or by its token shape."""
    calls = [c for c in re.findall(r"\b([A-Za-z_]\w*)\s*\(", src)
             if c not in ("if", "for", "while", "switch", "sizeof", "return")]
    if calls:
        return calls[0] + "()"
    return re.sub(r"\b\w+\b", "ID", src)[:40]


def kloc(path):
    n = 0
    for ext in ("c", "h", "cc", "cpp", "hpp"):
        for f in glob.glob(os.path.join(path, "**", f"*.{ext}"), recursive=True):
            with open(f, errors="replace") as fh:
                n += sum(1 for _ in fh)
    return n / 1000.0


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet", required=True)
    ap.add_argument("--config", nargs="+", default=[DEFAULT_RULES],
                    help="one or more semgrep configs (they are unioned)")
    ap.add_argument("--cwes", nargs="+", default=MEMORY_CWES,
                    help="CWE prefixes, e.g. CWE121 CWE416 (or 'original' for the first 5)")
    ap.add_argument("--lang", nargs="+", default=["c", "cpp"], choices=["c", "cpp"])
    ap.add_argument("--split", default="dev", choices=["dev", "test", "tune", "final", "all"])
    ap.add_argument("--noise", nargs="*", default=[],
                    help="real code trees to measure findings/KLOC on")
    ap.add_argument("--misses", help="write missed flaw lines (clustered) to this file")
    ap.add_argument("--preprocess", default="auto", choices=["auto", "off", "force"],
                    help="fallback for files semgrep can't parse (force = every file)")
    ap.add_argument("--backend", default="semgrep", choices=["semgrep", "codeql", "both"])
    ap.add_argument("--codeql-db-dir", help="where CodeQL databases are cached "
                    "(juliet_<CWE>, noise_<name>); created if missing")
    ap.add_argument("--codeql-queries", nargs="+", default=codeql_backend.DEFAULT_QUERIES,
                    help="CodeQL query files / .qls suites")
    ap.add_argument("--codeql-threads", type=int, default=0)
    ap.add_argument("--out", default="benchmark.json")
    args = ap.parse_args()
    if args.backend != "semgrep" and not args.codeql_db_dir:
        ap.error("--codeql-db-dir is required for the codeql backend")

    cwes = ORIGINAL_CWES if args.cwes == ["original"] else \
        [c.split("_", 1)[0] for c in args.cwes]

    # 1. ground truth
    cases = load_manifest(args.juliet, set(cwes), set(args.lang), args.split)
    files = sorted({p for c in cases.values() for p in c["files"]})
    print(f"[*] {len(cases)} test cases, {len(files)} files "
          f"(split={args.split}, lang={','.join(args.lang)})", file=sys.stderr)

    # 2. one semgrep pass over the CWE directories, filtered to our files
    dirs = sorted({os.path.join(args.juliet, "testcases",
                                os.path.relpath(p, os.path.join(args.juliet, "testcases"))
                                .split(os.sep)[0]) for p in files})
    if args.split == "dev":
        includes = ["*_01.c", "*_01.cpp"]
    elif args.split in ("tune", "final"):     # only scan this half's files
        includes = sorted({functional_variant(os.path.basename(p)) + "_*" for p in files})
    else:
        includes = None
    wanted = {os.path.abspath(p) for p in files}
    results, juliet_cov = [], {}
    if args.backend in ("semgrep", "both"):
        results, juliet_cov = scan_with_fallback(dirs, args.config, args.juliet, args.preprocess,
                                                 includes, only=wanted, label="juliet: ")
    if args.backend in ("codeql", "both"):
        for d in dirs:
            results += codeql_results(d, f"juliet_{os.path.basename(d).split('_', 1)[0]}",
                                      args, include_flags=[
                                          "-I" + os.path.join(args.juliet, "testcasesupport")])
    results = dedupe(results)
    byfile = collections.defaultdict(list)
    for r in results:
        ap_ = os.path.abspath(r["path"])
        if ap_ in wanted:
            byfile[ap_].append((r["start"]["line"], r["end"]["line"], short_rule(r["check_id"])))

    # 3. score
    region_cache = {}
    per_cwe = collections.defaultdict(lambda: collections.Counter())
    per_rule = collections.defaultdict(lambda: collections.Counter())
    rule_cases = collections.defaultdict(set)
    detected = {}
    missed = []
    for cid, case in cases.items():
        cwe = case["cwe"]
        hit_strict = hit_lenient = False
        for path, flaws in case["files"].items():
            path = os.path.abspath(path)
            if path not in region_cache:
                region_cache[path] = regions(path)
            bad, good = region_cache[path]
            for (s, e, rule) in byfile.get(path, []):
                if e - s <= MAX_SPAN and any(s <= fl <= e for fl in flaws):
                    hit_strict = True
                    per_cwe[cwe]["tp"] += 1
                    per_rule[rule]["tp"] += 1
                    rule_cases[rule].add(cid)
                elif in_ranges(s, good):
                    per_cwe[cwe]["fp"] += 1
                    per_rule[rule]["fp"] += 1
                else:
                    per_cwe[cwe]["off"] += 1
                    per_rule[rule]["off"] += 1
                if in_ranges(s, bad):
                    hit_lenient = True
        g = flow_group(case["variant"])
        per_cwe[cwe]["cases"] += 1
        per_cwe[cwe]["hit"] += hit_strict
        per_cwe[cwe]["cases_" + g] += 1
        per_cwe[cwe]["hit_" + g] += hit_strict
        per_cwe[cwe]["hit_lenient"] += hit_lenient
        detected[cid] = hit_strict
        if not hit_strict:
            for path, flaws in case["files"].items():
                lines = open(path, errors="replace").read().splitlines()
                for fl in flaws:
                    missed.append((cwe, os.path.basename(path), fl, lines[fl - 1].strip()))

    # unique contribution: cases only this rule catches
    case_rules = collections.defaultdict(set)
    for rule, cids in rule_cases.items():
        for cid in cids:
            case_rules[cid].add(rule)
    for cid, rules in case_rules.items():
        if len(rules) == 1:
            per_rule[next(iter(rules))]["unique"] += 1

    # 4. noise on real code
    noise = {}
    if args.noise:
        total_kloc = sum(kloc(p) for p in args.noise)
        nres, noise_cov = [], {}
        for t in args.noise:
            res = []
            if args.backend in ("semgrep", "both"):
                res, cov = scan_with_fallback([t], args.config, t, args.preprocess,
                                              label=f"{os.path.basename(t.rstrip('/'))}: ")
                noise_cov[t] = {k: v for k, v in cov.items() if k != "files"}
            if args.backend in ("codeql", "both"):
                res += codeql_results(t, f"noise_{os.path.basename(t.rstrip('/'))}", args,
                                      excludes=DEFAULT_EXCLUDES)
            nres += dedupe(res)
        counts = collections.Counter(short_rule(r["check_id"]) for r in nres)
        noise = {"targets": args.noise, "kloc": round(total_kloc, 1),
                 "parse_coverage": noise_cov,
                 "findings": len(nres),
                 "per_kloc": round(len(nres) / total_kloc, 2) if total_kloc else 0,
                 "per_rule": dict(counts.most_common())}
        for rule, n in counts.items():
            per_rule[rule]["noise"] = n

    # 5. report
    def pct(a, b):
        return round(a / b, 3) if b else 0.0

    rows = []
    for cwe in cwes:
        c = per_cwe.get(cwe)
        if not c:
            continue
        rows.append({"cwe": cwe, "test_cases": c["cases"], "detected": c["hit"],
                     "recall": pct(c["hit"], c["cases"]),
                     "recall_lenient": pct(c["hit_lenient"], c["cases"]),
                     "recall_intra": pct(c["hit_intra"], c["cases_intra"]),
                     "recall_inter": pct(c["hit_inter"], c["cases_inter"]),
                     "cases_inter": c["cases_inter"],
                     "tp_findings": c["tp"], "fp_findings": c["fp"], "off_target": c["off"],
                     "precision": pct(c["tp"], c["tp"] + c["fp"])})
    T = collections.Counter()
    for c in per_cwe.values():
        T.update(c)
    overall = {"test_cases": T["cases"], "detected": T["hit"],
               "recall": pct(T["hit"], T["cases"]),
               "recall_lenient": pct(T["hit_lenient"], T["cases"]),
               "recall_intra": pct(T["hit_intra"], T["cases_intra"]),
               "recall_inter": pct(T["hit_inter"], T["cases_inter"]),
               "cases_inter": T["cases_inter"],
               "tp_findings": T["tp"], "fp_findings": T["fp"], "off_target": T["off"],
               "precision": pct(T["tp"], T["tp"] + T["fp"]),
               "missed": T["cases"] - T["hit"]}
    rules = {r: dict(c) for r, c in sorted(per_rule.items(), key=lambda kv: -kv[1]["tp"])}

    clusters = collections.defaultdict(list)
    for m in missed:
        clusters[(m[0], sink_key(m[3]))].append(m)
    top_misses = sorted(clusters.items(), key=lambda kv: -len(kv[1]))
    report = {"config": args.config, "backend": args.backend,
              "codeql_queries": args.codeql_queries if args.backend != "semgrep" else None,
              "split": args.split, "lang": args.lang,
              "preprocess": args.preprocess,
              "juliet_parse_coverage": {k: v for k, v in juliet_cov.items() if k != "files"},
              "per_cwe": rows, "overall": overall, "per_rule": rules, "noise": noise,
              "top_miss_clusters": [{"cwe": k[0], "sink": k[1], "count": len(v),
                                     "example": f"{v[0][1]}:{v[0][2]}  {v[0][3]}"}
                                    for k, v in top_misses[:40]]}
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    if args.misses:
        by_var = collections.defaultdict(collections.Counter)
        for cid, case in cases.items():
            if not detected[cid]:
                by_var[case["cwe"]][case["variant"]] += 1
        with open(args.misses, "w") as f:
            f.write("missed test cases per CWE, by flow variant (01-34 intra, 41+ inter):\n")
            for cwe in sorted(by_var):
                f.write(f"  {cwe}: " + " ".join(f"{v}:{n}" for v, n in sorted(by_var[cwe].items()))
                        + "\n")
            f.write("\n")
            for (cwe, key), v in top_misses:
                f.write(f"== {cwe}  {key}  ({len(v)})\n")
                for m in v[:5]:
                    f.write(f"   {m[1]}:{m[2]}  {m[3]}\n")

    def inter(r):
        return f"{r['recall_inter']*100:>6.1f}%" if r["cases_inter"] else "     -"

    print(f"\n{'CWE':<10} {'cases':>6} {'recall':>8} {'intra':>7} {'inter':>7} {'lenient':>8} "
          f"{'prec':>7} {'FP':>6}")
    print("-" * 66)
    for r in rows:
        print(f"{r['cwe']:<10} {r['test_cases']:>6} {r['recall']*100:>7.1f}% "
              f"{r['recall_intra']*100:>6.1f}% {inter(r)} "
              f"{r['recall_lenient']*100:>7.1f}% {r['precision']*100:>6.1f}% {r['fp_findings']:>6}")
    print("-" * 66)
    o = overall
    print(f"{'OVERALL':<10} {o['test_cases']:>6} {o['recall']*100:>7.1f}% "
          f"{o['recall_intra']*100:>6.1f}% {inter(o)} "
          f"{o['recall_lenient']*100:>7.1f}% {o['precision']*100:>6.1f}% {o['fp_findings']:>6}"
          f"   missed={o['missed']}")
    print(f"\n{'rule':<38} {'TP':>6} {'FP':>6} {'uniq':>5} {'noise':>6}")
    for r, c in rules.items():
        print(f"{r[:37]:<38} {c.get('tp', 0):>6} {c.get('fp', 0):>6} "
              f"{c.get('unique', 0):>5} {c.get('noise', '-'):>6}")
    if noise:
        print(f"\nnoise: {noise['findings']} findings over {noise['kloc']} KLOC "
              f"= {noise['per_kloc']}/KLOC")
    print(f"\n[+] full report -> {args.out}")


if __name__ == "__main__":
    main()
