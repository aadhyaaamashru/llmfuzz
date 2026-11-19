#!/usr/bin/env python3
"""Real-bug benchmark: run the static-analysis stage on Magma's libraries and score it
against Magma's documented bugs (real CVEs re-inserted into real libraries).

Magma (Hazimeh et al., SIGMETRICS 2021) ships each library at a pinned commit plus one patch
per bug. A patch wraps the fix in `#ifdef MAGMA_ENABLE_FIXES` and adds a canary under
`#ifdef MAGMA_ENABLE_CANARIES`. This script:

  1. copies each library, applies the setup patches and every bug patch, and records which
     lines each bug patch touched (positions are tracked as later patches shift the file)
  2. strips fixes and canaries with `unifdef -l` (removed lines become blank, so line numbers
     stay put) -- what's left is the vulnerable library, nothing else
  3. runs static_analyzer.py on it exactly as on a real target (default excludes,
     preprocessing fallback)
  4. scores each bug:
       line-level      a finding within --window lines of a line the bug patch changed
       function-level  a finding anywhere in a function the bug patch changed (the
                       criterion of Lipp et al., ISSTA 2022, and Hassler et al., 2025)
     Automatic hits only say "a finding landed here". Whether the finding actually describes
     the bug has to be checked by hand: --hits writes each hit next to the bug's code.

  python3 benchmarks/magma_benchmark.py --magma magma --src src --work work --out magma.json \
      --hits magma_hits.txt
"""
import argparse
import collections
import concurrent.futures
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the static_analysis/ folder
sys.path.insert(0, HERE)
from static_analyzer import DEFAULT_EXCLUDES, function_spans  # noqa: E402

SRC_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
MERGE_GAP = 6          # changed lines closer than this belong to one region (one patch hunk)

def read_lines(path):
    try:
        with open(path, errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return []


# ---------------------------------------------------------------- fetch


def fetch(magma, name, dest):
    """Fetch a target at Magma's pinned commit (parsed from its fetch.sh)."""
    if os.path.isdir(dest) and os.listdir(dest):
        return
    script = open(os.path.join(magma, "targets", name, "fetch.sh")).read()
    os.makedirs(dest, exist_ok=True)
    url = re.search(r"git clone[^\n]*?(https://\S+)", script.replace("\\\n", " "))
    sha = re.search(r"checkout\s+([0-9a-f]{40})", script)
    if url and sha:
        for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", url.group(1)],
                    ["git", "fetch", "-q", "--depth", "1", "origin", sha.group(1)],
                    ["git", "checkout", "-q", "FETCH_HEAD"]):
            subprocess.run(cmd, cwd=dest, check=True)
        return
    tar = re.search(r'curl\s+"([^"]+)"', script)
    if not tar:
        raise RuntimeError(f"can't parse {name}/fetch.sh")
    archive = dest + ".tar.gz"
    subprocess.run(["curl", "-sSL", tar.group(1), "-o", archive], check=True)
    subprocess.run(["tar", "-C", dest, "--strip-components=1", "-xzf", archive], check=True)


# ---------------------------------------------------------------- build the vulnerable tree


def remap(line, opcodes):
    """Map a 1-based line in the old file to the new file."""
    i = line - 1
    for tag, i1, i2, j1, j2 in opcodes:
        if i1 <= i < i2 or (tag == "insert" and i == i1 and i1 == i2):
            if tag == "equal":
                return j1 + (i - i1) + 1
            return j1 + 1
    return line + (opcodes[-1][4] - opcodes[-1][2]) if opcodes else line


def changed_regions(opcodes):
    """New-file line ranges (1-based, inclusive) touched by a patch, hunks merged."""
    spans = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        lo, hi = j1 + 1, max(j1 + 1, j2)       # pure deletions: the line where it happened
        if spans and lo - spans[-1][1] <= MERGE_GAP:
            spans[-1][1] = max(spans[-1][1], hi)
        else:
            spans.append([lo, hi])
    return spans


def apply_patch(root, text):
    proc = subprocess.run(["patch", "-p1", "-s", "-f", "-d", root], input=text,
                          capture_output=True, text=True)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def prepare(magma, name, src, work, keep=False):
    """Copy src -> work, apply Magma patches, strip fixes/canaries. Returns the bug table.
    keep=True: the tree in `work` was prepared before; patch a scratch copy only to recompute
    the bug table, and leave `work` untouched."""
    if keep and os.path.isdir(work):
        with tempfile.TemporaryDirectory() as tmp:
            return prepare(magma, name, src, os.path.join(tmp, name))
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(src, work, ignore=shutil.ignore_patterns(".git"), symlinks=True)
    pdir = os.path.join(magma, "targets", name, "patches")

    for p in sorted(os.listdir(os.path.join(pdir, "setup"))) if os.path.isdir(
            os.path.join(pdir, "setup")) else []:
        if p.endswith(".patch"):
            ok, msg = apply_patch(work, open(os.path.join(pdir, "setup", p)).read())
            if not ok:
                print(f"    setup {p}: {msg[:200]}", file=sys.stderr)

    bugs = {}
    touched = set()
    for p in sorted(os.listdir(os.path.join(pdir, "bugs"))):
        if not p.endswith(".patch"):
            continue
        bug = p[:-len(".patch")]
        text = open(os.path.join(pdir, "bugs", p)).read().replace("%MAGMA_BUG%", bug)
        files = re.findall(r"^\+\+\+ b/(\S+)", text, re.M)
        before = {f: read_lines(os.path.join(work, f)) for f in files}
        ok, msg = apply_patch(work, text)
        regions = []
        for f in files:
            after = read_lines(os.path.join(work, f))
            ops = difflib.SequenceMatcher(None, before[f], after, autojunk=False).get_opcodes()
            # earlier bugs in this file move with this patch
            for other in bugs.values():
                for r in other["regions"]:
                    if r["file"] == f:
                        r["lo"], r["hi"] = remap(r["lo"], ops), remap(r["hi"], ops)
            for lo, hi in changed_regions(ops):
                regions.append({"file": f, "lo": lo, "hi": hi})
            touched.add(f)
        bugs[bug] = {"regions": regions, "patch_ok": ok, "patch_msg": "" if ok else msg[:300]}

    for f in sorted(touched):
        path = os.path.join(work, f)
        n = len(read_lines(path))
        # (LUA004's patch spells it ENABLE_MAGMA_FIXES; Magma never defines that either)
        subprocess.run(["unifdef", "-l", "-m", "-UMAGMA_ENABLE_FIXES", "-UENABLE_MAGMA_FIXES",
                        "-UMAGMA_ENABLE_CANARIES", path], capture_output=True)
        if len(read_lines(path)) != n:
            raise RuntimeError(f"unifdef changed the line count of {f}")
        left = [i + 1 for i, s in enumerate(read_lines(path)) if "MAGMA" in s]
        if left:
            print(f"    warning: MAGMA still in {f} at lines {left[:5]}", file=sys.stderr)
    for root, _, names in os.walk(work):           # leftovers from fuzzy patching
        for n in names:
            if n.endswith((".orig", ".rej")):
                os.remove(os.path.join(root, n))
    return bugs


# ---------------------------------------------------------------- analysis


def excluded(rel, excludes):
    parts = rel.split(os.sep)
    return any(p in excludes for p in parts[:-1]) or parts[-1] in excludes


def kloc(root, excludes):
    total = 0
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in excludes and not d.startswith(".")]
        for n in names:
            if n.endswith(SRC_EXT):
                total += len(read_lines(os.path.join(dirpath, n)))
    return total / 1000.0


def run_analyzer(root, out, backend="semgrep", codeql_db=None, codeql_queries=None):
    cmd = [sys.executable, os.path.join(HERE, "static_analyzer.py"), "--target", root,
           "--out", out, "--backend", backend]
    if codeql_db:
        cmd += ["--codeql-db", codeql_db]
    if codeql_queries:
        cmd += ["--codeql-queries", *codeql_queries]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-2000:])
        raise RuntimeError("static_analyzer.py failed")
    return json.load(open(out))


def function_spans_rel(root, rels, always_preprocess=()):
    """static_analyzer.function_spans keyed by path relative to root."""
    ab = function_spans(root, [os.path.join(root, r) for r in rels],
                        always_preprocess=[os.path.join(root, r) for r in always_preprocess])
    root = os.path.abspath(root)
    return collections.defaultdict(set, {os.path.relpath(k, root): v for k, v in ab.items()})


# ---------------------------------------------------------------- scoring


def score(name, bugs, findings, spans, window, excludes):
    by_file = collections.defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)
    rows = []
    for bug, b in sorted(bugs.items()):
        regions = b["regions"]
        scanned = [r for r in regions
                   if r["file"].endswith(SRC_EXT) and not excluded(r["file"], excludes)]
        funcs = set()
        for r in regions:
            for lo, hi, fn in spans.get(r["file"], ()):
                if lo <= r["hi"] and r["lo"] <= hi:
                    funcs.add((r["file"], lo, hi, fn))
        line_hits, fn_hits = [], []
        for f in {r["file"] for r in regions}:
            for fd in by_file.get(f, ()):
                if any(r["file"] == f and r["lo"] - window <= fd["line"] <= r["hi"] + window
                       for r in regions):
                    line_hits.append(fd)
                if any(ff == f and lo <= fd["line"] <= hi for ff, lo, hi, _ in funcs):
                    fn_hits.append(fd)
        status = ("patch-failed" if not b["patch_ok"] else
                  "not-scanned" if not scanned else "ok")
        rows.append({
            "bug": bug, "target": name, "status": status,
            "regions": regions,
            "functions": sorted({f"{fn} ({ff}:{lo}-{hi})" for ff, lo, hi, fn in funcs}),
            "line_hit": bool(line_hits), "function_hit": bool(fn_hits or line_hits),
            "line_hits": [h["id"] for h in line_hits],
            "function_hits": sorted({h["id"] for h in fn_hits + line_hits}),
            "patch_msg": b["patch_msg"],
        })
    return rows


def write_hits(path, results, work_root):
    with open(path, "w") as out:
        for t in results:
            fid = {f["id"]: f for f in t["findings"]}
            for row in t["bugs"]:
                out.write(f"\n{'=' * 100}\n{row['bug']}  [{row['status']}]  line-hit="
                          f"{row['line_hit']}  function-hit={row['function_hit']}\n")
                out.write(f"  functions: {', '.join(row['functions']) or '?'}\n")
                lines_cache = {}
                for r in row["regions"]:
                    src = lines_cache.setdefault(
                        r["file"], read_lines(os.path.join(work_root, t["target"], r["file"])))
                    out.write(f"  --- {r['file']}:{r['lo']}-{r['hi']} (vulnerable code)\n")
                    for i in range(max(1, r["lo"] - 2), min(len(src), r["hi"] + 2) + 1):
                        if src[i - 1].strip():
                            out.write(f"  {i:6d}  {src[i - 1]}\n")
                for h in row["function_hits"]:
                    f = fid[h]
                    tag = "LINE" if h in row["line_hits"] else "FUNC"
                    out.write(f"  [{tag}] {f['file']}:{f['line']} {f['rule_id']} ({f['cwe']}) "
                              f"{f['message'][:140]}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--magma", required=True, help="path to a clone of HexHive/magma")
    ap.add_argument("--src", required=True, help="where pristine target sources live/are fetched")
    ap.add_argument("--work", required=True, help="scratch dir for the patched copies")
    ap.add_argument("--targets", nargs="*", help="subset of targets (default: all)")
    ap.add_argument("--window", type=int, default=5, help="line-level tolerance (lines)")
    ap.add_argument("--jobs", type=int, default=1, help="targets to run in parallel")
    ap.add_argument("--backend", default="semgrep", choices=["semgrep", "codeql", "both"])
    ap.add_argument("--codeql-db-dir", help="cache CodeQL databases here as magma_<target> "
                    "(reused if present; the tree must be the same patched copy)")
    ap.add_argument("--codeql-queries", nargs="+")
    ap.add_argument("--keep-work", action="store_true",
                    help="don't re-create <work>/<target> if it exists (keeps cached CodeQL "
                         "databases valid)")
    ap.add_argument("--rescore", action="store_true",
                    help="reuse <work>/<target>.findings.json from an earlier run (no re-scan)")
    ap.add_argument("--out", default="magma.json")
    ap.add_argument("--hits", help="write each bug with the findings that hit it, for review")
    args = ap.parse_args()

    names = args.targets or sorted(os.listdir(os.path.join(args.magma, "targets")))
    excludes = set(DEFAULT_EXCLUDES)

    def run_target(name):
        print(f"[*] {name}", file=sys.stderr)
        src = os.path.join(args.src, name)
        fetch(args.magma, name, src)
        work = os.path.join(args.work, name)
        bugs = prepare(args.magma, name, src, work, keep=args.keep_work)
        tag = "" if args.backend == "semgrep" else f".{args.backend}"
        out = os.path.join(args.work, f"{name}{tag}.findings.json")
        db = os.path.join(args.codeql_db_dir, f"magma_{name}") if args.codeql_db_dir else None
        rep = json.load(open(out)) if args.rescore else run_analyzer(
            work, out, args.backend, db, args.codeql_queries)
        findings = rep.get("findings", [])
        bug_files = {r["file"] for b in bugs.values() for r in b["regions"]}
        spans = function_spans_rel(work, sorted(bug_files | {f["file"] for f in findings}),
                                   always_preprocess=bug_files)
        rows = score(name, bugs, findings, spans, args.window, excludes)
        unparsed = set((rep.get("parse_coverage") or {}).get("still_unparsed", []))
        timed_out = collections.defaultdict(set)
        for t in rep.get("timeouts", []):
            timed_out[t["file"]].add(t["rule"])
        for row in rows:
            files = {r["file"] for r in row["regions"]}
            row["unparsed_files"] = sorted(files & unparsed)
            row["timeouts"] = sorted({f"{f}:{rule}" for f in files for rule in timed_out[f]})
        size = kloc(work, excludes)
        bug_funcs = {(f, lo, hi) for row in rows for fn in row["functions"]
                     for f, lo, hi in [re.search(r"\((.+):(\d+)-(\d+)\)$", fn).groups()]}
        in_bug_fn = sum(1 for f in findings
                        if any(bf == f["file"] and int(lo) <= f["line"] <= int(hi)
                               for bf, lo, hi in bug_funcs))
        ok = [r for r in rows if r["status"] == "ok"]
        print(f"    {name}: {len(rows)} bugs ({len(ok)} scannable)  line-level "
              f"{sum(r['line_hit'] for r in ok)}  function-level "
              f"{sum(r['function_hit'] for r in ok)}  findings {len(findings)} "
              f"({len(findings) / size:.2f}/KLOC)  in bug functions {in_bug_fn}", file=sys.stderr)
        return {
            "target": name, "kloc": round(size, 1), "findings_total": len(findings),
            "findings_per_kloc": round(len(findings) / size, 2) if size else None,
            "findings_in_bug_functions": in_bug_fn,
            "parse_coverage": {k: v for k, v in (rep.get("parse_coverage") or {}).items()
                               if k != "files"},
            "timeouts": rep.get("timeouts", []),
            "bugs": rows, "findings": findings,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run_target, names))

    allrows = [r for t in results for r in t["bugs"]]
    ok = [r for r in allrows if r["status"] == "ok"]
    summary = {
        "bugs": len(allrows),
        "scannable": len(ok),
        "status": dict(collections.Counter(r["status"] for r in allrows)),
        "line_level": sum(r["line_hit"] for r in ok),
        "function_level": sum(r["function_hit"] for r in ok),
        "window": args.window,
        "kloc": round(sum(t["kloc"] for t in results), 1),
        "findings_total": sum(t["findings_total"] for t in results),
    }
    summary["findings_per_kloc"] = round(summary["findings_total"] / summary["kloc"], 2) \
        if summary["kloc"] else None
    json.dump({"summary": summary, "targets": results}, open(args.out, "w"), indent=1)
    if args.hits:
        write_hits(args.hits, results, args.work)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
