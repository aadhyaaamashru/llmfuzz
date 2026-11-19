#!/usr/bin/env python3
"""Real-bug benchmark #2: OSS-Fuzz bugs from ARVO (Mei et al., EuroS&P 2026) in C libraries
that were never used to tune any rule.

ARVO records, for each OSS-Fuzz crash, the project repo, the commit that fixed it and the
sanitizer's crash report. For each selected bug this script:

  1. checks out the commit just BEFORE the fix (the vulnerable code) from the project's repo
  2. ground truth = (a) the lines the fix changed, in the vulnerable file, and the functions
     containing them; (b) the crash site: the first stack frame in the project's own code
     (not libc / sanitizer / the fuzz harness), as a function name
  3. runs both tiers of the static-analysis stage on the vulnerable checkout:
       precise   rules/memory_safety.yaml (the current stage's Semgrep rules)
       wide net  rules/wide_net.yaml + wide_net.py: functions with risky memory operations,
                 then functions calling them, ranked exactly as the stage outputs them
  4. scores:
       line      a finding within --window lines of a fix-changed line or the crash line
       function  precise: a finding inside a fix-changed function or the crash function;
                 wide: one of those functions is on the wide net's list
       rank      wide net only: how far down the ranked function list the first bug function
                 sits (as a % of all functions in the library) -- i.e. how much of the
                 library the LLM must read, top-down, before it has seen the bug's function

Per-file results are cached by git blob hash, so bugs in the same library only re-scan files
that changed between their commits (Semgrep's rules are per-file, so this is exact).
CodeQL is not run here (whole-program databases per commit are too slow, and on Magma it added
one real bug); the numbers are the Semgrep tiers only.

  python3 benchmarks/arvo_benchmark.py --candidates candidates.json --repos repos --out arvo.json
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
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the static_analysis/ folder
sys.path.insert(0, HERE)
import preprocess  # noqa: E402
from static_analyzer import (DEFAULT_EXCLUDES, DEFAULT_RULES, function_spans,  # noqa: E402
                             innermost, run_semgrep)
import wide_net  # noqa: E402

SRC_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
WIDE_RULES = sorted(glob.glob(os.path.join(HERE, "rules", "wide_net*.yaml")))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-f]+ in (.+?) (/\S+?):(\d+)(?::\d+)?\s*$")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MAX_FILES, MAX_LINES, PER_PROJECT = 3, 80, 5


def git(repo, *args, check=True):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()[:300]}")
    return p.stdout


def is_test(rel):
    parts = rel.lower().split("/")
    return any(p in DEFAULT_EXCLUDES or "fuzz" in p for p in parts[:-1]) or "fuzz" in parts[-1]


def clone(url, dest):
    if not os.path.isdir(os.path.join(dest, ".git")) and not os.path.exists(
            os.path.join(dest, "HEAD")):
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url, dest],
                       check=True, capture_output=True, text=True)
    return dest


def fix_shape(repo, fix):
    """Source files the fix touched (non-test) and total changed lines, or None."""
    try:
        git(repo, "cat-file", "-e", f"{fix}^{{commit}}")
        out = git(repo, "diff", "--numstat", f"{fix}^", fix)
    except RuntimeError:
        return None
    files, lines = [], 0
    for ln in out.splitlines():
        a, d, path = ln.split("\t", 2)
        if path.endswith(SRC_EXT) and not is_test(path):
            files.append(path)
            lines += int(a if a != "-" else 0) + int(d if d != "-" else 0)
    return files, lines


def fix_regions(repo, fix, files):
    """Old-side (vulnerable) line ranges the fix changed, per file."""
    regions = []
    for f in files:
        out = git(repo, "diff", "-U0", f"{fix}^", fix, "--", f)
        for ln in out.splitlines():
            m = HUNK.match(ln)
            if m:
                a, b = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                lo, hi = (a, a + 1) if b == 0 else (a, a + b - 1)  # pure insertion: after line a
                regions.append({"file": f, "lo": max(lo, 1), "hi": hi})
    return regions


def crash_frame(output, tree_files):
    """(function, rel_path, line) of the first stack frame in the project's own code."""
    for ln in ANSI.sub("", output or "").splitlines():
        m = FRAME.match(ln)
        if not m:
            continue
        func, path, line = m.group(2), m.group(3), int(m.group(4))
        if (func == "LLVMFuzzerTestOneInput" or "/llvm-project/" in path
                or "compiler-rt" in path or "/libfuzzer" in path.lower()):
            continue
        parts = path.split("/")
        # /src/<checkout dir>/rel/path -> longest suffix that exists in the tree
        for k in range(3, len(parts)):
            rel = "/".join(parts[k:])
            if rel in tree_files:
                if is_test(rel):
                    break
                return {"function": re.sub(r"\(.*$", "", func).split("::")[-1].strip(),
                        "file": rel, "line": line}
        else:
            continue
    return None


class BlobCache:
    """Per-file semgrep results / function spans, keyed by (git blob sha, rules hash)."""

    def __init__(self, path):
        self.path = path
        self.data = json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        tmp = self.path + ".tmp"
        json.dump(self.data, open(tmp, "w"))
        os.replace(tmp, self.path)


def rule_ids(path):
    return set(re.findall(r"^\s*-\s*id:\s*([\w.-]+)", open(path).read(), re.M))


def scan_tree(root, files, blobs, rules, cache, tag):
    """{rel: [(line, rule_id)]} for one rules file over files (rel paths), blob-cached."""
    return scan_multi(root, files, blobs, [(rules, tag)], cache)


def scan_multi(root, files, blobs, rule_tags, cache):
    """Like scan_tree for several rules files at once: every rules file a file still lacks is
    run in ONE semgrep pass (parsing dominates the cost), results split back per file."""
    key = lambda tag, rel: f"{tag}:{blobs[rel]}"  # noqa: E731
    missing = [(rf, tag) for rf, tag in rule_tags
               if any(key(tag, r) not in cache.data for r in files)]
    if missing:
        todo = sorted({r for r in files for _, tag in missing if key(tag, r) not in cache.data})
        configs = [rf for rf, _ in missing]
        owner = {rid: tag for rf, tag in missing for rid in rule_ids(rf)}
        res = collections.defaultdict(set)
        for i in range(0, len(todo), 400):
            chunk = [os.path.join(root, r) for r in todo[i:i + 400]]
            raw = run_semgrep(chunk, configs)
            extra, _ = preprocess.recover(raw, lambda p: run_semgrep(p, configs), root,
                                          excludes=DEFAULT_EXCLUDES)
            for r in raw.get("results", []) + extra:
                rel = os.path.relpath(os.path.abspath(r["path"]), root)
                rid = r["check_id"].rsplit(".", 1)[-1]
                if rid in owner:
                    res[(owner[rid], rel)].add((r["start"]["line"], rid))
        for _, tag in missing:
            for r in todo:
                if key(tag, r) not in cache.data:
                    cache.data[key(tag, r)] = sorted(res.get((tag, r), ()))
    out = {}
    for r in files:
        out[r] = sorted({tuple(x) for _, tag in rule_tags for x in cache.data[key(tag, r)]})
    return out


def spans_tree(root, files, blobs, cache):
    key = lambda rel: f"spans4:{blobs[rel]}"  # noqa: E731   (4: + macro-defined/indented definitions)
    todo = [r for r in files if key(r) not in cache.data]
    if todo:
        sp = function_spans(root, [os.path.join(root, r) for r in todo],
                            excludes=DEFAULT_EXCLUDES)
        for r in todo:
            cache.data[key(r)] = sorted(sp.get(os.path.abspath(os.path.join(root, r)), ()))
    return {r: [tuple(x) for x in cache.data[key(r)]] for r in files}


def rules_hash(path):
    return hashlib.sha1(open(path, "rb").read()).hexdigest()[:10]


def score_bug(bug, regions, crash, spans, precise, wide, window):
    targets = set()                      # (file, lo, hi) of functions that count as "the bug's"
    for r in regions:
        for lo, hi, _ in spans.get(r["file"], ()):
            if lo <= r["hi"] and r["lo"] <= hi:
                targets.add((r["file"], lo, hi))
    crash_fn = None
    if crash:
        named = [(lo, hi) for lo, hi, n in spans.get(crash["file"], ()) if n == crash["function"]]
        if named:
            lo, hi = min(named, key=lambda s: abs(s[0] - crash["line"]))
        else:
            got = innermost(spans.get(crash["file"]), crash["line"])
            lo, hi = (got[0], got[1]) if got else (None, None)
        if lo is not None:
            crash_fn = (crash["file"], lo, hi)
            targets.add(crash_fn)
    lines = [(r["file"], r["lo"], r["hi"]) for r in regions]
    if crash and crash_fn and crash_fn[1] <= crash["line"] <= crash_fn[2]:
        lines.append((crash["file"], crash["line"], crash["line"]))   # only if line didn't drift

    def hit(findings):
        line = any(lo - window <= ln <= hi + window
                   for f, lo, hi in lines for ln, _ in findings.get(f, ()))
        fn = any(lo <= ln <= hi for f, lo, hi in targets for ln, _ in findings.get(f, ()))
        return line, fn or line

    return targets, crash_fn, hit(precise), hit(wide)[0]


def rank_functions(root, spans, wide):
    """Positions of every flagged function in the wide net's ranking (as the stage outputs it)."""
    hits = [(f, ln, rule) for f, v in wide.items() for ln, rule in v]

    def read_lines(rel):
        try:
            return open(os.path.join(root, rel), errors="replace").read().splitlines()
        except OSError:
            return []
    ranked = wide_net.score_functions(hits, spans, read_lines)
    nfn = sum(len(v) for v in spans.values())
    return {d["key"]: (i, bool(d["own"])) for i, d in enumerate(ranked)}, nfn, len(ranked), \
        sum(1 for d in ranked if d["own"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--repos", required=True, help="dir for blobless clones + worktrees")
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects", nargs="*")
    ap.add_argument("--per-project", type=int, default=PER_PROJECT)
    ap.add_argument("--window", type=int, default=5)
    args = ap.parse_args()
    cands = json.load(open(args.candidates))
    args.repos = os.path.abspath(args.repos)
    os.makedirs(args.repos, exist_ok=True)
    cache = BlobCache(os.path.join(args.repos, "blobcache.json"))
    ptag = f"p{rules_hash(DEFAULT_RULES)}"
    wtags = [(r, f"w{rules_hash(r)}") for r in WIDE_RULES]     # cached per rules file

    def scan_wide(root, fl, blobs):
        return scan_multi(root, fl, blobs, wtags, cache)
    done = {}
    if os.path.exists(args.out):
        for r in json.load(open(args.out))["bugs"]:
            done[r["id"]] = r
    rows = list(done.values())
    for proj, bugs in cands.items():
        if args.projects and proj not in args.projects:
            continue
        repo = os.path.join(args.repos, proj + ".git")
        try:
            clone(bugs[0]["repo"], repo)
        except subprocess.CalledProcessError as e:
            print(f"[!] {proj}: clone failed: {e.stderr.strip()[:200]}", file=sys.stderr)
            continue
        taken = sum(1 for r in rows if r["project"] == proj)
        for b in bugs:
            if taken >= args.per_project:
                break
            if b["id"] in done:
                continue
            shape = fix_shape(repo, b["fix"])
            if not shape or not shape[0] or len(shape[0]) > MAX_FILES or shape[1] > MAX_LINES:
                continue
            t0 = time.time()
            vul = git(repo, "rev-parse", f"{b['fix']}^").strip()
            wt = os.path.join(args.repos, "wt", proj)
            if os.path.isdir(wt):
                git(repo, "worktree", "remove", "--force", wt, check=False)
            git(repo, "worktree", "prune", check=False)
            git(repo, "worktree", "add", "-q", "--detach", "-f", wt, vul)
            blobs = {}
            for ln in git(repo, "ls-tree", "-r", vul).splitlines():
                meta, rel = ln.split("\t", 1)
                if rel.endswith(SRC_EXT) and not meta.startswith("120000"):   # skip symlinks
                    blobs[rel] = meta.split()[2]
            files = sorted(r for r in blobs if not any(
                p in DEFAULT_EXCLUDES or p.startswith(".") for p in r.split("/")[:-1])
                and os.path.isfile(os.path.join(wt, r)))
            regions = fix_regions(repo, b["fix"], shape[0])
            crash = crash_frame(b["crash_output"], set(blobs))
            spans = spans_tree(wt, files, blobs, cache)
            wide = scan_wide(wt, files, blobs)
            rel_files = sorted({r["file"] for r in regions} | ({crash["file"]} if crash else set()))
            rel_files = [f for f in rel_files if f in blobs and os.path.isfile(os.path.join(wt, f))]
            for f in rel_files:              # bug files inside excluded dirs still get spans
                if f not in spans:
                    spans.update(spans_tree(wt, [f], blobs, cache))
            precise = scan_tree(wt, rel_files, blobs, DEFAULT_RULES, cache, ptag)
            wide_rel = scan_wide(wt, rel_files, blobs)
            wide = {**wide, **wide_rel}
            wide = wide_net.fill_unparsed(wide, wt, sorted(set(files) | set(rel_files)))
            targets, crash_fn, (p_line, p_fn), w_line = score_bug(
                b, regions, crash, spans, precise, wide, args.window)
            lib_spans = {f: spans[f] for f in set(files) | set(rel_files) if f in spans}
            rank, nfn, n_flagged, n_own = rank_functions(wt, lib_spans, wide)
            # wide tier: flagged lines outside any recognized function form their own entries
            aug = wide_net.add_orphan_groups(
                [(f, ln, r) for f, v in wide.items() for ln, r in v], lib_spans)
            w_targets, _, _, _ = score_bug(b, regions, crash, aug, precise, wide, args.window)
            ranked = sorted(rank[t] for t in w_targets if t in rank)
            w_fn = bool(ranked)
            kloc = sum(sum(1 for _ in open(os.path.join(wt, f), errors="ignore"))
                       for f in files) / 1000
            row = {"id": b["id"], "project": proj, "crash_type": b["crash_type"],
                   "fix": b["fix"], "vulnerable": vul, "fix_files": shape[0],
                   "fix_lines": shape[1], "regions": regions, "crash": crash,
                   "crash_function_found": crash_fn is not None,
                   "targets": sorted(f"{f}:{lo}-{hi}" for f, lo, hi in targets),
                   "precise": {"line": p_line, "function": p_fn},
                   "wide": {"line": w_line, "function": w_fn,
                            "via": (("own" if ranked[0][1] else "calls") if ranked else None),
                            "rank_pct": (round(100 * ranked[0][0] / nfn, 1) if ranked else None)},
                   "library": {"functions": nfn, "kloc": round(kloc, 1),
                               "functions_flagged": n_flagged,
                               "functions_flagged_own": n_own,
                               "wide_hits": sum(len(v) for f, v in wide.items() if f in set(files)),
                               "precise_hits_in_bug_files": sum(len(v) for v in precise.values())},
                   "seconds": round(time.time() - t0)}
            rows.append(row)
            done[b["id"]] = row
            taken += 1
            cache.save()
            json.dump({"bugs": rows}, open(args.out, "w"), indent=1)
            print(f"[+] {proj} {b['id']} {b['crash_type']:<28} precise L{int(p_line)} F{int(p_fn)}"
                  f" | wide L{int(w_line)} F{int(w_fn)} rank {row['wide']['rank_pct']}% "
                  f"| {row['seconds']}s", file=sys.stderr, flush=True)
        if os.path.isdir(os.path.join(args.repos, "wt", proj)):
            git(repo, "worktree", "remove", "--force", os.path.join(args.repos, "wt", proj),
                check=False)
    json.dump({"bugs": rows, "summary": summarize(rows)}, open(args.out, "w"), indent=1)
    print(json.dumps(summarize(rows), indent=1))


def summarize(rows):
    n = len(rows)
    s = {"bugs": n, "projects": len({r["project"] for r in rows})}
    for tier in ("precise", "wide"):
        s[tier] = {k: sum(bool(r[tier][k]) for r in rows) for k in ("line", "function")}
    for pct in (5, 10, 25, 50):
        s["wide"][f"function_in_top_{pct}pct"] = sum(
            1 for r in rows if r["wide"]["rank_pct"] is not None and r["wide"]["rank_pct"] < pct)
    s["crash_function_located"] = sum(r["crash_function_found"] for r in rows)
    return s


if __name__ == "__main__":
    main()
