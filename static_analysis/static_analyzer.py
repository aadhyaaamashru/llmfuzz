#!/usr/bin/env python3
"""
Static analyzer stage for the LLM-guided fuzzing pipeline.

Takes a target (local path OR git URL), runs the static analyzers (Semgrep for local patterns,
CodeQL for data flow across functions), and emits normalized findings JSON for the
downstream LLM stage. Each finding says which analyzer produced it.

Usage:
    python3 static_analyzer.py --target tests/toy --out findings.json
    python3 static_analyzer.py --target https://github.com/randy408/libspng --out findings.json
    python3 static_analyzer.py --target tests/toy --config p/c --out findings.json   # stock rules
    python3 static_analyzer.py --target ../zlib --compile-commands ../zlib/build/compile_commands.json

Files Semgrep can't parse (project macros, split #if blocks) are re-scanned through a
line-aligned preprocessed copy; see preprocess.py. The output's `parse_coverage` lists any file
that still could not be parsed, so a 0-finding file is never silent.

The output schema is the contract with the LLM stage (Madhav). Each finding carries
enough to triage AND to generate a harness: the enclosing function + code context.
"""
import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import preprocess  # noqa: E402
import codeql_backend  # noqa: E402
import wide_net  # noqa: E402

DEFAULT_RULES = os.path.join(HERE, "rules", "memory_safety.yaml")
WIDE_RULES = sorted(glob.glob(os.path.join(HERE, "rules", "wide_net*.yaml")))


def is_git_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@")) or target.endswith(".git")


def clone(url: str, dest: str) -> str:
    print(f"[*] cloning {url} ...", file=sys.stderr)
    subprocess.run(["git", "clone", "--depth", "1", url, dest], check=True)
    return dest


# Directories that hold non-library code (tests, examples, docs). Bugs there are not reachable
# through the library's API, and a VDP won't accept them. Override with --exclude ''.
DEFAULT_EXCLUDES = ["test", "tests", "testing", "example", "examples", "doc", "docs",
                    "fuzz", "fuzzing", "oss-fuzz", "bench", "benchmark", "benchmarks",
                    # test programs that sit outside test/ dirs (e.g. mxml's testmxml.c). Checked
                    # on ~490 benchmark bugs: no bug's only location is in such a file
                    "test*.c", "test*.cc", "test*.cpp", "*_test.c", "*_test.cc", "*_test.cpp",
                    "*_tests.c", "*-test.c", "*_unittest.cc"]

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


_BATCH = 500        # files per semgrep call: the OS caps a command line's length


def _merge_semgrep(into, out):
    if not into:
        return out
    for k in ("results", "errors"):
        into.setdefault(k, []).extend(out.get(k, []))
    for k in ("scanned", "skipped"):
        into.setdefault("paths", {}).setdefault(k, []).extend(out.get("paths", {}).get(k, []))
    return into


def run_semgrep(targets, configs, excludes=()) -> dict:
    """Semgrep JSON for targets (directories and/or files). A Semgrep crash never sinks the
    whole scan: the failing batch is split until the file that crashes it is found; that file
    is skipped and reported in `errors` (type "SemgrepCrash") and `crashed_files`."""
    # same limits as benchmark.py, so the numbers measured there hold here
    cmd = ["semgrep", "--json", "--quiet", "--metrics", "off", "--disable-version-check",
           "--timeout", "30", "--max-target-bytes", "5000000",
           # never skip the rest of a file because some rules timed out on it (default: 3);
           # rules that do time out are listed in the output's `timeouts`
           "--timeout-threshold", "0"]
    for c in configs:
        cmd += ["--config", c]
    # Directories are expanded into an explicit file list here (excludes applied by
    # source_files) instead of being handed to Semgrep: inside a git repository Semgrep skips
    # untracked-and-gitignored files and applies its built-in ignore list (test/, tests/,
    # build/, vendor/, ...) to paths relative to the repository root -- so a target cloned
    # into an ignored folder, or sitting under a tests/ path, was silently scanned as empty.
    # Explicitly named files are always scanned.

    def run(batch):
        proc = subprocess.run(cmd + batch, capture_output=True, text=True)
        # semgrep exits 0 (no findings) or 1 (findings); anything else is a real error
        if proc.returncode in (0, 1):
            return json.loads(proc.stdout or "{}")
        if len(batch) == 1 and os.path.isdir(batch[0]):
            files = source_files(batch[0], excludes)
            if not files:
                return {}
            out = {}
            for i in range(0, len(files), _BATCH):
                out = _merge_semgrep(out, run(files[i:i + _BATCH]))
            return out
        if len(batch) > 1:
            mid = len(batch) // 2
            return _merge_semgrep(run(batch[:mid]), run(batch[mid:]))
        msg = (proc.stderr or "").strip()[-300:]
        print(f"[!] semgrep crashed on {batch[0]} (exit {proc.returncode}); skipping it",
              file=sys.stderr)
        return {"results": [], "crashed_files": [batch[0]],
                "errors": [{"type": "SemgrepCrash", "path": batch[0], "message": msg}]}

    files = []
    for t in targets:
        if os.path.isdir(t):
            files += source_files(t, excludes)
        elif not os.path.islink(t):
            files.append(t)
    targets = files
    merged = {}
    for i in range(0, len(targets), _BATCH):     # (no targets: nothing to scan -- never cwd)
        out = run(targets[i:i + _BATCH])
        crashed = merged.get("crashed_files", []) + out.pop("crashed_files", [])
        merged = _merge_semgrep(merged, out)
        if crashed:
            merged["crashed_files"] = crashed
    return merged


# Function boundaries come from Semgrep's own parser: one extra pass with this rule over the
# files that have findings (and their preprocessed copies when the raw file doesn't parse).
FN_RULE = """
rules:
  - id: sa-function-def
    languages: [c, cpp]
    severity: INFO
    message: "$FUNC"
    pattern-either:
      - pattern: |
          $RET $FUNC(...) { ... }
      - pattern: |
          $FUNC(...) { ... }
"""


# every extension Semgrep analyzes as C/C++ (checked against semgrep 1.185), so handing it
# this explicit file list never drops a file a directory scan would have covered
SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".C", ".hh", ".hpp", ".hxx", ".inl",
              ".ipp", ".tpp", ".pcc")


def source_files(root, excludes=()):
    """Every C/C++ source/header under root, skipping excluded and hidden directories."""
    out = []
    globs = [e for e in excludes if any(c in e for c in "*?[")]     # file-name patterns
    for d, sub, files in os.walk(root):
        sub[:] = sorted(x for x in sub if x not in set(excludes) and not x.startswith("."))
        # symlinks are skipped: semgrep refuses them as explicit targets (exit 2), and the
        # file they point to is scanned under its real path anyway
        out += [os.path.join(d, f) for f in sorted(files)
                if f.endswith(SOURCE_EXT) and not os.path.islink(os.path.join(d, f))
                and not any(fnmatch.fnmatch(f, g) for g in globs)]
    return out


def _fn_scan(rule, targets, spans, key_of):
    for i in range(0, len(targets), _BATCH):
        proc = subprocess.run(["semgrep", "--json", "--quiet", "--metrics", "off",
                               "--disable-version-check", "--timeout", "60",
                               "--config", rule] + list(targets[i:i + _BATCH]),
                              capture_output=True, text=True)
        for r in json.loads(proc.stdout or "{}").get("results", []):
            name = r["extra"]["message"].strip()
            spans.setdefault(key_of(r["path"]), set()).add(
                (r["start"]["line"], r["end"]["line"], name))


_SIG_START = re.compile(
    r"^(?:[A-Za-z_][\w\s\*&:<>,]*?[\s\*&])?((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\(")


def _brace_end(text, start):
    """Index of the '}' matching the '{' at text[start], skipping strings and comments."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


_C_TYPES = {"void", "int", "char", "short", "long", "unsigned", "signed", "float", "double",
            "static", "inline", "const", "extern", "struct", "enum", "union"}


def _def_name(header):
    """The function's name in a definition header: the first identifier followed by '(' (or
    by ')(' -- `void (API name)(...)`) that isn't a type keyword or an ALL_CAPS macro."""
    cands = re.findall(r"((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\)?\s*\(", header)
    for c in cands:
        if c not in _C_TYPES and c not in _NOT_FUNCS and not re.fullmatch(r"[A-Z0-9_]+", c):
            return c
    return None


_MACRO_DEF = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*$")       # `YY_DECL` on its own line, `{` next
_INDENT_BAD = re.compile(r"(else|if|while|for|switch|return|case|do|goto|sizeof)\b")


def _comment_lines(text, offs, n):
    """Per line: does it start inside a /* */ block comment?"""
    marks, inside, pos = [False] * n, [], 0
    while True:
        a = text.find("/*", pos)
        if a < 0:
            break
        b = text.find("*/", a + 2)
        b = len(text) if b < 0 else b + 2
        inside.append((a, b))
        pos = b
    j = 0
    for li in range(n):
        start = offs[li]
        while j < len(inside) and inside[j][1] <= start:
            j += 1
        marks[li] = j < len(inside) and inside[j][0] < start
    return marks


def heuristic_spans(path, known):
    """Functions Semgrep's parser didn't see. Typical causes: an attribute macro before the
    definition (`TIFF_NOSANITIZE_UNSIGNED_INT_OVERFLOW static int f(...)`), generated code that
    indents signatures (flex/bison), or a definition spelled entirely by a macro (flex's
    `YY_DECL` + `{`). A `name(` line whose parameter list is followed by `{` (before any `;` or
    `=`) and that isn't inside a known span is a function; its end is the matching brace.
    Indented candidates must have nothing but whitespace between `)` and `{`, so statements
    inside an unrecognized function body aren't mistaken for definitions."""
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return set()
    lines = text.split("\n")
    offs = [0]
    for ln in lines:
        offs.append(offs[-1] + len(ln) + 1)
    in_comment = _comment_lines(text, offs, len(lines))
    covered = lambda line: any(lo <= line <= hi for lo, hi, _ in known)  # noqa: E731
    found, i = set(), 0
    while i < len(lines):
        ln = lines[i]
        stripped = ln.lstrip(" \t")
        indent = len(ln) - len(stripped)
        indented = indent > 0
        if (covered(i + 1) or not stripped or stripped[0] in "#/*}" or in_comment[i]
                or (i and lines[i - 1].rstrip().endswith("\\"))     # macro / #if continuation
                or (indented and (indent > 4 or _INDENT_BAD.match(stripped)))):
            i += 1
            continue
        rest = text[offs[i]:offs[min(len(lines), i + 20)]]
        mm = _MACRO_DEF.match(ln)
        if mm and not indented:
            nxt = rest.split("\n", 1)[1].lstrip() if "\n" in rest else ""
            if not nxt.startswith("{"):
                i += 1
                continue
            name, brace = mm.group(1), rest.index("{")
        else:
            m = _SIG_START.match(stripped)
            if not m or m.group(1) in _NOT_FUNCS or m.group(1) == "defined":
                i += 1
                continue
            # indented: needs an explicit return type and a non-macro name (else it is far more
            # likely a statement inside a function body the parser didn't recognize)
            if indented and (not stripped[:m.start(1)].strip()
                             or re.fullmatch(r"[A-Z0-9_]+", m.group(1).rsplit("::", 1)[-1])):
                i += 1
                continue
            # the body must open before any ';' (else a prototype or a call) and before any
            # '=' (else an initializer such as a function-pointer table)
            brace, semi, eq = rest.find("{"), rest.find(";"), rest.find("=")
            if brace < 0 or (0 <= semi < brace) or (0 <= eq < brace):
                i += 1
                continue
            if indented and not re.search(r"\)\s*$", rest[:brace]):
                i += 1
                continue
            name = _def_name(rest[:brace]) or m.group(1)
        end = _brace_end(text, offs[i] + brace)
        if end is None:
            break
        last = text.count("\n", 0, end) + 1
        found.add((i + 1, last, name))
        i = last
    return found


def function_spans(root, paths, always_preprocess=(), excludes=(), compile_commands=None,
                   defines=()):
    """{abspath: {(first_line, last_line, name)}} for the given files. Files Semgrep can't parse
    (or listed in always_preprocess, where a partial parse could miss the function that matters)
    are also read through their line-aligned preprocessed copy."""
    paths = sorted({os.path.abspath(p) for p in paths if os.path.isfile(p)})
    spans = {}
    with tempfile.TemporaryDirectory() as tmp:
        rule = os.path.join(tmp, "functions.yaml")
        with open(rule, "w") as f:
            f.write(FN_RULE)
        _fn_scan(rule, paths, spans, os.path.abspath)
        always = {os.path.abspath(p) for p in always_preprocess}
        redo = [p for p in paths if not spans.get(p) or p in always]
        if redo:
            pp = preprocess.Preprocessor(root, excludes, compile_commands, defines)
            try:
                copies = {}
                for p in redo:
                    copy, _ = pp.preprocess(p)
                    if copy:
                        copies[os.path.abspath(copy)] = p
                _fn_scan(rule, sorted(copies), spans, lambda c: copies[os.path.abspath(c)])
            finally:
                pp.cleanup()
    for p in paths:                      # definitions the parser skipped (attribute macros)
        extra = heuristic_spans(p, spans.get(p, set()))
        if extra:
            spans.setdefault(p, set()).update(extra)
    return spans


def innermost(spans, line):
    """(first, last, name) of the smallest span containing line, or None."""
    best = None
    for lo, hi, name in spans or ():
        if lo <= line <= hi and (best is None or hi - lo < best[1] - best[0]):
            best = (lo, hi, name)
    return best


_NOT_FUNCS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case"}


def enclosing_function(lines, line_idx):
    """Fallback when Semgrep found no function around the line: scan upward for the
    nearest line that looks like a C function signature (not a control statement)."""
    pat = re.compile(r"^[\w\*\s]*?\b(\w+)\s*\([^;]*\)\s*\{?\s*$")
    for i in range(min(line_idx, len(lines) - 1), -1, -1):
        s = lines[i].strip()
        if not s or s.startswith(("#", "//", "/*", "*")) or s.endswith(";"):
            continue
        if lines[i][:1].isspace():          # signatures start at column 0 in C style
            continue
        m = pat.match(lines[i])
        if m and m.group(1) not in _NOT_FUNCS:
            return m.group(1)
    return None


def code_context(path, line, radius=4, spans=None):
    """Return (snippet, enclosing_function) around a 1-indexed line."""
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None, None
    lo = max(0, line - 1 - radius)
    hi = min(len(lines), line + radius)
    snippet = "\n".join(lines[lo:hi])
    span = innermost(spans, line)
    return snippet, (span[2] if span else enclosing_function(lines, line - 1))


def parse_cwe(meta):
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str):
        m = re.search(r"CWE-\d+", cwe)
        return m.group(0) if m else cwe
    return None


def normalize(raw, target_root, spans=None):
    """Semgrep results -> findings (schema is the contract with the LLM stage).

    Duplicates (same rule, file, line — Semgrep emits one per matching pattern alternative)
    are dropped, and findings are ordered ERROR > WARNING > INFO so the LLM triages the
    high-signal tier first. IDs are assigned after ordering.
    """
    seen, results = set(), []
    for r in raw.get("results", []):
        key = (r.get("check_id"), os.path.abspath(r.get("path", "")),
               r.get("start", {}).get("line"))
        if key not in seen:
            seen.add(key)
            results.append(r)
    # order by the path inside the library: Semgrep reports paths as the target was typed
    # (relative or absolute), CodeQL always absolute -- raw paths would make the F-numbers
    # depend on how the target was named
    root = os.path.abspath(target_root) if os.path.isdir(target_root) else None
    results.sort(key=lambda r: (
        SEVERITY_ORDER.get((r.get("extra", {}).get("severity") or "").lower(), 3),
        os.path.relpath(os.path.abspath(r.get("path", "")), root) if root else r.get("path", ""),
        r.get("start", {}).get("line", 0)))

    findings = []
    for i, r in enumerate(results, 1):
        path = r.get("path", "")
        start = r.get("start", {}).get("line", 0)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        snippet, func = code_context(path, start,
                                     spans=(spans or {}).get(os.path.abspath(path)))
        rel = os.path.relpath(path, target_root) if os.path.isdir(target_root) else path
        findings.append({
            "id": f"F{i:03d}",
            "rule_id": r.get("check_id", "").rsplit(".", 1)[-1],
            "cwe": parse_cwe(meta),
            "bug_class": meta.get("bug_class"),
            "severity": (extra.get("severity") or "").lower() or None,
            "file": rel,
            "line": start,
            "function": func,            # enclosing function: what the harness must reach
            "message": (extra.get("message") or "").strip(),
            "code_context": snippet,     # the LLM reads this to triage + build a harness
            "analyzer": extra.get("sa_analyzer", "semgrep"),
            # matched on the macro-expanded copy; code_context is still the original source
            "preprocessed": bool(extra.get("sa_preprocessed")),
        })
    return merge_duplicates(findings)


def merge_duplicates(findings):
    """Semgrep and CodeQL reporting the same bug class on the same line is one finding for the
    LLM to triage, not two: keep the first (they're severity-ordered) and record the agreement
    in `also_reported_by` (a confidence signal)."""
    kept, by_key = [], {}
    for f in findings:
        key = (f["file"], f["line"], f["cwe"])
        first = by_key.get(key)
        if first is not None and first["analyzer"] != f["analyzer"]:
            seen = first.setdefault("also_reported_by", [])
            if f["analyzer"] not in seen:
                seen.append(f["analyzer"])
            continue
        by_key.setdefault(key, f)
        kept.append(f)
    for i, f in enumerate(kept, 1):
        f["id"] = f"F{i:03d}"
    return kept


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="local path or git URL")
    ap.add_argument("--config", nargs="+", default=[DEFAULT_RULES],
                    help="one or more semgrep configs (unioned): local rules files and/or "
                         "registry packs like p/c")
    ap.add_argument("--exclude", nargs="*", default=DEFAULT_EXCLUDES,
                    help="directory names to skip (default: tests/examples/docs/fuzz). "
                         "Pass --exclude with no values to scan everything.")
    ap.add_argument("--compile-commands",
                    help="compile_commands.json of the build that gets fuzzed: its -I/-D flags "
                         "are used when preprocessing files Semgrep can't parse")
    ap.add_argument("-D", "--define", action="append", default=[],
                    help="extra macro for preprocessing, e.g. -D SPNG_USE_MINIZ (repeatable)")
    ap.add_argument("--no-preprocess", action="store_true",
                    help="don't re-scan unparseable files through the preprocessor")
    ap.add_argument("--backend", default="both" if codeql_backend.available() else "semgrep",
                    choices=["semgrep", "codeql", "both"],
                    help="analyzer(s) to run; results are unioned (default: both when the "
                         "codeql CLI is installed)")
    ap.add_argument("--codeql-db", help="CodeQL database to use; created here if it doesn't "
                    "exist (default: a temporary one)")
    ap.add_argument("--codeql-queries", nargs="+", default=codeql_backend.DEFAULT_QUERIES)
    ap.add_argument("--no-wide-net", dest="wide_net", action="store_false",
                    help="skip the wide-net tier (every risky memory operation, grouped and "
                         "ranked per function; see wide_net.py)")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()
    if args.backend != "semgrep" and not codeql_backend.available():
        ap.error("the codeql CLI is not installed (brew install --cask codeql)")

    target = args.target
    if is_git_url(target):
        tmp = tempfile.mkdtemp(prefix="sa_target_")
        target = clone(target, os.path.join(tmp, "repo"))

    raw, coverage, timeouts = {"results": []}, None, []
    # the wide net always runs through Semgrep (one pass together with the precise rules)
    configs = args.config + (WIDE_RULES if args.wide_net else [])
    if args.backend in ("semgrep", "both") or args.wide_net:
        if args.backend == "codeql":
            configs = list(WIDE_RULES)
        print(f"[*] running semgrep (config={', '.join(configs)}) on {target} ...",
              file=sys.stderr)
        raw = run_semgrep([target], configs, args.exclude)
        scan = None if args.no_preprocess else (lambda paths: run_semgrep(paths, configs))
        extra, coverage = preprocess.recover(
            raw, scan, target, excludes=args.exclude,
            compile_commands=args.compile_commands, defines=args.define)
        raw["results"] = raw.get("results", []) + extra
        if args.wide_net and coverage and coverage.get("still_unparsed"):
            # never let a file Semgrep can't read contribute nothing: line-pattern fallback
            fb = wide_net.fallback_results([os.path.join(target, r)
                                            for r in coverage["still_unparsed"]])
            raw["results"] += fb
            coverage["wide_net_fallback"] = sorted(coverage["still_unparsed"])
            print(f"[*] wide net: line-pattern fallback on {len(coverage['still_unparsed'])} "
                  f"unparsed file(s), {len(fb)} operations", file=sys.stderr)
        print(f"[*] {preprocess.summary_line(coverage)}", file=sys.stderr)
        timeouts = sorted(preprocess.timeouts(raw, target) + coverage.pop("timeouts", []),
                          key=lambda t: (t["file"], t["rule"]))
        if timeouts:
            print(f"[!] {len(timeouts)} rule/file pairs timed out (findings there may be "
                  "missing): " + ", ".join(f"{t['rule']} on {t['file']}" for t in timeouts[:5]),
                  file=sys.stderr)
    if args.backend in ("codeql", "both"):
        print(f"[*] running codeql on {target} ...", file=sys.stderr)
        db, tmp_db = args.codeql_db, None
        if db is None:
            tmp_db = tempfile.mkdtemp(prefix="sa_cqdb_")
            db = os.path.join(tmp_db, "db")
        try:
            if not os.path.exists(os.path.join(db, "codeql-database.yml")):
                codeql_backend.create_db(target, db, excludes=args.exclude,
                                         compile_commands=args.compile_commands,
                                         defines=args.define)
            cq = codeql_backend.results(codeql_backend.analyze(db, args.codeql_queries),
                                        os.path.abspath(target))
        finally:
            if tmp_db:
                shutil.rmtree(tmp_db, ignore_errors=True)
        # same scope as Semgrep: drop results in excluded directories (headers can live there)
        globs = [e for e in args.exclude if any(c in e for c in "*?[")]
        cq = [r for r in cq if not set(os.path.relpath(r["path"], target).split(os.sep)[:-1])
              & set(args.exclude)
              and not any(fnmatch.fnmatch(os.path.basename(r["path"]), g) for g in globs)]
        print(f"[*] codeql: {len(cq)} results", file=sys.stderr)
        raw["results"] = raw.get("results", []) + cq
    span_files = {r.get("path", "") for r in raw["results"]}
    if args.wide_net:      # call-graph propagation needs every function, not just flagged files
        span_files |= set(source_files(target, args.exclude))
    spans = function_spans(target, span_files,
                           excludes=args.exclude, compile_commands=args.compile_commands,
                           defines=args.define)
    wide_raw = [r for r in raw["results"] if wide_net.is_wide(r)]
    raw["results"] = [r for r in raw["results"] if not wide_net.is_wide(r)]
    findings = normalize(raw, target, spans)
    for f in findings:
        f["tier"] = "precise"
    hotspots, n_own = [], 0
    if args.wide_net:
        hotspots, n_own = wide_net.group(wide_raw, target, spans, code_context)
        print(f"[*] wide net: {len(wide_raw)} risky operations; {len(hotspots)} functions "
              f"flagged ({n_own} with risky operations, {len(hotspots) - n_own} calling them)",
              file=sys.stderr)

    by_cwe, by_severity = {}, {}
    for f in findings:
        key = f["cwe"] or "unknown"
        by_cwe[key] = by_cwe.get(key, 0) + 1
        sev = f["severity"] or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1

    out = {
        "target": args.target,
        "analyzer": {"semgrep": "semgrep", "codeql": "codeql",
                     "both": "semgrep+codeql"}[args.backend],
        "config": args.config,
        "codeql_queries": [os.path.relpath(q, HERE) if os.path.abspath(q).startswith(HERE)
                           else q for q in args.codeql_queries]
        if args.backend != "semgrep" else None,
        "excluded_dirs": args.exclude,
        "preprocessing": None if args.no_preprocess else {
            "compile_commands": args.compile_commands, "defines": args.define},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total": len(findings), "by_cwe": by_cwe, "by_severity": by_severity,
                    "wide_net_functions": len(hotspots) if args.wide_net else None,
                    "wide_net_functions_with_operations": n_own if args.wide_net else None,
                    "wide_net_operations": len(wide_raw) if args.wide_net else None},
        "parse_coverage": coverage,
        # rule/file pairs Semgrep gave up on (30 s each): findings there may be missing
        "timeouts": timeouts,
        # files Semgrep crashed on (skipped, so nothing was found there)
        "crashed_files": [os.path.relpath(p, target) for p in raw.get("crashed_files", [])],
        # tier "precise" first (specific bug patterns, severity-ordered), then tier "wide":
        # one entry per function with risky memory operations, ranked (W001 = read first)
        "findings": findings + hotspots,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] {len(findings)} precise findings + {len(hotspots)} wide-net hotspot functions "
          f"-> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
