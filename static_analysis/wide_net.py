"""Wide-net tier: aim for "no known bug left off the list", let the LLM do the filtering.

Two kinds of functions are flagged:

  1. functions with risky memory operations of their own -- every copy/index/allocation/free/
     division whose size, index or pointer isn't a constant (rules/wide_net.yaml), kept EVEN
     WHEN A CHECK SITS NEXT TO IT: real bugs are usually a check that exists but is wrong.
     Ranked by a weighted count of those operations.
  2. functions that only CALL risky functions (up to 3 calls deep). Bugs whose fix is a missing
     logic check (a mode string, a parser state flag) live in code that never touches memory
     itself; the memory error happens in a callee. Ranked after group 1, by the callees' risk.

Raw operations are far too many to hand over one by one (~55 per KLOC), so the output is one
entry per function, best first; the LLM reads the list top-down.

Tuned on Magma's tuning libraries (libpng, libsndfile, libtiff, libxml2, lua): 60/60 bug
functions flagged; 48/60 in the top 25% of all functions. The plain weighted count ranked bug
functions as well as or better than every alternative tried (diversity of kinds, density,
name hints, boosting functions with precise findings, mixing inherited risk into group 1).
"""
import collections
import os
import re

# weight per wide-net rule: operations that directly size or move memory count more
WEIGHTS = {
    "wide-copy-variable-size": 3,
    "wide-computed-alloc": 3,
    "wide-unbounded-string": 2,
    "wide-index-write": 2,
    "wide-length-decode": 2,
    "wide-divide-by-variable": 2,
    "wide-check-arith": 2,
    "wide-index-read": 1,
    "wide-terminator-read": 1,
    "wide-delete": 1,
    "wide-release-call": 1,
    "wide-field-fixed-offset": 1,
    "wide-call-result-fixed-offset": 1,
    "wide-param-fixed-offset": 1,
    "wide-countdown-loop": 2,
    "wide-loop-advance": 1,
    "wide-scan-variable-size": 2,
    "wide-indirect-call": 1,
    "wide-pointer-arith-deref": 1,
    "wide-free": 1,
    "wide-size-field-store": 1,
    "wide-size-arith": 1,
}
INHERIT = 0.5          # a caller inherits half its riskiest callee's score ...
DEPTH = 3              # ... through up to 3 levels of calls

RULE_PREFIX = "wide-"
KIND = {
    "wide-copy-variable-size": "variable-size copy/compare",
    "wide-computed-alloc": "allocation with computed size",
    "wide-unbounded-string": "unbounded string/format call",
    "wide-index-write": "write through variable index",
    "wide-length-decode": "value assembled from input bytes",
    "wide-divide-by-variable": "division by a variable",
    "wide-check-arith": "bounds check that can overflow",
    "wide-terminator-read": "reads until a terminator (strcmp/atoi/...)",
    "wide-delete": "object released with delete",
    "wide-release-call": "call that releases/removes an object",
    "wide-field-fixed-offset": "struct-held buffer read at a fixed offset",
    "wide-call-result-fixed-offset": "call result read at a fixed offset",
    "wide-param-fixed-offset": "pointer parameter read at a fixed offset",
    "wide-countdown-loop": "count-down loop that underflows at 0",
    "wide-loop-advance": "pointer/index advanced inside a loop",
    "wide-scan-variable-size": "memchr-style scan of a caller-given length",
    "wide-indirect-call": "call through a function pointer from a struct",
    "wide-index-read": "read through variable index",
    "wide-pointer-arith-deref": "pointer arithmetic",
    "wide-free": "memory release",
    "wide-size-field-store": "size/count field set",
    "wide-size-arith": "size arithmetic",
}


def _by_line(pairs):
    """One hotspot per line, every reason kept (no cap: a capped list silently drops the lines a
    bug can be on -- mxml 2.12's CVE line 2914 fell past the old 40-entry cap)."""
    kinds = collections.defaultdict(list)
    for ln, kind in pairs:
        if kind not in kinds[ln]:
            kinds[ln].append(kind)
    return [{"line": ln, "kind": " + ".join(kinds[ln])} for ln in sorted(kinds)]


_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_CALLS = {"if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
              "defined", "alignof", "_Alignof", "typeof", "__typeof__", "__attribute__"}


def is_wide(result):
    return result.get("check_id", "").rsplit(".", 1)[-1].startswith(RULE_PREFIX)


def _innermost(spans, line):
    best = None
    for lo, hi, name in spans or ():
        if lo <= line <= hi and (best is None or hi - lo < best[1] - best[0]):
            best = (lo, hi, name)
    return best


ORPHAN_GAP = 40        # orphan operations closer than this many lines form one group
ORPHAN_PREFIX = "<code outside any recognized function"


def add_orphan_groups(hits, spans):
    """Safety net: a flagged operation is never dropped because the function around it wasn't
    recognized (macro-spelled definitions, generated code, parse failures). Operations outside
    every known span are grouped by proximity into pseudo-functions that are ranked like any
    other. Returns a new spans dict."""
    orphans = collections.defaultdict(set)
    for path, line, _ in hits:
        if _innermost(spans.get(path), line) is None:
            orphans[path].add(line)
    if not orphans:
        return spans
    out = {p: set(v) for p, v in spans.items()}
    for path, lines in orphans.items():
        lines = sorted(lines)
        lo = prev = lines[0]
        for ln in lines[1:] + [None]:
            if ln is not None and ln - prev <= ORPHAN_GAP:
                prev = ln
                continue
            out.setdefault(path, set()).add(
                (lo, prev, f"{ORPHAN_PREFIX}: {os.path.basename(path)}:{lo}-{prev}>"))
            if ln is not None:
                lo = prev = ln
    return out


def score_functions(hits, spans, read_lines):
    """Rank every function.

    hits        iterable of (path, line, rule_id) wide-net operations
    spans       {path: iterable of (first, last, name)} for ALL source files (callers of risky
                functions can sit in files with no operations of their own)
    read_lines  callable(path) -> list of source lines

    Returns a list (best first) of dicts: key (path, first, last), name, own, inherited,
    ops [(line, rule)], calls [(line, callee name, callee score)]. Functions with score 0
    (no risky operations, no risky callees) are left out.
    """
    spans = add_orphan_groups(hits, spans)
    own, ops = collections.Counter(), collections.defaultdict(set)
    for path, line, rule in hits:
        span = _innermost(spans.get(path), line)
        if span is None:
            continue
        key = (path, span[0], span[1])
        if (line, rule) not in ops[key]:
            ops[key].add((line, rule))
            own[key] += WEIGHTS.get(rule, 1)
    names, by_name, calls = {}, collections.defaultdict(list), {}
    for path, sp in spans.items():
        lines = None
        for lo, hi, name in sp:
            key = (path, lo, hi)
            names[key] = name
            if name.startswith(ORPHAN_PREFIX):
                calls[key] = []
                continue
            by_name[name].append(key)
            short = name.rsplit("::", 1)[-1]     # C++: `Object::streamReset` is called as
            if short != name:                    # `obj.streamReset(` / `streamReset(`
                by_name[short].append(key)
            if lines is None:
                lines = read_lines(path) or []
            sites = []
            for i in range(lo, min(hi, len(lines))):       # body: skip the signature line
                for c in _CALL.findall(lines[i]):
                    if c not in _NOT_CALLS and c != name and c != name.rsplit("::", 1)[-1]:
                        sites.append((i + 1, c))
            calls[key] = sites
    callees = {k: {g for _, c in v for g in by_name.get(c, ()) if g != k}
               for k, v in calls.items()}
    total = {k: float(own[k]) for k in names}
    for _ in range(DEPTH):
        total = {k: own[k] + INHERIT * max([total[g] for g in callees[k]] or [0.0])
                 for k in names}
    out = []
    for k in names:
        if total[k] <= 0:
            continue
        risky_calls = sorted({(ln, c, round(max(total[g] for g in by_name[c] if g != k), 1))
                              for ln, c in calls[k] if any(total[g] > 0 and g != k
                                                           for g in by_name.get(c, ()))})
        out.append({"key": k, "name": names[k], "own": own[k],
                    "orphan": names[k].startswith(ORPHAN_PREFIX),
                    "inherited": round(total[k] - own[k], 1),
                    "ops": sorted(ops.get(k, ())), "calls": risky_calls})
    # group 1 (own operations) by own score; then group 2 (calls only) by inherited score
    out.sort(key=lambda d: (d["own"] == 0, -(d["own"] or d["inherited"]), d["key"]))
    return out


def _read_lines(path):
    try:
        with open(path, errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return []


def group(results, target_root, spans, code_context):
    """Wide-net Semgrep results -> one finding per flagged function, best-ranked first.

    results       raw Semgrep results of the wide-net rules
    spans         {abspath: {(first, last, name)}} for all source files (function_spans)
    code_context  static_analyzer.code_context
    """
    hits = [(os.path.abspath(r.get("path", "")), r.get("start", {}).get("line", 0),
             r.get("check_id", "").rsplit(".", 1)[-1]) for r in results]
    pre = {(os.path.abspath(r.get("path", "")), r.get("start", {}).get("line", 0))
           for r in results if r.get("extra", {}).get("sa_preprocessed")}
    ranked = score_functions(hits, spans, _read_lines)
    n_own = sum(1 for d in ranked if d["own"])
    out = []
    for rank, d in enumerate(ranked, 1):
        path, lo, hi = d["key"]
        rel = os.path.relpath(path, target_root) if os.path.isdir(target_root) else path
        if d["own"]:
            top = max(d["ops"], key=lambda h: (WEIGHTS.get(h[1], 1), -h[0]))[0]
            counts = collections.Counter(rule for _, rule in d["ops"])
            parts = [f"{n} x {KIND.get(rule, rule)}" for rule, n in
                     sorted(counts.items(), key=lambda kv: (-WEIGHTS.get(kv[0], 1), -kv[1]))]
            why = "risky memory operations"
            message = (f"Hotspot #{rank} of {len(ranked)} (score {d['own']}): "
                       + ", ".join(parts) + ". Nearby checks were not taken as proof of "
                       "safety -- real bugs are often a check that exists but is wrong.")
            hotspots = _by_line((ln, KIND.get(rule, rule)) for ln, rule in d["ops"])
            n_ops = len(d["ops"])
        else:
            best = max(d["calls"], key=lambda c: (c[2], -c[0]))
            top = best[0]
            callees = sorted({(c[2], c[1]) for c in d["calls"]}, reverse=True)
            why = "calls risky functions"
            message = (f"Hotspot #{rank} of {len(ranked)} (inherited score {d['inherited']}): "
                       "no risky memory operations of its own, but it calls "
                       + ", ".join(f"{name} (score {s})" for s, name in callees[:5])
                       + ". Bugs whose fix is a missing check (state, mode, length) often "
                       "sit in such a caller while the crash happens in the callee.")
            hotspots = _by_line((ln, f"calls {name}") for ln, name, _ in d["calls"])
            n_ops = len(d["calls"])
        snippet, _ = code_context(path, top, spans=spans.get(path))
        out.append({
            "id": f"W{rank:03d}",
            "rule_id": "wide-net-hotspot",
            "cwe": None,
            "bug_class": "hotspot",
            "severity": "info",
            "file": rel,
            "line": top,
            "function": d["name"],
            "message": message,
            "code_context": snippet,
            "analyzer": "semgrep",
            "preprocessed": any((path, ln) in pre for ln, _ in d["ops"]),
            "tier": "wide",
            "rank": rank,
            "flagged_for": why,
            "score": d["own"] or d["inherited"],
            "function_span": [lo, hi],
            "hotspots": hotspots,          # every flagged line, one entry per line
            "hotspots_total": n_ops,       # operations (a line can hold several)
        })
    return out, n_own


# ------------------------------------------------------------------ fallback for unparsed files
# When Semgrep cannot parse a file at all (even its preprocessed copy) the file would otherwise
# contribute nothing. These line patterns approximate the wide-net rules so such a file still
# gets its risky operations flagged (cruder: no expression structure, so more noise).
_IDX = r"[A-Za-z_]\w*(?:\s*(?:->|\.)\s*\w+)*\s*\[\s*(?![0-9]+\s*\]|\])[^\]\n]*\]"
FALLBACK = [
    ("wide-copy-variable-size", re.compile(
        r"\b(?:memcpy|memmove|memset|memcmp|strncpy|strncat|strncmp|wmemcpy|bcopy|fread|recv|"
        r"read|pread|std::copy|copy_n|memchr|memrchr|memmem|strnlen)\s*\(")),
    ("wide-unbounded-string", re.compile(
        r"\b(?:strcpy|strcat|sprintf|vsprintf|gets|strlen|strchr|strrchr|strstr|strdup|"
        r"wcscpy|wcscat|stpcpy)\s*\(")),
    ("wide-terminator-read", re.compile(
        r"\b(?:strcmp|strcasecmp|strcoll|strspn|strcspn|strpbrk|strtok|atoi|atol|atof|strtol|"
        r"strtoul|strtoll|strtoull|strtod|sscanf)\s*\(")),
    ("wide-index-write", re.compile(_IDX + r"\s*(?:[-+*/|&^]?=(?!=)|\+\+|--)")),
    ("wide-index-read", re.compile(_IDX)),
    ("wide-field-fixed-offset", re.compile(r"(?:->|\.)\s*\w+\s*\[\s*(?:0[xX][0-9a-fA-F]+|[1-9]\d*)\s*\]")),
    ("wide-pointer-arith-deref", re.compile(r"\*\s*\(\s*\w+\s*[-+]\s*\w|\*\s*\w+\s*(?:\+\+|--)|\b\w+\s*[-+]=\s*\w")),
    ("wide-computed-alloc", re.compile(r"\b\w*(?:alloc|Alloc)\w*\s*\([^;]*[*+<]")),
    ("wide-free", re.compile(r"\bfree\s*\(|\bdelete\b|\b\w*(?:_free|Free|_destroy|_release|Release)\s*\(")),
    ("wide-release-call", re.compile(r"(?i)\b\w*(?:delete|destroy|remove|erase|dispose|unref|dealloc)\w*\s*\(")),
    ("wide-divide-by-variable", re.compile(r"[^/*\s]\s*[/%]=?\s*\(?\s*[A-Za-z_]\w*")),
]


def regex_fallback(path):
    """[(line, rule_id)] from the line patterns above, skipping comments and preprocessor lines."""
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return []
    # blank out comments and string literals, keeping line numbers
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    out = []
    for no, ln in enumerate(text.split("\n"), 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        for rule, pat in FALLBACK:
            if pat.search(ln):
                out.append((no, rule))
    return out


def fallback_results(paths):
    """Semgrep-shaped results for regex_fallback over paths (absolute)."""
    return [{"check_id": rule, "path": p, "start": {"line": ln}, "end": {"line": ln},
             "extra": {"severity": "INFO", "message": KIND.get(rule, rule),
                       "metadata": {}, "sa_fallback": True}}
            for p in paths for ln, rule in regex_fallback(p)]


def fill_unparsed(hits_by_file, root, files):
    """Benchmarks: their cached scans don't record parse status, so a source file with NO
    wide-net hits at all (the rules match nearly any indexed access, so in practice that means
    Semgrep couldn't parse it) gets the line-pattern fallback. Returns the filled dict."""
    out = dict(hits_by_file)
    for f in files:
        if not out.get(f):
            got = regex_fallback(os.path.join(root, f))
            if got:
                out[f] = sorted(set(got))
    return out
