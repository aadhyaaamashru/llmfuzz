#!/usr/bin/env python3
"""
Preprocessing fallback for files Semgrep cannot parse.

Why this exists
---------------
Semgrep reads raw C/C++ without running the preprocessor. Real libraries contain two things
that break its parser, and whole files get dropped (0 findings, reported only as a warning):
  1. project macros used like keywords: zlib `local`, expat `XMLCALL`, spng `SPNG_TARGET_CLONES(...)`
  2. `#if/#else` blocks where each branch holds half a construct (e.g. two different
     `if (...) {` openers sharing one closing `}`)
The compiler never sees either, because its preprocessor resolves them first. So for the files
Semgrep fails on, we run the preprocessor on a temporary copy and scan that copy as well.

What changes and what does not
------------------------------
* The library's own files are never modified: we write a temporary copy.
* System headers are never read (`-nostdinc`; any header the project doesn't ship is replaced by
  an empty stub). So `memcpy`, `NULL`, `stderr` stay exactly as written, and libc hardening
  (_FORTIFY_SOURCE, which rewrites memcpy into __builtin___memcpy_chk) cannot kick in.
* Line numbers are preserved: every preprocessed line is written back at its original line
  number, so findings point at the real file and line, and the code context the LLM reads is
  the original source.
* What DOES change: the project's own macros are expanded, and of each `#if/#else` only the branch
  that matches the build configuration is kept. Pass the real build's flags (compile_commands.json
  and/or -D) so this matches the binary that gets fuzzed. Findings from the original (partial)
  parse are kept too, so we only ever add findings, never lose them.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

C_SRC = {".c"}
CXX_SRC = {".cc", ".cpp", ".cxx", ".c++", ".C"}
HEADERS = {".h", ".hh", ".hpp", ".hxx", ".inc"}
CXX_HEADERS = {".hh", ".hpp", ".hxx"}
MAX_STUB_ROUNDS = 200

_MARKER = re.compile(r'^#\s*(?:line\s+)?(\d+)\s+"((?:[^"\\]|\\.)*)"')
_MISSING = [re.compile(r"fatal error: '([^']+)' file not found"),              # clang
            re.compile(r"fatal error: ([^:\s]+): No such file or directory")]  # gcc


# Templates a build turns into generated headers, most specific first:
# pnglibconf.h.prebuilt (libpng), config.h.cmake / .cmake.in (CMake), config.h.in (autoconf)
_TEMPLATE_SUFFIXES = (".prebuilt", ".cmake.in", ".cmake", ".cmakein", ".in", ".dist",
                      ".default", ".generic")
_CMAKEDEFINE01 = re.compile(r"^\s*#\s*cmakedefine01\s+(\w+).*$")
_CMAKEDEFINE = re.compile(r"^\s*#\s*cmakedefine\s+(\w+)(.*)$")
_AC_UNDEF = re.compile(r"^\s*#\s*undef\s+([A-Z_][A-Z0-9_]*)\s*(/\*.*)?$")
_SUBST = re.compile(r"@[A-Za-z_]\w*@|\$\{[A-Za-z_]\w*\}")


_PERL_BLOCK = re.compile(r"\{-.*?-\}", re.S)       # OpenSSL's configuration.h.in templates
_FACTS = None


def platform_facts():
    """What a configure script would detect about this machine, for config headers we have to
    make up: SIZEOF_* from the compiler's own __SIZEOF_*__ macros, and the C99 headers that
    every modern libc has. (php's headers stop with `#error "Unknown SIZEOF_SIZE_T"` without
    them.)"""
    global _FACTS
    if _FACTS is None:
        _FACTS = {}
        cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
        try:
            out = subprocess.run([cc, "-dM", "-E", "-x", "c", os.devnull], capture_output=True,
                                 text=True, timeout=60).stdout if cc else ""
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        names = {"SHORT": "SHORT", "INT": "INT", "LONG": "LONG", "LONG_LONG": "LONG_LONG",
                 "POINTER": "VOID_P", "SIZE_T": "SIZE_T", "PTRDIFF_T": "PTRDIFF_T",
                 "FLOAT": "FLOAT", "DOUBLE": "DOUBLE", "LONG_DOUBLE": "LONG_DOUBLE",
                 "WCHAR_T": "WCHAR_T", "INT128": "INT128"}
        for m in re.finditer(r"#define __SIZEOF_(\w+)__ (\d+)", out):
            if m.group(1) in names:
                _FACTS["SIZEOF_" + names[m.group(1)]] = m.group(2)
        if "SIZEOF_LONG_LONG" in _FACTS:
            _FACTS.setdefault("SIZEOF_INT64_T", "8")
            _FACTS.setdefault("SIZEOF_OFF_T", "8")
            _FACTS.setdefault("SIZEOF_INTMAX_T", _FACTS["SIZEOF_LONG_LONG"])
            _FACTS.setdefault("SIZEOF_CHAR", "1")
        for h in ("STDINT_H", "INTTYPES_H", "STDLIB_H", "STRING_H", "STRINGS_H", "STDDEF_H",
                  "STDARG_H", "STDBOOL_H", "LIMITS_H", "UNISTD_H", "ERRNO_H", "SYS_TYPES_H",
                  "SYS_STAT_H", "FCNTL_H", "MEMORY_H", "MATH_H", "TIME_H", "LOCALE_H"):
            _FACTS["HAVE_" + h] = "1"
        _FACTS["STDC_HEADERS"] = "1"
    return _FACTS


def facts_header():
    return "".join(f"#ifndef {k}\n#define {k} {v}\n#endif\n"
                   for k, v in sorted(platform_facts().items()))


def render_template(text, autoconf=False):
    """Approximate the configure step with every option on: `#cmakedefine X` -> `#define X`,
    `@VAR@`/`${VAR}` -> 1, and (autoconf `.in`) `#undef FEATURE` -> `#define FEATURE 1`
    (`#undef SIZEOF_INT` gets the real size). Lower-case autoconf names (`#undef size_t`,
    `#undef inline`) are type fallbacks, not features, and are left alone. OpenSSL-style Perl
    blocks (`{- ... -}`) are dropped."""
    out = []
    text = _PERL_BLOCK.sub("", text)
    facts = platform_facts()
    for line in text.splitlines():
        m = _CMAKEDEFINE01.match(line)
        if m:
            line = f"#define {m.group(1)} 1"
        else:
            m = _CMAKEDEFINE.match(line)
            if m:
                line = f"#define {m.group(1)}{m.group(2)}"
            elif autoconf:
                m = _AC_UNDEF.match(line)
                if m:
                    line = f"#define {m.group(1)} {facts.get(m.group(1), '1')}"
        out.append(_SUBST.sub("1", line))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- detection
def _line_count(path):
    try:
        with open(path, errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def parse_problems(raw):
    """Files Semgrep could not fully parse.

    Returns {abspath: {"path": as-reported, "status": "failed"|"partial", "lines_lost": int}}.
    Semgrep reports these only as 'warn'-level errors: a 'Syntax error' means the whole file was
    dropped; 'PartialParsing' lists the regions it skipped and kept the rest.
    """
    probs = {}
    for e in raw.get("errors", []):
        t = e.get("type")
        kind = t[0] if isinstance(t, list) else (t or "")
        if kind == "PartialParsing":
            for loc in (t[1] if isinstance(t, list) and len(t) > 1 else []):
                p = loc.get("path")
                if not p:
                    continue
                d = probs.setdefault(os.path.abspath(p),
                                     {"path": p, "status": "partial", "lines_lost": 0})
                if d["status"] == "partial":
                    d["lines_lost"] += loc["end"]["line"] - loc["start"]["line"] + 1
        elif re.search(r"syntax|pars|lexical", kind, re.I):
            p = e.get("path")
            if not p:
                m = re.search(r" at line (.+?):\d+:", e.get("message", ""))
                p = m.group(1) if m else None
            if p:
                probs[os.path.abspath(p)] = {"path": p, "status": "failed",
                                             "lines_lost": _line_count(p)}
    return probs


# --------------------------------------------------------------------------- build flags
_PATH_OPTS = ("-I", "-iquote", "-isystem", "-idirafter", "-include", "-imacros")
_DEF_OPTS = ("-D", "-U")


def load_compile_commands(path):
    """compile_commands.json -> {realpath(source): [preprocessor flags of the real build]}.

    Keeps only what affects preprocessing (-I/-iquote/-isystem/-include/-D/-U/-std=), with
    relative paths made absolute against each entry's directory.
    """
    with open(path) as f:
        entries = json.load(f)
    db = {}
    for e in entries:
        d = e.get("directory", ".")
        args = e.get("arguments") or shlex.split(e.get("command", ""))
        flags, i = [], 0
        while i < len(args):
            a = args[i]
            opt = next((o for o in _PATH_OPTS + _DEF_OPTS
                        if a == o or (o in ("-I", "-D", "-U") and a.startswith(o))), None)
            if opt is None:
                if a.startswith("-std="):
                    flags.append(a)
                i += 1
                continue
            if a == opt:                       # separate form: -I dir
                if i + 1 >= len(args):
                    break
                val, i = args[i + 1], i + 2
            else:                              # joined form: -Idir, -DFOO=1
                val, i = a[len(opt):], i + 1
            if opt in _PATH_OPTS:
                val = os.path.normpath(os.path.join(d, val))
            flags += [opt + val] if opt in ("-I", "-D", "-U") else [opt, val]
        db[os.path.realpath(os.path.join(d, e["file"]))] = flags
    return db


# --------------------------------------------------------------------------- preprocessing
def align(text, src, nlines):
    """Put each preprocessed line that came from `src` back at its original line number.

    Lines from headers are dropped (headers are scanned on their own), so the copy has exactly
    `nlines` lines and a finding on line N of the copy is a finding on line N of the original.
    Returns (aligned_text, number_of_code_lines_kept).
    """
    want = os.path.realpath(src)
    is_main = {}
    out = [""] * nlines
    cur, line, kept = False, 0, 0
    for raw in text.split("\n"):
        m = _MARKER.match(raw)
        if m:
            line = int(m.group(1))
            name = m.group(2).replace('\\"', '"').replace("\\\\", "\\")
            if name not in is_main:
                is_main[name] = not name.startswith("<") and os.path.realpath(name) == want
            cur = is_main[name]
            continue
        if cur and raw.strip() and 1 <= line <= nlines:
            out[line - 1] = f"{out[line - 1]} {raw.strip()}" if out[line - 1] else raw
            kept += 1
        line += 1
    return "\n".join(out) + "\n", kept


class Preprocessor:
    def __init__(self, root, excludes=(), compile_commands=None, defines=()):
        self.root = os.path.abspath(root)
        self.excludes = set(excludes)
        self.cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
        if not self.cc:
            raise RuntimeError("no C compiler (clang/gcc) found for preprocessing")
        ver = subprocess.run([self.cc, "--version"], capture_output=True, text=True).stdout
        self.err_limit = "-ferror-limit=0" if "clang" in ver else "-fmax-errors=0"
        self.defines = [d if d.startswith(_DEF_OPTS) else "-D" + d for d in defines]
        self.db = load_compile_commands(compile_commands) if compile_commands else {}
        self.work = tempfile.mkdtemp(prefix="sa_pp_")
        self.stubs = os.path.join(self.work, "_stubs")
        os.makedirs(self.stubs)
        self._inc = None
        self._tmpl = None
        self._n = 0

    def cleanup(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _heuristic_includes(self):
        """No build info: put every project directory that holds headers on the include path."""
        if self._inc is None:
            dirs = []
            for d, sub, files in os.walk(self.root):
                sub[:] = sorted(s for s in sub if not s.startswith(".") and s not in self.excludes)
                if any(os.path.splitext(f)[1] in HEADERS for f in files):
                    dirs.append(d)
            dirs.sort(key=lambda d: (d.count(os.sep), d))
            self._inc = [self.root] + [d for d in dirs if d != self.root]
        return self._inc

    def _generated_header(self, missing):
        """Contents for a header the build would generate (config.h, pnglibconf.h,
        libxml/xmlversion.h), rendered from the template the project ships with every
        optional feature switched on, so `#ifdef FEATURE_SUPPORTED` code is analyzed instead of
        vanishing. '' when there's no template (libc headers etc.)."""
        if self._tmpl is None:
            self._tmpl = {}
            for d, sub, files in os.walk(self.root):
                sub[:] = sorted(s for s in sub if not s.startswith(".") and s not in self.excludes)
                for f in files:
                    for rank, suf in enumerate(_TEMPLATE_SUFFIXES):
                        base = f[:-len(suf)]
                        if f.endswith(suf) and os.path.splitext(base)[1] in HEADERS:
                            path = os.path.join(d, f)
                            key = (rank, path.count(os.sep), path)
                            self._tmpl.setdefault(base, []).append((key, path, suf))
        cands = self._tmpl.get(os.path.basename(missing))
        if not cands:
            # a configure-generated header with no template (php_config.h): platform facts
            return facts_header() if "config" in os.path.basename(missing).lower() else ""
        # prefer a template whose location matches the include path ("libxml/xmlversion.h")
        sub = os.path.dirname(os.path.normpath(missing))
        cands = sorted(cands, key=lambda c: (not os.path.dirname(c[1]).endswith(sub), c[0]))
        _, path, suf = cands[0]
        try:
            with open(path, errors="replace") as f:
                return render_template(f.read(), autoconf=(suf == ".in"))
        except OSError:
            return ""

    def flags_for(self, path):
        real = os.path.realpath(path)
        entry = self.db.get(real)
        if entry is None and self.db:
            # headers aren't in the compile db: borrow a source file's flags from the same dir
            d = os.path.dirname(real)
            entry = next((v for k, v in self.db.items() if os.path.dirname(k) == d), None)
        if entry is not None:
            return entry + self.defines
        return ["-I" + d for d in self._heuristic_includes()] + self.defines

    @staticmethod
    def lang(path):
        ext = os.path.splitext(path)[1]
        if ext in CXX_SRC or ext in CXX_HEADERS:
            return "c++"
        if ext == ".h":
            try:
                names = os.listdir(os.path.dirname(path) or ".")
            except OSError:
                names = []
            ncxx = sum(os.path.splitext(n)[1] in CXX_SRC for n in names)
            nc = sum(os.path.splitext(n)[1] in C_SRC for n in names)
            return "c++" if ncxx > nc else "c"
        return "c"

    def preprocess(self, path):
        """Write a line-aligned preprocessed copy of `path`. Returns (copy_path or None, note)."""
        src = os.path.abspath(path)
        cmd = [self.cc, "-E", "-nostdinc", "-w", self.err_limit, "-x", self.lang(src),
               *self.flags_for(src), "-idirafter", self.stubs, src]
        for _ in range(MAX_STUB_ROUNDS):
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                   timeout=120)
            except subprocess.TimeoutExpired:
                return None, "preprocessor timed out"
            missing = next((m.group(1) for rx in _MISSING for m in [rx.search(p.stderr)] if m),
                           None)
            if missing is None:
                break
            # a header the project doesn't ship: a generated one (config.h) is rendered from
            # the project's template; anything else (libc) becomes an empty stub
            stub = os.path.normpath(os.path.join(self.stubs, missing))
            if not stub.startswith(self.stubs + os.sep) or os.path.exists(stub):
                return None, f"cannot resolve #include {missing!r}"
            os.makedirs(os.path.dirname(stub), exist_ok=True)
            with open(stub, "w") as f:
                f.write(self._generated_header(missing))
        else:
            return None, "too many missing headers"
        if not p.stdout.strip():
            err = next((l for l in p.stderr.splitlines() if "error" in l), "no output")
            return None, f"preprocessor failed: {err[:200]}"
        aligned, kept = align(p.stdout, src, _line_count(src))
        if not kept:
            return None, "no code survives in this build configuration"
        self._n += 1
        out = os.path.join(self.work, str(self._n), os.path.basename(src))
        os.makedirs(os.path.dirname(out))
        with open(out, "w") as f:
            f.write(aligned)
        return out, "ok"


# --------------------------------------------------------------------------- driver
def timeouts(raw, root, path_map=None):
    """Rule/file pairs Semgrep timed out on, as [{"file": rel, "rule": short_id}].
    path_map: {copy_abspath: rel} to report preprocessed copies under the original file."""
    out = []
    for e in raw.get("errors", []):
        if e.get("type") != "Timeout" or not e.get("path"):
            continue
        ap = os.path.abspath(e["path"])
        rel = (path_map or {}).get(ap) or os.path.relpath(ap, os.path.abspath(root))
        out.append({"file": rel, "rule": (e.get("rule_id") or "").rsplit(".", 1)[-1]})
    return out


def recover(raw, scan, root, only=None, excludes=(), compile_commands=None, defines=(),
            force=False):
    """Re-scan the files Semgrep couldn't parse, through a preprocessed copy.

    raw   : Semgrep JSON from the normal pass
    scan  : callable(list_of_file_paths) -> Semgrep JSON (same rules as the normal pass);
            None = don't preprocess, only report the files that didn't parse
    only  : optional set of absolute paths to restrict recovery to
    force : preprocess every scanned file, not just failing ones (to test faithfulness)

    Returns (extra_results, coverage). extra_results have their `path` mapped back to the
    original file and `extra.sa_preprocessed = True`; line numbers are already original.
    """
    probs = parse_problems(raw)
    if force:
        for p in raw.get("paths", {}).get("scanned", []):
            probs.setdefault(os.path.abspath(p), {"path": p, "status": "ok", "lines_lost": 0})
    if only is not None:
        probs = {k: v for k, v in probs.items() if k in only}
    coverage = {"files_scanned": len(raw.get("paths", {}).get("scanned", [])),
                "parse_problems": sum(v["status"] != "ok" for v in probs.values()),
                "preprocessed": 0, "recovered": 0, "improved": 0, "still_unparsed": [],
                "files": {}}
    root = os.path.abspath(root)
    if not probs:
        return [], coverage
    if scan is None:   # preprocessing disabled: just report what Semgrep couldn't read
        coverage["files"] = {os.path.relpath(k, root): {"before": v["status"],
                                                        "lines_lost_before": v["lines_lost"]}
                             for k, v in sorted(probs.items())}
        coverage["still_unparsed"] = [r for r, f in coverage["files"].items()
                                      if f["before"] == "failed"]
        return [], coverage

    pp = Preprocessor(root, excludes, compile_commands, defines)
    try:
        mapping, report = {}, {}
        for ap, info in sorted(probs.items()):
            rel = os.path.relpath(ap, root)
            copy, note = pp.preprocess(ap)
            report[rel] = {"before": info["status"], "lines_lost_before": info["lines_lost"],
                           "preprocess": note}
            if copy:
                mapping[os.path.abspath(copy)] = (info["path"], rel, ap)

        coverage["preprocessed"] = len(mapping)
        extra = []
        if mapping:
            raw2 = scan(sorted(mapping))
            probs2 = parse_problems(raw2)
            coverage["timeouts"] = [dict(t, preprocessed=True) for t in timeouts(
                raw2, root, {c: rel for c, (_, rel, _) in mapping.items()})]
            for copy, (_, rel, _) in mapping.items():
                p2 = probs2.get(copy)
                report[rel]["after"] = p2["status"] if p2 else "ok"
                report[rel]["lines_lost_after"] = p2["lines_lost"] if p2 else 0
            before = {(r.get("check_id"), os.path.abspath(r["path"]), r["start"]["line"])
                      for r in raw.get("results", [])}
            for r in raw2.get("results", []):
                hit = mapping.get(os.path.abspath(r["path"]))
                if not hit:
                    continue
                orig, rel, ap = hit
                r["path"] = orig
                r.setdefault("extra", {})["sa_preprocessed"] = True
                extra.append(r)
                if (r.get("check_id"), ap, r["start"]["line"]) not in before:
                    report[rel]["new_findings"] = report[rel].get("new_findings", 0) + 1
    finally:
        pp.cleanup()

    for rel, f in report.items():
        if f["before"] == "ok":
            continue
        after = f.get("after")
        if after == "ok":
            coverage["recovered"] += 1
        elif after == "partial" and (f["before"] == "failed"
                                     or f["lines_lost_after"] < f["lines_lost_before"]):
            coverage["improved"] += 1
        elif f["before"] == "failed":
            coverage["still_unparsed"].append(rel)
    coverage["files"] = report
    return extra, coverage


def summary_line(cov):
    s = (f"{cov['parse_problems']} of {cov['files_scanned']} files did not fully parse; "
         f"preprocessed {cov['preprocessed']}: recovered {cov['recovered']}, "
         f"improved {cov['improved']}")
    if cov["still_unparsed"]:
        s += f"; STILL UNPARSED (0 findings): {', '.join(cov['still_unparsed'])}"
    return s
