#!/usr/bin/env python3
"""
CodeQL backend for the static-analysis stage.

CodeQL analyzes C/C++ by watching a build: each compiler invocation is replayed through its
extractor into a database, which queries then search (with real cross-function data flow,
which Semgrep OSS doesn't have). Libraries all build differently, so -- like the preprocessing
fallback -- this backend doesn't run the project's build system. It compiles every source file
on its own (`clang -c`), with the project's header directories on the include path and
generated headers (config.h, pnglibconf.h) rendered from the project's own templates
(see preprocess.Preprocessor). A file that doesn't compile cleanly is still extracted as far
as the compiler gets. Pass the real build's compile_commands.json to use its exact flags.

Results come back as Semgrep-shaped dicts (check_id / path / start / end / extra), so
static_analyzer.normalize() and benchmark.py score both backends the same way.
"""
import concurrent.futures
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import preprocess  # noqa: E402

QUERY_PACK = os.path.join(HERE, "codeql")                 # our queries (a CodeQL pack)
DEFAULT_QUERIES = [os.path.join(QUERY_PACK, "memory-safety.qls")]
SOURCE_LANG = {".c": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".c++": "c++"}
MAX_HEADER_ROUNDS = 50
# Export / visibility macros a configure step normally defines (php's ZEND_API, XMLPUBFUN,
# PNG_EXPORT...). Left undefined, every declaration using one is an error, and past 1,000 errors
# CodeQL's extractor drops the whole file. Defined as empty, like a plain Unix build.
# (Only export-style suffixes: OSSL_CALLBACK is a real function-pointer type, not a macro.)
_EXPORT_MACRO = re.compile(r"unknown type name '([A-Z][A-Z0-9_]*(?:_API|API|_EXPORTS?|_EXTERN|"
                           r"_DECL|PUBFUN|PUBVAR|_VISIBLE|_PUBLIC|_CDECL|_STDCALL))'")
SEVERITY = {"error": "ERROR", "warning": "WARNING", "recommendation": "INFO", "note": "INFO"}


def available():
    return shutil.which("codeql") is not None


_COMPILERS = {}


def compiler(cxx=False):
    """The real clang binary. On macOS /usr/bin/clang is a SIP-protected shim, and CodeQL's
    tracer has to copy every protected binary it runs through -- calling the toolchain's clang
    directly (and no shell per file) makes extraction ~4x faster."""
    name = "clang++" if cxx else "clang"
    if name not in _COMPILERS:
        path = None
        if sys.platform == "darwin":
            p = subprocess.run(["xcrun", "-f", name], capture_output=True, text=True)
            path = p.stdout.strip() or None
        _COMPILERS[name] = path or shutil.which(name) or shutil.which("gcc") or name
    return _COMPILERS[name]


_SYSROOT = []


def sysroot_flags():
    """On macOS the system headers live in the SDK; /usr/bin/clang finds it through xcrun, but
    the real clang binary we call needs it spelled out (without it <stdlib.h> isn't found and
    every libc declaration would be missing from the database)."""
    if not _SYSROOT and sys.platform == "darwin":
        p = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True, text=True)
        _SYSROOT.append(["-isysroot", p.stdout.strip()] if p.stdout.strip() else [])
    return _SYSROOT[0] if _SYSROOT else []


# Run by `codeql database create --command`: compile every file (argv lists, no shell).
_DRIVER = """import concurrent.futures, json, os, subprocess, sys
cmds = json.load(open(sys.argv[1]))
def run(c):
    subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with concurrent.futures.ThreadPoolExecutor(int(sys.argv[2])) as pool:
    list(pool.map(run, cmds))
"""


def sources(root, excludes=(), only=None):
    """Every C/C++ translation unit under root (headers are extracted through includes)."""
    if only is not None:
        return sorted(os.path.abspath(p) for p in only
                      if os.path.splitext(p)[1] in SOURCE_LANG)
    out = []
    globs = [e for e in excludes if any(c in e for c in "*?[")]     # file-name patterns
    for d, sub, files in os.walk(root):
        sub[:] = sorted(s for s in sub if not s.startswith(".") and s not in set(excludes))
        out += [os.path.join(d, f) for f in files if os.path.splitext(f)[1] in SOURCE_LANG
                and not any(fnmatch.fnmatch(f, g) for g in globs)]
    return sorted(os.path.abspath(p) for p in out)


class Build:
    """Per-file compile commands for a source tree, with missing generated headers resolved."""

    def __init__(self, root, excludes=(), compile_commands=None, defines=(), include_flags=None):
        self.root = os.path.abspath(root)
        self.pp = preprocess.Preprocessor(root, excludes, compile_commands, defines)
        self.gen = os.path.join(self.pp.work, "_generated")
        os.makedirs(self.gen, exist_ok=True)
        self.include_flags = include_flags
        self.defines = list(self.pp.defines)
        self.empty_macros = set()          # learned export macros, defined empty for all files

    def cleanup(self):
        self.pp.cleanup()

    def command(self, path):
        lang = SOURCE_LANG[os.path.splitext(path)[1]]
        base = (self.include_flags + self.defines if self.include_flags is not None
                else self.pp.flags_for(path))
        std = ["-std=gnu++17"] if lang == "c++" and not any(f.startswith("-std=") for f in base) \
            else []
        # _FORTIFY_SOURCE=0: macOS turns libc hardening on by default, which rewrites
        # strcpy/memcpy/sprintf into __builtin___*_chk builtins that CodeQL's library models
        # (and our queries) don't recognize as the libc functions
        return [compiler(lang == "c++"), *sysroot_flags(), "-x", lang, *std, "-w",
                "-D_FORTIFY_SOURCE=0", *base, *(f"-D{m}=" for m in sorted(self.empty_macros)),
                "-idirafter", self.gen]

    def resolve_headers(self, path):
        """Create generated/stub headers until the file preprocesses (real system headers)."""
        cmd = self.command(path) + ["-E", path, "-o", os.devnull]
        for _ in range(MAX_HEADER_ROUNDS):
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                                   timeout=120)
            except subprocess.TimeoutExpired:
                return
            missing = next((m.group(1) for rx in preprocess._MISSING
                            for m in [rx.search(p.stderr)] if m), None)
            if missing is None:
                return
            stub = os.path.normpath(os.path.join(self.gen, missing))
            if not stub.startswith(self.gen + os.sep):
                return
            if os.path.exists(stub):          # another thread made it, or it can't help
                continue
            os.makedirs(os.path.dirname(stub), exist_ok=True)
            tmp = f"{stub}.{os.getpid()}.{id(cmd)}"
            with open(tmp, "w") as f:
                f.write(self.pp._generated_header(missing))
            os.replace(tmp, stub)

    def learn_macros(self, path):
        """Find export macros this file needs (see _EXPORT_MACRO); two rounds per file."""
        for _ in range(2):
            try:
                p = subprocess.run(self.command(path) + ["-fsyntax-only", "-ferror-limit=0", path],
                                   capture_output=True, text=True, errors="replace", timeout=180)
            except subprocess.TimeoutExpired:
                return
            new = set(_EXPORT_MACRO.findall(p.stderr)) - self.empty_macros
            if not new:
                return
            self.empty_macros |= new


def create_db(root, db, excludes=(), only=None, compile_commands=None, defines=(),
              include_flags=None, threads=None, log=sys.stderr):
    """Build a CodeQL database for root by compiling every source file. Returns db path."""
    threads = threads or os.cpu_count() or 4
    files = sources(root, excludes, only)
    if not files:
        raise RuntimeError(f"no C/C++ sources under {root}")
    build = Build(root, excludes, compile_commands, defines, include_flags)
    try:
        with concurrent.futures.ThreadPoolExecutor(threads) as pool:
            list(pool.map(build.resolve_headers, files))
            list(pool.map(build.learn_macros, files))
        if build.empty_macros:
            print(f"[*] codeql: defining export macros as empty: "
                  f"{', '.join(sorted(build.empty_macros))}", file=log)
        work = tempfile.mkdtemp(prefix="sa_cq_")
        cmds = os.path.join(work, "commands.json")
        with open(cmds, "w") as f:
            json.dump([build.command(p) + ["-c", p, "-o", os.devnull] for p in files], f)
        driver = os.path.join(work, "driver.py")
        with open(driver, "w") as f:
            f.write(_DRIVER)
        command = " ".join(shlex.quote(a) for a in [sys.executable, driver, cmds, str(threads)])
        print(f"[*] codeql: extracting {len(files)} files from {root}", file=log)
        proc = subprocess.run(["codeql", "database", "create", db, "--language=cpp",
                               f"--source-root={root}", f"--command={command}", "--overwrite",
                               f"--threads={threads}"], capture_output=True, text=True)
        shutil.rmtree(work, ignore_errors=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout[-3000:] + proc.stderr[-3000:])
            raise RuntimeError("codeql database create failed")
    finally:
        build.cleanup()
    return db


def analyze(db, queries=None, out=None, threads=0, ram=None):
    """Run queries (paths, .qls suites or pack refs) on db. Returns the SARIF dict."""
    queries = queries or DEFAULT_QUERIES
    own = out is None
    if own:
        fd, out = tempfile.mkstemp(suffix=".sarif")
        os.close(fd)
    cmd = ["codeql", "database", "analyze", db, *queries, "--format=sarif-latest",
           f"--output={out}", f"--threads={threads}", "--no-print-diagnostics-summary",
           "--no-print-metrics-summary",
           # results are cached per query path; without --rerun an edited .qll is ignored
           "--rerun"]
    if ram:
        cmd.append(f"--ram={ram}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout[-3000:] + proc.stderr[-3000:])
        raise RuntimeError("codeql database analyze failed")
    with open(out) as f:
        sarif = json.load(f)
    if own:
        os.remove(out)
    return sarif


def _rule_meta(run):
    meta = {}
    tools = [run.get("tool", {}).get("driver", {})] + run.get("tool", {}).get("extensions", [])
    for t in tools:
        for r in t.get("rules", []):
            meta[r["id"]] = r
    return meta


def results(sarif, root):
    """SARIF -> Semgrep-shaped result dicts (paths absolute)."""
    out = []
    for run in sarif.get("runs", []):
        meta = _rule_meta(run)
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri")
            region = loc.get("region", {})
            if not uri or "startLine" not in region:
                continue
            rule = meta.get(r.get("ruleId"), {})
            props = rule.get("properties", {})
            cwes = [t.split("/")[-1].upper() for t in props.get("tags", [])
                    if t.startswith("external/cwe/")]
            sev = props.get("problem.severity") or r.get("level") or "warning"
            out.append({
                "check_id": r.get("ruleId", "codeql"),
                "path": os.path.join(root, uri),
                "start": {"line": region["startLine"]},
                "end": {"line": region.get("endLine", region["startLine"])},
                "extra": {
                    "message": r.get("message", {}).get("text", ""),
                    "severity": SEVERITY.get(sev, "WARNING"),
                    "metadata": {"cwe": cwes, "bug_class": props.get("sa-bug-class"),
                                 "query_name": rule.get("shortDescription", {}).get("text")},
                    "sa_analyzer": "codeql",
                },
            })
    return out


def scan(root, db_dir=None, queries=None, excludes=(), compile_commands=None, defines=(),
         keep_db=False):
    """Create a database for root, run queries, return Semgrep-shaped results."""
    tmp = None
    if db_dir is None:
        tmp = tempfile.mkdtemp(prefix="sa_cqdb_")
        db_dir = os.path.join(tmp, "db")
    try:
        create_db(root, db_dir, excludes, compile_commands=compile_commands, defines=defines)
        return results(analyze(db_dir, queries), os.path.abspath(root))
    finally:
        if tmp and not keep_db:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="build a CodeQL db for a tree and/or run queries")
    ap.add_argument("root")
    ap.add_argument("--db", required=True)
    ap.add_argument("--create", action="store_true")
    ap.add_argument("--include-flags", nargs="*", help="override include flags (e.g. -Idir)")
    ap.add_argument("--queries", nargs="*")
    ap.add_argument("--out", help="write SARIF here")
    a = ap.parse_args()
    if a.create:
        create_db(a.root, a.db, include_flags=a.include_flags)
    if a.queries is not None:
        res = results(analyze(a.db, a.queries or None, a.out), os.path.abspath(a.root))
        print(json.dumps([(r["check_id"], os.path.relpath(r["path"], a.root),
                           r["start"]["line"]) for r in res], indent=0))
