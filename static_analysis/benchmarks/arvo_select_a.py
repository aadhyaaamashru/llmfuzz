"""Freeze the ARVO test set (decided before any scoring):
  - C libraries that parse a data format / protocol, not one of Magma's 9 libraries
  - ASan memory-error crashes only; fix commit is a single commit in the project's own repo
  - at most 5 bugs per library, sampled with a fixed seed (453)
Fix-size filtering (<=3 C source files, <=80 changed lines) happens after cloning, in order,
taking the next sampled bug until 5 qualify.

  python3 benchmarks/arvo_select_a.py arvo.db candidates_a.json   (arvo.db: from ARVO-Meta)
"""
import json, random, sqlite3, sys
PROJECTS = ["c-blosc2", "matio", "libdwarf", "wolfmqtt", "libarchive", "lcms", "pcre2", "htslib",
            "file", "leptonica", "libexif", "zstd", "readstat", "libucl", "libssh2", "libplist",
            "jq", "flac", "oniguruma", "libspng", "mdbtools", "md4c", "libredwg", "selinux", "ndpi"]
TYPES = ["Heap-buffer-overflow", "Stack-buffer-overflow", "Global-buffer-overflow",
         "Heap-use-after-free", "Heap-double-free", "Stack-use-after", "Use-after-poison",
         "Null-dereference", "Segv on unknown address", "UNKNOWN", "Negative-size-param",
         "Memcpy-param-overlap", "Bad-free", "Stack-buffer-underflow", "Heap-buffer-underflow",
         "Dynamic-stack-buffer-overflow"]
db = sqlite3.connect(sys.argv[1])
out = {}
for p in PROJECTS:
    rows = db.execute("select localId, crash_type, fix_commit, repo_addr, fuzz_target, crash_output "
                      "from arvo where project=? and sanitizer='asan' and submodule_bug=0", (p,)).fetchall()
    rows = [r for r in rows if r[2] and "\n" not in r[2].strip() and len(r[2].strip()) == 40
            and any(r[1].startswith(t) for t in TYPES)]
    rows.sort()
    random.Random(453).shuffle(rows)
    out[p] = [dict(id=r[0], crash_type=r[1], fix=r[2].strip(), repo=r[3], fuzz_target=r[4],
                   crash_output=r[5]) for r in rows]
    print(p, len(rows))
json.dump(out, open(sys.argv[2], "w"), indent=1)
