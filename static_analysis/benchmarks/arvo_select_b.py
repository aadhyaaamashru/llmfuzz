"""ARVO set B (frozen before scoring): every project with >=3 qualifying ASan memory bugs that is
not a Magma library, not in set A, git-hosted, and not on the too-large-to-scan-per-bug list.
Fixed-seed sample per project (run with --per-project 2); same fix-size filter as set A (in
arvo_benchmark).

  python3 benchmarks/arvo_select_b.py arvo.db candidates_b.json
"""
import json, random, sqlite3, sys
SET_A = ["c-blosc2", "matio", "libdwarf", "wolfmqtt", "libarchive", "lcms", "pcre2", "htslib",
            "file", "leptonica", "libexif", "zstd", "readstat", "libucl", "libssh2", "libplist",
            "jq", "flac", "oniguruma", "libspng", "mdbtools", "md4c", "libredwg", "selinux", "ndpi"]
TYPES = ["Heap-buffer-overflow", "Stack-buffer-overflow", "Global-buffer-overflow",
         "Heap-use-after-free", "Heap-double-free", "Stack-use-after", "Use-after-poison",
         "Null-dereference", "Segv on unknown address", "UNKNOWN", "Negative-size-param",
         "Memcpy-param-overlap", "Bad-free", "Stack-buffer-underflow", "Heap-buffer-underflow",
         "Dynamic-stack-buffer-overflow"]
MAGMA = {"libpng", "libsndfile", "libtiff", "libxml2", "lua", "openssl", "php-src", "php",
         "poppler", "sqlite3"}
TOO_LARGE = {"ffmpeg", "binutils-gdb", "wireshark", "imagemagick", "graphicsmagick", "gdal",
             "ghostpdl", "skia", "opencv", "qt", "qt/qtqa", "serenity", "llvm", "envoy",
             "tensorflow", "v8", "chromium", "libreoffice", "mysql-server", "postgresql",
             "duckdb", "arrow", "perfetto", "icu", "samba", "kamailio", "opensips",
             "freeradius-server", "zeek", "edk2", "qemu", "fluent-bit", "gpac", "radare2",
             "openthread", "wolfssl", "openvswitch", "vlc", "mongoose", "pcl", "rdkit", "assimp",
             "kimageformats", "karchive", "gstreamer", "libvips", "opencv", "ntopng", "unicorn",
             "tarantool", "wamr", "fwupd", "cyclonedds", "openexr", "harfbuzz", "freetype2",
             "llvm-project", "cpython3", "systemd", "grpc", "binutils-preconditions", "poco",
             "capstonenext"}
db = sqlite3.connect(sys.argv[1])
rows = db.execute("select localId, project, crash_type, fix_commit, repo_addr, fuzz_target, "
                  "crash_output from arvo where sanitizer='asan' and submodule_bug=0").fetchall()
by = {}
for r in rows:
    fix = (r[3] or "").strip()
    if "\n" in fix or len(fix) != 40 or not any(r[2].startswith(t) for t in TYPES):
        continue
    if not (r[4] or "").startswith(("https://github.com", "https://gitlab.com", "https://git.",
                                    "https://gitlab.", "https://bitbucket.org")):
        continue
    by.setdefault(r[1], []).append(r)
out = {}
for p in sorted(by):
    if p in MAGMA or p in SET_A or p in TOO_LARGE or len(by[p]) < 3:
        continue
    rs = sorted(by[p]); random.Random(453).shuffle(rs)
    out[p] = [dict(id=r[0], crash_type=r[2], fix=r[3].strip(), repo=r[4], fuzz_target=r[5],
                   crash_output=r[6]) for r in rs]
json.dump(out, open(sys.argv[2], "w"), indent=1)
print(len(out), "projects:", " ".join(f"{p}({len(v)})" for p, v in out.items()))
