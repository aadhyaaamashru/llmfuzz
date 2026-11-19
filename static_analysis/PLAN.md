# Static Analysis Stage — plan & how-to

Owner: Aadhyaaa. This is the first stage of the pipeline: it takes a C/C++ library and
emits normalized **findings JSON** that the LLM stage (Madhav) consumes.

```
1. Static analyzer (this)   library URL ──► findings.json            runs FIRST, once per library
2. LLM (Madhav)             findings.json ──► drop false alarms, write harness + seeds
3. Fuzzer (microVM)         build library + harness with AFL++/ASan ──► crashes
4. Replay                   crash ──► confirm ──► report
```

Design principle: **maximize recall here, not precision.** A bug missed here is missed forever;
precision is the LLM's job, and the fuzzer is the final ground truth. The stage is
**target-agnostic** (any local path or git URL) and emits **two tiers** in one schema:
`precise` findings (specific bug patterns from Semgrep rules and CodeQL data-flow queries) and a
`wide` tier — every function with risky memory operations (or calling them), ranked, so no real
bug is left off the list (see "Wide-net tier"). On 588 real bugs from 4 benchmarks the wide tier
lists the bug's function for 584 (the 4 others are not inside any function); the precise tier alone
for ~40%.

## Progression

1. **Script** — `static_analyzer.py`: clone → Semgrep → normalize → JSON.  ✅
2. **Toy cases** — `tests/toy/`: all 5 planted bugs found, 0 findings on `clean.c`.  ✅
3. **Benchmark** — `benchmarks/juliet_benchmark.py` against Juliet (line-level scoring, held-out split, noise on
   real code).  ✅
4. **Semgrep tuned to its plateau** — 30 local rules (`rules/memory_safety.yaml`).  ✅
   Every single-function bug Juliet still misses needs cross-function or alias analysis.
5. **Preprocessing fallback** — files Semgrep can't parse are re-scanned (see below).  ✅
6. **Real-bug benchmark** — `magma_benchmark.py` against Magma (138 real CVEs in 9 libraries).  ✅
7. **CodeQL backend** — cross-function queries, tuned the same way (see "CodeQL backend").  ✅
8. **Wide-net tier** — recall on real bugs: Magma held-out, ARVO (OSS-Fuzz) and DARPA CGC
   (`arvo_benchmark.py`, `cgc_benchmark.py`).  ✅
9. **Run on the chosen library** (mxml / quirc / tinycbor) and hand `findings.json` to Madhav.  ⬜

## Results (Juliet, 16 memory-safety CWEs that AddressSanitizer can confirm)

Starting point (4 rules, 5 CWEs, `_01` only): 16% recall, 36% precision.

**The stage = Semgrep + CodeQL, findings unioned.**

| split | cases | Semgrep alone | **Semgrep + CodeQL** | single-fn | cross-fn | precision |
|---|---|---|---|---|---|---|
| dev (`_01`, tuned on) | 665 | 98.6% | – | – | – | – |
| tune (tuned on) | 13,197 | 90.3% | 97.8% | 98.1% | 97.4% | 38.6% |
| **final (never tuned on)** | **13,165** | **90.5%** | **97.7%** | **98.1%** | **97.3%** | **38.7%** |

Missed cases on `final`: ~1,250 with Semgrep alone → **298** with both. Tune and final agree
(97.8% vs 97.7%), so the tuning didn't overfit the half it saw.

Noise on real code (4 libraries, 107 KLOC): **3.0 findings / KLOC** with both (Semgrep alone 2.88;
CodeQL adds 13 findings).

Per CWE, `final` split:

| CWE | what | Semgrep alone | **+ CodeQL** | cross-fn (both) | precision (both) |
|---|---|---|---|---|---|
| 121 | stack overflow | 100% | 100% | 100% | 38% |
| 122 | heap overflow | 98.7% | 98.7% | 97.5% | 36% |
| 124 / 127 | buffer under-write / under-read | 100% | 100% | 100% | 42% |
| 126 | over-read | 100% | 100% | 100% | 42% |
| 134 | format string | 100% | 100% | 100% | 26% |
| 194 / 195 | sign conversion → huge size | 100% | 100% | 100% | 27% |
| 415 | double free | 43.5% | **92.3%** | 90% | 61% |
| 416 | use after free | 90.3% | **100%** | 100% | 64% |
| 476 | NULL deref | 58.3% | **90.1%** | 81% | 76% |
| 590 | free of stack memory | 51.4% | **94.6%** | 94% | 88% |
| 680 | int overflow → overflow | 50.0% | 50.0% | 50% | 20% |
| 690 | unchecked malloc → NULL | 62.1% | **95.1%** | 97% | 78% |
| 761 | free of moved pointer | 100% | 100% | 100% | 92% |
| 789 | huge allocation | 100% | 100% | 100% | 20% |

CodeQL alone on `final` (it only targets the cross-function classes; the rest is Semgrep's job):
double free 52.8% (cross-fn 90%), use after free 44.1% (100%), NULL deref 76.8% (81%), unchecked
malloc 93.0% (95%), free of stack memory 91.9% (94%); precision 98.4%. Its 31 "false alarms" on
`final` are all `sa/unchecked-alloc-deref` in CWE-476's `null_check_after_deref` cases:
`p = malloc(..); *p = 5;`, which Juliet labels safe *for CWE-476* but is a real unchecked malloc.

How to read it:
- **recall** = test cases with a finding on Juliet's labeled flaw line (span ≤ 15 lines).
- **single-fn / cross-fn**: Juliet flow variants 01–34 keep the bug in one function, 41+ split
  it across functions/files.
- **noise** = findings per 1,000 lines on 4 real libraries (libspng, libexpat, zlib, tinyxml2):
  the triage load the LLM pays. It is not a false-positive rate (no ground truth there).

What's still missed (298 cases):
- **CWE-680 `new int[n]`** (129): modern compilers saturate the `new[]` size, so it fails to
  allocate instead of overflowing — ASan can't confirm it. Not a real target.
- **aliasing** (variants 32 pointer-to-pointer, 33 C++ reference) and **C++ containers**
  (72–74: `std::vector`/`list`/`map` holding the pointer) for the temporal / NULL classes.
- a few heap-overflow (CWE-122) cross-function shapes.

Semgrep's own tuning history (before CodeQL): last round on `final`, double free 12.6% → 43.5%,
NULL deref 24.5% → 58.3%, unchecked malloc 60.5% → 62.1%, moved-pointer free 97.7% → 100%;
overall 89.0% → 90.5%. (Caveat: the alternating split put every `malloc`-sink variant of
CWE-194/195 in `tune`, so the sign-conversion rule's gain has no counterpart in `final`.)

## Results on real bugs (Magma)

Juliet's bugs are small textbook examples. To see how the stage does on real code we ran it on
**Magma** (Hazimeh et al., SIGMETRICS 2021): 9 real libraries with 138 real, previously reported
bugs (mostly CVEs) put back into the code. The stage runs exactly as on a real target (default
excludes, preprocessing fallback). Full per-bug results with hand verdicts: `benchmarks/results/magma_precise.json`.

Stage = Semgrep + CodeQL. The CodeQL queries were tuned on the five *tuning* libraries only
(libpng, libsndfile, libtiff, libxml2, lua); openssl, php, poppler and sqlite3 are *held out*.

| | bugs | finding ≤ 5 lines from the bug | finding in the bug's function | **hand-checked: finding describes the bug** |
|---|---|---|---|---|
| all 9 libraries | 138 | 17 | 45 | **15 (10.9%)** — Semgrep 14, CodeQL +1 |
| tuning libraries | 60 | 9 | 18 | 10 (Semgrep 9 + CodeQL's XML005) |
| **held-out libraries** | **78** | **8** | **27** | **5 (6.4%)** — all Semgrep |
| the 7 libraries Hassler et al. used | 116 | – | 39 | **11 (9.5%)** |

| library | bugs | ≤ 5 lines | in function | confirmed | findings / KLOC (both) |
|---|---|---|---|---|---|
| libpng | 7 | 0 | 4 | 2 | 4.2 |
| libsndfile | 18 | 3 | 5 | 4 | 3.1 |
| libtiff | 14 | 2 | 3 | 0 | 8.7 |
| libxml2 | 17 | 4 | 5 | 4 | 2.3 |
| lua | 4 | 0 | 1 | 0 | 2.6 |
| openssl | 20 | 4 | 7 | 2 | 3.1 |
| php | 16 | 3 | 6 | 2 | 4.8 |
| poppler | 22 | 0 | 7 | 1 | 3.5 |
| sqlite3 | 20 | 1 | 7 | 0 | 6.4 |

Noise: 14,116 findings over 3.2 M lines = **4.4 / KLOC** — CodeQL adds 269 findings (0.08 / KLOC)
to Semgrep's.

**What CodeQL added on real bugs: one** — libxml2 CVE-2017-5130 (XML005), the integer overflow in
`malloc(RESERVE_SIZE + size)`, found by `cpp/multiplication-overflow-in-alloc`. Its cross-function
queries, which close the Juliet gap, found no real Magma bug: Magma's bugs are mostly
overflows and over-reads whose size goes wrong in a parser, not the free/NULL/alloc shapes those
queries model. Before the noise fixes, CodeQL put a warning in 13 more held-out buggy functions,
but none described the bug (e.g. sqlite CVE-2017-2518, SQL010: CodeQL flagged the exact line,
`pTerm->prereqRight |= extraRight;`, but as a NULL dereference — the real bug is a stale pointer
into a reallocated array).

- **Comparison.** Hassler, Görz & Lipp (2025) hand-checked five analyzers on Magma v1.1 (112 bugs,
  7 libraries): Semgrep with its stock rules found 2, CodeQL 8, Flawfinder 5, Clang SA 3, Infer 2 —
  all five together 12. This stage finds 11 of 116 on the same 7 libraries. (Different Magma
  version and different people checking, so roughly comparable, not exact.)
- **Automatic counts overstate.** "A finding in the bug's function" drops from 45 to 15 after
  checking by hand (3×; Hassler et al. measured 3.3×). Report the hand-checked number.
- **Juliet vs real code.** 97.7% on Juliet vs 11% here: the gap Lipp et al. (ISSTA 2022) reported —
  tools that do well on synthetic tests miss 47–80% of real CVEs even at function level. Our
  function-level miss rate is 67%.
- **Confirmed** = PNG003/004, SND005/010/012/013, XML001/005/006/011, SSL006/007, PHP007/015,
  PDF010: almost all are a `memcpy`/`strcat` whose size check is missing or overflows.

Why the rest are missed:
- the size goes wrong in parser arithmetic or a missing bounds check, and the crash happens
  later (often in another function) — neither tool models "this length came from the file and
  was never checked against the buffer" well enough to find these without drowning in noise
  (we tried; see the CodeQL section)
- not a memory pattern: infinite loop (SSL019), divide by zero (PDF001), unbounded recursion (PDF020)
- integer overflow inside allocation arithmetic the rules don't model (XML005 `RESERVE_SIZE+size`)
- 4 bugs are in files the stage can't read: 3 that Semgrep can't parse even preprocessed (openssl
  `x509_vfy.c`, poppler `GfxState.h`, `Annot.cc`) and sqlite's `shell.c.in` (a template, not C)

What the real-code run fixed (Juliet results unchanged by all three):
1. **Generated settings headers.** libpng's `pngrutil.c` (5 of its 7 bugs) wasn't scanned at all:
   its code sits under `#ifdef PNG_READ_SUPPORTED`, defined in `pnglibconf.h`, which only exists
   after a build. Preprocessing now builds such headers from the project's template
   (`pnglibconf.h.prebuilt`, `config.h.in`, `config.h.cmake`) with every option on.
2. **Silent timeouts.** One double-free clause took 49 s on a single libpng file; after 3 rule
   timeouts Semgrep silently skips the rest of a file. The clause is rewritten (0.9 s, same Juliet
   results), Semgrep no longer skips files, and any timeout is listed in the output (`timeouts`).
3. **`function` field.** It was wrong for 77 of the 98 findings on mxml/quirc/tinycbor (it said `if`).
   It now comes from Semgrep's own parse of the file (0 wrong).

Precision fixes spotted but not applied (so the measured version stays fixed): `"%" PRIu16`
format strings flagged as non-literal (22 false alarms in 4 libraries), `memcpy(&x, &y, sizeof(x))`,
and `p = malloc(n); memcpy(p, src, n)`.

## Wide-net tier: "never leave a real bug off the list" (`wide_net.py`, `rules/wide_net*.yaml`)

The precise rules above point at the right function for only ~1 in 3 real bugs: they stay quiet
whenever a check sits next to risky code, and real bugs are usually a check that exists but is
*wrong* (`if (len > sizeof buf) return; ... buf[len] = 0;`). Since the LLM stage filters false
alarms and the fuzzer confirms, the stage now adds a second, deliberately noisy tier:

- **What is flagged** — every memory operation whose size, index or pointer isn't a constant,
  even when a check is nearby: variable-size copies/compares/scans, variable-index reads/writes,
  pointer arithmetic, allocations with computed sizes, frees / `delete` / release-like calls,
  size fields set, size arithmetic, bounds checks that can overflow (`a + b > n`), division by
  a variable, terminator-reading calls (`strcmp`, `atoi`, ...), fixed offsets into buffers held
  in structs, returned by calls or passed in (`packet->payload[13]`, `kv[1]`, `buf[4]`),
  count-down loops, pointer walks, calls through function pointers. ~25 rules in 6 files.
- **One entry per function, ranked** — raw operations are ~55 per KLOC, so they are grouped by
  function and ranked by a weighted count (copies/allocations weigh 3, most others 1–2). Then
  come functions with no risky operation of their own that *call* risky ones (up to 3 levels):
  bugs whose fix is a missing logic check live there, and the crash happens in the callee.
- **Nothing is silently dropped** — functions Semgrep's parser misses (attribute macros,
  `Class::method`, flex's `YY_DECL`, indented generated code) are recovered by brace matching;
  flagged lines still outside any function form their own entries; files Semgrep cannot parse
  at all (it fails on whole files such as nlohmann `json.hpp`, `stb_image.h`, lwan) get a
  line-pattern fallback; a file Semgrep crashes on is skipped and listed, not fatal.
- Output: `"tier": "wide"` entries (`W001`, `W002`, ...) after the precise findings, each with
  `rank`, `score`, `flagged_for`, `function_span`, `hotspots` (every flagged line + why; no cap — an
  earlier 40-entry cap hid mxml 2.12's CVE line 2914). Additive schema.

On the candidates the list is 37–98 functions with risky operations plus their callers —
small enough for the LLM to read in full; on big libraries it reads top-down.

### Results on real bugs (is the bug's function on the list?)

Four real-bug benchmarks. The wide net was designed on Magma's 5 tuning libraries only; the
"frozen" column is the version fixed before scoring the others (a clean test). Every miss on a
clean set was then examined and the gap fixed generically ("final" column) — so "final" is not
a clean test for the specific bugs that prompted a fix, and the frozen number is the one to quote
as unbiased.

| benchmark | real bugs | old stage (precise) | **frozen (clean)** | **final** | exact line (final) | top 25% of list (final; random) |
|---|---|---|---|---|---|---|
| Magma held-out (openssl, php, poppler, sqlite) | 77 | 27 | **73** | **77** | 47 | 63 (~19) |
| ARVO set A: OSS-Fuzz bugs, 25 C libraries | 121 | 71 | **119** | **121** | 114 | 108 (54) |
| ARVO set B: OSS-Fuzz bugs, 78 more C/C++ projects | 149 | 59 | **140** | **149** | 135 | 131 (66) |
| DARPA CGC (cb-multios), 241 programs | 241 | 43 | **232/236** | **237** | 170 | 161 (88) |
| Magma tuning (designed on — not a test) | 60 | 18 | 60 | 60 | 48 | 41 |

- **ARVO** (Mei et al., EuroS&P 2026): reproduced OSS-Fuzz crashes with the fixing commit. Ground
  truth = functions the fix changed + the crashing function (first stack frame in project code).
  Projects chosen by a rule fixed before scoring (`benchmarks/arvo_select_a.py`, `arvo_select_b.py`): set A = C
  data-format/protocol libraries, ≤5 bugs each; set B = every other project with ≥3 ASan memory
  bugs, ≤2 each, minus a fixed list of codebases too large to scan once per bug.
- **CGC**: vulnerabilities are marked `#ifdef PATCHED`; the vulnerable build is made with
  `unifdef`, ground truth = lines that differ. The 4 final misses are bugs outside any function
  (a wrong global constant, an emptied macro, embedded bytecode) — no function-level tool can be
  credited for them.
- **Random baseline**: chance that a random ordering of the same functions puts a bug function in
  the top 25% — the ranking is 2–3× better, i.e. the list carries signal, not just size.
- **Cost**: ~50% of functions have risky operations of their own; with callers, 70–85% of
  functions are listed. Against known bugs >99% of listed functions are false alarms (some may be
  unknown bugs). That is the trade the pipeline asks for: the LLM filters, the fuzzer confirms.

Clean-set misses and what fixed them: files Semgrep can't parse (json ×2, lwan, stb ×2 → fallback);
macro-spelled / indented generated functions (MapServer's flex lexer → recovery + orphan groups);
`strcmp` on unterminated data (libexif → terminator rule); fixed offsets into packets / call
results (nDPI, irssi → offset rules); count-down pointer walk (libjpeg-turbo → loop rules); call
through a function pointer of a shorter struct (p11-kit → indirect-call rule); C++ `delete` /
`DeleteItem` (CGC → lifetime rules); `Class::method` and the call graph (poppler); overflow
inside a bounds check (php → check-arith).

The benchmarks also found robustness bugs that would have silently hidden code on any library:
command line too long on ~10k files (now batched), Semgrep crashing on a symlinked header (now
skipped + reported in `crashed_files`), and whole-file parse failures (fallback above).
Moving the stage into the team repo found one more: inside a git repository Semgrep skips
git-ignored files and applies its built-in ignore list (`test/`, `tests/`, `build/`, `vendor/`…)
to paths relative to the repository root, so a target in an ignored folder — or the toy fixtures
under `tests/` — was scanned as empty. Semgrep now always gets an explicit file list (our own
walk, our excludes; extensions widened to every one Semgrep reads as C/C++). Same results on
mxml, the toy set and Magma; nothing can be dropped silently any more.

### Target check: mxml v2.12 (the team's library; no tuning on it)

`results/mxml-v2.12/findings.json`: 93 precise + 146 wide functions (of 202), ~1 min. Every memory bug
fixed upstream after 2.12 is on the list, at its exact line:

| known bug (upstream fix) | precise tier | wide tier |
|---|---|---|
| stack overflow writing a double, `mxml-file.c:2914` (Issue #233, `4f5577d`; the team's target bug) | F009 at 2914 (`unbounded-sprintf`) | `mxml_write_node` #3/146, line 2914 listed |
| same pattern, `mxml-file.c:2884` (same fix) | F008 at 2884 | same function, line listed |
| use-after-free in 6 `mxmlSet*` functions when the new value is the node's own (Issue #241, `0b1caf4`) | — | all 6 flagged (#65–#90), each one's `free()` line listed |

This check exposed a 40-entry cap on each function's `hotspots` list that hid line 2914 from
the JSON (the function was still listed); the cap is gone.

## Benchmark method (for the report)

- Ground truth: Juliet `manifest.xml` flaw lines. TP = finding span contains a flaw line;
  FP = finding inside an `OMITGOOD` (labeled-safe) region; anything else is "off-target".
- Splits, so rules aren't tuned and scored on the same cases:
  - `dev`   = `_01` baseline variants (first tuning round)
  - `tune`  = half of the remaining cases (every other functional variant per CWE)
  - `final` = the other half — **never tuned on**; this is the number to report
- `--preprocess force` re-scans every file through the preprocessor; identical scores to the
  normal run show preprocessing doesn't change what the rules find.

```bash
python3 benchmarks/juliet_benchmark.py --juliet juliet-test-suite-c --split final --out final.json
python3 benchmarks/juliet_benchmark.py --juliet juliet-test-suite-c --split final --backend both \
    --codeql-db-dir cqdb --out final_both.json        # databases are cached in cqdb/
python3 benchmarks/juliet_benchmark.py --juliet juliet-test-suite-c --split dev \
    --noise ../corpus/libspng ../corpus/zlib --misses misses.txt
```

Magma (`benchmarks/magma_benchmark.py`, ~1 h for all 9 libraries on a laptop; run one library at a time —
parallel runs overload the machine and make Semgrep time out):
- each library is fetched at Magma's pinned commit; every bug patch is applied, and the lines each
  patch touches are recorded (tracked as later patches shift the file)
- `unifdef -l` strips Magma's fixes and canaries; removed lines become blank, so line numbers don't
  move and what's left is just the vulnerable library
- line-level: a finding within 5 lines of a changed line; function-level: a finding in a function
  the patch changed (Lipp et al. / Hassler et al.); `--hits` writes each hit beside the bug's code
  for hand-checking, `--rescore` re-scores saved findings without re-scanning

```bash
git clone https://github.com/HexHive/magma
python3 benchmarks/magma_benchmark.py --magma magma --src magma_src --work magma_work \
    --out magma.json --hits magma_hits.txt          # --targets libpng lua  for a subset
```

## Preprocessing fallback (`preprocess.py`)

Semgrep reads raw C. Project macros used like keywords (zlib `local`, expat `XMLCALL`) and
`#if/#else` blocks that each hold half a construct make it drop whole files with only a warning
(libspng's `spng.c` — the whole library — produced 0 findings). For files that don't parse, the
stage runs the preprocessor on a temporary copy and scans that too:
- library files are never modified; findings point at the original file and line
- system headers are not read (`-nostdinc` + empty stubs), so `memcpy`/`NULL` stay as written
  and libc hardening (`_FORTIFY_SOURCE`) can't rewrite them
- original findings are kept, so this only adds findings
- a header the build would generate (`config.h`, `pnglibconf.h`) is built from the project's own
  template (`config.h.in`, `config.h.cmake`, `pnglibconf.h.prebuilt`) with every option switched
  on, so `#ifdef FEATURE` code is analyzed instead of disappearing
- `--compile-commands build/compile_commands.json` or `-D NAME` picks the same `#if` branches as
  the fuzzing build (not needed for the current candidates: their switches are OS/compiler toggles)

## CodeQL backend (`codeql_backend.py`, `codeql/`)

Semgrep looks at one function at a time; CodeQL builds a database of the whole program and
follows values across functions — exactly the bugs Semgrep can't see (memory freed in one function
and used in another, a NULL set in one function and dereferenced in another).

**Building the database without the project's build system.** CodeQL learns C/C++ by watching a
compile. Every library builds differently, so (like the preprocessing fallback) the stage compiles
every `.c`/`.cc` file on its own with clang, under CodeQL's tracer:
- the project's header directories go on the include path; headers the build would generate are
  rendered from the project's templates (`config.h.in`, `pnglibconf.h.prebuilt`, ...), or filled
  with the platform's sizes when there is no template (`php_config.h`)
- export macros a configure step would define (`ZEND_API`, `OPENSSL_EXPORT`) are defined empty
  when the compiler reports them missing — otherwise CodeQL drops the file after 1,000 errors
- macOS specifics: the real clang binary (CodeQL's tracer copies every SIP-protected binary it
  runs — 4× slower), the SDK path (`-isysroot`, or `<stdlib.h>` isn't found), and
  `-D_FORTIFY_SOURCE=0` (otherwise `strcpy`/`memcpy` become builtins CodeQL doesn't recognize)
- with the real build's `compile_commands.json` (`--compile-commands`), its exact flags are used

**Queries** (`codeql/memory-safety.qls`):

| query | finds | what's different from CodeQL's own query |
|---|---|---|
| `sa/double-free` | a pointer freed, then freed again — also in another function | CodeQL's requires both frees in one function, one dominating the other; it also stops tracking at `&p` and at calls taking `&p` |
| `sa/use-after-free` | a freed pointer dereferenced or passed on — also in another function | same two changes |
| `sa/null-deref` | a local set to NULL reaching a dereference unchecked — also in another function | (no stock query does this); ignores "init to NULL, fill in later" and `init(&p)` |
| `sa/unchecked-alloc-deref` | malloc/calloc/realloc/fopen result dereferenced with no NULL check — also in another function | allocations checked where they happen (`if ((s->b = malloc(n)) == NULL)`) don't count; wrappers (`return calloc(...)`) count as allocators |
| `sa/free-non-heap` | stack / static / alloca memory reaching `free`/`delete` — also in another function | (no stock query) |
| `cpp/multiplication-overflow-in-alloc` | integer overflow in an allocation size | CodeQL's experimental query, kept because it found libxml2 CVE-2017-5130 on a tuning library |

Both free queries also stop tracking a field once it's reassigned right after the free
(`free(s->buf); s->buf = NULL;`) — data flow doesn't treat a field store as replacing the old
value, and libpng alone produced 127 false alarms without this.

**How it was tuned (same rules as Semgrep).** Queries were only changed against Juliet's `tune`
half and five Magma *tuning* libraries (libpng, libsndfile, libtiff, libxml2, lua). The numbers
reported are Juliet's `final` half and the four *held-out* Magma libraries (openssl, php, poppler,
sqlite3), which no query change was based on. A query stays only if it improves the tuning data:
- dropped: 42 of CodeQL's 43 standard memory-safety queries (`codeql/standard-memory.qls`) — no
  Juliet case Semgrep + our queries miss, no real Magma bug on the tuning libraries, and noise
  (`cpp/missing-null-test` alone: 320 Juliet false alarms, 334 findings on libxml2)
- dropped: two queries of our own for real-code bug shapes — "length read from input used
  unchecked" and "divisor from input never checked for zero" — 0 confirmed bugs on the tuning
  libraries, 1–3 findings / KLOC of noise
- real-code false-alarm fixes kept: NULL sources limited to local variables (libxml2
  3,768 → 3 findings), allocations checked where they happen (libsndfile 105 → 29), fields reset
  after free (libpng 127 → 0) — each checked to cost no Juliet recall

After the held-out run, three more noise fixes (each again checked against Juliet `tune` — the
stage's recall didn't move). They were prompted by mxml (not a benchmark library) and by the
held-out libraries' noise, so the held-out *noise* numbers after them are not blind. The
hand-checked held-out result is the same before and after (CodeQL confirmed 0 held-out bugs
either way); the automatic "finding in the bug's function" count dropped from 32 to 27, because
the 13 CodeQL function-level hits the fixes removed were all unrelated warnings:
- a helper that frees memory only on some paths (`mxmlRelease`: frees when the reference count
  hits 0) no longer counts as freeing it for its callers — mxml 77 → 0 use-after-free alarms
- a NULL that is a function's failure value (`if (n > MAX) p = 0; else p = xMalloc(n);`) is not a
  NULL-dereference source — sqlite3Malloc alone gave 1,557 alarms (Juliet case lost by CodeQL
  here, variant 12, is still caught by Semgrep)
- one finding per source: an unchecked `malloc` dereferenced in 689 places is one finding at
  its first dereference, not 689

**Limits.** Big projects that need their configure step (openssl, php, sqlite's generated
`parse.h`/`opcodes.h`) extract only partly with the generic build — CodeQL sees fewer of their
functions. Use the real build's `compile_commands.json` for those. Not handled: pointer aliasing
(`int **pp`, C++ references to the pointer) and C++ containers holding the pointer.

## Run it

```bash
pip install semgrep
brew install --cask codeql          # optional: without it the stage runs Semgrep only
codeql pack download codeql/cpp-queries codeql/cpp-all && (cd codeql && codeql pack install)

python3 static_analyzer.py --target tests/toy --out findings.json
python3 static_analyzer.py --target https://github.com/michaelrsweet/mxml --out findings.json
# a tag: git clone https://github.com/michaelrsweet/mxml /tmp/mxml && git -C /tmp/mxml checkout v2.12
#        python3 static_analyzer.py --target /tmp/mxml --out findings.json
```

## Output schema (the contract with the LLM stage)

```json
{
  "id": "F001",
  "rule_id": "unbounded-string-copy",   // short rule id
  "cwe": "CWE-120",
  "bug_class": "buffer-overflow",
  "severity": "error",                   // error > warning > info; findings are sorted this way
  "file": "buffer_overflow.c",
  "line": 7,
  "function": "copy_name",               // enclosing function (from Semgrep's parse); what the harness must reach
  "message": "...",
  "code_context": "...surrounding source...",
  "analyzer": "semgrep",                 // "semgrep" or "codeql" (CodeQL rule_ids: sa/..., cpp/...)
  "preprocessed": false,                 // matched on the macro-expanded copy
  "tier": "precise"                      // "precise" (this shape) or "wide" (below)
}
```

Wide-net entries (`"tier": "wide"`) come after all precise findings, one per function, best first:

```json
{
  "id": "W001", "tier": "wide", "rule_id": "wide-net-hotspot", "severity": "info",
  "rank": 1, "score": 37,
  "flagged_for": "risky memory operations",   // or "calls risky functions"
  "file": "src/parser.c", "line": 412,          // the heaviest risky line
  "function": "parse_chunk", "function_span": [380, 470],
  "message": "Hotspot #1 of 86 (score 37): 3 x variable-size copy/compare, 9 x write through variable index, ...",
  "hotspots": [{"line": 401, "kind": "size arithmetic"}, {"line": 412, "kind": "variable-size copy/compare + write through variable index"}],
                                               // EVERY flagged line in the function, one entry per line (no cap)
  "hotspots_total": 23,                        // operations; a line can hold several
  "code_context": "...", "analyzer": "semgrep", "cwe": null, "bug_class": "hotspot"
}
```

Read the precise tier first, then the wide tier top-down; the wide tier is where nearly all real
bugs' functions are (98–100% on the benchmarks), most of them in its top quarter.

Top level also has `summary` (counts by CWE/severity, plus `wide_net_functions`,
`wide_net_functions_with_operations`, `wide_net_operations`), `excluded_dirs`, `preprocessing`,
`parse_coverage` (files that didn't parse; `still_unparsed` lists files Semgrep couldn't read —
the wide net covers them with its line-pattern fallback, listed in `wide_net_fallback`),
`timeouts` (rule/file pairs Semgrep gave up on after 30 s) and `crashed_files` (files Semgrep
crashed on — skipped). All additions since the first version are additive.

Next schema upgrades (with CodeQL): `function` → full enclosing-function source, and
`reachable_from` = public API entry points that reach the flaw.

## Files

```
static_analysis/
├── static_analyzer.py        # the stage
├── wide_net.py               # wide-net tier: per-function ranking, call graph, fallbacks
├── preprocess.py             # fallback for files Semgrep can't parse
├── codeql_backend.py         # builds a CodeQL database (compiles every file), runs queries
├── codeql/                   # CodeQL pack: memory-safety.qls + our queries (queries/*.ql)
├── rules/memory_safety.yaml  # 30 local Semgrep rules (precise tier)
├── rules/wide_net*.yaml      # wide-net tier rules (6 files, loaded together)
├── tests/toy/*.c             # known-bug fixtures + clean.c
├── results/                  # example outputs (mxml-v2.12/, toy/)
├── benchmarks/
│   ├── juliet_benchmark.py   # Juliet scoring + real-code noise (--backend semgrep|codeql|both)
│   ├── magma_benchmark.py    # real-bug scoring on Magma (138 CVEs, 9 libraries), precise tier
│   ├── magma_wide_eval.py    # wide-net scoring on Magma (uses magma_benchmark.py's --keep-work)
│   ├── arvo_select_[ab].py   # frozen ARVO bug selection (sets A and B)
│   ├── arvo_benchmark.py     # real-bug scoring on ARVO (reproduced OSS-Fuzz bugs + fix commits)
│   ├── cgc_benchmark.py      # real-bug scoring on DARPA CGC programs (#ifdef PATCHED)
│   └── results/              # every run behind the numbers here (*_frozen = clean, *_final)
├── README.md                 # how to run it and read the output
└── PLAN.md
```
