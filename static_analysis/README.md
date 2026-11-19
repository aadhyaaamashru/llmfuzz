# Static analysis (stage 1)

Give it a C/C++ library and it writes `findings.json`, a list of places in the code where a
memory-safety bug (buffer overflow, use-after-free, NULL dereference…) could be. The LLM stage
reads that list to decide what to fuzz.

```
[1] static analysis (this folder)   library ──► findings.json
[2] LLM                             findings.json ──► drop false alarms, write harness + dictionary + seeds
[3] AFL++                           fuzz the harness ──► crashes
[4] replay                          crash ──► confirm under ASan
```

**It over-reports on purpose.** A bug missed here can never be found later, while a false alarm
costs only a little LLM time. The LLM filters the list, and the fuzzer decides what is real.
On 588 real, known bugs it lists the buggy function for 584 of them (see
[How well it works](#how-well-it-works)).

---

## Setup (once)

```bash
pip install semgrep                     # required — tested with semgrep 1.185.0, Python 3.12
brew install --cask codeql              # optional — tested with CodeQL 2.27.4 (needs clang / Xcode CLT)
codeql pack download codeql/cpp-queries codeql/cpp-all
(cd static_analysis/codeql && codeql pack install)
```

There are no other Python dependencies. Without CodeQL the stage runs Semgrep only. CodeQL adds
data-flow checks that follow memory across functions (use-after-free, double free, NULL
dereference).

## Run

```bash
cd static_analysis

# a quick check on the bundled examples (6 small files, 5 with a known bug)
python3 static_analyzer.py --target tests/toy --out data/toy.json
#   [+] 6 precise findings + 10 wide-net hotspot functions -> data/toy.json

# a real library: any local folder, or a git URL (cloned for you)
git clone https://github.com/michaelrsweet/mxml data/mxml && git -C data/mxml checkout v2.12
python3 static_analyzer.py --target data/mxml --out data/mxml.json     # ~1 minute
#   [+] 93 precise findings + 146 wide-net hotspot functions -> data/mxml.json
```

Progress is printed to the terminal, and the last line says what was written. The library
doesn't need to be built or configured first. `data/` is just a suggestion: git ignores it, so
your downloads and outputs never get committed by accident. The target can be anywhere.

That's all you need to scan a library. Everything under `benchmarks/` is only for testing the
tool (see [Benchmarks](#benchmarks-optional-only-to-re-check-the-numbers-above)).

| option | what it does |
|---|---|
| `--target PATH_OR_URL` | library to scan (required). A git URL scans the default branch; to scan a tag, clone it and pass the folder |
| `--out FILE` | where to write the JSON (default `findings.json`) |
| `--backend semgrep\|codeql\|both` | analyzers to run (default `both` when CodeQL is installed) |
| `--codeql-db DIR` | keep the CodeQL database here and reuse it on the next run (saves most of CodeQL's time) |
| `--exclude NAME …` | folders / file patterns to skip. Default: test, tests, examples, docs, fuzz, bench and test-program files like `test*.c`. `--exclude` with nothing after it scans everything |
| `--compile-commands FILE` | the library's `compile_commands.json`, if you have one: its `-I`/`-D` flags are used for files that need preprocessing |
| `-D NAME` | extra macro for preprocessing (repeatable) |
| `--no-wide-net` | precise findings only (not recommended — see below) |

---

## Reading `findings.json`

`findings` is one list with two kinds of entries. Read it **top to bottom**.

| tier | ids | what it is | mxml v2.12 |
|---|---|---|---|
| `"precise"` | `F001`, `F002`, … | a specific bug pattern on a specific line, e.g. *"sprintf() with no size limit"*, *"pointer used after free()"*. Sorted by severity: error, then warning, then info | 93 |
| `"wide"` | `W001`, `W002`, … | the **wide net**: every function that does risky memory work (variable-size copies, writes through a computed index, pointer arithmetic, frees, length decoding, …) or calls functions that do, one entry per function, **riskiest first**. Each entry lists every risky line in that function | 146 of 202 functions |

The precise entries point at only about 1 in 3 real bugs. The wide entries exist so that
the other 2 in 3 are still on the list.

### A precise entry

```json
{
  "id": "F009",
  "tier": "precise",
  "rule_id": "unbounded-sprintf",
  "cwe": "CWE-787",
  "bug_class": "buffer-overflow",
  "severity": "error",
  "file": "mxml-file.c",
  "line": 2914,
  "function": "mxml_write_node",
  "message": "sprintf() writes formatted output with no destination bound.",
  "code_context": "...the lines around 2914...",
  "analyzer": "semgrep",
  "preprocessed": false
}
```

| field | meaning |
|---|---|
| `file`, `line` | where it is (paths are relative to the target folder) |
| `function` | the function that contains it, which is what the harness has to reach |
| `rule_id`, `cwe`, `bug_class`, `message` | what kind of bug it might be |
| `severity` | `error` > `warning` > `info` |
| `code_context` | a few lines of source around `line` |
| `analyzer` | `semgrep` or `codeql` (CodeQL rule ids start with `sa/` or `cpp/`) |
| `preprocessed` | `true` if the finding was found in a macro-expanded copy of the file, because Semgrep couldn't read the original |

### A wide entry

```json
{
  "id": "W003",
  "tier": "wide",
  "rank": 3,
  "score": 81,
  "flagged_for": "risky memory operations",
  "file": "mxml-file.c",
  "line": 2782,
  "function": "mxml_write_node",
  "function_span": [2714, 3027],
  "hotspots": [
    {"line": 2745, "kind": "call through a function pointer from a struct"},
    {"line": 2914, "kind": "unbounded string/format call"}
  ],
  "hotspots_total": 67,
  "message": "Hotspot #3 of 146 (score 81): 13 x unbounded string/format call, 1 x bounds check that can overflow, ...",
  "code_context": "...", "rule_id": "wide-net-hotspot", "cwe": null, "bug_class": "hotspot",
  "severity": "info", "analyzer": "semgrep", "preprocessed": true
}
```

| field | meaning |
|---|---|
| `rank` | position in the list (1 = look at first) |
| `function`, `function_span` | the function and its first and last line |
| `hotspots` | **every** risky line in the function, one entry per line, with the reason(s). Nothing is capped |
| `hotspots_total` | number of risky operations (one line can hold several) |
| `line` | the single riskiest line, which is also the one shown in `code_context` |
| `flagged_for` | `"risky memory operations"`: the function does risky work itself. `"calls risky functions"`: it doesn't, but it calls functions that do, and `hotspots` names them (e.g. `mxmlLoadString` → `calls mxml_load_data`) |
| `score` | how the ranking was decided: risky operations weighted by kind (variable-size copies and size calculations count most). For `"calls risky functions"` entries it is half the callee's score |

### How the LLM stage should use it

1. Go through the **precise** entries first. They are few and line-exact.
2. Then go **down the wide list** in order. For each function, read `function_span` and look at the
   `hotspots` lines. The ranking carries signal: on real-bug benchmarks the bug's function lands
   in the top quarter of the list about twice as often as a random ordering would put it there.
3. The `"calls risky functions"` entries are often the **public API entry points**
   (`mxmlLoadString`, `mxmlLoadFile`, `mxmlSaveString`, …). Those are what a fuzzing harness calls.
4. **Most entries are false alarms. That's by design.** Dropping them is the LLM's job, and
   whether a bug is real is decided by the fuzzer, not by this list.
5. Check for blind spots. Each of these should normally be empty or zero:
   - `parse_coverage.still_unparsed`: files Semgrep couldn't read even after preprocessing (the
     wide net still covers them with line patterns, listed in `parse_coverage.wide_net_fallback`)
   - `crashed_files`: files Semgrep crashed on, which were skipped
   - `timeouts`: rule/file pairs Semgrep gave up on after 30 s

Other top-level fields: `target`, `analyzer`, `config` (rule files), `codeql_queries`,
`excluded_dirs`, `preprocessing`, `generated_at`, `summary` (counts by CWE and severity, plus
`wide_net_functions`, `wide_net_functions_with_operations`, `wide_net_operations`).

> **Contract with the LLM stage:** fields are only ever *added*, never renamed or removed.

---

## Example: mxml v2.12 (the team's target)

Output: [`results/mxml-v2.12/findings.json`](results/mxml-v2.12/findings.json). Every memory bug
that was fixed in mxml after v2.12 is on the list, at its exact line:

| known bug (fixed upstream in v3.0) | precise entries | wide list |
|---|---|---|
| stack buffer overflow writing a floating-point value, `mxml-file.c:2914` (Issue #233) | **F009**, line 2914 | `mxml_write_node` **#3 of 146**, line 2914 listed |
| same pattern, `mxml-file.c:2884` (same fix) | **F008**, line 2884 | same function, line listed |
| use-after-free in 6 `mxmlSet*` functions when the new value comes from the same node (Issue #241) | — | all 6 listed (#65–#90), each with its `free()` line |

`mxmldoc.c`, `mmd.c` and `zipc.c` belong to the documentation tool that ships in the mxml repo,
not to the library itself. If you only fuzz the library, skip their entries.

---

## How well it works

Measured on real bugs with known locations. **Juliet (synthetic test cases) is not used as
evidence.**

| benchmark | real bugs | precise entries only | **wide list, clean test** | **wide list, final** | top 25% of the list (random ordering would give) |
|---|---|---|---|---|---|
| Magma held-out (openssl, php, poppler, sqlite) | 77 | 27 | **73** | **77** | 63 (~19) |
| ARVO set A: OSS-Fuzz bugs, 25 C libraries | 121 | 71 | **119** | **121** | 108 (54) |
| ARVO set B: OSS-Fuzz bugs, 78 more C/C++ projects | 149 | 59 | **140** | **149** | 131 (66) |
| DARPA CGC (cb-multios), 241 programs | 241 | 43 | **232/236** | **237** | 161 (88) |
| Magma tuning libraries (developed on, not a test) | 60 | 18 | — | 60 | 41 |

- **Clean test** is the honest number: the rules were frozen before these bugs were scored, and
  were developed only on the Magma tuning libraries.
- **Final** is the number after fixing each clean-test miss with a *general* rule, never one
  written for that specific bug. It is not a clean measurement for those bugs.
- The 4 bugs still missed are in CGC and are not inside any function: a wrong global constant,
  a `#define`, an emptied macro, and embedded bytecode.
- **The cost is noise.** 70–85% of a library's functions end up on the list, and more than 99% of
  listed functions contain no known bug. That's the trade-off the pipeline wants: the LLM filters,
  the fuzzer confirms.

---

## Benchmarks (optional: only to re-check the numbers above)

**You don't need any of this to scan a library.** The scripts in `benchmarks/` are the tool's
tests. Each one takes a set of real bugs whose location is already known, rebuilds the buggy
version of the code, runs `static_analyzer.py` on it, and checks whether the bug made the list.
That's how the table above was produced.

| script | what it tests on |
|---|---|
| `magma_benchmark.py`, then `magma_wide_eval.py` | **Magma**: 138 real CVEs re-inserted into 9 libraries (libpng, openssl, sqlite, …). The first script scores the precise entries, the second the wide list |
| `arvo_select_a.py` / `arvo_select_b.py`, then `arvo_benchmark.py` | **ARVO**: real bugs found by Google's OSS-Fuzz, each with the commit that fixed it. The select scripts pick the bugs (fixed rule, chosen before scoring) |
| `cgc_benchmark.py` | **DARPA Cyber Grand Challenge**: 241 small programs whose bugs are marked `#ifdef PATCHED` |
| `juliet_benchmark.py` | **Juliet**: NIST's synthetic test cases (precise rules only, not used as evidence) |

The benchmark data isn't in the repo because it's several GB. Download it into `data/`, which
git ignores:

```bash
cd static_analysis && mkdir -p data

# Magma (needs unifdef)
git clone https://github.com/HexHive/magma data/magma
python3 benchmarks/magma_benchmark.py --magma data/magma --src data/magma_src \
    --work data/magma_work --keep-work --out data/magma.json
python3 benchmarks/magma_wide_eval.py --work data/magma_work --magma-results data/magma.json \
    --libs openssl php poppler sqlite3

# ARVO: put arvo.db from https://github.com/n132/ARVO-Meta (releases) in data/
python3 benchmarks/arvo_select_a.py data/arvo.db data/arvo_a_bugs.json
python3 benchmarks/arvo_benchmark.py --candidates data/arvo_a_bugs.json --repos data/arvo_repos \
    --out data/arvo_a.json
# set B: arvo_select_b.py, then arvo_benchmark.py with --per-project 2

# DARPA CGC (needs unifdef)
git clone https://github.com/trailofbits/cb-multios data/cb-multios
python3 benchmarks/cgc_benchmark.py --src data/cb-multios/challenges --work data/cgc_work \
    --out data/cgc.json

# Juliet
git clone https://github.com/arichardson/juliet-test-suite-c data/juliet-test-suite-c
python3 benchmarks/juliet_benchmark.py --juliet data/juliet-test-suite-c --split final \
    --out data/juliet.json
```

Each script prints a summary at the end, and its header explains the scoring in detail.
`benchmarks/results/` holds the runs behind the table above. `*_frozen.json` files are the
clean-test runs and `*_final.json` files are after the fixes. `magma_precise.json` holds the
Magma bug locations and the precise-entry scoring, `magma_wide_*.json` the wide-list scoring, and
`juliet.json` the Juliet run.

---

## Files

```
static_analysis/
├── static_analyzer.py      # the stage: entry point, Semgrep + CodeQL, output JSON
├── wide_net.py             # the wide net: groups risky operations per function, ranks them,
│                           #   follows calls, line-pattern fallback for unreadable files
├── preprocess.py           # re-scans files Semgrep can't parse through the C preprocessor
├── codeql_backend.py       # builds a CodeQL database without the library's build system
├── rules/
│   ├── memory_safety.yaml  # precise Semgrep rules
│   └── wide_net*.yaml      # wide-net Semgrep rules (all files matching this are loaded)
├── codeql/                 # CodeQL query pack (use-after-free, double free, NULL deref, …)
├── tests/toy/              # 6 tiny C files with known bugs, for a quick check
├── results/                # example outputs: mxml-v2.12/, toy/
├── benchmarks/             # optional: tests of the tool on known real bugs + results/
└── data/                   # (yours, not committed) downloads and scan outputs
```

## Rules for changing this stage

- **Never trade recall for precision.** If a change removes a known bug from the list, it's wrong,
  however much noise it cuts.
- **Stay target-agnostic.** Nothing specific to one library.
- **Only add fields to the JSON.** The LLM stage parses it.
- **Re-run the benchmarks** after changing rules, and keep tuning separate from testing: tune on
  the Magma tuning libraries only.

## Troubleshooting

- **`the codeql CLI is not installed`**: install it (see Setup) or pass `--backend semgrep`.
- **CodeQL is slow the first time on macOS.** Pass `--codeql-db DIR` so later runs reuse the
  database.
- **`[!] semgrep crashed on FILE`**: that file was skipped and is listed in `crashed_files`.
  Everything else was still scanned.
- **The target can live anywhere**, including inside this repo or the git-ignored `data/` folder.
  Files are passed to Semgrep one by one, so Semgrep's own ignore rules can't silently drop any.
