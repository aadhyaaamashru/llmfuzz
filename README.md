# Static Analysis + LLMs for Coverage-Guided Fuzzing

> Finding real memory-safety bugs in open-source C/C++ libraries by letting an
> LLM, guided by static analysis, aim AFL++ at the code most likely to be vulnerable.

**Project Name:** _TBD_ — `FLAG` (Fuzzing with LLM-Aided Guidance)

**Course:** CS453 | FALL 2026
**Team:** Aadhyaaa Mashru · Madhav Malik · Mikkel Hebel · Nikhil Kanade · Shivum Varshney

---

## Overview

Blind fuzzing can run for hours without ever reaching interesting code. This project
puts a "brain" in front of the fuzzer so its time is spent where bugs are likely to be:

1. **Static analysis** scans the target library and flags memory-safety / undefined-behavior warnings.
2. **An LLM agent** reviews each flagged site in context, discards likely false positives, and
   produces a fuzzing plan: a harness that reaches the flagged code, a token dictionary, seed
   inputs, and the build/run configuration.
3. **AFL++** runs that plan inside a sandbox; the agent watches coverage and revises the
   harness / dictionary / options if the flagged code isn't being reached.
4. **Validation** — a finding only counts if AFL++ produces a crashing input that reproduces
   under a sanitizer.

The goal is to find a **real, previously unknown vulnerability** — not to benchmark the pipeline.

## How it works

```
target library
     │
     ▼
[1] Static analyzer  (CodeQL / Semgrep, via API)  ──►  flagged sites (JSON)
     │
     ▼
[2] LLM agent  ──►  triage false positives
                    generate harness (main.c) + dictionary + seeds + AFL++ plan
     │
     ▼
[3] AFL++ (sandboxed)  ──►  coverage feedback
                            └─► revise harness / options if flagged code not reached
     │
     ▼
[4] Crash?  ──►  replay  ──►  confirm with ASan / UBSan report
```

The whole pipeline is driven by a single orchestrator script — each stage above is a step
in that script, not a separate tool you run by hand.

## Repository layout

| folder | what it is |
|---|---|
| [`static_analysis/`](static_analysis/) | Stage 1, the static analyzer (Semgrep + CodeQL): library ──► `findings.json`. How to run it and read its output: [static_analysis/README.md](static_analysis/README.md) |

 _Other stages: TBD_

## Requirements

- Docker
- Python 3.9+

## Setup

```bash
./setup.sh
```

This builds a Docker image with everything installed (Semgrep, CodeQL, clang), clones the
target library into `targets/`, and runs the pipeline inside the container. Output goes to
`results/<library>-<version>/findings.json`. The first run takes a few minutes; later runs reuse the image
and skip anything already done.

## Configuration

 _TBD_

## Usage

```bash
./setup.sh                                     # default: mxml v2.12
./setup.sh --target <git url>                  # another library, latest version
./setup.sh --target <git url> --ref <tag>      # another library, specific version
./setup.sh --rerun                             # scan again even if findings.json exists
./setup.sh --clean-build                       # delete everything and build from scratch (see below)
./setup.sh --sa                                # static analysis only
./setup.sh --llm                               # LLM stage only (not implemented yet)
./setup.sh --fuzz                              # fuzzing only (not implemented yet)
```

With no stage flag, every stage runs. Stages always run inside Docker.

`--clean-build` deletes the `llmfuzz` image and its containers, the `llmfuzz-codeql` volume
(CodeQL databases for every library), and the `results/` and `targets/` folders. It then
rebuilds the image without cache and runs as usual. It can be combined with the other flags.
