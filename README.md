# Static Analysis + LLMs for Coverage-Guided Fuzzing

> Finding real memory-safety bugs in open-source C/C++ libraries by letting an
> LLM, guided by static analysis, aim AFL++ at the code most likely to be vulnerable.

**Project Name:** _TBD_ — `FLAG` (Fuzzing with LLM-Aided Guidance)

**Course:** CS453 <!-- TODO: term / year -->
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

 _TBD_

## Requirements

 _TBD_

## Setup

 _TBD_

## Configuration

 _TBD_
                                             |
## Usage

 _TBD_

