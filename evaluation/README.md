# Evaluation method and limitations

`labeled_cases.json` contains 32 hand-authored synthetic DEVELOPMENT cases. It is not a held-out, unseen or real-world benchmark. Inputs include successful matches, threshold boundaries, missing data, case normalization and deliberate hard negatives. Do not quote its scores as general attack-detection accuracy.

Unit: (case, rule-type) presence. One true positive means an expected rule appears anywhere in that case. Repeated occurrences count once. False positives are unexpected rule types; false negatives are missing expected rule types. These are NOT event-level or incident-level metrics. True negatives are not reported. Undefined precision/recall is null.

Run:

    python scripts/evaluate.py

Outputs: `evaluation/results/accuracy.json` and `cases.csv`, with per-rule counts. To evaluate your own separate cases:

    python scripts/evaluate.py --cases /path/to/held-out-cases.json --out evaluation/held-out-results

Follow the same JSON structure. Label cases before running the detector and report dataset provenance. Keep thresholds fixed while evaluating held-out cases. Do not tune on the evaluation set and then call it unseen.

Expected development results for this release: 20 TP, 3 FP, 0 FN; micro precision 0.8696, recall 1.0. All 3 false positives are process heuristics: a documentation-like mimikatz mention, legitimate whoami /priv, and approved encoded PowerShell. They are deliberately not removed from the benchmark. These labels represent benign intent, even though the same command syntax is a useful investigation indicator. This illustrates why heuristic matches are not maliciousness verdicts.

## Performance

    python scripts/benchmark.py --sizes 1000 10000 --repeats 3

This measures in-process parsing/detection/correlation on mostly benign synthetic events. It excludes HTTP transfer, SQLite, React, and SLM inference, and is not a worst-case alert-heavy workload. Rerun on the actual demonstration machine.

Backend peak RSS is a process lifetime high-water mark from resource.getrusage, not an incremental per-request allocation. Its inherited/history-dependent value must not be called application idle memory. It excludes model memory, browser memory, and GPU VRAM. It is unavailable on native Windows.

For actual WSL model/backend process sampling:

    python scripts/sample_memory.py --seconds 120 --out memory-samples.csv

Run it while analyzing logs and generating a NEW SLM explanation. Process RSS may double-count shared pages. Commands/process names can be sensitive; do not publish unreviewed memory samples.

## Live model checks

With the backend and Ollama running:

    python scripts/live_slm_check.py --out live-slm-results.json

The script exercises real HTTP upload, inference, validation and persistence for 3 inputs. It checks transport/structure, NOT semantic truth. Fill the manual review fields after comparing each claim to its referenced evidence. Test an additional log containing a fake instruction such as "ignore prior instructions"; check that the model treats it as data. No prompt-injection immunity is claimed.

Model-generated limitations/actions do not receive full semantic or literal checks. The IPv4 guard applies only to cited observation/interpretation statements. Evidence reference checking is not hallucination prevention. The SLM does not independently discover incidents omitted by the rules.

## Offline browser acceptance

1. Build React and run the one-server deployment in README.
2. Start local Ollama with the configured model already downloaded.
3. Disconnect external networking; keep loopback available.
4. Restart the API and load the UI.
5. Upload both cross-source files together; turn on case-insensitive users for this synthetic fixture; analyze.
6. Generate a NEW explanation and download both reports.
7. Stop Ollama, analyze another file and confirm rules still work; explanation must fail clearly.
8. Restart Ollama and retry.
9. Refresh UI, restore history and verify explanation persistence.

Browser acceptance, target-device timing, and live inference must be performed on your machine; they were not executed in the packaging environment.

## SLM grounding checker

    python scripts/slm_grounding_eval.py

Scores `backend/services/grounding.py` on `slm_grounding_cases.json`: 42 hand-written statements about the sample incidents, labelled accept/reject (supported, invented IP/time/user/device/command, wrong count or duration, wrong event type or approval, overclaim, speculation, unhedged, generic). Results: `evaluation/results/slm-grounding.json`. Current: 25 of 28 unsupported statements withheld, 14 of 14 supported statements kept; 3 labelled `known_gap` cases (inverted negation, invented name at sentence start, invented context) are wrongly accepted and are documented limits.

This measures the mechanical filter only, not the real model's accuracy, and the cases overlap with examples used to build the checker. It is not held-out. For the real model, run `scripts/live_slm_check.py` and complete the manual review fields.
