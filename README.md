# 🦉 TriageOwl

**Offline Security Incident Triage Assistant** — rules find the incidents, a local Small Language Model explains them, and every claim links back to a log line. No cloud, no API keys, no data leaving the machine.

> PS 2 · Domain: Cybersecurity | Small Language Models (SLMs)

```
 auth.csv / endpoint.json ──► parse ──► detect (8 rules) ──► correlate ──► score ──► SQLite
                                                                  │
                                       evidence rows ─────────────┤
                                                                  ▼
                                   local SLM (Ollama, llama3.2:1b) ──► grounding checks ──► report (UI · MD · JSON)
```

## Why TriageOwl

SOC analysts drown in authentication and endpoint logs, and many sites cannot send them to a cloud service. TriageOwl runs entirely on one laptop: deterministic rules decide *what* is suspicious and *how severe* it is, and a 1B-parameter model only helps *explain* it. Because a small model can invent details, every statement it writes is mechanically checked against the log rows it cites, and unsupported ones are withheld and shown as such.

## How it meets the problem statement

| Requirement | How TriageOwl does it |
|---|---|
| **Log processing** (CSV / JSON) | Auth and endpoint files, up to 20 at once. Column aliases, Windows event IDs (4624/4625/4688/4728/4732), epoch and ISO timestamps, source-aware evidence IDs (`S1-E17`), file hashes. |
| **≥ 3 suspicious patterns** | **Eight** rules: repeated failures (brute force), password spray, distributed/rotating-IP attack, success after failure burst, off-hours login, off-hours failures, unapproved privilege change, suspicious process command line. |
| **Event correlation** | Findings are clustered into incidents by shared user or device within a configurable time span (default 60 min), across files. |
| **Severity classification** | Transparent points per distinct rule (+10 per extra rule, cap 100): Critical ≥ 80, High ≥ 50, Medium ≥ 30, else Low. The score explanation is shown with each incident. |
| **SLM integration** | Local Ollama model returns schema-constrained JSON: cited observations and hedged interpretations about *why the sequence matters for priority*. |
| **Evidence-based reporting** | Per-incident report (Markdown and JSON): threats, severity, scoring, SLM notes, supporting log rows with original fields, source hashes, recommended actions. |
| **Offline** | Backend binds to loopback; Ollama URL must be loopback HTTP; no CDN assets (`/docs` disabled). Rules and reports work even if the model is down. |

## Evidence reliability (what makes it different)

A small model's output is treated as untrusted. Before anything is shown, each statement is checked against the rows it cites (`backend/services/grounding.py`):

- IDs, IPs, dates/times, usernames, hostnames and commands must exist in the cited rows
- counts and durations must be derivable ("5 failed logins" must match the cited rows)
- event-type and approval claims must match the rows (no "successful login" citing a failure)
- no certainty or compromise claims; observations can't speculate; interpretations must be hedged
- repeats and restatements of rule findings are dropped; limitations are generated from the data, not by the model

Withheld statements are listed with the reason. These checks are mechanical: they do **not** prove a statement is true, so analyst review is still required.

## Quick start

Requirements: Python 3.10+, Node 20.19+, [Ollama](https://ollama.com) with `llama3.2:1b` (pulled once; no network needed afterwards).

```bash
# backend
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-test.txt
.venv/bin/python -m unittest discover -s backend/tests -v
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 5000

# frontend (second terminal)
cd frontend && npm install && npm run dev        # http://127.0.0.1:5173

# model (third terminal, once)
ollama pull llama3.2:1b && ollama serve
```

Open the UI, pick a sample scenario (or upload your own CSV/JSON), click **Run triage**, then **Explain with local SLM** on an incident. For a single-server demo build the frontend (`npm run build`) and open http://127.0.0.1:5000. Windows, configuration and troubleshooting: [docs/USER-GUIDE.md](docs/USER-GUIDE.md).

### Input format

```text
time,user,device,ip,event,detail,approved
```

ISO 8601 timestamps preferred. Aliases such as `timestamp`, `username`, `host`, `src_ip`, `action`, `commandline` are accepted.

## Demo scenarios (`sample-data/`)

| Scenario | Expected result |
|---|---|
| `auth_logs.csv` | 3 incidents: Critical 100 (brute force → login → admin change → encoded PowerShell), Medium 35, Low 15 |
| `endpoint_logs.json` | Critical 85: unapproved admin change + encoded PowerShell; the approved change is suppressed |
| `password_spray.json` | Medium 40: one spray finding |
| `rotating_ips.json` | High 75: brute force + distributed attack |
| `cross-source/` (both files) | One Critical 100 incident with evidence from both sources |

## Measured results (and their limits)

- **Tests:** 56 backend tests pass (8 HTTP tests are skipped unless FastAPI is installed).
- **Detection:** on 32 hand-written development cases: 20 TP, 3 FP, 0 FN (case/rule precision 0.87, recall 1.0). The 3 false positives are deliberate hard negatives for command-line heuristics. Not a held-out or real-world benchmark. See [evaluation/README.md](evaluation/README.md).
- **Speed:** in-process parse + detect + correlate: ~14 ms for 1,000 events, ~160 ms for 10,000 (synthetic, excludes SLM and HTTP). Rerun `scripts/benchmark.py` on your hardware.
- **SLM grounding checker:** on 42 labelled statements, 25/28 unsupported statements withheld, 14/14 supported kept (a regression set, not held-out). The real model's live quality and latency have **not** been measured in the development environment; use `scripts/live_slm_check.py` and `scripts/sample_memory.py` on the target machine.

## Limitations

Findings are indicators, not verdicts. Rules cover eight patterns and do not detect arbitrary attacks; process matching is heuristic; shared egress IPs or automation can cause false positives; the `approved` flag in logs is trusted, not verified; the SLM can be wrong in ways the checks cannot see (inverted negation, invented context). No automatic response is ever taken. Full list: [docs/USER-GUIDE.md](docs/USER-GUIDE.md).

## Repository layout

```
backend/        FastAPI app: services/ (parser, detector, correlation, slm, grounding), routes/, database/, tests/
frontend/       React + Vite UI
sample-data/    Synthetic auth/endpoint logs
evaluation/     Labelled cases, results, method notes
scripts/        evaluate, benchmark, grounding eval, live SLM check, browser smoke, memory sampler
docs/           User guide, changelog, test notes, acceptance checklist
```

## License

Add a license before publishing. Sample data is synthetic.