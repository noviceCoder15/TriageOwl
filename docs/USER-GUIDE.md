# TriageOwl user guide (setup, schema, configuration, limitations)

React + Python/FastAPI + SQLite + local Ollama.

## Main improvements

- Password-spray detection across distinct accounts from one source IP.
- Distributed/rotating-IP detection against one account.
- Per-account failure aggregation no longer requires device/IP, so sparse records can trigger it.
- Repeated off-hours failures as a separate indicator (not every isolated bad password).
- Expanded explainable process patterns; known false positives are measured and documented.
- Select auth and endpoint files together for one analysis. Stable source IDs, filename, hash and original record number travel into evidence and reports.
- Opt-in case-insensitive user matching; case-folded device matching; original text preserved.
- Structured local SLM observations and interpretations, each checked against the evidence it cites (see "SLM safety and scope"); application-generated limitations.
- Separate rule and SLM panels; model failure does not hide rule results.
- Analysis timing, backend peak-RSS metadata and model inference timings in reports.
- 32 synthetic labeled development cases; evaluation and benchmarking scripts; 32 dependency-free tests and 8 optional HTTP tests.
- Optional automated browser smoke test and real-model HTTP checker.
- No external Swagger/CDN documentation: /docs and /redoc disabled; /openapi.json remains available.
- No placeholder MITRE claims.

## Dependency note

Exact top-level npm versions are pinned, but no resolved lockfile is committed. Run `npm install`, review and commit the generated `package-lock.json`, then use `npm ci`. Python dependencies are pinned at the top level only.

## Prerequisites / one-time connected setup

Python 3.10+; Node 20.19+ (or newer supported LTS) and npm; Ollama with `llama3.2:1b` downloaded. This ZIP does not contain dependencies or model weights. Provision them once online or via an approved air-gap transfer. Runtime core analysis/inference/reporting uses loopback and local files only.

### WSL / Linux / macOS: backend terminal

Run in the folder containing `backend` and `frontend`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-test.txt
.venv/bin/python -m unittest discover -s backend/tests -v
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 5000 --reload
```

### Frontend terminal

```bash
cd /path/to/new/triage/frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173 . Keep backend and Ollama inside the same WSL environment for the default loopback configuration.

### Ollama terminal

If not already installed in WSL, use the official Linux installer in WSL. If extraction complains about zstd, install that package first. Once installed:

```bash
ollama pull llama3.2:1b
ollama serve
```

Skip serve if the server is already running. Never run two instances on the same port. Click Refresh SLM status in the UI. No model re-download is needed when upgrading this app if the model is already present.

### Windows PowerShell backend alternative

For a Windows-native deployment, run the backend and Ollama on Windows together:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-test.txt
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -v
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 5000 --reload
```

Frontend commands are the same in a separate terminal. Backend RSS metadata is unavailable on native Windows; use OS tools and clearly state the measurement scope. Avoid mixing a Windows backend with a separate WSL Ollama instance for this configuration.

## Single-server deployment for offline demo

With dependencies installed:

```bash
cd frontend
npm run build
cd ..
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 5000
```

Start/restart the API AFTER building. Open http://127.0.0.1:5000 . No Vite process is needed. On Windows replace the venv interpreter with `.\.venv\Scripts\python.exe`. Keep Ollama running for explanations. Test with external networking disconnected, generating a NEW explanation rather than restoring an old one.

## Demo and regression expectations

1. Auth sample: 30 accepted, 0 skipped, 3 incidents. Rahul Critical 100, now 6 findings including off-hours failure burst; Priya Medium 35; Neha Low 15.
2. endpoint_logs.json: 3 accepted; guest on WS-11 Critical 85; approved analyst privilege event suppressed.
3. password_spray.json: 6 accepted; one spray finding, Medium 40 (High begins at 50).
4. rotating_ips.json: 6 accepted; brute + distributed, High 75 (25 + 40 + 10). This is not a probability.
5. Select BOTH files in sample-data/cross-source/ together (Ctrl/Shift-select). Enable case-insensitive users for this fixture and Run triage. Expect 8 accepted and one Critical 100 incident with evidence from S1 and S2. Users differ in capitalization across sources; devices match after case-folding. No endpoint IP match is required.
6. Generate an explanation; inspect citations; download MD and JSON; refresh and restore history.

See ACCEPTANCE.md for additional checks.

## Detection semantics and limitations

Defaults: failure count 5 in 10 minutes, spray 5 distinct accounts per IP, distributed 5 distinct IPs per account, off-hours 22 to 6, UTC offset 0, correlation span 60 minutes.

Eight rule types: brute, spray, distributed, success_after, offhours, offhours_failure, priv, proc. Findings are indicators, not maliciousness verdicts. A successful login must follow the end of a detected account-failure burst within 15 minutes; source IP need not match, and this can increase false positives. Failure bursts use a non-overlapping emission policy after reaching threshold; this is not a continuous SIEM session engine. Shared egress IPs, automation, account collisions across realms and admin commands can cause false positives. Identity keys do not implement directory/realm resolution.

Correlation uses known user OR device and bounded total span when adding findings, preferring user overlap. Candidate lookup is indexed, but clusters are assigned greedily and are not fully merged as graph components. Shared devices can connect different users. A single detection burst can itself span its configured failure window; keep that window <= correlation span if you require every incident to respect the same total bound. Duplicate records across files are NOT deduplicated: avoid uploading overlapping exports, which can inflate failure counts.

Severity sums the highest points per distinct rule plus 10 per additional rule, capped at 100. Points: brute 25, spray 40, distributed 40, success_after 40, offhours 15, offhours_failure 10, priv 35, proc 40. Critical >=80, High >=50, Medium >=30, otherwise Low. Related rules can overlap; score inflation from overlapping indicators is a known policy limitation. No asset-criticality context is used.

## Input schema

CSV header / JSON object fields:

```text
time,user,device,ip,event,detail,approved
```

Aliases: timestamp/ts/@timestamp/datetime; username/account; host/hostname/computer; src_ip/source_ip; event_type/action/event_id/eventid; details/message/commandline/command; authorized.

Canonical event aliases include login_failed, login_success, logon_failure, logon_success, group_change/privilege_change/priv_change, process_start/process and logoff. Windows IDs 4624/4625/4728/4732/4688 are supported. Numeric event 1 is only interpreted as process when provider=sysmon. Other event types remain other and generate a warning. This is not a raw EVTX or nested ECS parser.

Use ISO 8601 time with Z/offset. Naive timestamps assume UTC with a warning. Invalid records are skipped; an input file with no valid records rejects the entire analysis. JSON can be an array or an object with events/logs array. Missing user/device become unknown; IP becomes '-'. Unknown user/device values cannot connect clusters. Data should be UTF-8. Maximum 20 files, 20 MB combined decoded UTF-8 text, 100,000 records; HTTP envelope limit 24 MB.

UTC offset is fixed, not daylight-saving-aware. Equal off-hours endpoints disable that rule. Approved privilege changes require approved/authorized = true/yes/1. This flag is trusted metadata, not independently verified authorization.

## SLM safety and scope

The model explains ONLY rule-detected incidents; it does not independently detect missed threats. It receives evidence loaded from SQLite, not client-authored incident objects.

How accuracy is enforced (all mechanical, in `backend/services/grounding.py`):

- The prompt carries FACTS computed by the application (counts, users, devices, IPs, UTC span per finding) plus the evidence rows. Rows carry only the fields needed; `approved` is sent only for privilege changes (it defaults to false on every other row and invited false "unapproved" claims). The schema travels in Ollama's `format` field only.
- The model writes only observations (max 4) and interpretations (max 2). Limitations are generated by the application from the incident data. Investigation steps are not generated by the model: the rule-based "Recommended investigation" list is the single source, so nothing is said twice.
- Each statement is checked against the rows it cites. It is withheld if it has an unknown evidence ID; an IP, date or clock time not in the cited rows; an identifier, user or device not in the cited rows; a count or duration that cannot be derived (counts next to "failed", "different IPs" etc. must match the cited rows or their finding); an event-type claim without a matching cited row (successful/failed login, group change, process); an approval claim contradicting the `approved` flag; certainty or compromise wording; speculation inside an observation; an interpretation without hedging; generic filler; or a near-duplicate of an earlier statement or of a rule finding.
- Supported statements are kept even when others fail. Withheld statements are listed with the reason in the UI, JSON and Markdown report. If nothing survives, the model is retried once at temperature 0 with the rejection reasons in the prompt; after that the request fails and the rule results remain.

What this does NOT do: prove a statement is true. It cannot catch a wrong claim that uses only values present in the cited rows, inverted negation ("no failed logins"), invented plain-word names at the start of a sentence, invented context, IPv6, or omissions. Hypotheses remain model-generated and need analyst review. Prompt injection is mitigated by separating instructions from data, not solved. Never execute commands from logs or model responses. There is no automatic containment.

Checker measurement: `python scripts/slm_grounding_eval.py` scores the checker on 42 hand-written statements (see evaluation/README.md). It does not measure the real model. Evidence prompt limit 22,000 characters; no silent row truncation. Context 8192; 900 output tokens; temperature 0 with a fixed seed and repeat penalty; timeout 180 seconds. Length-truncated or invalid JSON is rejected. Model runtime may continue after a client timeout.

## Configuration

Set BEFORE starting backend (no auto .env loading):

- OLLAMA_MODEL: default llama3.2:1b, must exactly match installed tag.
- OLLAMA_URL: default http://127.0.0.1:11434; only HTTP loopback without path/credentials is allowed. Proxies/redirects are disabled for inference requests.
- TRIAGE_DB: default backend/database/triage-v3.sqlite3; parent folder must exist.

Bash example: `export OLLAMA_MODEL='your-installed-model:tag'`
PowerShell: `$env:OLLAMA_MODEL='your-installed-model:tag'`

This application's loopback restriction is not a guarantee about the independent Ollama runtime's update/telemetry settings. Apply your host/network policy for sensitive data.

## Testing, evaluation and performance

See TESTING.md, evaluation/README.md and ACCEPTANCE.md. Run from project root:

```bash
.venv/bin/python -m unittest discover -s backend/tests -v
.venv/bin/python scripts/evaluate.py
.venv/bin/python scripts/benchmark.py --sizes 1000 10000 --repeats 3
.venv/bin/python scripts/live_slm_check.py --out live-slm-results.json
.venv/bin/python scripts/sample_memory.py --seconds 120 --out memory-samples.csv
```

Last two require the actual local services; memory sampler requires Linux/WSL. Browser automation is optional, with a one-time browser download:

```bash
.venv/bin/python -m pip install -r backend/requirements-browser.txt
.venv/bin/python -m playwright install chromium
# Build frontend, start single-server app on port 5000, then:
.venv/bin/python scripts/browser_smoke.py
```

Browser smoke checks page load, upload and JSON download, not live-model semantics or network isolation. Browser dependencies may need OS provisioning on Linux. If HTTP dependencies are missing, 8 API tests are SKIPPED; do not count skips as passing tests.

## API

- GET /api/health
- POST /api/analyze: {"files":[{"filename":"auth.csv","content":"..."},{"filename":"endpoint.json","content":"..."}],"config":{}}
- POST /api/analyze: {"sample":true}
- GET /api/analyses
- GET /api/analyses/{analysisId}
- POST /api/explain: {"analysisId":"stored-id","incidentId":1}
- GET /api/slm/status
- GET /api/reports/{analysisId}/{incidentId}?format=md or json
- GET /openapi.json (local schema; interactive /docs disabled)

## Privacy and operational boundaries

Bind to 127.0.0.1. No login, encrypted storage, retention policy, directory integration, rate limiting or multi-user isolation is provided. Do not expose publicly or to a LAN. Host/origin checks are defense-in-depth, not protection from other local processes/users. Logs and model explanations persist in plaintext SQLite and exported reports. Secure the folder with OS permissions and disk protection.

Hashes are of submitted UTF-8 TEXT, not guaranteed original file bytes/encoding. Uploads are read as text in the browser. Preserve original files for forensic chain-of-custody. Full source uploads are not persisted; only supporting rows and analysis metadata are retained. Stop backend before deleting DB/WAL/SHM to reset history. Back up data first.

## Repository layout

backend/main.py; routes/{logs,incidents,reports}.py; services/{parser,detector,correlation,severity,pipeline,slm,reporting}.py; database/db.py; tests/
frontend/src/App.jsx; api.js; styles.css
sample-data/; evaluation/; scripts/

No production security or representative detection benchmark is claimed. This release improves known gaps without claiming they are all solved.
