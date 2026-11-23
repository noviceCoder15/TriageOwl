# Target-machine acceptance checklist

Do not declare a test passed just because code/tests for it exist. Record actual outcomes on your target system.

| Check | Expected |
|---|---|
| auth_logs.csv | 30 events, 3 incidents: Critical100 / Medium35 / Low15; Rahul 6 findings |
| endpoint_logs.json | 3 events, 1 Critical85 incident, approved change suppressed |
| password_spray.json | 6 events, Medium40 spray incident |
| rotating_ips.json | 6 events, High75 brute+distributed incident |
| both cross-source files selected together, case-insensitive users enabled | 8 events, one Critical100 incident, evidence from S1 and S2 |
| 4 per-account failures in 10 minutes at working hours | no brute finding |
| 5 per-account failures in 10 minutes at working hours | brute finding |
| malformed JSON / empty CSV / unsupported extension | clear error, subsequent valid upload works |
| mixed invalid timestamps | invalid rows skipped, source-aware warnings |
| valid events from unrelated users/devices | no unrelated cluster merge |
| source provenance | duplicate E1 across two files remains S1-E1 / S2-E1 |
| live model | separate observations/hypotheses, valid citations, specific missing context |
| saved history | explanation restored after browser refresh |
| report | both MD/JSON include source hashes, original evidence, severity, actions and saved explanation |
| internet disconnected | new upload, new inference, downloads and restored history all work |
| Ollama stopped | rules/reports still work, explanation fails clearly |
| Ollama restarted | new explanation works; no model re-download |
| SLM statements | after Explain, every statement cites rows that show it; a "withheld" list appears when the checker removed something; no limitation/step is repeated between the SLM panel and the rule-based actions |

Record analysis ms, model wall ms, actual process memory, model/runtime versions and hardware. Screenshot successes and relevant warnings. The 32-case development benchmark is NOT proof of unseen accuracy.
