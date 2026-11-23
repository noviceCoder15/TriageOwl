# v3 packaging verification

## Executed in the packaging environment

- Python backend and scripts compile successfully.
- 32 core tests PASSED.
- 8 FastAPI HTTP tests SKIPPED because FastAPI/uvicorn are not installed here. They are not counted as passes. Install backend/requirements-test.txt and rerun locally.
- All JS/JSX source files and Vite configuration parsed successfully with the locally available Babel parser. This catches the previous invalid-await class of syntax error. It does not replace bundling/browser execution.
- 32 labeled synthetic DEVELOPMENT cases evaluated: 20 TP, 3 FP, 0 FN; micro case/rule precision 0.8696, recall 1.0. Not unseen or representative accuracy. See evaluation/results and evaluation/README.md.
- Synthetic in-process performance benchmark ran with 1,000 and 10,000 events, 3 repeats each. Median times: 14.21 ms and 160.0 ms in this environment. These exclude HTTP, persistence, browser and SLM. They are NOT laptop or end-to-end performance claims.
- Structured model response validation and request construction tested with mocks, including rejection paths. A live Ollama model was NOT run here.
- SQLite persistence, source-aware multi-file correlation and report content tested.

## Not executed / unresolved

- FastAPI HTTP integration, live Ollama, Playwright browser smoke, target-device offline acceptance.
- Full Vite build: dependencies are not installed. Offline npm lockfile generation was attempted and failed with ENOTCACHED for plugin-react metadata. No lockfile is fabricated. Run npm install while connected and commit the generated lockfile. Exact direct npm versions are pinned, not transitive versions.
- Model RAM, GPU memory, actual full-system limits and resource-constrained inference.
- Independent held-out detection benchmark or automatic semantic proof of explanations.

The original project's later local success does not certify this changed version. Rerun ACCEPTANCE.md against v3. Do not mark skipped tests as passed. Do not quote development recall as a general security guarantee.

- v4.1: 56 tests (48 + 8 grounding), 8 HTTP tests skipped without FastAPI. SLM grounding checker scored by `scripts/slm_grounding_eval.py` (see evaluation/README.md). The real model was not run.
