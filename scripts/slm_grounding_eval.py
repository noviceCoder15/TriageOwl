"""Score the SLM grounding checker on labelled statements (no model or network needed).

    python scripts/slm_grounding_eval.py [--cases evaluation/slm_grounding_cases.json] [--out evaluation/results/slm-grounding.json]

Each case is a statement a model might write about a sample incident, labelled accept/reject BEFORE running the checker.
The result measures the checker's mechanical filtering, not the quality of the real model's output.
"""
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.services import samples, grounding
from backend.services.pipeline import analyze

ap = argparse.ArgumentParser()
ap.add_argument('--cases', default=str(ROOT / 'evaluation/slm_grounding_cases.json'))
ap.add_argument('--out', default=str(ROOT / 'evaluation/results/slm-grounding.json'))
args = ap.parse_args()
cases = json.loads(Path(args.cases).read_text())['cases']
incidents = {}
def incident(name, number):
    if name not in incidents:
        cfg = next(s for s in samples.listing() if s['id'] == name)['config']
        incidents[name] = analyze(samples.load(name), cfg)['incidents']
    return incidents[name][number - 1]

rows, tally = [], dict(tp=0, fp=0, fn=0, tn=0)
for case in cases:
    got = 'reject' if grounding.problems(case['statement'], case['section'], case['evidence_ids'], incident(case['sample'], case['incident'])) else 'accept'
    # "positive" = bad statement correctly withheld
    key = ('tp' if got == 'reject' else 'fn') if case['expect'] == 'reject' else ('tn' if got == 'accept' else 'fp')
    tally[key] += 1
    rows.append(dict(case, got=got, correct=got == case['expect']))
known = [r for r in rows if r.get('known_gap')]
regular = [r for r in rows if not r.get('known_gap')]
bad = tally['tp'] + tally['fn']; good = tally['tn'] + tally['fp']
summary = dict(cases=len(rows), unsupported_withheld=f"{tally['tp']}/{bad}", supported_kept=f"{tally['tn']}/{good}",
               recall_of_bad=round(tally['tp'] / bad, 4), supported_pass_rate=round(tally['tn'] / good, 4),
               known_gaps_accepted=sum(r['got'] == 'accept' for r in known), known_gap_cases=len(known),
               mismatches_excluding_known_gaps=[r['statement'] for r in regular if not r['correct']])
Path(args.out).parent.mkdir(parents=True, exist_ok=True)
Path(args.out).write_text(json.dumps(dict(summary=summary, tally=tally, cases=rows), indent=1))
print(json.dumps(summary, indent=1))
