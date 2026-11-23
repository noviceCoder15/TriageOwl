import argparse,json,csv,sys,time,platform
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.services.pipeline import analyze
from backend.services.detector import POINTS

def evaluate(path):
    cases=json.loads(Path(path).read_text());rows=[];totals=dict(tp=0,fp=0,fn=0);by_rule={k:dict(tp=0,fp=0,fn=0) for k in POINTS}
    for case in cases:
        result=analyze(case['files'],case.get('config'))
        actual={f['rule'] for x in result['incidents'] for f in x['findings']};expected=set(case['expected_rules'])
        tp=actual&expected;fp=actual-expected;fn=expected-actual
        for label,values in [('tp',tp),('fp',fp),('fn',fn)]:
            totals[label]+=len(values)
            for rule in values:by_rule[rule][label]+=1
        rows.append(dict(case=case['name'],expected=','.join(sorted(expected)),actual=','.join(sorted(actual)),
            tp=len(tp),fp=len(fp),fn=len(fn),analysis_ms=result['metrics']['analysis_ms']))
    def rates(x):
        return {**x,'precision':round(x['tp']/(x['tp']+x['fp']),4) if x['tp']+x['fp'] else None,
            'recall':round(x['tp']/(x['tp']+x['fn']),4) if x['tp']+x['fn'] else None}
    report=dict(basis='Micro-averaged case/rule presence. Repeated occurrences within a case counted once; not event/incident precision.',
        dataset='Hand-authored synthetic development cases, NOT an independent unseen or real-world benchmark.',
        cases=len(cases),metrics=rates(totals),per_rule={k:rates(v) for k,v in by_rule.items()},python=platform.python_version())
    return report,rows
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--cases',default=str(ROOT/'evaluation/labeled_cases.json'));ap.add_argument('--out',default=str(ROOT/'evaluation/results'));args=ap.parse_args()
    report,rows=evaluate(args.cases);out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    (out/'accuracy.json').write_text(json.dumps(report,indent=2))
    with (out/'cases.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(json.dumps(report,indent=2))
