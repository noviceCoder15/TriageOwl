import argparse,json,urllib.request,time,csv
from pathlib import Path
ap=argparse.ArgumentParser(description='Live localhost smoke test; human semantic review remains required.')
ap.add_argument('--base',default='http://127.0.0.1:5000');ap.add_argument('--out',default='live-slm-results.json');args=ap.parse_args()
if args.base not in ('http://127.0.0.1:5000','http://localhost:5000'):ap.error('Use documented loopback server.')
def call(path,body=None):
    req=urllib.request.Request(args.base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=200) as r:return json.load(r)
root=Path(__file__).resolve().parents[1];results=[]
for name in ['password_spray.json','rotating_ips.json','endpoint_logs.json']:
    start=time.perf_counter()
    try:
        data=call('/api/analyze',dict(files=[dict(filename=name,content=(root/'sample-data'/name).read_text())]))
        if not data['incidents']:raise ValueError('Expected at least one incident.')
        x=data['incidents'][0];explanation=call('/api/explain',dict(analysisId=data['analysisId'],incidentId=x['id']))
        results.append(dict(file=name,transport_and_structural_checks='passed',wall_ms=round((time.perf_counter()-start)*1000,2),
            attempts=explanation.get('attempts'),statements_kept=len(explanation.get('claims',[])),statements_withheld=len(explanation.get('unsupported',[])),
            withheld_reasons=[u['reason'] for u in explanation.get('unsupported',[])],explanation=explanation,manual_review=dict(supported_claims=None,no_invented_intent=None,sequence_useful=None,specific_uncertainty=None)))
    except Exception as e:results.append(dict(file=name,error=str(e)))
Path(args.out).write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
