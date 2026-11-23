import sys,json,argparse,platform,time,csv,statistics
from pathlib import Path
from datetime import datetime,timedelta,timezone
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.services.pipeline import analyze
ap=argparse.ArgumentParser();ap.add_argument('--sizes',nargs='+',type=int,default=[1000,10000]);ap.add_argument('--repeats',type=int,default=3);ap.add_argument('--out',default=str(ROOT/'evaluation/results/performance.json'));args=ap.parse_args()
if args.repeats<1 or any(n<1 or n>100000 for n in args.sizes):ap.error('Use positive repeats and sizes 1..100000.')
results=[]
for n in args.sizes:
    base=datetime(2026,11,23,12,tzinfo=timezone.utc)
    # Mostly working-hours normal activity, ending with a short account-failure burst.
    rows=[dict(time=(base+timedelta(milliseconds=i)).isoformat(),user=f'user{i%100}',device=f'WS-{i%50}',ip=f'192.0.2.{i%200+1}',event='process_start',detail='notepad.exe') for i in range(max(0,n-5))]
    rows.extend(dict(time=(base+timedelta(seconds=i)).isoformat(),user='attack',device='WS-T',ip='192.0.2.250',event='login_failed',detail='Synthetic') for i in range(min(n,5)))
    payload=[dict(filename='benchmark.json',content=json.dumps(rows))]
    runs=[analyze(payload) for _ in range(args.repeats)];times=[r['metrics']['analysis_ms'] for r in runs]
    results.append(dict(events=n,repeats=args.repeats,min_ms=min(times),median_ms=statistics.median(times),max_ms=max(times),backend_peak_rss_mb=runs[-1]['metrics']['backend_process_peak_rss_mb']))
report=dict(platform=platform.platform(),python=platform.python_version(),results=results,
    limitations='Synthetic mostly-benign in-process workload. Excludes HTTP/browser/SQLite/SLM. Lifetime backend peak RSS, not per-run incremental RAM. Not representative of worst-case alert volume. Rerun on target laptop.')
out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
