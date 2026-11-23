import argparse,csv,time,subprocess,sys
from datetime import datetime,timezone
ap=argparse.ArgumentParser(description='Linux/WSL process RSS sampler, no Python dependencies.')
ap.add_argument('--seconds',type=int,default=120);ap.add_argument('--out',default='memory-samples.csv');args=ap.parse_args()
if not sys.platform.startswith('linux'):ap.error('Run inside Linux/WSL; Windows-host processes are not visible.')
with open(args.out,'w',newline='') as f:
    writer=csv.writer(f);writer.writerow(['utc','pid','ppid','rss_kib','command'])
    for _ in range(max(1,args.seconds)):
        data=subprocess.check_output(['ps','-eo','pid=,ppid=,rss=,args='],text=True)
        now=datetime.now(timezone.utc).isoformat()
        for line in data.splitlines():
            fields=line.strip().split(None,3)
            if len(fields)==4 and any(s in fields[3] for s in ['ollama','uvicorn','vite']):writer.writerow([now,*fields])
        f.flush();time.sleep(1)
print('Saved process samples. Sum selected PIDs cautiously: RSS can double-count shared pages; this is not GPU VRAM or whole-system/browser memory.')
