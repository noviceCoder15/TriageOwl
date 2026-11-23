from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]/'sample-data'
SETS={
 'auth':('Auth logs: brute force, privilege change, off-hours',['auth_logs.csv'],{}),
 'endpoint':('Endpoint log: unapproved admin change + encoded PowerShell',['endpoint_logs.json'],{}),
 'spray':('Password spraying across accounts',['password_spray.json'],{}),
 'rotating':('One account attacked from rotating IPs',['rotating_ips.json'],{}),
 'cross':('Cross-source: auth + endpoint files together',['cross-source/auth.csv','cross-source/endpoint.json'],{'case_insensitive_users':True})}
def listing():return [dict(id=k,label=v[0],files=[Path(f).name for f in v[1]],config=v[2]) for k,v in SETS.items()]
def load(name):
    if name not in SETS:raise ValueError('Unknown sample set.')
    return [dict(filename=Path(f).name,content=(ROOT/f).read_text(encoding='utf-8')) for f in SETS[name][1]]
