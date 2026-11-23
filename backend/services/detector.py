from collections import defaultdict, deque
from datetime import datetime,timedelta
import re
DEFAULTS=dict(thr=5,win=10,ns=22,ne=6,tz_offset=0,correlation_minutes=60,spray_users=5,rotating_ips=5,case_insensitive_users=False)
POINTS=dict(brute=25,spray=40,distributed=40,success_after=40,offhours=15,offhours_failure=10,priv=35,proc=40)
ACTIONS={
'brute':['Review failure reasons, source context, lockout policy and MFA configuration.'],
'spray':['Investigate the source across targeted accounts; distinguish shared NAT or authorized testing before blocking.'],
'distributed':['Review the targeted account across all sources and verify proxy/VPN context.'],
'success_after':['Verify the successful session with the account owner; if compromise is confirmed, revoke sessions and rotate credentials.'],
'offhours':['Check the user schedule, fixed UTC offset and approved maintenance.'],
'offhours_failure':['Check whether off-hours failures are expected automation or unauthorized attempts.'],
'priv':['Check the change ticket and actor authorization; preserve evidence and revert only if unauthorized.'],
'proc':['Review command line, parent process, signer and execution outcome; isolate only if malicious activity is confirmed.']}
def stamp(r):return datetime.fromisoformat(r['time'].replace('Z','+00:00'))
def config(values=None):
    values=values or {}
    if set(values)-set(DEFAULTS):raise ValueError('Unknown configuration keys: '+', '.join(sorted(set(values)-set(DEFAULTS))))
    c={**DEFAULTS,**values}
    for k,lo,hi in [('thr',2,1000),('win',1,1440),('ns',0,23),('ne',0,23),('tz_offset',-12,14),('correlation_minutes',1,1440),('spray_users',2,1000),('rotating_ips',2,1000)]:
        v=c[k]
        if isinstance(v,bool) or not isinstance(v,(int,float)) or not lo<=v<=hi or (k!='tz_offset' and int(v)!=v):raise ValueError(f'Invalid {k}: expected {lo} to {hi}.')
    if not isinstance(c['case_insensitive_users'],bool):raise ValueError('case_insensitive_users must be true/false.')
    return c
PROCESS_PATTERNS=[
 ('encoded PowerShell',r'(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*?\s-(?:enc|encodedcommand)\b'),
 ('credential-tool marker',r'(?i)\bmimikatz\b|sekurlsa::'),
 ('certutil download syntax',r'(?i)\bcertutil(?:\.exe)?\b.*-urlcache'),
 ('privilege enumeration',r'(?i)\bwhoami(?:\.exe)?\s+/priv\b'),
 ('netcat executable',r'(?i)\bnc\.exe\b'),
 ('script-based download/execute',r'(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:downloadstring|invoke-expression|invoke-webrequest)'),
 ('scheduled-task creation',r'(?i)\bschtasks(?:\.exe)?\b.*\s/create\b'),
 ('remote script launch',r'(?i)\b(?:mshta|regsvr32)(?:\.exe)?\b.*https?://')]

def detect(logs,c):
    findings=[]
    def add(rule,title,ev):
        ev=sorted({r['id']:r for r in ev}.values(),key=lambda r:r['time'])
        findings.append(dict(rule=rule,title=title,time=ev[0]['time'],end=ev[-1]['time'],points=POINTS[rule],evidence=[r['id'] for r in ev],
            users=sorted({r['user_key'] for r in ev if r['user_key']!='unknown'}),devices=sorted({r['device_key'] for r in ev if r['device_key']!='unknown'})))
    failed=[r for r in logs if r['event']=='login_failed']
    success=[r for r in logs if r['event']=='login_success']
    window=timedelta(minutes=c['win'])
    def bursts(keyfn,required,distinct=None):
        groups=defaultdict(list)
        for r in failed:
            key=keyfn(r)
            if key is not None:groups[key].append(r)
        result=[]
        for rows in groups.values():
            q=deque()
            for r in rows:
                while q and stamp(r)-stamp(q[0])>window:q.popleft()
                q.append(r)
                if (len({distinct(x) for x in q}) if distinct else len(q))>=required:
                    result.append(list(q));q.clear()
        return result
    # Missing device/IP do not disable basic per-account failure aggregation.
    for ev in bursts(lambda r:r['user_key'] if r['user_key']!='unknown' else None,c['thr']):
        add('brute',f'{len(ev)} failed logins against one account within {c["win"]} minutes',ev)
        # A sequence is suspicious, not proof that the source belongs to an attacker.
        ok=next((r for r in success if r['user_key']==ev[0]['user_key'] and stamp(ev[-1])<stamp(r)<=stamp(ev[-1])+timedelta(minutes=15)),None)
        if ok:add('success_after','Successful login following an account failure burst; verify session legitimacy',ev+[ok])
        def off(r):
            h=(stamp(r)+timedelta(hours=c['tz_offset'])).hour
            return (h>=c['ns'] or h<c['ne']) if c['ns']>c['ne'] else c['ns']<=h<c['ne']
        if all(off(r) for r in ev):add('offhours_failure','Repeated failed logins outside configured hours',ev)
    for ev in bursts(lambda r:r['ip'] if r['ip']!='-' and r['user_key']!='unknown' else None,c['spray_users'],lambda r:r['user_key']):
        add('spray',f'Possible password spray: {len({r["user_key"] for r in ev})} accounts targeted from one IP',ev)
    for ev in bursts(lambda r:r['user_key'] if r['ip']!='-' and r['user_key']!='unknown' else None,c['rotating_ips'],lambda r:r['ip']):
        add('distributed',f'Possible distributed account targeting: {len({r["ip"] for r in ev})} source IPs',ev)
    for r in logs:
        h=(stamp(r)+timedelta(hours=c['tz_offset'])).hour
        off=(h>=c['ns'] or h<c['ne']) if c['ns']>c['ne'] else c['ns']<=h<c['ne']
        if r['event']=='login_success' and off:add('offhours','Login outside configured working hours',[r])
        if r['event']=='priv_change' and not r['approved']:add('priv','Privilege change without approval recorded; verify authorization',[r])
        if r['event']=='process':
            matches=[label for label,pattern in PROCESS_PATTERNS if re.search(pattern,r['detail'])]
            if matches:add('proc','Potentially suspicious command: '+', '.join(matches),[r])
    return sorted(findings,key=lambda f:(f['time'],f['rule']))
