import csv, io, json, hashlib, re
from datetime import datetime, timezone
ALIASES={'4624':'login_success','4625':'login_failed','4728':'priv_change','4732':'priv_change','4688':'process',
'login_success':'login_success','logon_success':'login_success','login_failed':'login_failed','logon_failure':'login_failed',
'group_change':'priv_change','priv_change':'priv_change','privilege_change':'priv_change','process':'process','process_start':'process','logoff':'logoff'}

KEYWORDS=[(r'log\s*(?:off|out)|sign[ _-]?out','logoff'),
 (r'(?:fail|invalid|denied|incorrect|unsuccessful|reject).*(?:log|auth|pass|cred|sign)|(?:log|auth|pass|cred|sign).*(?:fail|invalid|denied|incorrect|unsuccessful|reject)|bad[ _-]?password','login_failed'),
 (r'success|logon|login|accepted|authenticated|sign[ _-]?in','login_success'),
 (r'priv|sudo|admin|group|role|elevat','priv_change'),
 (r'proc|exec|spawn|cmd|command|script','process')]
def guess_event(action):
    """Keyword fallback for event names that are not exact aliases (e.g. 'Failed password', 'user_logon')."""
    for pattern,event in KEYWORDS:
        if re.search(pattern,action):return event
    return 'other'
def parse_time(ts):
    """ISO 8601 first; also epoch seconds/milliseconds and YYYY/MM/DD HH:MM:SS."""
    if re.fullmatch(r'\d{10}(?:\.\d+)?|\d{13}',ts):
        n=float(ts);return datetime.fromtimestamp(n/1000 if n>1e11 else n,timezone.utc)
    try:return datetime.fromisoformat(ts.replace('Z','+00:00'))
    except ValueError:return datetime.strptime(ts,'%Y/%m/%d %H:%M:%S')
def parse_files(files,case_insensitive=False):
    if not files or len(files)>20:raise ValueError('Upload 1 to 20 CSV/JSON files.')
    if sum(len(f['content'].encode('utf-8')) for f in files)>20*1024*1024:raise ValueError('Combined UTF-8 text limit is 20 MB.')
    logs=[];sources=[];warnings=[];skipped=0;count=0
    for index,f in enumerate(files,1):
        name=f['filename'];content=f['content'];sid=f'S{index}'
        if not content.strip():raise ValueError(f'{name}: file is empty.')
        if name.lower().endswith('.csv'):
            try:rows=list(csv.DictReader(io.StringIO(content.lstrip('\ufeff')),strict=True))
            except csv.Error as e:raise ValueError(f'{name}: malformed CSV: {e}') from e
        elif name.lower().endswith('.json'):
            rows=json.loads(content)
            if isinstance(rows,dict):rows=rows.get('events',rows.get('logs'))
            if not isinstance(rows,list):raise ValueError(f'{name}: JSON must be an array or events/logs array.')
        else:raise ValueError(f'{name}: only .csv and .json files are supported.')
        count+=len(rows)
        if count>100000:raise ValueError('Combined record limit is 100,000.')
        valid=0
        for num,row in enumerate(rows,1):
            try:
                if not isinstance(row,dict):raise ValueError('Record must be an object.')
                r={str(k).strip().lower():v for k,v in row.items() if k is not None}
                def get(*keys):return next((str(r[k]).strip() for k in keys if r.get(k) is not None and str(r[k]).strip()),'')
                ts=get('time','timestamp','ts','@timestamp','datetime')
                t=parse_time(ts)
                if t.tzinfo is None:
                    message=f'{sid}: timezone-naive timestamps interpreted as UTC.'
                    if message not in warnings:warnings.append(message)
                    t=t.replace(tzinfo=timezone.utc)
                user=get('user','username','account') or 'unknown';device=get('device','host','hostname','computer') or 'unknown'
                action=get('event','event_type','action','event_id','eventid').lower()
                if action=='1' and get('provider').lower()=='sysmon':action='process'
                event=ALIASES.get(action)
                if event is None:
                    event=guess_event(action) if action else 'other'
                    note=f'{sid}: event names not in the alias table were mapped by keyword (e.g. "{action}" -> {event}); verify the mapping.'
                    if event!='other' and not any(w.startswith(f'{sid}: event names') for w in warnings):warnings.append(note)
                ip=get('ip','src_ip','source_ip') or '-'
                logs.append(dict(id=f'{sid}-E{num}',time=t.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
                    user=user,device=device,user_key=user.casefold() if case_insensitive else user,
                    device_key=device.casefold(),ip=ip,event=event,detail=get('detail','details','message','commandline','command'),
                    approved=get('approved','authorized').lower() in ('true','yes','1'),source_id=sid,source=name,source_record=num,raw=row))
                valid+=1
            except (ValueError,TypeError,OverflowError) as e:
                skipped+=1
                if len(warnings)<100:warnings.append(f'{sid} {name} record {num} skipped: {e}')
        if not valid:raise ValueError(f'{name}: no valid timestamped records. '+ '; '.join(warnings[-3:]))
        sources.append(dict(id=sid,filename=name,source_sha256=hashlib.sha256(content.encode('utf-8')).hexdigest(),accepted=valid,skipped=len(rows)-valid))
    logs.sort(key=lambda r:(r['time'],r['id']))
    other=sum(r['event']=='other' for r in logs)
    if other:warnings.append(f'{other} unrecognized event types retained as other; no direct event rule applies to them.')
    return dict(logs=logs,sources=sources,skipped=skipped,warnings=warnings[:100])
