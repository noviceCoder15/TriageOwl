from datetime import datetime,timedelta
from .detector import ACTIONS

def correlate(findings,logs,minutes=60):
    def ts(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
    clusters=[];user_index={};device_index={}
    for f in findings:
        linked=set()
        for user in f['users']:linked.update(user_index.get(user,set()))
        for device in f['devices']:linked.update(device_index.get(device,set()))
        candidates=[clusters[i] for i in sorted(linked) if ts(max(clusters[i]['end'],f['end']))-ts(min(clusters[i]['start'],f['time']))<=timedelta(minutes=minutes)]
        if candidates:
            c=max(candidates,key=lambda c:(bool(set(f['users'])&c['users']),c['end']))
            c['findings'].append(f);c['users'].update(f['users']);c['devices'].update(f['devices']);c['end']=max(c['end'],f['end'])
        else:
            c=dict(findings=[f],users=set(f['users']),devices=set(f['devices']),start=f['time'],end=f['end'],index=len(clusters));clusters.append(c)
        for user in f['users']:user_index.setdefault(user,set()).add(c['index'])
        for device in f['devices']:device_index.setdefault(device,set()).add(c['index'])
    lookup={r['id']:r for r in logs};incidents=[]
    for c in clusters:
        rules=sorted({f['rule'] for f in c['findings']});base=sum(max(f['points'] for f in c['findings'] if f['rule']==rule) for rule in rules)
        bonus=10*(len(rules)-1);score=min(100,base+bonus)
        ids=list(dict.fromkeys(i for f in c['findings'] for i in f['evidence']));rows=[lookup[i] for i in ids];rows.sort(key=lambda r:(r['time'],r['id']))
        incidents.append(dict(id=0,findings=c['findings'],rules=rules,start=c['start'],end=c['end'],score=score,
            severity='Critical' if score>=80 else 'High' if score>=50 else 'Medium' if score>=30 else 'Low',
            users=sorted({r['user'] for r in rows}),devices=sorted({r['device'] for r in rows}),evidenceIds=ids,rows=rows,
            summary=' '.join(f'{f["title"]} [{", ".join(f["evidence"])}].' for f in c['findings'])+' Indicators require investigation; compromise is not established.',
            actions=list(dict.fromkeys(a for rule in rules for a in ACTIONS[rule])),
            scoreExplanation=f'Unique-rule points {base} + multi-rule bonus {bonus}, capped at 100. Critical >=80, High >=50, Medium >=30; otherwise Low. This is a policy priority score, not probability.'))
    incidents.sort(key=lambda x:(-x['score'],x['start']))
    for i,x in enumerate(incidents,1):x['id']=i
    return incidents
