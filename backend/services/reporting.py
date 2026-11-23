import json

def markdown(x,data):
    parts=[f'# Incident INC-{x["id"]}: {x["severity"]} ({x["score"]}/100)',
        'Analysis: '+data['analysisId'],f'Window UTC: {x["start"]} to {x["end"]}',
        'Users: '+', '.join(x['users']),'Devices: '+', '.join(x['devices']),
        '\n## Source provenance',json.dumps(data['sources'],indent=2),
        '\n## Rule observations',x['summary'],'\n## Scoring',x['scoreExplanation'],
        '\n## Local SLM interpretation',x.get('explanation',{}).get('text','Not generated: this is a rule-only report.'),
        x.get('explanation',{}).get('validation',''),
        *(['Withheld model statements (unsupported or repeated):\n'+'\n'.join(f'- {u["statement"]} [{u["reason"]}]' for u in x['explanation']['unsupported'])] if x.get('explanation',{}).get('unsupported') else []),
        '\n## Conditional investigation / response',*['- '+a for a in x['actions']],
        '\n## Evidence (original fields retained)',*['- '+r['id']+' | '+json.dumps(r,ensure_ascii=True) for r in x['rows']],
        '\n## Measurements',json.dumps(dict(analysis=data.get('metrics'),slm=x.get('explanation',{}).get('metrics')),indent=2),
        '\n## Limitations','Indicators do not prove compromise. Input approval flags are not independently verified. '
        'Hashes describe submitted UTF-8 text, not necessarily original file bytes. '
        'Reports contain sensitive information. No response action is executed automatically.']
    return '\n\n'.join(parts)+'\n'
