import sqlite3,json,os,uuid
from pathlib import Path
DEFAULT=Path(__file__).resolve().parent/'triage-v3.sqlite3'
def connect():
    con=sqlite3.connect(os.environ.get('TRIAGE_DB',str(DEFAULT)),timeout=15)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY,created TEXT DEFAULT CURRENT_TIMESTAMP,payload TEXT NOT NULL)')
    return con
def save(payload):
    key=uuid.uuid4().hex;payload['analysisId']=key
    with connect() as con:con.execute('INSERT INTO analyses(id,payload) VALUES (?,?)',(key,json.dumps(payload)))
    return payload
def get(key):
    with connect() as con:row=con.execute('SELECT payload FROM analyses WHERE id=?',(key,)).fetchone()
    return json.loads(row[0]) if row else None
def history():
    with connect() as con:rows=con.execute('SELECT id,created,payload FROM analyses ORDER BY created DESC,rowid DESC LIMIT 50').fetchall()
    return [dict(analysisId=k,created=t,events=json.loads(p)['events'],incidents=len(json.loads(p)['incidents'])) for k,t,p in rows]
def save_explanation(key,incident_id,result):
    with connect() as con:
        con.execute('BEGIN IMMEDIATE')
        row=con.execute('SELECT payload FROM analyses WHERE id=?',(key,)).fetchone()
        if not row:raise ValueError('Analysis does not exist.')
        p=json.loads(row[0]);found=False
        for x in p['incidents']:
            if x['id']==incident_id:x['explanation']=result;found=True
        if not found:raise ValueError('Incident does not exist.')
        con.execute('UPDATE analyses SET payload=? WHERE id=?',(json.dumps(p),key))
