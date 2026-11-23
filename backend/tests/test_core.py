import unittest,json,os,tempfile
from pathlib import Path
from unittest.mock import patch
from backend.services.pipeline import analyze
from backend.services.parser import parse_files
from backend.services.detector import config
from backend.services.slm import validate_output,explain,base
from backend.services.reporting import markdown
from backend.database import db
ROOT=Path(__file__).resolve().parents[2]
def row(minute=0,**kwargs):return {**dict(time=f'2026-11-23T12:{minute:02d}:00Z',user='alice',device='WS-01',ip='192.0.2.1',event='login_failed',detail='Synthetic'),**kwargs}
def file(rows,name='x.json'):return dict(filename=name,content=json.dumps(rows))
def run(rows,c=None):return analyze([file(rows)],c)
def valid_model(ids):return dict(observations=[dict(statement='The supplied record shows a privilege change.',evidence_ids=ids)],interpretations=[dict(statement='This may warrant checking authorization.',evidence_ids=ids)])
class CoreTests(unittest.TestCase):
    def test_brute(self):self.assertIn('brute',run([row(i) for i in range(5)])['incidents'][0]['rules'])
    def test_spray(self):self.assertIn('spray',run([row(i,user=f'u{i}') for i in range(6)])['incidents'][0]['rules'])
    def test_distributed(self):self.assertIn('distributed',run([row(i,ip=f'192.0.2.{i+1}') for i in range(6)])['incidents'][0]['rules'])
    def test_threshold(self):self.assertEqual(run([row(i) for i in range(4)])['incidents'],[])
    def test_window(self):self.assertEqual(run([row(i*11) for i in range(5)])['incidents'],[])
    def test_sparse_brute(self):self.assertIn('brute',run([row(i,device='unknown',ip='-') for i in range(5)])['incidents'][0]['rules'])
    def test_success_sequence(self):self.assertIn('success_after',run([*[row(i) for i in range(5)],row(6,event='login_success')])['incidents'][0]['rules'])
    def test_wrong_account_success(self):self.assertNotIn('success_after',{r for x in run([*[row(i) for i in range(5)],row(6,user='bob',event='login_success')])['incidents'] for r in x['rules']})
    def test_approval(self):self.assertEqual(run([row(event='group_change',approved=True)])['incidents'],[])
    def test_unknown_event(self):self.assertEqual(run([row(event='backup_success')])['incidents'],[])
    def test_offhours_failure(self):self.assertIn('offhours_failure',run([row(i,time=f'2026-11-23T23:0{i}:00Z') for i in range(5)])['incidents'][0]['rules'])
    def test_timezone(self):self.assertEqual(run([row(time='2026-11-23T20:00:00Z',event='login_success')])['incidents'],[]);self.assertTrue(run([row(time='2026-11-23T20:00:00Z',event='login_success')],{'tz_offset':5.5})['incidents'])
    def test_casefold_opt_in(self):
        rows=[row(i,user='Alice' if i%2 else 'alice') for i in range(6)]
        self.assertEqual(run(rows)['incidents'],[]);self.assertTrue(run(rows,{'case_insensitive_users':True})['incidents'])
    def test_normalization_preserves_original(self):
        result=parse_files([file([row(user='Alice',device='WORKSTATION')])],True)['logs'][0]
        self.assertEqual(result['user_key'],'alice');self.assertEqual(result['user'],'Alice');self.assertEqual(result['device_key'],'workstation')
    def test_cross_source(self):
        files=[dict(filename=p.name,content=p.read_text()) for p in [ROOT/'sample-data/cross-source/auth.csv',ROOT/'sample-data/cross-source/endpoint.json']]
        data=analyze(files,{'case_insensitive_users':True});self.assertEqual(len(data['incidents']),1)
        self.assertEqual({r['source_id'] for r in data['incidents'][0]['rows']},{'S1','S2'})
        self.assertEqual(len({r['id'] for r in data['incidents'][0]['rows']}),8)
    def test_unknown_entities_separate(self):
        rows=[row(i,event='group_change',user='unknown',device='unknown') for i in range(2)]
        self.assertEqual(len(run(rows)['incidents']),2)
    def test_correlation_span(self):
        rows=[row(i,event='group_change') for i in [0,20,40]]
        self.assertEqual(len(run(rows,{'correlation_minutes':30})['incidents']),2)
    def test_missing_ip_still_correlates(self):
        rows=[row(event='group_change',ip='-'),row(1,event='process_start',ip='-',detail='powershell.exe -enc TEST')]
        self.assertEqual(run(rows)['incidents'][0]['score'],85)
    def test_repeat_not_inflate(self):self.assertEqual(run([row(i,event='group_change') for i in range(3)])['incidents'][0]['score'],35)
    def test_malformed(self):
        for f in [dict(filename='x.csv',content=''),dict(filename='x.json',content='[{bad'),dict(filename='x.txt',content='nonempty'),file([row(time='bad')])]:
            with self.assertRaises(ValueError):analyze([f])
    def test_partial_ids(self):
        p=parse_files([file([row(2),row(time='bad'),row(0)])]);self.assertEqual(p['skipped'],1);self.assertEqual([r['id'] for r in p['logs']],['S1-E3','S1-E1'])
    def test_csv_bom_and_quotes(self):
        f=dict(filename='x.csv',content='\ufefftime,user,device,event,detail\n2026-11-23T12:00:00Z,u,d,process_start,"hello, ""world""\nnext line"\n')
        p=parse_files([f]);self.assertEqual(p['logs'][0]['detail'],'hello, "world"\nnext line')
    def test_config_invalid(self):
        for c in [{'thr':0},{'thr':2.5},{'win':float('nan')},{'case_insensitive_users':'yes'},{'fake':1}]:
            with self.assertRaises(ValueError):config(c)
    def test_json_wrappers(self):
        for key in ['events','logs']:
            self.assertEqual(len(parse_files([dict(filename='x.json',content=json.dumps({key:[row()]}))])['logs']),1)
    def test_sysmon_id_requires_provider(self):
        r=row(event='1',detail='powershell.exe -enc TEST');self.assertEqual(run([r])['incidents'],[])
        r['provider']='sysmon';self.assertTrue(run([r])['incidents'])
    def test_model_reference_checks(self):
        x=run([row(event='group_change')])['incidents'][0]
        out=valid_model(['S1-E1']);self.assertTrue(validate_output(out,x)['claims'])
        for ids in [[],['S1-E99']]:
            out=valid_model(ids)
            with self.assertRaises(ValueError):validate_output(out,x)
    def test_model_unknown_ip(self):
        x=run([row(event='group_change')])['incidents'][0];out=valid_model(['S1-E1']);out['observations'][0]['statement']='Source was 203.0.113.99'
        result=validate_output(out,x)  # the bad statement is withheld, the supported interpretation survives
        self.assertEqual(result['structured']['observations'],[]);self.assertIn('IP not in cited rows',result['unsupported'][0]['reason'])
        out['interpretations'][0]['statement']='This may involve 203.0.113.99.'
        with self.assertRaises(ValueError):validate_output(out,x)
    def test_model_malformed_and_length(self):
        x=run([row(event='group_change')])['incidents'][0]
        for response in [{'response':'oops'},{'response':'{}'},{'response':'{}','done_reason':'length'}]:
            with patch('backend.services.slm.request',return_value=response):
                with self.assertRaises(ValueError):explain(x)
    def test_mocked_structured_model(self):
        x=run([row(event='group_change')])['incidents'][0]
        with patch('backend.services.slm.request',return_value=dict(response=json.dumps(valid_model(['S1-E1'])),eval_count=100)) as req:
            result=explain(x);self.assertIn('[S1-E1]',result['text']);self.assertEqual(result['metrics']['eval_tokens'],100);self.assertIn('format',req.call_args.args[1])
    def test_loopback_only(self):
        for url in ['http://10.0.0.1:11434','https://example.com','http://localhost:11434/path']:
            with patch.dict(os.environ,OLLAMA_URL=url):
                with self.assertRaises(ValueError):base()
    def test_persistence_reporting(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,TRIAGE_DB=str(Path(temp)/'x.db')):
            p=db.save(run([row(event='group_change')]));key=p['analysisId'];x=p['incidents'][0]
            db.save_explanation(key,x['id'],dict(text='Example [S1-E1]',validation='IDs only'))
            p=db.get(key);text=markdown(p['incidents'][0],p)
            self.assertIn('source_record',text);self.assertIn('source_sha256',text);self.assertIn('Example [S1-E1]',text);self.assertEqual(len(db.history()),1)
    def test_samples(self):
        for name,count in [('auth_logs.csv',3),('endpoint_logs.json',1)]:
            path=ROOT/'sample-data'/name;p=analyze([dict(filename=name,content=path.read_text())]);self.assertEqual(len(p['incidents']),count)
if __name__=='__main__':unittest.main()
