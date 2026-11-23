import json,unittest
from unittest.mock import patch
from backend.services.parser import parse_files,guess_event
from backend.services.pipeline import analyze
from backend.services import samples,slm

def csv_text(rows):return 'time,user,device,ip,event,detail\n'+'\n'.join(rows)+'\n'

class V4(unittest.TestCase):
    def test_keyword_event_mapping(self):
        for text,event in [('Failed password','login_failed'),('failed_logon','login_failed'),('Accepted publickey','login_success'),
                           ('User Logout','logoff'),('added_to_admin_group','priv_change'),('process_failed','process'),('heartbeat','other')]:
            self.assertEqual(guess_event(text.lower()),event,text)
    def test_epoch_and_slash_timestamps(self):
        p=parse_files([dict(filename='a.csv',content=csv_text(['1763640000,u,d,1.1.1.1,login_success,x','1763640000123,u,d,1.1.1.1,login_success,x','2026/11/20 09:00:00,u,d,1.1.1.1,login_success,x']))])
        self.assertEqual(len(p['logs']),3);self.assertEqual(p['skipped'],0)
    def test_bad_time_still_skipped(self):
        p=parse_files([dict(filename='a.csv',content=csv_text(['soon,u,d,1.1.1.1,login_success,x','2026-11-20T09:00:00Z,u,d,1.1.1.1,login_success,x']))])
        self.assertEqual(p['skipped'],1)
    def test_unseen_log_vocabulary_detects_brute_force(self):
        rows=[f'{1763640000+i},bob,PC1,1.2.3.4,Failed password,x' for i in range(5)]+['1763640400,bob,PC1,1.2.3.4,Accepted password,ok']
        r=analyze([dict(filename='a.csv',content=csv_text(rows))])
        self.assertEqual(r['incidents'][0]['rules'],['brute','success_after']);self.assertTrue(any('mapped by keyword' in w for w in r['warnings']))
    def test_all_sample_sets_match_acceptance(self):
        expected={'auth':[(100,),(35,),(15,)],'endpoint':[(85,)],'spray':[(40,)],'rotating':[(75,)],'cross':[(100,)]}
        for name,scores in expected.items():
            cfg=[s for s in samples.listing() if s['id']==name][0]['config']
            r=analyze(samples.load(name),cfg);self.assertEqual([(i['score'],) for i in r['incidents']],scores,name)
    def test_unknown_sample_rejected(self):
        with self.assertRaises(ValueError):samples.load('../etc/passwd')
    def test_model_retry_then_success(self):
        x=analyze(samples.load('endpoint'))['incidents'][0];ids=x['evidenceIds']
        good=dict(observations=[dict(statement='guest was added to local Administrators on WS-11.',evidence_ids=ids[:1])],interpretations=[dict(statement='This may indicate escalation.',evidence_ids=ids[:1])])
        with patch('backend.services.slm.request',side_effect=[dict(response='oops'),dict(response=json.dumps(good))]) as req:
            result=slm.explain(x)
        self.assertEqual(req.call_count,2);self.assertIn('[%s]'%ids[0],result['text'])
        self.assertEqual(result['attempts'],2);self.assertEqual(req.call_args_list[1].args[1]['options']['temperature'],0)
        self.assertIn('previous answer was rejected',req.call_args_list[1].args[1]['prompt'])
    def test_model_fails_after_two_attempts(self):
        x=analyze(samples.load('endpoint'))['incidents'][0]
        with patch('backend.services.slm.request',return_value=dict(response='oops')) as req:
            with self.assertRaises(ValueError):slm.explain(x)
        self.assertEqual(req.call_count,2)

if __name__=='__main__':unittest.main()
