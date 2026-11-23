import json,unittest
from pathlib import Path
from unittest.mock import patch
from backend.services import grounding,samples,slm
from backend.services.pipeline import analyze
ROOT=Path(__file__).resolve().parents[2]
_cache={}
def incident(name,number=1):
    if name not in _cache:
        cfg=next(s for s in samples.listing() if s['id']==name)['config'];_cache[name]=analyze(samples.load(name),cfg)['incidents']
    return _cache[name][number-1]
F5=['S1-E17','S1-E18','S1-E19','S1-E20','S1-E21']

class Grounding(unittest.TestCase):
    def test_labelled_cases_match(self):
        """Every labelled case behaves as labelled; documented known gaps are still accepted (update the docs if one starts to be caught)."""
        for case in json.loads((ROOT/'evaluation/slm_grounding_cases.json').read_text())['cases']:
            got='reject' if grounding.problems(case['statement'],case['section'],case['evidence_ids'],incident(case['sample'],case['incident'])) else 'accept'
            expected='accept' if case.get('known_gap') and case['expect']=='reject' else case['expect']
            self.assertEqual(got,expected,case['statement'])
    def test_prompt_is_grounded_and_lean(self):
        x=incident('auth');prompt=slm.build_prompt(x)
        self.assertIn('FACTS',prompt);self.assertIn('5 login failed',prompt)
        self.assertNotIn('source_record',prompt);self.assertNotIn('"approved": false, "id"',prompt)
        self.assertEqual(prompt.count('"approved"'),1)  # only the privilege-change row carries the flag
        self.assertNotIn('Return JSON matching this schema',prompt)  # schema travels in `format`, not duplicated in the prompt
    def test_repeats_are_dropped(self):
        x=incident('auth');out=dict(observations=[
            dict(statement='rahul.m had five failed logins from 185.220.101.4.',evidence_ids=F5),
            dict(statement='From 185.220.101.4, rahul.m had five failed logins.',evidence_ids=F5),
            dict(statement='5 failed logins against one account within 10 minutes',evidence_ids=F5)],
            interpretations=[dict(statement='Repeated failures from one IP may indicate password guessing.',evidence_ids=F5)])
        accepted,rejected=grounding.filter_statements(out,x)
        self.assertEqual(len(accepted['observations']),1);self.assertEqual(len(rejected),2)
        self.assertTrue(all('repeat' in r['reason'] for r in rejected))
    def test_limitations_are_deterministic_and_relevant(self):
        lim=grounding.limitations(incident('endpoint'))
        self.assertTrue(any('parent process' in t for t in lim));self.assertTrue(any('approved' in t for t in lim))
        self.assertFalse(any('MFA' in t for t in lim))  # no failed logins in this incident
        self.assertEqual(len(lim),len(set(lim)))
    def test_model_cannot_supply_limitations_or_actions(self):
        x=incident('endpoint');ids=x['evidenceIds'][:1]
        out=dict(observations=[dict(statement='guest was added to local Administrators on WS-11.',evidence_ids=ids)],
                 interpretations=[dict(statement='This may warrant review.',evidence_ids=ids)],limitations=['Invented limit'],investigation_actions=['Delete the account'])
        r=slm.validate_output(out,x);self.assertNotIn('Invented limit',r['text']);self.assertNotIn('Delete the account',r['text']);self.assertNotIn('investigation_actions',r['structured'])
    def test_partial_output_is_kept_and_reported(self):
        x=incident('endpoint');ids=x['evidenceIds']
        out=dict(observations=[dict(statement='guest was added to local Administrators on WS-11.',evidence_ids=ids[:1]),dict(statement='guest was added to Administrators on WS-99.',evidence_ids=ids[:1])],
                 interpretations=[dict(statement='This is certainly a compromise.',evidence_ids=ids[:1])])
        r=slm.validate_output(out,x);self.assertEqual(len(r['structured']['observations']),1);self.assertEqual(len(r['unsupported']),2);self.assertIn('2 model statement(s) were withheld',r['validation'])
    def test_retry_feedback_names_the_problem(self):
        x=incident('endpoint');ids=x['evidenceIds'][:1]
        bad=dict(observations=[dict(statement='guest logged in from 203.0.113.9.',evidence_ids=ids)],interpretations=[dict(statement='Certainly compromised.',evidence_ids=ids)])
        good=dict(observations=[dict(statement='guest was added to local Administrators on WS-11.',evidence_ids=ids)],interpretations=[dict(statement='This may warrant review.',evidence_ids=ids)])
        with patch('backend.services.slm.request',side_effect=[dict(response=json.dumps(bad)),dict(response=json.dumps(good))]) as req:
            r=slm.explain(x)
        self.assertEqual(r['attempts'],2);self.assertIn('203.0.113.9',req.call_args_list[1].args[1]['prompt'])
    def test_no_retry_when_some_statements_survive(self):
        x=incident('endpoint');ids=x['evidenceIds'][:1]
        out=dict(observations=[dict(statement='guest was added to Administrators on WS-99.',evidence_ids=ids)],interpretations=[dict(statement='This may warrant review.',evidence_ids=ids)])
        with patch('backend.services.slm.request',return_value=dict(response=json.dumps(out))) as req:
            r=slm.explain(x)
        self.assertEqual(req.call_count,1);self.assertEqual(r['attempts'],1);self.assertEqual(len(r['unsupported']),1)
if __name__=='__main__':unittest.main()
