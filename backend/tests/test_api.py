import unittest,tempfile,os,json
from pathlib import Path
from unittest.mock import patch
try:
    from fastapi.testclient import TestClient
    from backend.main import app
    READY=True
except ImportError:READY=False
@unittest.skipUnless(READY,'Install backend/requirements-test.txt to run FastAPI HTTP tests.')
class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,TRIAGE_DB=str(Path(self.temp.name)/'test.db'));self.env.start()
        self.client=TestClient(app,base_url='http://127.0.0.1:5000')
    def tearDown(self):self.client.close();self.env.stop();self.temp.cleanup()
    def sample(self):
        r=self.client.post('/api/analyze',json={'sample':True});self.assertEqual(r.status_code,200);return r.json()
    def test_health(self):self.assertEqual(self.client.get('/api/health').status_code,200)
    def test_analyze_history_report(self):
        p=self.sample();key=p['analysisId'];ident=p['incidents'][0]['id']
        self.assertEqual(self.client.get('/api/analyses/'+key).json()['events'],30)
        self.assertEqual(len(self.client.get('/api/analyses').json()),1)
        self.assertEqual(self.client.get(f'/api/reports/{key}/{ident}').status_code,200)
        self.assertEqual(self.client.get(f'/api/reports/{key}/{ident}?format=json').json()['incident']['id'],ident)
    def test_invalid_input(self):
        for body in [{'filename':'x.csv','content':''},{'filename':'x.txt','content':'text'},{'filename':'x.json','content':'{bad'}]:self.assertEqual(self.client.post('/api/analyze',json=body).status_code,400)
    def test_cross_origin_write(self):self.assertEqual(self.client.post('/api/analyze',json={'sample':True},headers={'Origin':'https://example.invalid'}).status_code,403)
    def test_bad_host(self):self.assertEqual(self.client.get('/api/health',headers={'Host':'evil.invalid'}).status_code,403)
    def test_missing(self):self.assertEqual(self.client.get('/api/analyses/missing').status_code,404)
    def test_model_down(self):
        p=self.sample()
        with patch('backend.routes.incidents.slm.explain',side_effect=ConnectionError('Stopped for test')):
            r=self.client.post('/api/explain',json={'analysisId':p['analysisId'],'incidentId':1});self.assertEqual(r.status_code,503)
        self.assertTrue(self.client.get('/api/analyses/'+p['analysisId']).json()['incidents'])
    def test_mocked_model_persistence(self):
        p=self.sample();result=dict(text='Reviewed [S1-E17]',model='mock',unsupported=[],validation='Mock test')
        with patch('backend.routes.incidents.slm.explain',return_value=result):
            r=self.client.post('/api/explain',json={'analysisId':p['analysisId'],'incidentId':1});self.assertEqual(r.status_code,200)
        self.assertEqual(self.client.get('/api/analyses/'+p['analysisId']).json()['incidents'][0]['explanation'],result)
