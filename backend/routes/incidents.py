from fastapi import APIRouter,HTTPException
from pydantic import BaseModel,Field
from ..database import db
from ..services import slm
router=APIRouter()
def resolve(key,ident):
    data=db.get(key)
    if data is None:raise HTTPException(404,'Analysis not found.')
    x=next((x for x in data['incidents'] if x['id']==ident),None)
    if x is None:raise HTTPException(404,'Incident not found.')
    return data,x
@router.get('/analyses')
def history():return db.history()
@router.get('/analyses/{key}')
def analysis(key:str):
    data=db.get(key)
    if data is None:raise HTTPException(404,'Analysis not found.')
    return data
@router.get('/slm/status')
def status():return slm.status()
class ExplainRequest(BaseModel):
    analysisId:str=Field(min_length=1,max_length=64)
    incidentId:int=Field(ge=1)
@router.post('/explain')
def explain(body:ExplainRequest):
    _,x=resolve(body.analysisId,body.incidentId)
    try:
        result=slm.explain(x);db.save_explanation(body.analysisId,body.incidentId,result);return result
    except Exception as e:raise HTTPException(503,'Local SLM unavailable or output rejected: '+str(e))
