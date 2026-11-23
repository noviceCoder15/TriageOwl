from pathlib import Path
from fastapi import APIRouter,HTTPException
from pydantic import BaseModel,Field
from ..services.pipeline import analyze
from ..database import db
from ..services import samples
router=APIRouter()
class InputFile(BaseModel):
    filename:str=Field(min_length=1,max_length=255)
    content:str=Field(max_length=20*1024*1024)
class AnalyzeRequest(BaseModel):
    files:list[InputFile]=Field(default_factory=list,max_length=20)
    config:dict=Field(default_factory=dict)
    sample:bool=False
    sampleSet:str=Field(default='',max_length=32)
    filename:str=''
    content:str=''
@router.post('/analyze')
def run(body:AnalyzeRequest):
    try:
        if body.sampleSet:files=samples.load(body.sampleSet)
        elif body.sample:
            path=Path(__file__).resolve().parents[2]/'sample-data'/'auth_logs.csv'
            files=[dict(filename=path.name,content=path.read_text())]
        elif body.files:files=[f.model_dump() for f in body.files]
        else:files=[dict(filename=body.filename,content=body.content)]
        return db.save(analyze(files,body.config))
    except (ValueError,TypeError,OverflowError) as e:raise HTTPException(400,str(e))

@router.get('/samples')
def sample_sets():return samples.listing()
