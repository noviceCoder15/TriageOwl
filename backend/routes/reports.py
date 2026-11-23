from fastapi import APIRouter,HTTPException
from fastapi.responses import Response
from .incidents import resolve
from ..services.reporting import markdown
router=APIRouter()
@router.get('/reports/{key}/{ident}')
def report(key:str,ident:int,format:str='md'):
    data,x=resolve(key,ident)
    if format=='json':return dict(analysisId=key,sources=data['sources'],metrics=data['metrics'],incident=x)
    if format!='md':raise HTTPException(400,'Use format=md or json.')
    return Response(markdown(x,data),media_type='text/markdown',headers={'Content-Disposition':f'attachment; filename="INC-{ident}.md"'})
