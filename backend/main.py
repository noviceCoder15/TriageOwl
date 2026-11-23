from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse,FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
app=FastAPI(title='Offline Incident Triage v3',version='3.0.0',docs_url=None,redoc_url=None)
@app.middleware('http')
async def guard(request:Request,call_next):
    host=request.url.hostname
    if host not in ('localhost','127.0.0.1','::1'):return JSONResponse({'detail':'Local hosts only.'},status_code=403)
    origin=request.headers.get('origin')
    if request.method not in ('GET','HEAD','OPTIONS') and origin not in (None,'http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:5000','http://localhost:5000'):
        return JSONResponse({'detail':'Cross-origin writes rejected.'},status_code=403)
    # Count actual streamed request bytes, including requests without Content-Length.
    if request.method=='POST':
        body=bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body)>24*1024*1024:return JSONResponse({'detail':'Request exceeds 24 MB; decoded input limit is 20 MB.'},status_code=413)
        request._body=bytes(body)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY'
    return response
from .routes import logs,incidents,reports
for router in (logs.router,incidents.router,reports.router):app.include_router(router,prefix='/api')
@app.get('/api/health')
def health():return {'status':'ok','version':'3.0.0','local_only':True}
dist=Path(__file__).resolve().parents[1]/'frontend'/'dist'
if dist.is_dir():
    app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
    @app.get('/')
    def ui():return FileResponse(dist/'index.html')
