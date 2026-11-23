import time,platform,os
from .parser import parse_files
from .detector import config,detect
from .correlation import correlate

def peak_rss():
    try:
        import resource
        value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(value/(1024*1024 if platform.system()=='Darwin' else 1024),2)
    except ImportError:return None

def analyze(files,values=None):
    t=time.perf_counter();c=config(values)
    p=parse_files(files,c['case_insensitive_users']);parse_ms=(time.perf_counter()-t)*1000
    findings=detect(p['logs'],c);incidents=correlate(findings,p['logs'],c['correlation_minutes'])
    return dict(events=len(p['logs']),skipped=p['skipped'],warnings=p['warnings'],sources=p['sources'],config=c,incidents=incidents,
        metrics=dict(parse_ms=round(parse_ms,2),analysis_ms=round((time.perf_counter()-t)*1000,2),
            backend_process_peak_rss_mb=peak_rss(),memory_note='Lifetime process high-water RSS, not per-request allocation; excludes Ollama/browser; unavailable on native Windows.',
            python=platform.python_version(),platform=platform.platform()))
