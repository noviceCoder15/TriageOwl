import argparse,json
from pathlib import Path
from playwright.sync_api import sync_playwright
ap=argparse.ArgumentParser(description='Browser smoke test against built, single-server UI. Does not invoke live inference.')
ap.add_argument('--url',default='http://127.0.0.1:5000');ap.add_argument('--screenshot',default='browser-smoke.png');args=ap.parse_args()
if args.url not in ('http://127.0.0.1:5000','http://localhost:5000'):ap.error('Use the built single-server deployment on port 5000.')
root=Path(__file__).resolve().parents[1]
with sync_playwright() as p:
    browser=p.chromium.launch();page=browser.new_page();errors=[]
    page.on('pageerror',lambda err:errors.append(str(err)))
    page.goto(args.url)
    page.get_by_role('button',name='Load auth sample',exact=True).click()
    page.get_by_text('30 events / 0 skipped / 3 incidents',exact=True).wait_for(timeout=30000)
    page.locator('input[type=file]').set_input_files([str(root/'sample-data/password_spray.json')])
    page.get_by_text('6 events / 0 skipped / 1 incidents',exact=True).wait_for(timeout=30000)
    page.get_by_role('heading',name='Rule-based observations',exact=True).wait_for()
    with page.expect_download() as event:page.get_by_role('button',name='Download JSON',exact=True).click()
    download=event.value;path=download.path();data=json.loads(Path(path).read_text())
    assert 'spray' in data['incident']['rules']
    page.screenshot(path=args.screenshot,full_page=True)
    browser.close()
    if errors:raise RuntimeError('Browser errors: '+repr(errors))
print('Browser upload and JSON download smoke checks passed. Live-model and fully offline browser tests are separate.')
