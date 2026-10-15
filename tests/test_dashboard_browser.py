#!/usr/bin/env python3
"""Offline DOM/visual tests. Injects the shipped UI and a conspicuously synthetic fixture.

Requires Playwright and Chromium as TEST tools only. Does not validate Rust HTTP serving,
CSP enforcement, real deployment readback, or production-camera behavior.
Run: python tests/test_dashboard_browser.py --chromium /usr/bin/chromium --artifacts /tmp/fss-ui
"""
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'crates/fss-cli/src/bin/fss-dashboard/web'

def run(chromium, artifacts):
    html = (WEB / 'index.html').read_text()
    html = html.replace('<script type="module" src="/app.js"></script>', '')
    html = html.replace('<link rel="icon" href="/favicon.svg" type="image/svg+xml">', '')
    html = html.replace('<link rel="stylesheet" href="/style.css">', '')
    model = (WEB / 'model.js').read_text().replace('export ', '')
    app = '\n'.join((WEB / 'app.js').read_text().splitlines()[1:])
    fixture = json.loads((WEB / 'demo.json').read_text())
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chromium, headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width':1512, 'height':1080})
        errors=[]
        page.on('pageerror',lambda e: errors.append(str(e)))
        page.set_content(html)
        page.add_style_tag(content=(WEB / 'style.css').read_text())
        page.evaluate('(fixture) => { window.__fixture=fixture; window.__calls=0; window.__fail=false; window.fetch=async()=>{ window.__calls++; return new Response(window.__fail ? "{}" : JSON.stringify(window.__fixture), {status:window.__fail ? 503:200,headers:{"Content-Type":"application/json"}}); }; }',fixture)
        page.add_script_tag(content='{\n'+model+'\n'+app+'\n}')
        page.wait_for_selector('#workspace:not([hidden])')
        assert page.locator('#demo-banner').is_visible()
        assert page.locator('#recent-events .event-row').count()==6
        assert page.locator('.metric-value').all_text_contents()==['9','4','2','1']
        assert '1789398468000000123' in page.locator('#inspector').inner_text()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        artifacts.mkdir(parents=True,exist_ok=True)
        page.screenshot(path=str(artifacts/'overview-dark.png'),full_page=True)
        page.locator('.nav-link[data-view=events]').click()
        page.locator('#event-search').fill('tamper')
        assert page.locator('#all-events .event-row').count()==1
        page.locator('#all-events .event-row').click()
        assert 'Sensor tamper' in page.locator('#inspector').inner_text()
        page.locator('#clear-filters').click()
        page.locator('#state-filter').select_option('witnessed')
        assert page.locator('#all-events .event-row').count()==3
        page.locator('#clear-filters').click()
        page.locator('.nav-link[data-view=graph]').click()
        assert page.locator('#graph g[role=button]').count()==3
        old=page.locator('#graph svg').get_attribute('viewBox')
        page.locator('#zoom-in').click()
        assert old != page.locator('#graph svg').get_attribute('viewBox')
        page.locator('#zoom-fit').click()
        assert old == page.locator('#graph svg').get_attribute('viewBox')
        page.locator('#graph g[role=button]').first.click()
        assert 'SELECTED EXACT REFERENCE' in page.locator('#inspector').inner_text()
        page.screenshot(path=str(artifacts/'graph-dark.png'),full_page=True)
        page.locator('#relation-filter').select_option('sensor_tamper')
        assert page.locator('#graph g[role=button]').count()==1
        page.keyboard.press('Control+k')
        assert page.locator('#command-dialog').is_visible()
        page.locator('#command-search').fill('Operations')
        page.keyboard.press('Enter')
        assert page.locator('#operations-view').is_visible()
        assert not page.locator('#inspector').is_visible()
        page.locator('#theme-toggle').click()
        assert page.locator('html').get_attribute('data-theme')=='light'
        page.screenshot(path=str(artifacts/'operations-light.png'),full_page=True)
        page.locator('.nav-link[data-view=overview]').click()
        page.screenshot(path=str(artifacts/'overview-light.png'),full_page=True)
        page.set_viewport_size({'width':390,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(artifacts/'overview-mobile.png'),full_page=True)
        page.locator('.nav-link[data-view=graph]').click()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(artifacts/'graph-mobile.png'),full_page=True)
        page.set_viewport_size({'width':1512,'height':1080})
        page.locator('#pause-toggle').click()
        assert page.locator('#paused-banner').is_visible()
        assert page.locator('#pause-toggle').get_attribute('aria-pressed')=='true'
        page.evaluate('window.__fail=true')
        page.locator('#refresh').click()
        page.wait_for_selector('#error-panel:not([hidden])')
        assert not page.locator('#workspace').is_visible()
        assert page.locator('#recent-events .event-row').count()==0
        assert page.locator('#graph g').count()==0
        assert page.locator('#graph-event option').count()==0
        page.screenshot(path=str(artifacts/'unavailable.png'),full_page=True)
        page.evaluate('window.__fail=false')
        page.locator('#retry').click()
        page.wait_for_selector('#workspace:not([hidden])')
        # Untrusted metadata is literal text in every render surface; never HTML.
        page.evaluate('''() => { const r=JSON.parse(window.__fixture.events[0].recordJson); r.uncertaintyReason='<img src=x onerror="window.__xss=true">'; r.zoneIds=['<svg onload=alert(1)>']; window.__fixture.events[0].recordJson=JSON.stringify(r); }''')
        page.locator('#refresh').click()
        page.wait_for_function("document.getElementById('zone-filter').textContent.includes('<svg')")
        assert page.locator('#workspace img').count()==0
        assert page.evaluate('window.__xss === undefined')
        assert not errors,errors
        browser.close()
    print('PASS: offline Chromium DOM, exact timestamps, filters, graph, keyboard navigation, themes, mobile layout, failed-read clearing, recovery and text-injection checks.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium',default='/usr/bin/chromium')
    parser.add_argument('--artifacts',type=Path,default=Path('/tmp/fss-dashboard-ui'))
    args=parser.parse_args()
    run(args.chromium,args.artifacts)
