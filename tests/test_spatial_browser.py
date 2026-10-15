"""Browser integration for shipped modules under the native server's CSP, using explicit fixtures.
No Rust server/deployment/camera qualification is implied by the routed responses.
"""
import argparse, hashlib, json
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
WEB=ROOT/'crates/fss-cli/src/bin/fss-dashboard/web'
CSP="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
def digest(label):return 'sha256:'+hashlib.sha256(label.encode()).hexdigest()
def fixture():
    states=['indeterminate','corroborated','indeterminate','resolved','witnessed','hypothesized','rejected','witnessed','witnessed']
    kinds=['unknown_presence','perimeter_breach','sensor_tamper','benign_routine','unknown_presence','covert_approach','benign_routine','unknown_presence','perimeter_breach']
    events=[]
    for i,(state,kind) in enumerate(zip(states,kinds),1):
        record=dict(schema='fss.event_hypothesis.v1',eventId=f'event:demo:{i:03}',state=state,kind=kind,revision=1,supersedes=None,timeInterval={'earliestNs':str(1789398468000000123-i*1000000000),'latestNs':str(1789398482000000789-i*1000000000)},zoneIds=['zone:north-gate' if i%2 else 'zone:service-entry'],trackIds=[],modelReceipts=[],evidence=[],probability={'lower':.2,'upper':.8,'calibrationGeneration':None},uncertaintyReason='Synthetic fixture; no event or camera qualification.')
        events.append(dict(recordJson=json.dumps(record),revisionDigest=digest(f'revision {i}'),eventRoot=digest(f'event {i}'),sequence=str(42-i),revisions=1))
    meta=dict(format='fss.operator_dashboard.v1',demo=True,site='site:observatory-demo',ledgerRoot=digest('demo ledger'),sequence='41',latestEvidenceNs='1789398500000000000',anchorJson='{}',events=events,imports=[],counts=dict(events=9,imports=0,openObligations=2,indeterminateOperations=1,coverageRecords=0,sourceCoverageRecords=0,deletions=0),integrity=dict(doctor='SyntheticFixture',ledgerTailUncommitted=False,effectTailUncommitted=False,effectJournalPresent=True,filesRead='0',bytesRead='0'),families=[],operationStates=[],obligationStates=[],scope='Synthetic browser fixture only')
    return dict(format='fss.spatial_dashboard.v1',metadata=meta,scene=None,sceneDigest=digest('demo scene'),framesAuthorized=False)

def run(artifacts, offline=False):
 with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--use-gl=angle','--use-angle=swiftshader','--enable-unsafe-swiftshader'])
    page=browser.new_page(viewport={'width':1600,'height':1100},device_scale_factor=1)
    errors=[];external=[];payload=fixture();fail=[False]
    page.on('pageerror',lambda e:errors.append(str(e)))
    def route(r):
        path=r.request.url.split('127.0.0.1:7744',1)[-1]
        if path=='/api/spatial':
            assert r.request.headers.get('x-fss-read')=='1'
            return r.fulfill(status=503 if fail[0] else 200,content_type='application/json',body=json.dumps({} if fail[0] else payload),headers={'Content-Security-Policy':CSP,'Cache-Control':'no-store'})
        files={'/':'spatial.html','/spatial':'spatial.html','/sensors':'spatial.html'}
        name=files.get(path,path.removeprefix('/'))
        f=WEB/name
        if f.is_file():
            mime='text/javascript' if f.suffix=='.js' else 'text/css' if f.suffix=='.css' else 'text/html'
            return r.fulfill(content_type=mime,body=f.read_bytes(),headers={'Content-Security-Policy':CSP,'Cache-Control':'no-store'})
        return r.fulfill(status=404,body='Not found')
    page.route('http://127.0.0.1:7744/**',route)
    page.on('request',lambda r:external.append(r.url) if not r.url.startswith('http://127.0.0.1:7744/') else None)
    if offline:
        import re
        html=(WEB/'spatial.html').read_text()
        html=re.sub(r'<script[^>]*>.*?</script>','',html)
        html=re.sub(r'<link[^>]+>','',html)
        page.set_content(html)
        page.add_style_tag(content=(WEB/'spatial.css').read_text())
        page.evaluate("p=>{window.__payload=p;window.__fail=false;window.fetch=async()=>new Response(JSON.stringify(window.__fail?{}:window.__payload),{status:window.__fail?503:200,headers:{'Content-Type':'application/json'}})}",payload)
        def code(file):return (WEB/file).read_text().replace('export ','')
        native=code('model.js')
        spatial=code('spatial-model.js')
        renderer='\n'.join(code('view3d.js').splitlines()[1:])
        demo='\n'.join(code('demo-scene.js').splitlines()[2:])
        app='\n'.join(code('spatial.js').splitlines()[4:])
        assembly='const Native=(()=>{'+native+';return {normalizeSnapshot,human,shortDigest};})();'
        names='add,sub,mul,dot,cross,unit,center,lookAt,project,transform,frustum,cameraMatrix,sceneBounds,validateScene,bindThreats,freshness,MAX_SCENE_BYTES'
        assembly+='const Spatial=(()=>{'+spatial+';return {'+names+'};})();'
        assembly+='const Render=(()=>{const {'+names+'}=Spatial;'+renderer+';return {PropertyView};})();'
        assembly+='const Demo=(()=>{const {lookAt}=Spatial;'+demo+';return {makeDemoScene};})();'
        assembly+='(()=>{const {normalizeSnapshot,human,shortDigest}=Native; const {validateScene,bindThreats,center,freshness,MAX_SCENE_BYTES}=Spatial;const {PropertyView}=Render;const {makeDemoScene}=Demo;'+app+'})();'
        page.add_script_tag(content='{'+assembly+'}')
    else:
        page.goto('http://127.0.0.1:7744/')
    page.wait_for_selector('#data-workspace:not([hidden])')
    page.wait_for_function("document.querySelectorAll('#world .world-label').length>5")
    assert page.locator('#threat-list .threat-card').count()==7
    assert page.locator('#camera-dock .camera-tile').count()==4
    assert page.locator('#demo-banner').is_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.wait_for_timeout(350)
    artifacts.mkdir(parents=True,exist_ok=True)
    page.screenshot(path=str(artifacts/'property-3d.png'),full_page=True)
    page.locator('#top').click();page.wait_for_timeout(100)
    page.screenshot(path=str(artifacts/'property-top.png'),full_page=True)
    page.locator('#orbit').click()
    page.locator('[data-layer=roof]').uncheck();page.wait_for_timeout(100)
    page.screenshot(path=str(artifacts/'property-cutaway.png'),full_page=True)
    page.locator('[data-layer=roof]').check()
    page.locator('#camera-dock .camera-actions button').first.click()
    assert page.locator('#camera-perspective').is_visible()
    assert 'North gate' in page.locator('#perspective-name').inner_text()
    page.screenshot(path=str(artifacts/'camera-viewpoint.png'),full_page=True)
    page.locator('#leave-camera').click()
    page.locator('#threat-list .threat-card').filter(has_text='Unplaced').first.click()
    assert 'no permitted world coordinates' in page.locator('#selection').inner_text()
    page.locator('#nav-sensors').click()
    assert page.locator('#camera-wall .camera-tile').count()==4
    assert page.locator('#sensor-readings .reading-card').count()==3
    page.screenshot(path=str(artifacts/'sensor-wall.png'),full_page=True)
    page.locator('#filter-other').click();assert page.locator('#camera-wall .camera-tile').count()==0
    page.locator('#filter-all').click();page.locator('#sensor-search').fill('North');assert page.locator('#camera-wall .camera-tile').count()==1
    page.locator('#sensor-search').fill('');page.locator('#nav-property').click()
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(artifacts/'property-mobile.png'),full_page=True)
    page.locator('#legend-detail').click();assert page.locator('#legend-dialog').is_visible()
    page.keyboard.press('Escape');assert not page.locator('#legend-dialog').is_visible()
    page.set_viewport_size({'width':1600,'height':1100})
    fail[0]=True
    if offline:page.evaluate('window.__fail=true')
    page.locator('#refresh').click();page.wait_for_selector('#failure:not([hidden])')
    assert page.locator('#world .world-label').count()==0
    assert page.locator('#camera-dock canvas').count()==0
    assert page.locator('#threat-list .threat-card').count()==0
    fail[0]=False
    if offline:page.evaluate('window.__fail=false')
    page.locator('#retry').click();page.wait_for_selector('#data-workspace:not([hidden])')
    # Missing real geometry remains absent, with events retained as unplaced.
    payload['metadata']['demo']=False
    if offline:page.evaluate('window.__payload.metadata.demo=false')
    page.locator('#refresh').click();page.wait_for_selector('#no-geometry:not([hidden])')
    assert page.locator('#threat-list .threat-card').count()==7
    assert not page.locator('#demo-banner').is_visible()
    assert page.locator('#camera-dock .camera-tile').count()==0
    assert page.locator('#world .world-label').count()==0
    # Restore the scene after absence: the live canvas must still be attached.
    payload['metadata']['demo']=True
    if offline:page.evaluate('window.__payload.metadata.demo=true')
    page.locator('#refresh').click();page.wait_for_function("document.querySelectorAll('#world .world-label').length>5")
    assert page.locator('#world canvas').count()==1
    assert not external,external
    assert not errors,errors
    browser.close()
 print(('PASS: offline injected modules (CSP/HTTP not exercised)' if offline else 'PASS: routed modules under CSP') + '; 3D render, viewpoint, cutaway, uncertainty states, unplaced events, sensor wall, filters, mobile, failed-read clearing and recovery')
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--artifacts',type=Path,default=Path('/tmp/fss-spatial-previews'));ap.add_argument('--offline',action='store_true');a=ap.parse_args();run(a.artifacts,a.offline)
