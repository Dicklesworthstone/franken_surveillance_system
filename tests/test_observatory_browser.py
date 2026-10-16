#!/usr/bin/env python3
"""Offline interaction/visual regression for the shipped Observatory modules.

Playwright and Chromium are test tools, never runtime dependencies. This harness
injects the exact DOM/styles/modules and synthetic responses without navigating
or opening a network listener. It does not exercise native HTTP, CSP, hardware
WebGL, real cameras, source availability, or field calibration.
"""
import argparse
import json
from pathlib import Path
import re
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'crates/fss-cli/src/bin/fss-dashboard/web'
MODULES = ['model.js', 'spatial-model.js', 'demo-scene.js', 'view3d.js', 'spatial.js']


def mount(page):
    markup = (WEB / 'spatial.html').read_text(encoding='utf-8')
    markup = re.sub(r'<script[^>]*>.*?</script>', '', markup, flags=re.S)
    markup = re.sub(r'<link[^>]*>', '', markup)
    page.set_content(markup)
    page.add_style_tag(content=(WEB / 'spatial.css').read_text(encoding='utf-8'))
    fixture = json.loads((WEB / 'demo.json').read_text(encoding='utf-8'))
    page.evaluate('''metadata => {
        window.__metadata = metadata;
        window.__fail = false;
        window.__calls = 0;
        window.__override = null;
        window.__modules = {};
        window.fetch = async (url, options) => {
            window.__calls++;
            if (url !== '/api/spatial') throw new Error('Unexpected preview/network request in synthetic mode');
            if (options.headers['X-FSS-Read'] !== '1') throw new Error('Missing read header');
            return new Response(JSON.stringify(window.__override || {
                format: 'fss.spatial_dashboard.v1', metadata: window.__metadata,
                scene: null, sceneDigest: 'sha256:'+'a'.repeat(64), framesAuthorized: false
            }), {status:window.__fail ? 503 : 200, headers:{'Content-Type':'application/json'}});
        };
    }''', fixture)
    # Rebind only module transport. Each file keeps a private scope and its real exports.
    for name in MODULES:
        source = (WEB / name).read_text(encoding='utf-8')
        exports = re.findall(r'export (?:const|function|class) (\w+)', source)
        source = re.sub(r"import\s*\{([^}]+)\}\s*from\s*['\"]\./([^'\"]+)['\"];?",
                        lambda m: 'const {' + m.group(1) + '}=window.__modules[' + json.dumps(m.group(2)) + '];', source)
        source = source.replace('export ', '')
        page.add_script_tag(content='window.__modules[' + json.dumps(name) + '] = (()=>{' + source + ';return {' + ','.join(exports) + '};})();')
    page.wait_for_selector('#data-workspace:not([hidden])', timeout=20000)


def run(chromium, artifacts):
    artifacts.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chromium, headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width':1512, 'height':1120}, device_scale_factor=1,
                                reduced_motion='reduce')
        failures = []
        page.on('pageerror', lambda error: failures.append(str(error)))
        page.set_default_timeout(8000)
        mount(page)
        page.locator('#pause').click()
        page.wait_for_timeout(650)
        assert page.locator('#demo-banner').is_visible()
        assert page.locator('#threat-list .threat-card').count() == 7
        assert page.locator('#camera-dock .camera-tile').count() == 4
        assert page.locator('#threat-count').inner_text() == '7'
        assert page.locator('#unplaced-count').inner_text() == '1'
        assert page.locator('#unplaced-tray').is_visible()
        assert page.locator('#event-time rect').count() == 9
        assert page.locator('#world canvas').get_attribute('width') != '300'
        assert page.locator('#world .world-label').count() > 4
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
        page.screenshot(path=str(artifacts / 'property.png'), full_page=True)

        # Filters affect the list, not the spatial model or unresolved inventory.
        annotations = page.locator('#world .world-label').count()
        page.locator('[data-frontier=unplaced]').click()
        assert page.locator('#threat-list .threat-card').count() == 1
        assert page.locator('#world .world-label').count() == annotations
        assert 'map still shows all' in page.locator('#frontier-scope').inner_text()
        page.locator('[data-frontier=all]').click()
        page.locator('.threat-card').first.click()
        page.locator('[data-tab=evidence]').click()
        assert page.locator('.evidence-totals strong').all_text_contents() == ['2', '1', '1']
        assert page.locator('.evidence-node').count() == 3
        assert 'not an independence certificate' in page.locator('.evidence-domain').inner_text()
        page.screenshot(path=str(artifacts / 'evidence-trail.png'), full_page=True)
        page.locator('.evidence-node').first.click()
        assert page.locator('#detail-dialog').is_visible()
        assert 'NOT HYDRATED' in page.locator('#detail-kicker').inner_text()
        assert 'sha256:' in page.locator('#detail-body').inner_text()
        page.locator('#detail-close').click()

        # Alternative hypotheses remain individually selectable and labeled.
        page.locator('.threat-card').filter(has_text='Sensor tamper').click()
        assert page.locator('.hypothesis-option').count() == 2
        page.locator('.hypothesis-option').nth(1).click()
        assert page.locator('.hypothesis-option').nth(1).get_attribute('aria-pressed') == 'true'
        page.locator('[data-lens=uncertainty]').click()
        assert page.locator('[data-lens=uncertainty]').get_attribute('aria-pressed') == 'true'
        assert page.locator('#threat-list .threat-card').count() == 7
        page.locator('#fit').click()
        page.wait_for_timeout(350)
        page.screenshot(path=str(artifacts / 'uncertainty.png'), full_page=True)
        page.locator('#top').click()
        assert page.locator('#top').get_attribute('aria-pressed') == 'true'
        page.wait_for_timeout(300)
        page.screenshot(path=str(artifacts / 'plan.png'), full_page=True)
        page.locator('label').filter(has=page.locator('[data-layer=roof]')).click()
        assert not page.locator('[data-layer=roof]').is_checked()
        page.locator('label').filter(has=page.locator('[data-layer=roof]')).click()
        page.locator('[data-lens=context]').click()
        page.locator('#orbit').click()

        # Geometry perspective and retained/synthetic preview are distinct actions.
        page.locator('#camera-dock .camera-actions button').first.click()
        page.wait_for_selector('#camera-perspective:not([hidden])')
        assert 'not live' in page.locator('#perspective-name').inner_text()
        page.locator('#leave-camera').click()
        page.wait_for_selector('#camera-perspective[hidden]', state='attached')
        page.locator('#camera-dock .preview-expand').first.click()
        assert page.locator('#detail-dialog canvas').count() == 1
        assert 'NOT A CAMERA FEED' in page.locator('#detail-kicker').inner_text()
        page.locator('#detail-close').click()
        page.locator('#nav-sensors').click()
        assert page.locator('#camera-wall .camera-tile').count() == 4
        assert page.locator('#sensor-readings .reading-card').count() == 3
        page.wait_for_timeout(600)
        page.screenshot(path=str(artifacts / 'sensors.png'), full_page=True)
        page.locator('#filter-other').click()
        assert page.locator('#camera-wall .camera-tile').count() == 0
        assert page.locator('#sensor-readings .reading-card').count() == 3
        page.locator('#sensor-search').fill('no sensor has this label')
        assert page.locator('#sensor-readings .reading-card').count() == 0
        assert 'No sensors match' in page.locator('#camera-wall').inner_text()
        page.locator('#sensor-search').fill('')
        page.locator('#filter-all').click()

        page.keyboard.press('Control+k')
        assert page.locator('#command-dialog').is_visible()
        page.locator('#command-query').fill('Property workspace')
        assert page.locator('.command-option').count() == 1
        page.keyboard.press('ArrowDown')
        page.keyboard.press('Enter')
        assert page.locator('#property-page').is_visible()
        assert not page.locator('#command-dialog').is_visible()
        page.locator('#command-search-open').click()
        page.locator('#command-query').fill('')
        page.screenshot(path=str(artifacts / 'commands.png'), full_page=True)
        page.keyboard.press('Escape')

        # Exact canonical bytes are not rebuilt from imprecise JS timestamps.
        page.locator('.threat-card').first.click()
        page.locator('.selection-eyebrow button').click()
        assert '1789398468000000123' in page.locator('#detail-body').inner_text()
        page.locator('#detail-close').click()
        page.locator('#integrity-open').click()
        assert 'Indeterminate effects' in page.locator('#detail-body').inner_text()
        page.locator('#detail-close').click()
        page.set_viewport_size({'width':390, 'height':844})
        page.wait_for_timeout(500)
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
        page.screenshot(path=str(artifacts / 'mobile.png'), full_page=True)
        page.locator('#nav-sensors').click()
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
        page.screenshot(path=str(artifacts / 'mobile-sensors.png'), full_page=True)
        page.set_viewport_size({'width':1512, 'height':1120})
        page.locator('#nav-property').click()
        assert page.locator('#pause').get_attribute('aria-pressed') == 'true'
        assert page.locator('#paused-notice').is_visible()

        # Failed reads remove source metadata, pixels, graph objects and modal state.
        page.evaluate('window.__fail=true')
        page.locator('#refresh').click()
        page.wait_for_selector('#failure:not([hidden])')
        assert not page.locator('#data-workspace').is_visible()
        for selector in ['#threat-list .threat-card', '#camera-dock canvas', '#camera-wall canvas',
                         '#world .world-label', '#detail-body *', '#command-results *', '#event-time *']:
            assert page.locator(selector).count() == 0, selector
        assert page.locator('#basis-label').inner_text() == ''
        assert page.locator('#world-name').get_attribute('title') is None
        page.screenshot(path=str(artifacts / 'unavailable.png'), full_page=True)
        page.evaluate('window.__fail=false')
        page.locator('#retry').click()
        page.wait_for_selector('#data-workspace:not([hidden])')
        assert page.locator('.threat-card').count() == 7

        # Untrusted event text is inert in both summary and exact-record surfaces.
        page.evaluate('''() => {
            const r=JSON.parse(window.__metadata.events[0].recordJson);
            r.uncertaintyReason='<img src=x onerror="window.__xss=true">';
            r.zoneIds=['<svg onload=alert(1)>'];
            window.__metadata.events[0].recordJson=JSON.stringify(r);
        }''')
        page.locator('#refresh').click()
        page.wait_for_function("document.getElementById('selection').textContent.includes('<img')")
        assert page.locator('#data-workspace img').count() == 0
        assert page.evaluate('window.__xss === undefined')
        assert not failures, failures
        renderer=page.locator('#world').get_attribute('data-renderer')
        browser.close()
    print('PASS: offline Observatory DOM, linked evidence, alternative locations, lenses, '
          'camera perspective/expansion, sensor filters, commands, exact records, mobile layout, '
          'failure clearing, retry and text-injection checks. Renderer:', renderer)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium', default='/usr/bin/chromium')
    parser.add_argument('--artifacts', type=Path, default=Path('/tmp/fss-observatory-previews'))
    args=parser.parse_args()
    run(args.chromium, args.artifacts)
