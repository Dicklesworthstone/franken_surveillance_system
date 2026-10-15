import {normalizeSnapshot,human,shortDigest} from './model.js';
import {validateScene,bindThreats,center,freshness,MAX_SCENE_BYTES} from './spatial-model.js';
import {PropertyView} from './view3d.js';
import {makeDemoScene} from './demo-scene.js';
const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;};
const button=(text,action,cls='')=>{const b=el('button',cls,text);b.type='button';b.addEventListener('click',action);return b;};
const tag=(text,cls='')=>el('span',`tag ${cls}`,human(text));
const GLYPHS={person:'♙',animal:'◇',vehicle:'▱',unknown:'◈'};
const SENSOR_ICONS={camera:'▣',motion:'⌁',contact:'◫',temperature:'♧',smoke:'♨',audio:'≋',other:'◌'};
let state=null,scene=null,threats=[],selected=null,wallFilter='all',page=location.pathname==='/sensors'?'sensors':'property';
let request=null,timer=null,version=0,images=[],previewViews=[],imageRequests=[],busy=false;
const world=new PropertyView($('world'),{onSelect:select});
function notify(message){$('toast').textContent=message;$('toast').hidden=false;setTimeout(()=>$('toast').hidden=true,3500);}
function setPage(next){page=next;$('property-page').hidden=page!=='property';$('sensors-page').hidden=page!=='sensors';$('nav-property').classList.toggle('active',page==='property');$('nav-sensors').classList.toggle('active',page==='sensors');for(const id of['nav-property','nav-sensors']){const active=id===`nav-${page}`;if(active)$(id).setAttribute('aria-current','page');else $(id).removeAttribute('aria-current');}$('heading').textContent=page==='property'?'The whole picture.':'Every perspective. In view.';$('subtitle').textContent=page==='property'?'Property, perspectives, and uncertainty. In one place.':'Declared cameras and sensors, with freshness and availability kept visible.';if(state){renderCameras();world.invalidate();}}
function viewCamera(s){if(!s.pose){notify('No registered camera pose is supplied.');return;}setPage('property');world.fromCamera(s);$('camera-perspective').hidden=false;$('perspective-name').textContent=`${s.label} · geometric viewpoint, not a live image`;select('sensor',s.id);}
function orbit(mode='orbit'){world.reset(mode);$('camera-perspective').hidden=true;$('orbit').classList.toggle('selected',mode==='orbit');$('top').classList.toggle('selected',mode==='top');}
function select(kind,id){selected={kind,id};world.select(kind,id);renderThreats();renderSelection();}
function renderSummary(){const sensors=scene?.sensors??[],localized=threats.filter(t=>t.hypotheses.length).length;const items=[['',sensors.filter(s=>s.kind==='camera').length,'declared cameras'],['',sensors.filter(s=>s.kind!=='camera').length,'other sensors'],['alert',localized,'positioned candidates'],['unknown',threats.length-localized,'unplaced candidates']];$('summary').replaceChildren(...items.map(([cls,n,label])=>{const d=el('div',`summary-item ${cls}`);d.append(el('span','marker'),el('b','',String(n)),el('span','',label));return d;}));}
function renderThreats(){
 $('threat-count').textContent=String(threats.length);
 $('threat-list').replaceChildren(...threats.map(t=>{const b=button('',()=>{select('threat',t.id);if(t.hypotheses.length)world.focus(t.hypotheses[0].position);},`threat-card ${selected?.id===t.id?'selected':''}`);b.setAttribute('aria-pressed',String(selected?.id===t.id));b.setAttribute('aria-label',`${human(t.kind)}; native ${t.state}; position ${t.knowledge}; ${t.hypotheses.length?'located':'unplaced'}`);const glyph=el('span',`threat-icon ${t.knowledge==='stale'?'stale':t.severity}`,GLYPHS[t.shape]);const content=el('div');content.append(el('h3','',human(t.kind)),el('p','',t.zones.join(' · ')||'No zone recorded'));const tags=el('div','threat-tags');tags.append(tag(t.knowledge,t.knowledge),tag(t.state));if(!t.hypotheses.length)tags.append(tag('Unplaced','conflicted'));if(t.hypotheses.length>1)tags.append(tag(`${t.hypotheses.length} alternatives`));content.append(tags);b.append(glyph,content);return b;}));
 if(!threats.length)$('threat-list').append(el('div','empty','No unresolved candidates in this retained snapshot. This is not proof of absence.'));
}
function fact(dl,name,value){dl.append(el('dt','',name),el('dd','',String(value)));}
function renderSelection(){
 const d=$('selection');d.replaceChildren();
 if(!selected){d.append(el('p','','Select an event or camera to inspect its basis.'));return;}
 if(selected.kind==='threat'){
  const t=threats.find(t=>t.id===selected.id);if(!t)return;
  d.append(el('h3','',human(t.kind)),tag(`Position ${t.knowledge}`,t.knowledge));
  if(t.reason||!t.hypotheses.length)d.append(el('p','unplaced',t.reason||'This localization has no permitted world coordinates.'));
  const dl=el('dl');fact(dl,'Lifecycle',human(t.state));fact(dl,'Severity',t.severity==='unrated'?'Not supplied':`${human(t.severity)} · declared`);fact(dl,'Alternatives',t.hypotheses.length);fact(dl,'Revision',String(t.record.revision));
  if(t.localization){fact(dl,'Observed at',`${t.localization.observedAtUnixMs} ms (declared Unix)`);fact(dl,'Freshness',`${t.age} · not a current-visibility proof`);}
  t.hypotheses.forEach((h,i)=>fact(dl,`Position ${i+1}`,h.position.map(v=>v.toFixed(2)).join(', ')));d.append(dl);
  d.append(el('p','basis',t.localization?.basis||'No matching spatial basis.'),el('p','basis',t.record.uncertaintyReason||'No additional event uncertainty text recorded.'));
  d.append(button('Copy revision ↗',()=>copy(t.revisionDigest)),button('Inspect evidence ↗',()=>location.assign('/evidence')));
 }else{
  const s=scene?.sensors.find(s=>s.id===selected.id);if(!s)return;const p=s.pose?center(s.pose):s.position;
  d.append(el('h3','',s.label),tag(s.status));const dl=el('dl');fact(dl,'Type',human(s.kind));fact(dl,'Position',p?p.map(v=>v.toFixed(2)).join(', '):'Unplaced');fact(dl,'Knowledge',s.knowledge);if(s.pose){fact(dl,'Convention','Xc = R Xw + t');fact(dl,'Image domain',s.intrinsics.imageDomain);}d.append(dl,el('p','basis',s.basis));
  if(s.pose)d.append(button('Look through camera ↗',()=>viewCamera(s)));
  if(p)d.append(button('Locate on property',()=>{setPage('property');world.focus(p);}));
 }
}
function now(){return state?.metadata.demo?1789398500000:Date.now();}
function clearPreviews(){for(const c of imageRequests)c.abort();imageRequests=[];for(const bitmap of images)bitmap.close();images=[];for(const view of previewViews)view.dispose();previewViews=[];}
function cameraTile(sensor,index,compact=false){
 const tile=el('article','camera-tile'),preview=el('div','camera-preview');const stamp=el('span','preview-stamp');
 const rendered=el('div','rendered-camera');preview.append(rendered);
 if(state.metadata.demo&&sensor.pose){const view=new PropertyView(rendered,{interactive:false,overlay:false});view.layers.frusta=false;view.setScene(scene,threats);view.fromCamera(sensor);previewViews.push(view);stamp.textContent='SYNTHETIC VIEW · NOT A CAMERA FEED';stamp.classList.add('synthetic');}
 else{const empty=el('div','preview-empty');empty.append(el('span','',sensor.status==='redacted'?'◫':'▣'),el('p','',sensor.status==='redacted'?'Preview redacted':sensor.status==='offline'?'Sensor declared offline':sensor.frame&&state.framesAuthorized?'Reading approved preview…':'No authorized image preview'),el('small','','No image is replaced by a model rendering.'));rendered.append(empty);stamp.textContent=sensor.frame?'RETAINED STILL · NOT LIVE':'IMAGE UNAVAILABLE';}
 preview.append(stamp);const meta=el('div','camera-meta'),row=el('div','row');row.append(el('h3','',sensor.label),tag(sensor.status));meta.append(row,el('p','',sensor.pose?'Registered geometric viewpoint supplied':'No registered optical pose'));
 const actions=el('div','camera-actions');const look=button('3D viewpoint ↗',()=>viewCamera(sensor));look.disabled=!sensor.pose;actions.append(look,button('Details',()=>{setPage('property');select('sensor',sensor.id);}));meta.append(actions);tile.append(preview,meta);
 if(!state.metadata.demo&&sensor.frame&&state.framesAuthorized&&sensor.status==='available')return{tile,load:()=>loadFrame(sensor,index,rendered,stamp,version)};
 return{tile,load:null};
}
async function bytesBounded(response,limit){
 const length=response.headers.get('content-length');if(length&&(!/^\d+$/.test(length)||Number(length)>limit))throw Error('Response exceeds its byte limit');
 const reader=response.body.getReader(),chunks=[];let total=0;try{while(true){const{value,done}=await reader.read();if(done)break;total+=value.length;if(total>limit)throw Error('Response exceeds its byte limit');chunks.push(value);}}catch(e){await reader.cancel();throw e;}finally{reader.releaseLock();}
 const joined=new Uint8Array(total);let at=0;for(const chunk of chunks){joined.set(chunk,at);at+=chunk.length;}return joined;
}
async function loadFrame(sensor,index,host,stamp,token){
 if(token!==version||document.hidden)return;
 const controller=new AbortController();imageRequests.push(controller);const timeout=setTimeout(()=>controller.abort(),8000);
 try{
  const hex=state.sceneDigest.replace(/^sha256:/,'');const response=await fetch(`/api/frame/${index}/${hex}`,{headers:{'X-FSS-Read':'1'},credentials:'omit',cache:'no-store',signal:controller.signal});
  if(!response.ok)throw Error('Preview is unavailable or no longer authorized');const mime=response.headers.get('content-type');if(!['image/png','image/jpeg'].includes(mime))throw Error('Unsupported preview image');
  const bytes=await bytesBounded(response,4*1024*1024);if(token!==version||document.hidden)return;
  const bitmap=await createImageBitmap(new Blob([bytes],{type:mime}));if(token!==version||document.hidden){bitmap.close();return;}if(bitmap.width*bitmap.height>4194304||bitmap.width>4096||bitmap.height>4096){bitmap.close();throw Error('Decoded preview exceeds its pixel limit');}
  images.push(bitmap);const canvas=el('canvas');canvas.width=bitmap.width;canvas.height=bitmap.height;canvas.setAttribute('aria-label',`${sensor.label}, explicitly selected retained image preview`);canvas.getContext('2d').drawImage(bitmap,0,0);host.replaceChildren(canvas);
  const age=freshness(sensor.frame.capturedAtUnixMs,30000,now());stamp.textContent=`RETAINED STILL · ${age.toUpperCase()} · ${sensor.frame.capturedAtUnixMs} ms`;stamp.classList.toggle('ready',age==='recent');
 }catch(e){if(token!==version)return;const error=el('div','preview-empty');error.append(el('span','','◌'),el('p','','Preview unavailable'),el('small','',e.name==='AbortError'?'Preview read timed out or was cancelled.':e.message));host.replaceChildren(error);stamp.textContent='IMAGE UNAVAILABLE';}
 finally{clearTimeout(timeout);imageRequests=imageRequests.filter(c=>c!==controller);}
}
function renderCameras(){
 clearPreviews();$('camera-dock').replaceChildren();$('camera-wall').replaceChildren();$('sensor-readings').replaceChildren();
 const sensors=scene?.sensors??[],query=$('sensor-search').value.toLowerCase(),filtered=sensors.filter(s=>`${s.label} ${s.id} ${s.kind}`.toLowerCase().includes(query));const cameras=filtered.filter(s=>s.kind==='camera');
 $('sensor-count').textContent=`${filtered.length} matching / ${sensors.length} declared sensors`;
 $('no-sensors').hidden=sensors.length>0;
 const loads=[];
 // At most four simultaneous WebGL contexts in demo; inactive view cameras are disposed.
 const shown=page==='property'?sensors.filter(s=>s.kind==='camera').slice(0,4):wallFilter==='other'?[]:cameras;
 for(const s of shown){const{tile,load}=cameraTile(s,sensors.indexOf(s),page==='property');(page==='property'?$('camera-dock'):$('camera-wall')).append(tile);if(load)loads.push(load);}
 if(page==='property'&&!shown.length)$('camera-dock').append(el('div','empty','No camera inventory supplied. Add exact camera poses and explicitly authorized image previews through --scene.'));
 if(page==='sensors'&&wallFilter!=='cameras')for(const s of filtered.filter(s=>s.kind!=='camera')){
  const card=el('article','reading-card'),top=el('div','reading-top'),text=el('div');text.append(el('h3','',s.label),el('p','',human(s.kind)));top.append(el('span','reading-icon',SENSOR_ICONS[s.kind]),text);
  const available=s.status==='available'&&s.knowledge!=='redacted'&&s.reading;const value=el('div','reading-value',available?String(s.reading.value):'—');if(available)value.append(el('small','',s.reading.unit));
  const bottom=el('div','reading-bottom');bottom.append(tag(available?freshness(s.reading.observedAtUnixMs,30000,now()):s.status),button('Locate ↗',()=>{setPage('property');select('sensor',s.id);if(s.position)world.focus(s.position);}));card.append(top,value,el('p','',available?`Recorded ${s.reading.observedAtUnixMs} ms`:'No readable current value'),bottom);$('sensor-readings').append(card);
 }
 const token=version;const loadNext=async()=>{for(const load of loads){if(token!==version||document.hidden)break;await load();}};loadNext();
}
function render(){
 $('site').textContent=state.metadata.site;$('demo-banner').hidden=!state.metadata.demo;$('mode-label').textContent=state.metadata.demo?'Frozen synthetic demonstration':'Retained snapshot · not live';$('basis-label').textContent=`Authority ${shortDigest(state.metadata.ledgerRoot)} · sequence ${state.metadata.sequence}`;
 $('world-name').textContent=scene?.frame||'Geometry not supplied';$('units').textContent=scene?scene.scale.kind==='relative'?'Z-up · relative source units':`Z-up · ${scene.scale.metresPerUnit} m / unit · declared ${scene.scale.kind} scale`:'No coordinate frame';
 $('no-geometry').hidden=!!scene?.mesh.vertices.length;
 if(scene)world.setScene(scene,threats);else { world.scene=null; world.canvas.width=world.canvas.width; world.overlay.replaceChildren(); }
 if(selected?.kind==='threat'&&!threats.some(t=>t.id===selected.id))selected=null;if(selected?.kind==='sensor'&&!scene?.sensors.some(s=>s.id===selected.id))selected=null;
 if(!selected&&threats.length)selected={kind:'threat',id:threats[0].id};
 renderSummary();renderThreats();renderSelection();$('loading').hidden=true;$('failure').hidden=true;$('data-workspace').hidden=false;setPage(page);
}
function clear(){version++;clearPreviews();state=null;scene=null;threats=[];selected=null;world.scene=null;world.canvas.width=world.canvas.width;world.overlay.replaceChildren();$('data-workspace').hidden=true;for(const id of['summary','threat-list','selection','camera-dock','camera-wall','sensor-readings'])$(id).replaceChildren();$('site').textContent='Snapshot unavailable';$('basis-label').textContent='';}
async function refresh(){
 if(busy||document.hidden)return;clearTimeout(timer);busy=true;$('refresh').disabled=true;$('retry').disabled=true;$('connection').textContent='Reading…';request=new AbortController();const timeout=setTimeout(()=>request?.abort(),12000);let success=false;
 try{
  const response=await fetch('/api/spatial',{headers:{'X-FSS-Read':'1'},cache:'no-store',credentials:'omit',signal:request.signal});if(!response.ok)throw Error(`The selected deployment or scene was refused (${response.status}). Check source integrity, site, and read limits.`);if(!response.headers.get('content-type')?.startsWith('application/json'))throw Error('Unexpected spatial response type');
  const raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bytesBounded(response,MAX_SCENE_BYTES)));
  if(raw.format!=='fss.spatial_dashboard.v1'||typeof raw.framesAuthorized!=='boolean'||!/^sha256:[a-f0-9]{64}$/.test(raw.sceneDigest))throw Error('Unsupported spatial response');
  raw.metadata=normalizeSnapshot(raw.metadata);let next=raw.metadata.demo?makeDemoScene(raw.metadata):raw.scene===null?null:validateScene(raw.scene);if(next&&next.site!==raw.metadata.site)throw Error('Scene and deployment sites differ');
  if(raw.metadata.demo)validateScene(next);
  version++;clearPreviews();state=raw;scene=next;threats=bindThreats(scene,raw.metadata,now());render();success=true;$('connection').textContent=raw.metadata.demo?'Synthetic · local renderer':`Read ${new Date().toLocaleTimeString()}`;
 }catch(e){clear();$('loading').hidden=true;$('failure').hidden=false;$('failure-detail').textContent=e.name==='AbortError'?'The read timed out or the browser tab became inactive.':e.message;$('connection').textContent='Unavailable';}
 finally{clearTimeout(timeout);request=null;busy=false;$('refresh').disabled=false;$('retry').disabled=false;if(success&&!document.hidden)timer=setTimeout(refresh,15000);}
}
async function copy(value){try{await navigator.clipboard.writeText(value);notify('Exact identity copied.');}catch{notify('Clipboard is unavailable. The original identity is visible in the evidence explorer.');}}
$('nav-property').addEventListener('click',()=>setPage('property'));$('nav-sensors').addEventListener('click',()=>setPage('sensors'));$('open-wall').addEventListener('click',()=>setPage('sensors'));
$('orbit').addEventListener('click',()=>orbit());$('top').addEventListener('click',()=>orbit('top'));$('fit').addEventListener('click',()=>orbit());$('leave-camera').addEventListener('click',()=>orbit());
$('full').addEventListener('click',()=>{if(document.fullscreenElement)document.exitFullscreen();else document.querySelector('.world-panel').requestFullscreen().catch(()=>notify('Fullscreen is unavailable in this browser.'));});
for(const c of document.querySelectorAll('[data-layer]'))c.addEventListener('change',()=>world.setLayer(c.dataset.layer,c.checked));
for(const type of['all','cameras','other'])$('filter-'+type).addEventListener('click',()=>{wallFilter=type;for(const t of['all','cameras','other'])$('filter-'+t).classList.toggle('selected',t===type);renderCameras();});
$('sensor-search').addEventListener('input',()=>{if(state)renderCameras();});
for(const id of['help','legend-detail'])$(id).addEventListener('click',()=>{if(!$('legend-dialog').open)$('legend-dialog').showModal();});$('close-help').addEventListener('click',()=>$('legend-dialog').close());
$('refresh').addEventListener('click',refresh);$('retry').addEventListener('click',refresh);$('copy-root').addEventListener('click',()=>{if(state)copy(state.metadata.ledgerRoot);});
document.addEventListener('keydown',e=>{if(['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)||$('legend-dialog').open||e.ctrlKey||e.metaKey||e.altKey)return;if(e.key==='1')setPage('property');if(e.key==='2')setPage('sensors');if(e.key==='0')orbit();});
document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden){request?.abort();clear();$('loading').hidden=false;$('connection').textContent='Hidden · content cleared';}else refresh();});
refresh();
