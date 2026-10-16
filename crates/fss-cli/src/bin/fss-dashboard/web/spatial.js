import {normalizeSnapshot,human,shortDigest,timeBounds,position,relativeTime} from './model.js';
import {validateScene,bindThreats,center,freshness,MAX_SCENE_BYTES,evidenceSummary,evidenceConstellation,frontierItems,sensorPage} from './spatial-model.js';
import {PropertyView} from './view3d.js';
import {makeDemoScene} from './demo-scene.js';

const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;};
const svg=(tag,attrs={},text)=>{const e=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=text;return e;};
// Embedded, consistently stroked icons. No icon fonts, remote SVGs, HTML interpolation, or CDN.
const PATHS={
 cube:'M12 2 21 7v10l-9 5-9-5V7Z M3 7l9 5 9-5 M12 12v10',
 grid:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 branch:'M6 4v12a3 3 0 0 0 3 3h9 M6 10h8a3 3 0 0 0 3-3V4 M4 2h4v4H4z M15 2h4v4h-4z M17 17h4v4h-4z',
 search:'M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15 M16 16l5 5',
 pin:'M12 22s8-8 8-13a8 8 0 1 0-16 0c0 5 8 13 8 13Z M12 6a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
 command:'M8 8H5a3 3 0 1 1 3-3v14a3 3 0 1 1-3-3h14a3 3 0 1 1-3 3V5a3 3 0 1 1 3 3H8z',
 help:'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M9 8a3 3 0 1 1 5 2.2c-1 .8-2 1.2-2 2.8 M12 17h.01',
 refresh:'M20 7a9 9 0 1 0 1 8 M20 2v6h-6',pause:'M8 4v16 M16 4v16',play:'m8 4 12 8-12 8Z',
 anchor:'M12 3a2 2 0 1 0 0 4 2 2 0 0 0 0-4 M12 7v14 M7 11h10 M3 14c0 9 18 9 18 0 M1 16l2-2 2 2 M19 16l2-2 2 2',
 fit:'M8 3H3v5 M16 3h5v5 M3 16v5h5 M21 16v5h-5 M8 8h8v8H8Z',
 expand:'M8 3H3v5 M16 3h5v5 M3 16v5h5 M21 16v5h-5',
 layers:'m12 3 10 5-10 5L2 8Z M2 12l10 5 10-5 M2 16l10 5 10-5',
 uncertainty:'M12 2 22 12 12 22 2 12Z M12 7v6 M12 17h.01',
 camera:'M3 6h12v12H3Z M15 10l6-4v12l-6-4',target:'M12 3v4 M12 17v4 M3 12h4 M17 12h4 M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10',
 roof:'m2 12 10-9 10 9 M5 10v11h14V10',label:'M3 3h8l10 10-8 8L3 11Z M7 7h.01',
 mouse:'M12 2a6 6 0 0 0-6 6v8a6 6 0 0 0 12 0V8a6 6 0 0 0-6-6 M12 5v5',close:'M5 5l14 14 M19 5 5 19',
 timeline:'M3 6h18 M3 12h18 M3 18h18 M7 3v6 M16 9v6 M10 15v6',
 shield:'M12 2 3 6v6c0 6 9 10 9 10s9-4 9-10V6Z M8 12l3 3 5-6',
 person:'M12 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6 M6 20v-5a6 6 0 0 1 12 0v5Z M9 20v2 M15 20v2',
 animal:'M5 8 3 4l6 3 M19 8l2-4-6 3 M5 8c-3 9 3 13 7 13s10-4 7-13L12 5Z M8 12h.01 M16 12h.01 M10 16l2 2 2-2',
 vehicle:'m5 7 2-4h10l2 4 M4 7h16l2 5v7H2v-7Z M5 19v2 M19 19v2 M5 12h3 M16 12h3',
 unknown:'M12 2 22 12 12 22 2 12Z M9 10a3 3 0 1 1 5 2l-2 2 M12 17h.01',
 motion:'M3 12h3l3-8 5 16 3-8h4',contact:'M4 3h6v18H4Z M15 5h5v14h-5 M10 8h5 M10 16h5',
 temperature:'M10 14V5a2 2 0 0 1 4 0v9a5 5 0 1 1-4 0Z M12 9v9',
 smoke:'M5 21h14 M7 17c-6-5 7-7 2-12 M14 17c-6-5 7-7 2-12 M19 16c-3-3 3-4 1-7',
 audio:'M5 9v6 M9 5v14 M13 2v20 M17 6v12 M21 10v4',other:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 8v8 M8 12h8',
 left:'m14 5-7 7 7 7',right:'m10 5 7 7-7 7',external:'M14 3h7v7 M21 3 10 14 M11 3H3v18h18v-8',copy:'M8 8h13v13H8Z M16 8V3H3v13h5',clock:'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20 M12 6v6l4 2',
};
function icon(name){const e=svg('svg',{viewBox:'0 0 24 24',class:'icon','aria-hidden':'true',focusable:'false'});e.append(svg('path',{d:PATHS[name]??PATHS.other}));return e;}
function icons(root=document){for(const node of root.querySelectorAll('[data-icon]')){if(node.querySelector(':scope > svg.icon'))continue;node.prepend(icon(node.dataset.icon));}}
function button(text,action,cls='',symbol){const b=el('button',cls);b.type='button';if(symbol)b.append(icon(symbol));if(text)b.append(el('span','',text));b.addEventListener('click',action);return b;}
const tag=(text,cls='')=>el('span',`tag ${cls}`,human(text));
let state=null,scene=null,threats=[],selected=null,page=location.pathname==='/sensors'?'sensors':'property',selectionTab='insight',frontier='all',referencePage=0,wallFilter='all',wallPage=0;
let request=null,timer=null,busy=false,paused=false,resumePending=false,version=0,previewVersion=0,previewViews=[],imageRequests=[],toastTimer=null,modalOpener=null;
const world=new PropertyView($('world'),{onSelect:(kind,id,h)=>select(kind,id,h),onView:updateView});
icons();
function notify(message){clearTimeout(toastTimer);$('toast').textContent=message;$('toast').hidden=false;toastTimer=setTimeout(()=>$('toast').hidden=true,3200);}
async function copy(value){try{await navigator.clipboard.writeText(value);notify('Exact value copied.');}catch{notify('Clipboard unavailable. Select the exact value in the record detail.');}}
function now(){return state?.metadata.demo?1789398500000:Date.now();}
function current(){return selected?.kind==='threat'?threats.find(t=>t.id===selected.id):scene?.sensors.find(s=>s.id===selected?.id);}
function zoneName(z){return z.replace(/^zone:/,'').replaceAll('-',' ').replace(/\b\w/g,s=>s.toUpperCase());}
function ordinal(t){return String(threats.findIndex(x=>x.id===t.id)+1).padStart(2,'0');}
function openDialog(id,opener=document.activeElement){modalOpener=opener;const d=$(id);if(!d.open)d.showModal();(d.querySelector('input')??d.querySelector('button'))?.focus();}
function closeDialog(id){$(id).close();if(modalOpener?.isConnected)modalOpener.focus({preventScroll:true});modalOpener=null;}
function clearDetails(){for(const id of['detail-dialog','command-dialog'])if($(id).open)$(id).close();$('detail-body').replaceChildren();$('command-results').replaceChildren();commands=[];}
function setPage(next){
 page=next==='sensors'?'sensors':'property';$('property-page').hidden=page!=='property';$('sensors-page').hidden=page!=='sensors';
 for(const p of['property','sensors']){for(const id of[`nav-${p}`,`tab-${p}`]){const b=$(id),active=p===page;b.classList.toggle('active',active);b.setAttribute('aria-pressed',String(active));if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}}
 $('heading').replaceChildren(...(page==='property'?[document.createTextNode('Your property. '),el('em','','In perspective.')]:[document.createTextNode('Every perspective. '),el('em','','One workspace.')]));
 $('subtitle').textContent=page==='property'?'A spatial picture of what is observed, what is inferred, and what is still unknown.':'Camera perspectives and declared sensor readings. Source, freshness, and uncertainty stay in view.';
 if(state){renderCameras();world.invalidate();}
}
function updateView(info){
 $('camera-perspective').hidden=!info.activeCamera;
 if(info.activeCamera)$('perspective-name').textContent=`${info.activeCamera.label} · geometric viewpoint, not live`;
 $('marker-status').textContent=info.limited?`${info.limited} annotations off-canvas or condensed · full list retained`:'';
 const a=$('axes'),angle=info.angle,e=info.elevation;a.replaceChildren();
 for(const[d,label,color]of[[[1,0,0],'X','#bfb0a4'],[[0,1,0],'Y','#b0c9bc'],[[0,0,1],'Z','#aac3d5']]){
   const x=35+(-Math.sin(angle)*d[0]+Math.cos(angle)*d[1])*20,y=35+(Math.sin(e)*(Math.cos(angle)*d[0]+Math.sin(angle)*d[1])-Math.cos(e)*d[2])*20;
   a.append(svg('line',{x1:35,y1:35,x2:x,y2:y,stroke:color,'stroke-width':1.2}),svg('text',{x:x+(x>35?4:-7),y:y+3,fill:color,'font-size':8},label));
 }
 a.append(svg('circle',{cx:35,cy:35,r:2,fill:'#d8e9e6'}));
}
function orbit(mode='orbit'){world.reset(mode);for(const id of['orbit','top']){const active=(id==='top')===(mode==='top');$(id).classList.toggle('selected',active);$(id).setAttribute('aria-pressed',String(active));}}
function viewCamera(s){if(!s?.pose||s.status==='redacted'){notify('No permitted camera pose is supplied.');return;}setPage('property');select('sensor',s.id);world.fromCamera(s);}
function select(kind,id,hypothesis=0){
 const same=selected?.kind===kind&&selected?.id===id;selected={kind,id,hypothesis};if(!same){selectionTab='insight';referencePage=0;}
 world.select(kind,id,hypothesis);renderThreats();renderSelection();renderTime();syncCameraSelection();
}
function focusThreat(t,h=0){select('threat',t.id,h);if(t.hypotheses[h])world.focus(t.hypotheses[h].position);else notify('This candidate stays unplaced. No coordinates were inferred.');}
function renderSummary(){
 const sensors=scene?.sensors??[],localized=threats.filter(t=>t.hypotheses.length).length;
 $('summary').replaceChildren(...[['',sensors.filter(s=>s.kind==='camera').length,'cameras'],['other',sensors.filter(s=>s.kind!=='camera').length,'sensors'],['alert',localized,'located'],['unknown',threats.length-localized,'unplaced']].map(([cls,n,label])=>{const d=el('div',`summary-item ${cls}`);d.append(el('span','marker'),el('b','',String(n)),el('span','',label));return d;}));
 $('camera-count').textContent=`${sensors.filter(s=>s.kind==='camera').length} declared`;
}
function renderThreats(){
 const host=$('threat-list'),scroll=host.scrollTop,focused=document.activeElement?.dataset.eventId,items=frontierItems(threats,frontier);
 $('threat-count').textContent=String(threats.length);$('unplaced-count').textContent=String(threats.filter(t=>!t.hypotheses.length).length);
 $('frontier-scope').textContent=frontier==='all'?'Native lifecycle and position knowledge remain separate.':`${items.length} of ${threats.length} in this list · map still shows all permitted positions`;
 host.replaceChildren(...items.map(t=>{
   const b=button('',()=>focusThreat(t),`threat-card ${selected?.kind==='threat'&&selected.id===t.id?'selected':''}`);b.dataset.eventId=t.id;b.setAttribute('aria-pressed',String(selected?.id===t.id));b.setAttribute('aria-label',`${human(t.kind)}; native ${t.state}; position ${t.knowledge}; ${t.hypotheses.length?'located':'unplaced'}`);
   const glyph=el('span',`threat-icon ${t.knowledge==='stale'?'stale':t.severity}`);glyph.append(icon(t.shape));const content=el('div');content.append(el('h3','',human(t.kind)),el('p','',t.zones.map(zoneName).join(' · ')||'Zone not recorded'));
   const tags=el('div','threat-tags');tags.append(tag(t.knowledge,t.knowledge),tag(t.state));if(t.hypotheses.length>1)tags.append(tag(`${t.hypotheses.length} alternatives`,'conflicted'));if(!t.hypotheses.length)tags.append(tag('Unplaced','unknown'));content.append(tags);b.append(glyph,content,el('span','event-index',ordinal(t)));return b;
 }));
 if(!items.length)host.append(el('div','empty',threats.length?'No candidates match this list filter. The full map and inventory are unchanged.':'No unresolved, non-benign event revisions. This is not proof of absence.'));
 host.scrollTop=scroll;if(focused)host.querySelector(`[data-event-id="${CSS.escape(focused)}"]`)?.focus({preventScroll:true});
 const unplaced=threats.filter(t=>!t.hypotheses.length),tray=$('unplaced-tray');tray.hidden=!unplaced.length;tray.replaceChildren();
 if(unplaced.length){tray.append(icon('uncertainty'),el('strong','',`${unplaced.length} candidate${unplaced.length===1?' has':'s have'} no permitted location.`),el('p','','Unknown does not mean absent. Nothing was placed at a guessed point.'),button('Inspect unplaced',()=>{setFrontier('unplaced');select('threat',unplaced[0].id);$('threat-list').scrollIntoView({block:'nearest'});}));}
}
function setFrontier(next){frontier=next;for(const b of document.querySelectorAll('[data-frontier]')){const active=b.dataset.frontier===frontier;b.classList.toggle('active',active);b.setAttribute('aria-pressed',String(active));}renderThreats();}
function fact(dl,name,value){dl.append(el('dt','',name),el('dd','',String(value)));}
function probability(t,body){
 const p=t.record.probability,heading=el('div','probability-heading');heading.append(el('span','','Recorded probability'),el('strong','',`${p.lower.toFixed(2)} – ${p.upper.toFixed(2)}`));
 const bar=svg('svg',{viewBox:'0 0 290 23',class:'probability-chart',role:'img','aria-label':`Recorded probability interval ${p.lower} to ${p.upper}; ${p.calibrationGeneration?'calibration generation recorded':'uncalibrated'}`});
 for(let i=0;i<=10;i++)bar.append(svg('line',{x1:5+i*28,x2:5+i*28,y1:9,y2:14,stroke:'#3d515b','stroke-width':1}));
 bar.append(svg('line',{x1:5+p.lower*280,x2:5+p.upper*280,y1:11.5,y2:11.5,stroke:'#a7ccd1','stroke-width':4,'stroke-linecap':'round'}));
 body.append(heading,bar,el('p','probability-note',p.calibrationGeneration?'Calibration generation recorded · not independently validated here':'Uncalibrated interval · not a confidence guarantee'));
}
function renderSelection(){
 if(!state)return;const host=$('selection'),item=current();host.replaceChildren();if(!item){host.append(el('h3','','Inspect what matters.'),el('p','basis','Choose a candidate or camera. Exact source references, alternatives, and unknowns stay attached to the selection.'));return;}
 const eyebrow=el('div','selection-eyebrow');eyebrow.append(el('span','',selected.kind==='threat'?`CANDIDATE ${ordinal(item)}`:'DECLARED SENSOR'),button('',()=>showRecord(item),'quiet-button','external'));host.append(eyebrow,el('h3','',selected.kind==='threat'?human(item.kind):item.label));
 const badges=el('div','selection-badges');
 if(selected.kind==='sensor'){
  const s=item,p=s.pose?center(s.pose):s.position;badges.append(tag(s.status,s.status),tag(s.knowledge,s.knowledge));host.append(badges);
  const facts=el('dl');fact(facts,'Type',human(s.kind));fact(facts,'World center',p?p.map(v=>v.toFixed(2)).join(', '):'Unplaced');if(s.pose){fact(facts,'Image model',s.intrinsics.imageDomain);fact(facts,'Dimensions',`${s.intrinsics.width} × ${s.intrinsics.height}`);fact(facts,'Convention','Xc = R Xw + t');}host.append(facts,el('p','basis',s.basis));
  const note=el('div','selection-warning');note.append(el('strong','','Geometry is not coverage.'),el('span','','A frustum illustrates the supplied optical model. It does not certify visibility, availability, or the accuracy of camera registration.'));host.append(note);
  const actions=el('div','selection-actions');const look=button('Camera viewpoint',()=>viewCamera(s),'primary-button','camera');look.disabled=!s.pose||s.status==='redacted';actions.append(look);if(p)actions.append(button('Locate',()=>{setPage('property');world.focus(p);},'','pin'));host.append(actions);
  return;
 }
 const t=item;badges.append(tag(t.knowledge,t.knowledge),tag(t.state));if(t.severity!=='unrated')badges.append(tag(`${t.severity} · declared`,t.severity));host.append(badges);
 const tabs=el('div','selection-tabs');for(const[key,label]of[['insight','Understanding'],['evidence','Evidence trail']]){const b=button(label,()=>{selectionTab=key;renderSelection();$('selection').querySelector(`[data-tab="${key}"]`)?.focus({preventScroll:true});},key===selectionTab?'active':'');b.dataset.tab=key;b.setAttribute('aria-pressed',String(key===selectionTab));tabs.append(b);}host.append(tabs);
 if(selectionTab==='evidence'){renderEvidence(t,host);return;}
 if(t.reason||!t.hypotheses.length){const warning=el('div','selection-warning');warning.append(el('strong','','Location is not established.'),el('span','',t.reason||'No permitted coordinates are supplied for this candidate.'));host.append(warning);}
 if(t.record.uncertaintyReason)host.append(el('p','uncertainty-copy',t.record.uncertaintyReason));
 if(t.hypotheses.length>1){const options=el('div','hypotheses');t.hypotheses.forEach((h,i)=>{const b=button('',()=>focusThreat(t,i),`hypothesis-option ${selected.hypothesis===i?'active':''}`);b.setAttribute('aria-pressed',String(selected.hypothesis===i));b.append(el('span','',`H${i+1} · spatial alternative`),el('code','',h.position.map(v=>v.toFixed(1)).join(', ')),icon('target'));options.append(b);});host.append(options);}
 probability(t,host);
 const facts=el('dl');fact(facts,'Revision',`${t.record.revision} · exact retained record`);fact(facts,'Spatial basis',t.localization?human(t.knowledge):'Not supplied / not matched');fact(facts,'Freshness',t.localization?`${human(t.age)} · declared time`:'Unknown');
 const summary=evidenceSummary(t);fact(facts,'References',`${summary.supports} supporting / ${summary.contradictions} contradicting`);host.append(facts);
 if(summary.namedDomains===1&&summary.references>1){const note=el('div','selection-warning');note.append(el('strong','','Shared failure domain'),el('span', '',`${summary.references} references name one domain. They must not be counted as independent corroboration.`));host.append(note);}
 const actions=el('div','selection-actions');actions.append(button('Trace the evidence',()=>{selectionTab='evidence';renderSelection();},'primary-button','branch'),button('',()=>showRecord(t),'','external'));host.append(actions);
}
function renderConstellation(t,host){
 const c=evidenceConstellation(t),height=Math.max(184,126+c.domains.length*10),chart=svg('svg',{viewBox:`0 0 296 ${height}`,class:'evidence-constellation',role:'img','aria-label':`Failure-domain constellation for ${t.id}. ${c.domains.length} declared domains and ${c.references} references. Domain separation is not an independence certificate.`});
 const cx=148,cy=58,count=Math.max(1,c.domains.length),radius=Math.min(92,58+count*5);
 chart.append(svg('circle',{cx,cy,r:29,class:'constellation-core'}),svg('text',{x:cx,y:cy-3,'text-anchor':'middle',class:'constellation-core-title'},'EVENT'),svg('text',{x:cx,y:cy+11,'text-anchor':'middle',class:'constellation-core-sub'},`${c.references} refs`));
 c.domains.forEach((domain,i)=>{
  const angle=-Math.PI/2+i*Math.PI*2/count,x=cx+Math.cos(angle)*radius,y=cy+72+Math.sin(angle)*Math.min(radius*.7,62);
  const cls=domain.contradictions&&domain.supports?'mixed':domain.contradictions?'counter':domain.supports?'support':'neutral';
  chart.append(svg('path',{d:`M ${cx} ${cy+27} Q ${cx+(x-cx)*.42} ${cy+48} ${x} ${y-18}`,class:`constellation-link ${cls}`}));
  const g=svg('g',{class:'constellation-domain'}),label=domain.name.length>24?domain.name.slice(0,22)+'…':domain.name;
  g.append(svg('rect',{x:x-54,y:y-17,width:108,height:34,rx:7,class:`constellation-domain-box ${cls}`}),svg('text',{x,y:y-3,'text-anchor':'middle',class:'constellation-domain-title'},label),svg('text',{x,y:y+10,'text-anchor':'middle',class:'constellation-domain-sub'},`+${domain.supports}  −${domain.contradictions}  ·${domain.neutral}`));
  g.append(svg('title',{},`${domain.name}\n${domain.references} declared references · ${domain.uniqueObjects} unique objects · ${domain.repeatedReferences} repeated references\n+${domain.supports} supporting · −${domain.contradictions} contradicting · ${domain.neutral} neutral\nFailure-domain grouping is correlation structure, not proof of independence.`));
  chart.append(g);
 });
 host.append(el('div','constellation-heading','Failure-domain constellation'),chart);
 const note=el('p','constellation-note');note.textContent=c.domains.length?`${c.domains.length} declared failure-domain group${c.domains.length===1?'':'s'}. Separate groups remain correlation structure; this view does not certify independent witnesses.`:'No named failure-domain structure is available.';host.append(note);
}
function renderEvidence(t,host){
 const summary=evidenceSummary(t),totals=el('div','evidence-totals');
 for(const[value,label,cls]of[[summary.supports,'supporting',''],[summary.contradictions,'contradicting','counter'],[summary.namedDomains,'named domains','']]){const row=el('div',cls);row.append(el('strong','',String(value)),el('span','',label));totals.append(row);}host.append(totals);
 host.append(el('p','basis','Declared relationships only. Objects have not been hydrated. Counts are not independent observations.'));
 renderConstellation(t,host);
 const size=4,edges=t.edges??[],pages=Math.max(1,Math.ceil(edges.length/size));referencePage=Math.max(0,Math.min(referencePage,pages-1));const visible=edges.slice(referencePage*size,(referencePage+1)*size);
 const height=70+visible.length*56,s=svg('svg',{viewBox:`0 0 296 ${height}`,class:'evidence-network',role:'group','aria-label':'Exact declared event evidence references'});
 s.append(svg('rect',{x:55,y:8,width:186,height:39,rx:7,fill:'#2a4039',stroke:'#507365'}),svg('text',{x:148,y:24,'text-anchor':'middle',fill:'#d6e9e2','font-size':10},human(t.kind)),svg('text',{x:148,y:37,'text-anchor':'middle',fill:'#a7bfbd','font-size':8},`revision ${t.record.revision} · ${shortDigest(t.revisionDigest)}`));
 visible.forEach((edge,i)=>{
  const y=70+i*56,neg=edge.relation==='contradicts'||edge.relation==='invalidates',color=neg?'#eec38c':edge.relation==='supports'?'#a3d5c5':'#b9b0d5',g=svg('g',{class:'evidence-node',role:'button',tabindex:0,'aria-label':`Inspect ${edge.relation} reference ${edge.digest}`});
  s.append(svg('path',{d:`M 69 47 L 28 47 L 28 ${y+20} L 55 ${y+20}`,fill:'none',stroke:color,'stroke-opacity':.45,'stroke-dasharray':neg?'4 3':'none'}));
  g.append(svg('rect',{x:55,y,width:228,height:42,rx:6,fill:'#1e2e35',stroke:neg?'#71604c':'#3f555e'}),svg('circle',{cx:68,cy:y+14,r:2.4,fill:color}),svg('text',{x:78,y:y+17,fill:color,'font-size':9},human(edge.relation)),svg('text',{x:68,y:y+31,fill:'#b6c6ce','font-size':9},`${human(edge.class)} · ${shortDigest(edge.digest)}`));
  const choose=()=>showEdge(edge);g.addEventListener('click',choose);g.addEventListener('keydown',e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();choose();}});s.append(g);
 });host.append(s);
 if(!edges.length)host.append(el('p','basis','No declared evidence references.'));
 if(edges.length>size){const nav=el('div','detail-page'),prev=button('←',()=>{referencePage--;renderSelection();}),next=button('→',()=>{referencePage++;renderSelection();});prev.disabled=!referencePage;next.disabled=referencePage+1>=pages;prev.setAttribute('aria-label','Previous evidence references');next.setAttribute('aria-label','Next evidence references');nav.append(prev,el('span','',`${referencePage*size+1}–${Math.min((referencePage+1)*size,edges.length)} of ${edges.length} references`),next);host.append(nav);}
 for(const group of summary.groups.slice(0,3)){const row=el('div','evidence-domain');row.append(el('strong','',group.name||'Failure domain not recorded'),el('span','',`${group.items.length} declared reference${group.items.length===1?'':'s'} · not an independence certificate`));host.append(row);}
 if(summary.groups.length>3)host.append(el('p','basis',`${summary.groups.length-3} additional domains are retained in the exact record.`));
 if(summary.duplicateReferences)host.append(el('p','selection-warning',`${summary.duplicateReferences} repeated object references. Distinct rows do not establish distinct observations.`));
 const actions=el('div','selection-actions');actions.append(button('Open exact record',()=>showRecord(t),'primary-button','external'));host.append(actions);
}
function showRecord(item){
 if(!item||!state)return;$('detail-kicker').textContent=selected?.kind==='sensor'?'OPERATOR-DECLARED SENSOR':'NATIVE RETAINED REVISION';$('detail-title').textContent=item.label||human(item.kind);const body=$('detail-body');body.replaceChildren();
 const content=item.recordJson||JSON.stringify(item,null,2);body.append(el('p','uncertainty-copy',item.recordJson?'The original canonical record is preserved verbatim, including full-width integers. No event state was upgraded by this visualization.':'Sensor information comes from the selected operator scene. It is not independently measured or activated here.'),el('pre','exact-record',content));
 if(item.revisionDigest){const card=el('div','source-card');card.append(el('strong','','Exact revision digest'),el('code','',item.revisionDigest),el('span','','Snapshot authority'),el('code','',state.metadata.ledgerRoot));body.append(card);}
 body.append(button('Copy exact record',()=>copy(content),'primary-button','copy'));openDialog('detail-dialog');
}
function showEdge(edge){
 $('detail-kicker').textContent='DECLARED REFERENCE · NOT HYDRATED';$('detail-title').textContent=human(edge.relation);const body=$('detail-body');body.replaceChildren();const facts=el('dl','detail-fields');
 for(const[label,value]of[['Object',edge.digest],['Provenance class',human(edge.class)],['Failure domain',edge.failureDomain||'Not recorded'],['Capsule',edge.capsuleDigest||'Not supplied'],['Identity reference',edge.identityDigest||'Not supplied']])fact(facts,label,value);
 body.append(facts,el('div','source-card','The relationship is retained by the event. Matching object digests or a shared sensor domain do not establish independent corroboration. This viewer did not load the source bytes.'),button('Copy object digest',()=>copy(edge.digest),'primary-button','copy'));openDialog('detail-dialog');
}
function showIntegrity(){
 if(!state)return;$('detail-kicker').textContent='READ-ONLY SNAPSHOT';$('detail-title').textContent='Keep custody and certainty separate.';const body=$('detail-body');body.replaceChildren();const facts=el('dl','detail-fields'),m=state.metadata;
 for(const[label,value]of[['Site',m.site],['Authority root',m.ledgerRoot],['Sequence',m.sequence],['Scene identity',state.sceneDigest],['Open obligations',m.counts.openObligations],['Indeterminate effects',m.counts.indeterminateOperations],['Uncommitted ledger tail',String(m.integrity.ledgerTailUncommitted)],['Uncommitted effect tail',String(m.integrity.effectTailUncommitted)],['Files / bytes read',`${m.integrity.filesRead} / ${m.integrity.bytesRead}`]])fact(facts,label,value);
 body.append(facts,el('div','source-card',m.scope),button('Copy authority root',()=>copy(m.ledgerRoot),'primary-button','copy'));openDialog('detail-dialog');
}
function renderTime(){
 if(!state)return;const events=state.metadata.events,host=$('event-time');host.replaceChildren();
 if(!events.length){host.append(el('p','basis','No retained event intervals. No coverage or absence is implied.'));$('time-range').textContent='';return;}
 const bounds=timeBounds(events),width=1000,s=svg('svg',{viewBox:'0 0 1000 65',role:'group','aria-label':'Latest retained event intervals, in relative source time. Not a historical playback.'});
 for(let i=0;i<=8;i++){const x=8+i*123;s.append(svg('line',{x1:x,x2:x,y1:4,y2:40,stroke:'#2a4048','stroke-width':1}));if(i%2===0)s.append(svg('text',{x,y:57,'text-anchor':i===8?'end':'start',class:'time-text'},relativeTime(bounds.start+(bounds.end-bounds.start)*BigInt(i)/8n,bounds.start)));}
 events.forEach((e,i)=>{
  const x=8+position(e.start,bounds,976),end=8+position(e.end,bounds,976),unresolved=threats.find(t=>t.id===e.id);
  const bar=svg('rect',{x,y:9+(i%2)*13,width:Math.max(4,end-x),height:8,rx:2,class:`time-bar ${e.id===selected?.id?'active':''}`,tabindex:0,role:'button','aria-label':`${human(e.kind)}, ${e.id}, interval ${e.start} to ${e.end} nanoseconds`});bar.append(svg('title',{},`${e.id}\n${e.start}–${e.end} ns\nLatest retained revision, not a reconstructed past state`));
  const choose=()=>{if(unresolved)select('threat',e.id);else showRecord(e);};bar.addEventListener('click',choose);bar.addEventListener('keydown',ev=>{if(['Enter',' '].includes(ev.key)){ev.preventDefault();choose();}});s.append(bar);
 });host.append(s);$('time-range').textContent=`${events.length} intervals · ${relativeTime(bounds.end,bounds.start)}`;
}
function clearPreviews(){previewVersion++;for(const c of imageRequests)c.abort();imageRequests=[];for(const view of previewViews)view.dispose();previewViews=[];}
function syncCameraSelection(){for(const tile of document.querySelectorAll('[data-sensor-id]'))tile.classList.toggle('selected',selected?.kind==='sensor'&&selected.id===tile.dataset.sensorId);}
function cameraTile(sensor,index,number){
 const tile=el('article','camera-tile');tile.dataset.sensorId=sensor.id;const preview=el('div','camera-preview'),rendered=el('div','rendered-camera'),stamp=el('span','preview-stamp');preview.append(rendered);
 if(state.metadata.demo&&sensor.pose){
  // Demo thumbnails use bounded software rendering: one WebGL context for the workspace,
  // not a new GPU context for each of the 64 possible declared sensors.
  const v=new PropertyView(rendered,{interactive:false,overlay:false,software:true});v.layers.frusta=false;v.setScene(scene,threats);v.fromCamera(sensor);previewViews.push(v);stamp.textContent='SYNTHETIC VIEW · NOT LIVE';stamp.classList.add('synthetic');
 }else{
  const missing=el('div','preview-empty');missing.append(icon(sensor.status==='redacted'?'shield':'camera'),el('p','',sensor.status==='redacted'?'Preview redacted':sensor.status==='offline'?'Sensor declared offline':sensor.frame&&state.framesAuthorized?'Reading approved preview…':'No authorized preview'),el('small','','No missing image is replaced by a model rendering.'));rendered.append(missing);stamp.textContent=sensor.frame?'RETAINED STILL · NOT LIVE':'IMAGE UNAVAILABLE';
 }
 const expand=button('',()=>expandCamera(sensor,tile),'preview-expand','expand');expand.setAttribute('aria-label',`Expand ${sensor.label} preview`);expand.title='Expand retained or synthetic preview';
 preview.append(stamp,el('span','preview-camera-index',`C${String(number).padStart(2,'0')}`),expand);
 if(state.metadata.demo)preview.append(el('div','preview-reticle'));
 const meta=el('div','camera-meta'),row=el('div','row');row.append(el('h3','',sensor.label),tag(sensor.status,sensor.status));meta.append(row,el('p','',state.metadata.demo?'Geometric perspective · synthetic data':sensor.frame?'Operator-approved retained still':'Declared sensor · pixels unavailable'));
 const actions=el('div','camera-actions'),look=button('View from here',()=>viewCamera(sensor),'','camera');look.disabled=!sensor.pose||sensor.status==='redacted';actions.append(look,button('Inspect',()=>{setPage('property');select('sensor',sensor.id);},'','external'));meta.append(actions);tile.append(preview,meta);
 const load=!state.metadata.demo&&sensor.frame&&state.framesAuthorized&&sensor.status==='available'?()=>loadFrame(sensor,index,rendered,stamp,version,previewVersion):null;return {tile,load};
}
function expandCamera(sensor,tile){
 const source=tile.querySelector('canvas');if(!source){notify('No readable preview is available for this sensor.');return;}
 $('detail-kicker').textContent=state.metadata.demo?'SYNTHETIC PERSPECTIVE · NOT A CAMERA FEED':'OPERATOR-APPROVED RETAINED STILL · NOT LIVE';$('detail-title').textContent=sensor.label;
 const body=$('detail-body');body.replaceChildren();const container=el('div','camera-dialog-view'),canvas=el('canvas');canvas.width=source.width;canvas.height=source.height;canvas.getContext('2d').drawImage(source,0,0);canvas.setAttribute('aria-label',`${sensor.label}; ${state.metadata.demo?'synthetic render':'retained preview'}`);container.append(canvas);body.append(container,el('p','camera-dialog-note',state.metadata.demo?'This image is rendered from the synthetic property and declared optical transform. It is not a camera observation.':`Declared capture: ${sensor.frame?.capturedAtUnixMs??'unknown'} ms. Preview association and redaction are operator assertions, not independently proved here.`));
 if(sensor.pose)body.append(button('Enter geometric viewpoint',()=>{closeDialog('detail-dialog');viewCamera(sensor);},'primary-button','camera'));openDialog('detail-dialog');
}
async function bytesBounded(response,limit){
 const length=response.headers.get('content-length');if(length&&(!/^\d+$/.test(length)||Number(length)>limit))throw Error('Response exceeds its byte limit');
 const reader=response.body.getReader(),chunks=[];let total=0;try{while(true){const{value,done}=await reader.read();if(done)break;total+=value.length;if(total>limit)throw Error('Response exceeds its byte limit');chunks.push(value);}}catch(e){await reader.cancel();throw e;}finally{reader.releaseLock();}
 const joined=new Uint8Array(total);let at=0;for(const chunk of chunks){joined.set(chunk,at);at+=chunk.length;}return joined;
}
async function loadFrame(sensor,index,host,stamp,token,previewToken){
 if(token!==version||previewToken!==previewVersion||document.hidden)return;const c=new AbortController();imageRequests.push(c);const timeout=setTimeout(()=>c.abort(),8000);
 try{
  const hex=state.sceneDigest.replace(/^sha256:/,''),response=await fetch(`/api/frame/${index}/${hex}`,{headers:{'X-FSS-Read':'1'},credentials:'omit',cache:'no-store',signal:c.signal});
  if(!response.ok)throw Error('Preview is unavailable or no longer authorized');const mime=response.headers.get('content-type');if(!['image/png','image/jpeg'].includes(mime))throw Error('Unsupported preview image');
  const bytes=await bytesBounded(response,4*1024*1024);if(token!==version||previewToken!==previewVersion||document.hidden)return;
  const bitmap=await createImageBitmap(new Blob([bytes],{type:mime}));if(token!==version||previewToken!==previewVersion||document.hidden){bitmap.close();return;}if(bitmap.width*bitmap.height>4194304||bitmap.width>4096||bitmap.height>4096){bitmap.close();throw Error('Decoded preview exceeds its pixel limit');}
  const canvas=el('canvas'),scale=Math.min(1,640/bitmap.width,360/bitmap.height);canvas.width=Math.max(1,Math.round(bitmap.width*scale));canvas.height=Math.max(1,Math.round(bitmap.height*scale));canvas.setAttribute('aria-label',`${sensor.label}, explicitly selected retained image preview`);
  try{canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);}finally{bitmap.close();}host.replaceChildren(canvas);
  const age=freshness(sensor.frame.capturedAtUnixMs,30000,now());stamp.textContent=`RETAINED STILL · ${age.toUpperCase()} · ${sensor.frame.capturedAtUnixMs} ms`;
 }catch(e){if(token!==version||previewToken!==previewVersion)return;const missing=el('div','preview-empty');missing.append(icon('shield'),el('p','','Preview unavailable'),el('small','',e.name==='AbortError'?'Preview timed out or was cancelled.':e.message));host.replaceChildren(missing);stamp.textContent='IMAGE UNAVAILABLE';}
 finally{clearTimeout(timeout);imageRequests=imageRequests.filter(x=>x!==c);}
}
function renderCameras(){
 if(!state)return;clearPreviews();for(const id of['camera-dock','camera-wall','sensor-readings'])$(id).replaceChildren();
 const sensors=scene?.sensors??[],result=sensorPage(sensors,$('sensor-search').value,wallFilter,wallPage);wallPage=result.page;
 $('sensor-count').textContent=`${result.matching.length} matching / ${sensors.length} declared`;$('no-sensors').hidden=sensors.length>0;
 const cameraInventory=sensors.filter(s=>s.kind==='camera'),shown=page==='property'?cameraInventory.slice(0,4):result.cameras,loads=[];
 for(const s of shown){const {tile,load}=cameraTile(s,sensors.indexOf(s),cameraInventory.indexOf(s)+1);(page==='property'?$('camera-dock'):$('camera-wall')).append(tile);if(load)loads.push(load);}
 if(page==='property'&&!shown.length)$('camera-dock').append(el('div','empty','No camera inventory supplied. Add exact camera poses and explicitly authorized previews through --scene.'));
 if(page==='sensors'&&!result.matching.length&&sensors.length)$('camera-wall').append(el('div','empty','No sensors match this filter. Reset the search to inspect the complete declared inventory.'));
 $('wall-pagination').hidden=page!=='sensors'||result.pages<=1;$('wall-range').textContent=`${result.totalCameras?wallPage*6+1:0}–${Math.min((wallPage+1)*6,result.totalCameras)} of ${result.totalCameras} matching cameras`;$('wall-prev').disabled=!wallPage;$('wall-next').disabled=wallPage+1>=result.pages;
 if(page==='sensors')for(const s of result.readings){
  const card=el('article','reading-card');card.dataset.sensorId=s.id;const top=el('div','reading-top'),text=el('div');text.append(el('h3','',s.label),el('p','',human(s.kind)));top.append(icon(s.kind),text);
  const available=s.status==='available'&&s.knowledge!=='redacted'&&s.reading,value=el('div','reading-value',available?String(s.reading.value):'—');if(available)value.append(el('small','',s.reading.unit));
  const bottom=el('div','reading-bottom');bottom.append(tag(available?freshness(s.reading.observedAtUnixMs,30000,now()):s.status,s.status),button('Locate ↗',()=>{setPage('property');select('sensor',s.id);if(s.position)world.focus(s.position);}));card.append(top,value,el('p','',available?`Declared at ${s.reading.observedAtUnixMs} ms`:'No readable value; absence is not a zero measurement'),bottom);$('sensor-readings').append(card);
 }
 syncCameraSelection();const token=version,previewToken=previewVersion;
 (async()=>{for(const load of loads){if(token!==version||previewToken!==previewVersion||document.hidden)break;await load();}})();
}
function render(){
 $('site').textContent=state.metadata.site;$('site').title=state.metadata.site;$('demo-banner').hidden=!state.metadata.demo;$('mode-label').textContent=state.metadata.demo?'Frozen synthetic snapshot':'Retained snapshot · not live';
 $('basis-label').textContent=`#${state.metadata.sequence} · ${shortDigest(state.metadata.ledgerRoot)}`;
 $('world-name').textContent=state.metadata.demo?'Observatory residence · synthetic':scene?.frame||'Geometry not supplied';$('world-name').title=scene?.frame||'No coordinate frame';
 $('units').textContent=scene?scene.scale.kind==='relative'?'Relative source units · Z-up':`${scene.scale.metresPerUnit} m / unit · ${scene.scale.kind} declaration`:'No coordinate frame';
 $('no-geometry').hidden=!!scene?.mesh.vertices.length;
 if(scene)world.setScene(scene,threats);else world.clear();
 if(selected?.kind==='threat'&&!threats.some(t=>t.id===selected.id))selected=null;if(selected?.kind==='sensor'&&!scene?.sensors.some(s=>s.id===selected.id))selected=null;
 if(!selected&&threats.length)selected={kind:'threat',id:threats[0].id,hypothesis:0};
 if(selected){const item=current();selected.hypothesis=Math.min(selected.hypothesis??0,Math.max(0,(item?.hypotheses?.length??1)-1));world.select(selected.kind,selected.id,selected.hypothesis);}
 renderSummary();renderThreats();renderSelection();renderTime();$('loading').hidden=true;$('failure').hidden=true;$('data-workspace').hidden=false;setPage(page);
}
function clear(){
 version++;clearPreviews();clearDetails();state=null;scene=null;threats=[];selected=null;world.clear();$('camera-perspective').hidden=true;$('perspective-name').textContent='';$('data-workspace').hidden=true;
 for(const id of['summary','threat-list','selection','camera-dock','camera-wall','sensor-readings','event-time','unplaced-tray','axes'])$(id).replaceChildren();
 for(const id of['basis-label','world-name','units','time-range','marker-status','sensor-count','camera-count']){$(id).textContent='';$(id).removeAttribute('title');}
 $('site').textContent='Snapshot unavailable';$('site').removeAttribute('title');$('command-query').value='';
}
async function refresh(){
 if(document.hidden)return;if(busy){resumePending=true;return;}clearTimeout(timer);busy=true;$('refresh').disabled=true;$('retry').disabled=true;$('connection').textContent='Reading the retained snapshot…';
 request=new AbortController();const c=request,timeout=setTimeout(()=>c.abort(),12000);let success=false;
 try{
  const response=await fetch('/api/spatial',{headers:{'X-FSS-Read':'1'},cache:'no-store',credentials:'omit',signal:c.signal});if(!response.ok)throw Error(`The selected deployment or scene was refused (${response.status}). Check integrity, site and read limits.`);if(!response.headers.get('content-type')?.startsWith('application/json'))throw Error('Unexpected spatial response type');
  const raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bytesBounded(response,MAX_SCENE_BYTES)));
  if(raw.format!=='fss.spatial_dashboard.v1'||typeof raw.framesAuthorized!=='boolean'||!/^sha256:[a-f0-9]{64}$/.test(raw.sceneDigest))throw Error('Unsupported spatial response');
  raw.metadata=normalizeSnapshot(raw.metadata);const next=raw.metadata.demo?validateScene(makeDemoScene(raw.metadata)):raw.scene===null?null:validateScene(raw.scene);if(next&&next.site!==raw.metadata.site)throw Error('Scene and deployment sites differ');
  if(c.signal.aborted||document.hidden)throw new DOMException('View inactive','AbortError');
  version++;clearPreviews();clearDetails();state=raw;scene=next;threats=bindThreats(scene,raw.metadata,now());render();success=true;
  $('connection').textContent=raw.metadata.demo?'Demo data · on-device rendering':`Read at ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
 }catch(e){clear();$('loading').hidden=true;$('failure').hidden=false;$('failure-detail').textContent=e.name==='AbortError'?'Read timed out or the browser tab became inactive.':e.message;$('connection').textContent='Snapshot unavailable';}
 finally{clearTimeout(timeout);request=null;busy=false;$('refresh').disabled=false;$('retry').disabled=false;if(resumePending&&!document.hidden){resumePending=false;queueMicrotask(refresh);}else if(success&&!paused&&!document.hidden)timer=setTimeout(refresh,15000);}
}
function togglePause(){paused=!paused;$('pause').setAttribute('aria-pressed',String(paused));$('pause').replaceChildren(icon(paused?'play':'pause'),el('span','',paused?'Resume updates':'Pause updates'));$('paused-notice').hidden=!paused;clearTimeout(timer);if(!paused)refresh();}
let commands=[],commandIndex=0;
function renderCommands(){
 const q=$('command-query').value.trim().toLocaleLowerCase(),all=[
  {title:'Property workspace',detail:'View · 1',icon:'cube',run:()=>setPage('property')},
  {title:'Camera and sensor wall',detail:'View · 2',icon:'grid',run:()=>setPage('sensors')},
  {title:'Fit property scene',detail:'Camera · 0',icon:'fit',run:()=>{setPage('property');orbit();}},
  {title:'Read latest snapshot',detail:'Read only',icon:'refresh',run:refresh},
  {title:'Visual language and shortcuts',detail:'Guide',icon:'help',run:()=>openDialog('legend-dialog')},
 ];
 for(const t of threats)all.push({title:`${human(t.kind)} · ${ordinal(t)}`,detail:human(t.knowledge),icon:t.shape,search:`${t.id} ${t.zones.join(' ')}`,run:()=>{setPage('property');setFrontier('all');focusThreat(t);}});
 for(const s of scene?.sensors??[])all.push({title:s.label,detail:human(s.kind),icon:s.kind,search:s.id,run:()=>{setPage('property');select('sensor',s.id);const p=s.pose?center(s.pose):s.position;if(p)world.focus(p);}});
 const matching=all.filter(a=>`${a.title} ${a.detail} ${a.search??''}`.toLocaleLowerCase().includes(q));commands=matching.slice(0,12);commandIndex=0;
 const host=$('command-results');host.setAttribute('role','listbox');host.replaceChildren(...commands.map((a,i)=>{const b=button('',()=>{closeDialog('command-dialog');a.run();},'command-option');b.id=`command-${i}`;b.setAttribute('role','option');b.setAttribute('aria-selected',String(i===0));b.append(icon(a.icon),el('span','',a.title),el('small','',a.detail));return b;}));
 $('command-count').textContent=`${commands.length} / ${matching.length} results`;$('command-query').setAttribute('aria-activedescendant',commands.length?'command-0':'');
 if(!commands.length)host.append(el('div','empty','No matching view, event or sensor.'));
}
function openCommands(){renderCommands();openDialog('command-dialog');}
for(const id of['command-open','command-search-open'])$(id).addEventListener('click',openCommands);
$('command-close').addEventListener('click',()=>closeDialog('command-dialog'));
$('command-query').setAttribute('role','combobox');$('command-query').setAttribute('aria-controls','command-results');$('command-query').setAttribute('aria-expanded','true');$('command-query').addEventListener('input',renderCommands);
$('command-query').addEventListener('keydown',e=>{if(!commands.length)return;if(e.key==='Enter'){e.preventDefault();const action=commands[commandIndex];closeDialog('command-dialog');action.run();}if(['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();commandIndex=(commandIndex+(e.key==='ArrowDown'?1:commands.length-1))%commands.length;[...$('command-results').children].forEach((b,i)=>b.setAttribute('aria-selected',String(commandIndex===i)));$('command-query').setAttribute('aria-activedescendant',`command-${commandIndex}`);$(`command-${commandIndex}`).scrollIntoView({block:'nearest'});}});
for(const id of['nav-property','tab-property'])$(id).addEventListener('click',()=>setPage('property'));for(const id of['nav-sensors','tab-sensors','open-wall'])$(id).addEventListener('click',()=>setPage('sensors'));
for(const b of document.querySelectorAll('[data-frontier]'))b.addEventListener('click',()=>setFrontier(b.dataset.frontier));
for(const b of document.querySelectorAll('[data-lens]'))b.addEventListener('click',()=>{world.setLens(b.dataset.lens);for(const node of document.querySelectorAll('[data-lens]')){const active=node===b;node.classList.toggle('active',active);node.setAttribute('aria-pressed',String(active));}});
for(const c of document.querySelectorAll('[data-layer]')){world.layers[c.dataset.layer]=c.checked;c.addEventListener('change',()=>world.setLayer(c.dataset.layer,c.checked));}
$('orbit').addEventListener('click',()=>orbit());$('top').addEventListener('click',()=>orbit('top'));$('fit').addEventListener('click',()=>orbit());$('leave-camera').addEventListener('click',()=>orbit());
$('full').addEventListener('click',async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.querySelector('.world-panel').requestFullscreen();}catch{notify('Fullscreen is unavailable in this browser.');}});
for(const filter of['all','cameras','other'])$('filter-'+filter).addEventListener('click',()=>{wallFilter=filter;wallPage=0;for(const f of['all','cameras','other']){const active=f===filter;$('filter-'+f).classList.toggle('selected',active);$('filter-'+f).setAttribute('aria-pressed',String(active));}renderCameras();});
$('sensor-search').addEventListener('input',()=>{wallPage=0;renderCameras();});$('wall-prev').addEventListener('click',()=>{wallPage--;renderCameras();});$('wall-next').addEventListener('click',()=>{wallPage++;renderCameras();});
for(const id of['help','legend-detail','demo-guide'])$(id).addEventListener('click',()=>openDialog('legend-dialog'));$('close-help').addEventListener('click',()=>closeDialog('legend-dialog'));$('detail-close').addEventListener('click',()=>closeDialog('detail-dialog'));
$('integrity-open').addEventListener('click',showIntegrity);$('refresh').addEventListener('click',refresh);$('retry').addEventListener('click',refresh);$('pause').addEventListener('click',togglePause);$('copy-root').addEventListener('click',()=>{if(state)copy(state.metadata.ledgerRoot);});
for(const id of['legend-dialog','command-dialog','detail-dialog'])$(id).addEventListener('click',e=>{if(e.target===$(id)){const r=$(id).getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeDialog(id);}});
document.addEventListener('keydown',e=>{
 if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();if(!$('legend-dialog').open&&!$('detail-dialog').open)openCommands();return;}
 if(document.querySelector('dialog[open]')||['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)||e.ctrlKey||e.metaKey||e.altKey)return;
 if(e.key==='1')setPage('property');if(e.key==='2')setPage('sensors');if(e.key==='0')orbit();if(e.key==='?')openDialog('legend-dialog');
});
document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden){resumePending=false;request?.abort();clear();$('loading').hidden=false;$('failure').hidden=true;$('connection').textContent='Hidden tab · content cleared';}else refresh();});
refresh();
