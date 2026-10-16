// Deterministic operator-view contracts. No network, DOM or npm install.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const web = new URL('../crates/fss-cli/src/bin/fss-dashboard/web/', import.meta.url);
const load = async name => {
  let src = await readFile(new URL(name, web), 'utf8');
  if (name !== 'spatial-model.js') src = src.replace("'./spatial-model.js'", JSON.stringify(spatialUrl));
  return import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));
};
const spatialUrl='data:text/javascript;base64,'+Buffer.from(await readFile(new URL('spatial-model.js',web),'utf8')).toString('base64');
const m=await import(spatialUrl), core=await load('model.js');
const {makeDemoScene}=await load('demo-scene.js');
const {PropertyView}=await load('view3d.js');
const fixture=JSON.parse(await readFile(new URL('demo.json',web),'utf8'));
const metadata=core.normalizeSnapshot(fixture);
const scene=()=>makeDemoScene(metadata), now=1789398500000;
const near=(a,b,t=1e-8)=>assert.ok(Math.abs(a-b)<t, `${a} != ${b}`);
const vec=(a,b)=>a.forEach((n,i)=>near(n,b[i]));

test('exact nanoseconds survive the native JSON-to-inspector path',()=>{
 assert.equal(metadata.events[0].start,1789398468000000123n);
 assert.equal(metadata.events[0].end,1789398482000000789n);
 assert.equal(metadata.events[0].recordJson,fixture.events[0].recordJson);
});
test('synthetic geometry remains bounded with all source identities and alternatives',()=>{
 const s=m.validateScene(scene());assert.equal(s.sensors.length,7);assert.equal(s.placements.length,7);
 assert.ok(s.mesh.triangles.length>1000 && s.mesh.triangles.length<100000);
 assert.equal(m.bindThreats(s,metadata,now).length,7);
});
test('shared failure domains are exposed without synthesizing independence',()=>{
 const e=metadata.events[0], summary=m.evidenceSummary(e);
 assert.equal(summary.supports,2);assert.equal(summary.contradictions,1);
 assert.equal(summary.namedDomains,1);assert.equal(summary.groups[0].items.length,3);
 assert.equal(summary.uniqueObjects,3);assert.equal(summary.duplicateReferences,0);
 assert.equal(Object.hasOwn(summary,'independentObservations'),false);
});
test('only explicit Supports and Contradicts carry evidential direction',()=>{
 const edges=['supports','contradicts','derived_from','invalidates','supersedes','observed_after','required_by','explains','sensor_tamper','sensor_integrity_restoration'].map((relation,i)=>({relation,digest:`object:${i}`,failureDomain:'shared'}));
 const s=m.evidenceSummary({edges});assert.equal(s.supports,1);assert.equal(s.contradictions,1);assert.equal(s.neutral,8);
});
test('a repeated object reference remains repeated rather than a second observation',()=>{
 const edge={relation:'supports',digest:'same',failureDomain:'domain'};
 const s=m.evidenceSummary({edges:[edge,{...edge}]});assert.equal(s.uniqueObjects,1);assert.equal(s.duplicateReferences,1);assert.equal(s.supports,2);
});
test('unassigned domains never become named independent failure domains',()=>{
 const s=m.evidenceSummary({edges:[{digest:'x',relation:'supports',failureDomain:''}]});
 assert.equal(s.namedDomains,0);assert.equal(s.unassigned,1);
});
test('frontier filtering never mutates or silently filters the spatial inventory',()=>{
 const all=m.bindThreats(scene(),metadata,now), saved=all.map(t=>t.id);
 assert.equal(m.frontierItems(all,'unplaced').length,1);
 assert.ok(m.frontierItems(all,'uncertain').length>0);
 assert.deepEqual(all.map(t=>t.id),saved);assert.equal(all.length,7);
 assert.ok(m.frontierItems(all,'all').every((t,i)=>t===all[i]));
});
test('different authority leaves all seven unresolved events visible and unplaced',()=>{
 const s=scene();s.ledgerRoot='sha256:'+'f'.repeat(64);
 const t=m.bindThreats(s,metadata,now);assert.equal(t.length,7);assert.ok(t.every(t=>t.hypotheses.length===0&&t.knowledge==='unknown'));
});
test('conflicting locations are retained individually, not averaged',()=>{
 const t=m.bindThreats(scene(),metadata,now).find(t=>t.id.endsWith('003'));
 assert.equal(t.knowledge,'conflicted');assert.equal(t.hypotheses.length,2);
 assert.notDeepEqual(t.hypotheses[0].position,t.hypotheses[1].position);
});
test('expired and future-clock positions never retain an observed visual state',()=>{
 const s=scene();const p=s.placements.find(p=>p.knowledge==='observed');p.validForMs=1;
 assert.equal(m.bindThreats(s,metadata,now).find(t=>t.id===p.eventId).knowledge,'stale');
 p.observedAtUnixMs=String(now+100000);
 assert.equal(m.bindThreats(s,metadata,now).find(t=>t.id===p.eventId).age,'clock_conflict');
});
test('all 64 camera declarations remain reachable through bounded wall pages',()=>{
 const sensors=Array.from({length:64},(_,i)=>({id:`camera:${i}`,label:`Camera ${i}`,kind:'camera'}));
 const all=[];for(let page=0;page<11;page++)all.push(...m.sensorPage(sensors,'','all',page).cameras);
 assert.deepEqual(all,sensors);assert.equal(m.sensorPage(sensors,'','all',500).page,10);
});
test('sensor filters preserve zero matches and unavailable declarations',()=>{
 const sensors=scene().sensors;
 assert.equal(m.sensorPage(sensors,'no-match','all').matching.length,0);
 assert.equal(m.sensorPage(sensors,'','other').cameras.length,0);
 assert.equal(m.sensorPage(sensors,'','cameras').readings.length,0);
 assert.equal(m.sensorPage(sensors,'climate','all').readings.length,1);
});
test('asymmetric camera optical center is minus R transpose t, not translation',()=>{
 const pose={rotation:[[1,0,0],[0,0,-1],[0,1,0]],translation:[-3,2,-5]};
 const k={width:800,height:600,fx:400,fy:300,cx:310,cy:260};m.validatePose(pose);
 vec(m.center(pose),[3,5,2]);vec(m.project(pose,k,[3,15,2]),[310,260,10]);vec(m.project(pose,k,[5,15,4]),[390,200,10]);
 assert.equal(m.project(pose,k,[3,4,2]),null);
});
test('fresh camera poses replace old viewpoint references without requiring a renderer',()=>{
 const first=scene(), next=scene();next.sensors[0].label='Fresh registration';
 const view={scene:first,activeCamera:first.sensors[0],target:[0,0,0],invalidate(){}};
 PropertyView.prototype.setScene.call(view,next,[]);assert.equal(view.activeCamera,next.sensors[0]);
 const different=scene();different.frame='different frame';PropertyView.prototype.setScene.call(view,different,[]);assert.equal(view.activeCamera,null);
});
test('removed and redacted cameras cannot survive as an active viewpoint',()=>{
 for(const change of [s=>s.sensors.shift(),s=>{s.sensors[0].status='redacted';},s=>{s.sensors[0].knowledge='redacted';s.sensors[0].pose=null;s.sensors[0].position=null;}]){
  const first=scene(), next=scene();change(next);const view={scene:first,activeCamera:first.sensors[0],target:[0,0,0],invalidate(){}};
  PropertyView.prototype.setScene.call(view,next,[]);assert.equal(view.activeCamera,null);
 }
});
test('geometry uncertainty envelopes retain declared radii and source units',()=>{
 const s=scene(),threats=m.bindThreats(s,metadata,now), t=threats[0];
 const original=structuredClone(t.hypotheses);
 const view={scene:s,threats,bounds:m.sceneBounds(s),layers:{roof:true,frusta:true,threats:true,grid:false},lens:'context',selected:null,activeCamera:null};
 const g=PropertyView.prototype.geometry.call(view);
 assert.ok(g.opaque.length>0&&g.lines.length>0);assert.deepEqual(t.hypotheses,original);
 for(const vertices of Object.values(g))assert.ok(Array.from(vertices).every(Number.isFinite));
});
test('uncertainty lens changes presentation without deleting model surfaces or candidates',()=>{
 const s=scene(),ts=m.bindThreats(s,metadata,now),base={scene:s,threats:ts,bounds:m.sceneBounds(s),layers:{roof:true,frusta:true,threats:true,grid:false},selected:null,activeCamera:null};
 const a=PropertyView.prototype.geometry.call({...base,lens:'context'}),b=PropertyView.prototype.geometry.call({...base,lens:'uncertainty'});
 assert.equal(a.opaque.length,b.opaque.length);assert.equal(a.lines.length,b.lines.length);assert.equal(ts.length,7);
});

test('evidence constellation preserves correlation structure without inventing independence',()=>{
 const first=m.evidenceConstellation(metadata.events[0]);
 assert.equal(first.domains.length,1);
 assert.equal(first.domains[0].references,3);
 assert.equal(first.domains[0].supports,2);
 assert.equal(first.domains[0].contradictions,1);
 assert.equal(first.domains[0].uniqueObjects,3);
 assert.equal(Object.hasOwn(first,'independentObservations'),false);
 const synthetic={edges:[
  {relation:'supports',digest:'a',failureDomain:'domain:b'},
  {relation:'supports',digest:'a',failureDomain:'domain:b'},
  {relation:'contradicts',digest:'c',failureDomain:'domain:a'},
  {relation:'derived_from',digest:'d',failureDomain:''},
 ]};
 const c=m.evidenceConstellation(synthetic);
 assert.deepEqual(c.domains.map(d=>d.name),['domain:b','Failure domain not recorded','domain:a']);
 assert.equal(c.domains[0].repeatedReferences,1);
 assert.equal(c.domains[1].neutral,1);
 assert.equal(c.domains[2].contradictions,1);
});
