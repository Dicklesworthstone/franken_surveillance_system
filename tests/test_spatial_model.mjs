// Pure geometry/epistemic presentation contracts; no npm install or network.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const web = new URL('../crates/fss-cli/src/bin/fss-dashboard/web/', import.meta.url);
const source = await readFile(new URL('spatial-model.js', web), 'utf8');
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const m = await import(moduleUrl);
const demoSource = (await readFile(new URL('demo-scene.js',web),'utf8')).replace("'./spatial-model.js'",JSON.stringify(moduleUrl));
const {makeDemoScene} = await import(`data:text/javascript;base64,${Buffer.from(demoSource).toString('base64')}`);
const d = n => 'sha256:'+String(n).padStart(64,'0');
const metadata = {site:'site:spatial-test',ledgerRoot:d(100),events:Array.from({length:9},(_,i)=>({id:`event:demo:${String(i+1).padStart(3,'0')}`,revisionDigest:d(i+1),kind:i===3||i===6?'benign_routine':i===2?'sensor_tamper':'unknown_presence',state:i===3?'resolved':i===6?'rejected':i===1?'corroborated':'indeterminate'}))};
const scene = () => makeDemoScene(metadata);
const now = 1789398500000;
const near = (a,b,tolerance=1e-9) => assert.ok(Math.abs(a-b)<tolerance,`${a} != ${b}`);
const equalVector=(a,b)=>a.forEach((v,i)=>near(v,b[i]));
const pose={rotation:[[1,0,0],[0,0,-1],[0,1,0]],translation:[-3,2,-5]};
const k={width:800,height:600,fx:400,fy:300,cx:310,cy:260};

test('asymmetric Z-up camera has independently known center, optical axis and right/up controls',()=>{
  m.validatePose(pose);
  equalVector(m.center(pose),[3,5,2]);
  equalVector(m.project(pose,k,[3,15,2]),[310,260,10]);
  equalVector(m.project(pose,k,[5,15,2]),[390,260,10]);
  equalVector(m.project(pose,k,[3,15,4]),[310,200,10]);
  assert.equal(m.project(pose,k,[3,4,2]),null);
});
test('lookAt produces the independently specified asymmetric rotation rather than its inverse',()=>{
  const actual=m.lookAt([3,5,2],[3,15,2]);
  actual.rotation.forEach((r,i)=>equalVector(r,pose.rotation[i]));
  equalVector(actual.translation,pose.translation);
});
test('pinhole frustum corners preserve off-center intrinsics and source pixel-edge coordinates',()=>{
  const corners=m.frustum(pose,k,10);
  const expected=[[0,0],[800,0],[800,600],[0,600]];
  corners.forEach((p,i)=>equalVector(m.project(pose,k,p),[...expected[i],10]));
  equalVector(corners[0],[-4.75,15,10.666666666666666]);
});
test('WebGL clip coordinates match independent pinhole coordinates including off-center crop',()=>{
  const matrix=m.cameraMatrix(pose,k,.05,100);
  for(const p of [[3,15,2],[5,15,4],[-1,9,3]]){
    const v=[...p,1], clip=Array.from({length:4},(_,r)=>v.reduce((s,n,c)=>s+matrix[c*4+r]*n,0));
    const image=m.project(pose,k,p);
    near((clip[0]/clip[3]+1)*k.width/2,image[0],1e-4);
    near((1-clip[1]/clip[3])*k.height/2,image[1],1e-4);
    assert.ok(clip[2]/clip[3]>-1&&clip[2]/clip[3]<1);
  }
});
test('reflection, singular rotation and nonfinite transforms are refused',()=>{
  for(const rotation of [[[1,0,0],[0,1,0],[0,0,-1]],[[0,0,0],[0,1,0],[0,0,1]],[[2,0,0],[0,1,0],[0,0,1]],[[NaN,0,0],[0,1,0],[0,0,1]]])assert.throws(()=>m.validatePose({rotation,translation:[0,0,0]}));
});
test('the demonstration is a complete bounded scene with four cameras and three other sensors',()=>{
  const s=m.validateScene(scene());
  assert.equal(s.sensors.filter(s=>s.kind==='camera').length,4);
  assert.equal(s.sensors.filter(s=>s.kind!=='camera').length,3);
  assert.ok(s.mesh.triangles.length>300);
  assert.equal(s.placements.length,7);
});
test('all unresolved candidates remain present, including unknown locations and all conflicted alternatives',()=>{
  const bound=m.bindThreats(scene(),metadata,now);
  assert.equal(bound.length,7);
  assert.equal(bound.filter(t=>t.hypotheses.length).length,6);
  const unknown=bound.find(t=>t.id.endsWith('005'));assert.equal(unknown.knowledge,'unknown');assert.equal(unknown.hypotheses.length,0);
  const conflict=bound.find(t=>t.id.endsWith('003'));assert.equal(conflict.knowledge,'conflicted');assert.equal(conflict.hypotheses.length,2);
});
test('event lifecycle, position knowledge and severity are independent axes',()=>{
  const bound=m.bindThreats(scene(),metadata,now);
  const event=bound.find(t=>t.id.endsWith('001'));assert.equal(event.state,'indeterminate');assert.equal(event.knowledge,'inferred');assert.equal(event.severity,'high');
  assert.equal(bound.find(t=>t.id.endsWith('002')).state,'corroborated');
});
test('a changed authority root unplaces every candidate instead of guessing continuity',()=>{
  const s=scene();s.ledgerRoot=d(101);
  const bound=m.bindThreats(s,metadata,now);
  assert.equal(bound.length,7);assert.ok(bound.every(t=>!t.hypotheses.length&&t.knowledge==='unknown'&&t.localization===null));
});
test('a revised event does not inherit coordinates or declared severity from its predecessor',()=>{
  const s=scene();s.placements[0].revisionDigest=d(55);
  const first=m.bindThreats(s,metadata,now)[0];assert.equal(first.hypotheses.length,0);assert.equal(first.severity,'unrated');assert.match(first.reason,/different/);
});
test('no supplied scene leaves every unresolved event visible and unplaced',()=>{
  const bound=m.bindThreats(null,metadata,now);assert.equal(bound.length,7);assert.ok(bound.every(t=>t.hypotheses.length===0));
});
test('expiry and a future clock never preserve a recent-looking position',()=>{
  const s=scene();s.placements[0].validForMs=5;
  assert.equal(m.bindThreats(s,metadata,now)[0].knowledge,'stale');
  s.placements[0].observedAtUnixMs=String(now+60000);
  const t=m.bindThreats(s,metadata,now)[0];assert.equal(t.age,'clock_conflict');assert.equal(t.knowledge,'stale');
});
test('freshness distinguishes exact deadline, stale, invalid timestamp and clock conflict',()=>{
  assert.equal(m.freshness(String(now-30000),30000,now),'recent');
  assert.equal(m.freshness(String(now-30001),30000,now),'stale');
  assert.equal(m.freshness('bad',30000,now),'unknown');
  assert.equal(m.freshness(String(now+3000),30000,now),'clock_conflict');
});
for(const[name,edit]of[
 ['reflection',s=>{s.sensors[0].pose.rotation[0]=s.sensors[0].pose.rotation[0].map(n=>-n);}],
 ['wrong camera center',s=>{s.sensors[0].position=[0,0,0];}],
 ['invalid focal length',s=>{s.sensors[0].intrinsics.fx=0;}],
 ['raw distorted image domain',s=>{s.sensors[0].intrinsics.imageDomain='raw';}],
 ['unknown sensor with coordinates',s=>{s.sensors[0].knowledge='unknown';}],
 ['duplicate sensor',s=>{s.sensors.push(s.sensors[0]);}],
 ['invalid mesh reference',s=>{s.mesh.triangles[0][0]=s.mesh.vertices.length;}],
 ['invalid material reference',s=>{s.mesh.triangles[0][3]=32;}],
 ['nonfinite vertex',s=>{s.mesh.vertices[0][0]=Infinity;}],
 ['negative envelope radius',s=>{s.placements[0].hypotheses[0].radii[0]=-1;}],
 ['too many spatial alternatives',s=>{s.placements[0].hypotheses=Array(9).fill(s.placements[0].hypotheses[0]);}],
 ['redacted coordinate disclosure',s=>{s.placements[0].knowledge='redacted';}],
 ['missing position anchor',s=>{s.ledgerRoot=null;}],
 ['duplicate localization',s=>{s.placements.push(s.placements[0]);}],
 ['invalid severity',s=>{s.placements[0].severity='confirmed';}],
])test(`${name} is refused before rendering`,()=>{const s=scene();edit(s);assert.throws(()=>m.validateScene(s));});

const viewSource=(await readFile(new URL('view3d.js',web),'utf8')).replace("'./spatial-model.js'",JSON.stringify(moduleUrl));
const {PropertyView}=await import(`data:text/javascript;base64,${Buffer.from(viewSource).toString('base64')}`);
test('active camera viewpoint is rebound to the fresh pose rather than retaining an old object',()=>{
  const first=scene(),next=scene();next.sensors[0].label='New pose generation';
  const view={scene:first,activeCamera:first.sensors[0],target:[0,0,0],invalidate(){}};
  PropertyView.prototype.setScene.call(view,next,[]);
  assert.equal(view.activeCamera,next.sensors[0]);
  const changed=scene();changed.frame='different-coordinate-frame';
  PropertyView.prototype.setScene.call(view,changed,[]);assert.equal(view.activeCamera,null);
});
test('a removed or redacted camera cannot survive as the active viewpoint',()=>{
  for(const change of [s=>{s.sensors.shift();},s=>{s.sensors[0].knowledge='redacted';s.sensors[0].pose=null;s.sensors[0].position=null;}]){
    const first=scene(),next=scene();change(next);
    const view={scene:first,activeCamera:first.sensors[0],target:[0,0,0],invalidate(){}};
    PropertyView.prototype.setScene.call(view,next,[]);assert.equal(view.activeCamera,null);
  }
});
