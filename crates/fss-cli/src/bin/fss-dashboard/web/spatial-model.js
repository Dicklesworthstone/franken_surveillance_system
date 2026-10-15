// Presentation geometry only. Native coordinates: right-handed Z-up; Xc = R Xw + t.
export const SCENE_FORMAT = 'fss.operator_scene.v1';
export const MAX_SCENE_BYTES = 8 * 1024 * 1024;
export const STATES = ['observed', 'inferred', 'conflicted', 'unknown', 'not_observable', 'redacted', 'stale'];
export const SEVERITIES = ['low', 'medium', 'high', 'critical'];
export const add = (a,b) => a.map((v,i)=>v+b[i]);
export const sub = (a,b) => a.map((v,i)=>v-b[i]);
export const mul = (a,s) => a.map(v=>v*s);
export const dot = (a,b) => a.reduce((s,v,i)=>s+v*b[i],0);
export const cross = (a,b) => [a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]];
export const norm = a => Math.hypot(...a);
export const unit = a => { const n=norm(a); if(n<1e-12) throw Error('Degenerate direction'); return mul(a,1/n); };
export const mv = (r,p) => r.map(row=>dot(row,p));
export const transpose = r => r[0].map((_,i)=>r.map(row=>row[i]));
export const center = pose => mul(mv(transpose(pose.rotation),pose.translation),-1);
export const transform = (pose,p) => add(mv(pose.rotation,p),pose.translation);
export function lookAt(eye,target,up=[0,0,1]) {
  const forward=unit(sub(target,eye)), right=unit(cross(forward,up)), down=cross(forward,right);
  const rotation=[right,down,forward]; return {rotation,translation:mul(mv(rotation,eye),-1)};
}
export function project(pose,k,p) {
  const c=transform(pose,p); if(c[2]<=1e-6) return null;
  return [k.fx*c[0]/c[2]+k.cx,k.fy*c[1]/c[2]+k.cy,c[2]];
}
export function frustum(pose,k,d) {
  const c=center(pose), rt=transpose(pose.rotation);
  return [[0,0],[k.width,0],[k.width,k.height],[0,k.height]].map(([x,y])=>add(c,mv(rt,[(x-k.cx)*d/k.fx,(y-k.cy)*d/k.fy,d])));
}
export function cameraMatrix(pose,k,near=.05,far=2000) {
  const r=pose.rotation,t=pose.translation;
  const view=[r[0][0],r[1][0],r[2][0],0,r[0][1],r[1][1],r[2][1],0,r[0][2],r[1][2],r[2][2],0,t[0],t[1],t[2],1];
  const projection=[2*k.fx/k.width,0,0,0,0,-2*k.fy/k.height,0,0,2*k.cx/k.width-1,1-2*k.cy/k.height,(far+near)/(far-near),1,0,0,-2*far*near/(far-near),0];
  const out=new Float32Array(16);
  for(let col=0;col<4;col++) for(let row=0;row<4;row++) for(let i=0;i<4;i++) out[col*4+row]+=projection[i*4+row]*view[col*4+i];
  return out;
}
const assert=(v,m)=>{if(!v)throw Error(m);};
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=1e6;
const vector=p=>Array.isArray(p)&&p.length===3&&p.every(finite);
const text=(s,n=512)=>typeof s==='string'&&s.length>0&&s.length<=n;
const digest=s=>typeof s==='string'&&/^sha256:[a-f0-9]{64}$/.test(s);
export function validatePose(pose) {
  assert(pose&&Array.isArray(pose.rotation)&&pose.rotation.length===3&&pose.rotation.every(vector)&&vector(pose.translation),'Invalid world-to-camera transform');
  const r=pose.rotation;
  for(let i=0;i<3;i++) for(let j=0;j<3;j++) assert(Math.abs(dot(r[i],r[j])-(i===j?1:0))<1e-8,'Camera rotation is not orthonormal');
  assert(Math.abs(dot(r[0],cross(r[1],r[2]))-1)<1e-8,'Camera rotation is reflected');
  return pose;
}
export function validateScene(scene) {
  assert(scene&&scene.format===SCENE_FORMAT,'Unsupported spatial projection');
  assert(text(scene.site)&&text(scene.frame)&&['relative','estimated','measured'].includes(scene.scale?.kind),'Missing coordinate/scale declaration');
  assert(scene.scale.kind==='relative'||(finite(scene.scale.metresPerUnit)&&scene.scale.metresPerUnit>0),'Invalid metric scale');
  assert(scene.ledgerRoot===null||digest(scene.ledgerRoot),'Invalid scene anchor');
  assert(scene.mesh&&Array.isArray(scene.mesh.vertices)&&scene.mesh.vertices.length<=65536&&scene.mesh.vertices.every(vector),'Invalid or excessive vertices');
  assert(Array.isArray(scene.mesh.materials)&&scene.mesh.materials.length<=32&&scene.mesh.materials.every(m=>text(m.name)&&text(m.role)&&Array.isArray(m.color)&&m.color.length===3&&m.color.every(n=>finite(n)&&n>=0&&n<=1)),'Invalid material');
  assert(Array.isArray(scene.mesh.triangles)&&scene.mesh.triangles.length<=100000,'Excessive triangle count');
  for(const tri of scene.mesh.triangles) assert(Array.isArray(tri)&&tri.length===4&&tri.every(Number.isSafeInteger)&&tri.slice(0,3).every(i=>i>=0&&i<scene.mesh.vertices.length)&&tri[3]>=0&&tri[3]<scene.mesh.materials.length,'Invalid triangle reference');
  assert(Array.isArray(scene.sensors)&&scene.sensors.length<=64,'Invalid sensor inventory');
  const ids=new Set();
  for(const sensor of scene.sensors) {
    assert(text(sensor.id)&&text(sensor.label)&&!ids.has(sensor.id),'Duplicate or invalid sensor'); ids.add(sensor.id);
    assert(['camera','motion','contact','temperature','smoke','audio','other'].includes(sensor.kind),'Unknown sensor kind');
    assert(['available','offline','unknown','redacted'].includes(sensor.status),'Unknown sensor status');
    assert(sensor.position===null||vector(sensor.position),'Invalid sensor location');
    assert(text(sensor.basis)&&STATES.includes(sensor.knowledge),'Missing sensor basis/knowledge');
    if(sensor.pose!==null) {
      validatePose(sensor.pose); assert(sensor.kind==='camera','Only cameras carry optical transforms');
      const k=sensor.intrinsics;
      assert(k&&['fx','fy','cx','cy','width','height'].every(n=>finite(k[n]))&&k.fx>0&&k.fy>0&&k.width>0&&k.height>0&&k.width<=8192&&k.height<=8192&&k.imageDomain==='undistorted_pinhole','Invalid camera intrinsics/image domain');
      assert(sensor.position===null||norm(sub(center(sensor.pose),sensor.position))<1e-6,'Camera origin does not equal -Rᵀt');
    }
    assert(!['unknown','not_observable','redacted'].includes(sensor.knowledge)||(sensor.position===null&&sensor.pose===null),'Unknown sensor location must not expose coordinates');
    assert(sensor.frame===null||(digest(sensor.frame.digest)&&text(sensor.frame.capturedAtUnixMs)&&text(sensor.frame.privacy)&&digest(sensor.frame.sourceDigest)),'Invalid frame declaration');
    if(sensor.reading!==null) assert(finite(sensor.reading.value)&&text(sensor.reading.unit,32)&&text(sensor.reading.observedAtUnixMs),'Invalid sensor reading');
  }
  assert(Array.isArray(scene.placements)&&scene.placements.length<=256,'Invalid localization inventory');
  const events=new Set();
  for(const p of scene.placements) {
    assert(text(p.eventId)&&digest(p.revisionDigest)&&!events.has(p.eventId),'Duplicate or unbound localization'); events.add(p.eventId);
    assert(STATES.includes(p.knowledge)&&SEVERITIES.includes(p.severity)&&text(p.basis)&&text(p.observedAtUnixMs)&&Number.isSafeInteger(p.validForMs)&&p.validForMs>=0&&p.validForMs<=3600000,'Invalid localization basis');
    assert(['person','animal','vehicle','unknown'].includes(p.shape),'Unknown visual class');
    assert(Array.isArray(p.hypotheses)&&p.hypotheses.length<=8,'Localization hypotheses exceed bound');
    for(const h of p.hypotheses) assert(vector(h.position)&&vector(h.radii)&&h.radii.every(n=>n>=0&&n<=1000),'Invalid spatial uncertainty envelope');
    assert(!['unknown','not_observable','redacted'].includes(p.knowledge)||p.hypotheses.length===0,'Unknown/redacted location must not expose coordinates');
  }
  assert(scene.placements.length===0||digest(scene.ledgerRoot),'Localizations require an exact authority root');
  return scene;
}
export function freshness(timestamp,validFor,now=Date.now()) {
  if(typeof timestamp!=='string'||!/^\d{1,16}$/.test(timestamp)||!Number.isSafeInteger(Number(timestamp))) return 'unknown';
  const age=now-Number(timestamp); if(age < -2000) return 'clock_conflict';
  return age>validFor?'stale':'recent';
}
export function bindThreats(scene,metadata,now=Date.now()) {
  const declared=new Map((scene?.placements??[]).map(p=>[p.eventId,p]));
  return metadata.events.filter(e=>!['resolved','rejected'].includes(e.state)&&e.kind!=='benign_routine').map(e=>{
    const p=declared.get(e.id), matched=!!p&&p.revisionDigest===e.revisionDigest&&scene.ledgerRoot===metadata.ledgerRoot;
    const age=matched?freshness(p.observedAtUnixMs,p.validForMs,now):'unknown';
    const knowledge=age==='stale'||age==='clock_conflict'?'stale':matched?p.knowledge:'unknown';
    return {...e,localization:matched?p:null,knowledge,age,severity:matched?p.severity:'unrated',shape:matched?p.shape:'unknown',hypotheses:matched?p.hypotheses:[],reason:matched?null:p?'Localization is pinned to a different event revision or authority root.':'No world localization retained for this event.'};
  });
}
export function sceneBounds(scene) {
  const points=[...scene.mesh.vertices,...scene.sensors.flatMap(s=>s.pose?[center(s.pose)]:s.position?[s.position]:[])];
  if(!points.length)return{center:[0,0,0],radius:20};
  const low=[Infinity,Infinity,Infinity],high=[-Infinity,-Infinity,-Infinity];
  for(const p of points)for(let i=0;i<3;i++){low[i]=Math.min(low[i],p[i]);high[i]=Math.max(high[i],p[i]);}
  return{center:mul(add(low,high),.5),radius:Math.max(2,norm(sub(high,low))*.55)};
}
