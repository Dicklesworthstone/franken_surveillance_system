import * as T from "three";
import { mergeGeometries } from "three/addons/utils/BufferGeometryUtils.js";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { cameras, subjectAt } from "./scenarios.js";

const V = (x,y,z) => new T.Vector3(x,y,z);
const materials = new Map();
function paint(color, glow=false) {
  const key=color+glow;
  if (!materials.has(key)) materials.set(key, new T.MeshStandardMaterial({color,roughness:.81, flatShading:true, ...(glow?{emissive:color,emissiveIntensity:.8}:{})}));
  return materials.get(key);
}
function solid(parent,geo,color,x,y,z,glow=false) {
  const m=new T.Mesh(geo,paint(color,glow)); m.position.set(x,y,z); parent.add(m); return m;
}
const box=(p,x,y,z,w,h,d,c,g=false)=>solid(p,new T.BoxGeometry(w,h,d),c,x,y,z,g);
const cylinder=(p,x,y,z,rt,rb,h,c,n=12)=>solid(p,new T.CylinderGeometry(rt,rb,h,n),c,x,y,z);
function ell(p,x,y,z,a,b,c,color) { const m=solid(p,new T.IcosahedronGeometry(1,1),color,x,y,z);m.scale.set(a,b,c);return m; }
function rod(p,a,b,r,color) {const dir=V(...b).sub(V(...a)),m=cylinder(p,0,0,0,r,r,dir.length(),color,7);m.position.copy(V(...a).add(V(...b)).multiplyScalar(.5));m.quaternion.setFromUnitVectors(V(0,1,0),dir.normalize());return m;}
function bake(group) {
  const batches=new Map();group.updateWorldMatrix(true,true);
  for(const m of [...group.children]) {
    if(!m.isMesh) continue;
    const geo=m.geometry.index?m.geometry.toNonIndexed():m.geometry.clone();
    geo.applyMatrix4(m.matrix);geo.deleteAttribute("uv");geo.deleteAttribute("color");
    if(!batches.has(m.material))batches.set(m.material,[]);
    batches.get(m.material).push(geo);m.geometry.dispose();group.remove(m);
  }
  for(const [material,geos] of batches){const merged=mergeGeometries(geos);for(const g of geos)g.dispose();const mesh=new T.Mesh(merged,material);mesh.castShadow=mesh.receiveShadow=true;group.add(mesh);}
}
function house(p) {
  const siding="#c0b79d", roof="#394b52", trim="#dfd8bd", wood="#90674e";
  box(p,-1.2,1.78,-1.35,7.4,3.56,5.1,siding);
  for(let k=0;k<14;k++){let y=.2+k*.245;box(p,-1.2,y,1.215,7.42,.035,.055,"#a09882");box(p,-4.91,y,-1.35,.055,.035,5.1,"#a09882");}
  const pitch=.45;
  for(const sign of [-1,1]){
    const panel=box(p,-1.2+sign*2.02,4.43,-1.35,4.57,.18,5.85,roof);panel.rotation.z=-sign*pitch;
    for(let z=-4.14;z<=1.54;z+=.39){let seam=box(p,panel.position.x,4.54,z,4.57,.035,.038,"#526168");seam.rotation.z=panel.rotation.z;}
    for(const z of [-4.29,1.59]){let edge=box(p,panel.position.x,4.40,z,4.58,.17,.12,trim);edge.rotation.z=panel.rotation.z;}
  }
  const shape=new T.Shape();shape.moveTo(-3.7,0);shape.lineTo(3.7,0);shape.lineTo(0,1.8);shape.closePath();
  const gable=solid(p,new T.ExtrudeGeometry(shape,{depth:5.09,bevelEnabled:false}),siding,-1.2,3.5,-3.9);
  gable.castShadow=true;
  box(p,-1.2,4.05,1.24,1.14,.57,.08,wood);
  for(let i=0;i<4;i++)box(p,-1.2,3.85+i*.12,1.29,1.04,.038,.06,"#3f4540");
  function window(x,z,w,h,side=false){
    const win=new T.Group();win.position.set(x,1.92,z);if(side)win.rotation.y=-Math.PI/2;
    box(win,0,0,0,w+.16,h+.17,.12,trim);box(win,0,0,.085,w,h,.06,"#ffc27b",true);
    box(win,0,0,.133,.065,h,.05,wood);box(win,0,.04,.133,w,.06,.05,wood);
    win.updateMatrix();for(const m of [...win.children]){m.applyMatrix4(win.matrix);p.add(m);}
  }
  window(-3.5,1.25,1.5,1.5);window(.95,1.25,1.4,1.5);window(-4.97,-.05,1.6,1.45,true);window(-4.97,-2.4,1.24,1.4,true);
  box(p,-1.35,1.25,1.28,1.13,2.48,.14,wood);box(p,-1.35,1.76,1.37,.61,.95,.05,"#ffc78a",true);
  box(p,-1.28,.2,2.05,4.7,.4,1.8,"#9e8b74");
  for(let i=0;i<3;i++)box(p,-1.27,.07+i*.057,3.66-i*.26,2.15,.14+i*.11,.40,"#b5ab94");
  for(const x of [-3.42,.84])box(p,x,1.63,2.75,.16,2.8,.16,trim);
  const awning=box(p,-1.28,3.02,2.02,4.8,.16,2.1,roof);awning.rotation.x=.12;
  for(const x of [-2.23,-.5]){box(p,x,2.03,1.39,.18,.36,.18,"#ffca87",true);}
  box(p,4.28,1.38,-.95,4.28,2.76,5.4,"#989e8d");
  box(p,4.28,2.84,-.95,4.7,.22,5.82,roof);box(p,4.28,1.19,1.79,3.61,2.30,.1,wood);
  for(let i=0;i<8;i++)box(p,4.28,.25+i*.27,1.86,3.58,.035,.05,"#675143");
  for(let i=0;i<4;i++)box(p,3.02+i*.84,2.09,1.87,.62,.26,.04,"#eac595",true);
  box(p,.4,4.52,-2.7,.75,2,.79,"#8d7568");box(p,.4,5.55,-2.7,.9,.13,.93,"#655f58");
}
function lot(p) {
  box(p,0,-.55,0,21.4,.95,18.3,"#5d6455");box(p,0,-.10,0,21.4,.2,18.3,"#77865b");
  box(p,0,.018,8.4,21.45,.07,1.23,"#a5a695");box(p,0,.01,9.77,21.45,.13,1.5,"#677274");
  box(p,4.55,.015,4.55,4.25,.08,6.2,"#aea99b");
  for(let i=0;i<7;i++)box(p,-1.28,.055,4.04+i*.57,1.57,.10,.42,"#cec3a9");
  const wood="#a99a79";
  function fence(x,z,len,along){for(let a=0;a<=len;a+=.43)box(p,x+(along?a:0),.61,z+(along?0:a),along?.29:.13,1.22,along?.13:.29,wood);for(const y of [.30,.90])box(p,x+(along?len/2:0),y,z+(along?0:len/2),along?len:.13,.12,along?.13:len,"#867a60");}
  fence(-10,-8,20,true);fence(-10,-8,14,false);fence(10,-8,14,false);
  let seed=283;const rand=()=>((seed=(1664525*seed+1013904223)>>>0)/4294967296);
  function tree(x,z,h) {
    cylinder(p,x,h*.22,z,.18,.36,h*.44,"#765f4c",7);
    for(let i=0;i<8;i++){const a=i*2.4,rr=i?1.0:0;ell(p,x+Math.cos(a)*rr,h*(i===0?.86:.65+rand()*.13),z+Math.sin(a)*rr,1.20+rand()*.32,1.4+rand()*.5,1.2+rand()*.3,["#476a48","#628254","#78905b","#597950"][i%4]);}
  }
  for(const [x,z,h] of [[-8,-5,5.6],[8.0,-5.9,6.1],[-8.7,5.7,4.1],[7.9,5.5,4.1],[.2,-6.5,5.3]])tree(x,z,h);
  for(let i=0;i<11;i++)ell(p,-4.65+i*.61,.35,-4.36,.60,.48,.44,"#628053");
  for(const [x,z] of [[-4.2,2],[-3.7,2.7],[1.3,2.2],[-5.5,-.4],[-7.7,.5],[7.6,2.7]]){ell(p,x,.36,z,.68,.47,.60,"#657d49");}
  for(let i=0;i<60;i++){const x=rand()*19-9.5,z=rand()*15-7.5;if(x>-5.5&&x<6.9&&z<2.4||Math.abs(x+1.25)<1.1||x>2&&x<7)continue;ell(p,x,.045,z,.10+rand()*.13,.05,.13,"#899764");}
  for(const x of [-7.4,-6.7]){box(p,x,.57,.08,.59,1.1,.68,"#526560");box(p,x,1.16,.08,.68,.12,.75,"#364a46");}
  for(const z of [4.25,6.7]){cylinder(p,-2.42,.26,z,.07,.09,.52,"#495750");cylinder(p,-2.42,.55,z,.11,.11,.15,"#ffe0a1").material=paint("#ffe0a1",true);}
  // Parked estate car, offset from the driveway walking path.
  box(p,5.81,.66,3.56,1.54,.62,3.18,"#9cae9c");box(p,5.81,1.08,3.45,1.29,.49,1.75,"#41585a");
  box(p,5.81,1.34,3.42,1.30,.12,1.66,"#a8b8a5");for(const x of [5.05,6.56])for(const z of [2.52,4.55]){let w=cylinder(p,x,.39,z,.32,.32,.16,"#30373a");w.rotation.z=Math.PI/2;}
  for(const x of [5.30,6.30])box(p,x,.66,5.16,.32,.15,.06,"#ebdcc0");
}
function actor(animal,delivery) {
  const p=new T.Group(), limbs=[];
  if(animal) {
    ell(p,0,.40,0,.26,.29,.54,"#99968a");ell(p,0,.57,.40,.23,.21,.26,"#a5a191");ell(p,0,.59,.565,.216,.085,.13,"#33383b");ell(p,0,.54,.66,.09,.065,.08,"#2c3232");
    for(const x of [-.15,.15]){let ear=solid(p,new T.ConeGeometry(.103,.15,4),"#57595a",x,.77,.34);ear.rotation.y=.7;}
    for(let i=0;i<6;i++)ell(p,0,.45+i*.02,-.4-i*.11,.14-i*.008,.14-i*.008,.15,i%2?"#444b49":"#a6a295");
    for(const x of [-.15,.15])for(const z of [-.24,.25])limbs.push(box(p,x,.18,z,.095,.23,.12,"#454947"));
  } else {
    ell(p,0,1.58,0,.152,.195,.152,"#bc896c");
    ell(p,0,1.72,-.013,.16,.11,.155,delivery?"#566c82":"#3d4246");
    box(p,0,1.16,0,.44,.60,.26,delivery?"#447c9b":"#665766");
    for(const x of [-.24,.24]){let arm=box(p,x,1.13,delivery?.13:0,.12,.48,.14,delivery?"#527f95":"#665766");if(delivery)arm.rotation.x=-.68;}
    for(const x of [-.12,.12]){let leg=new T.Group();leg.position.set(x,.91,0);box(leg,0,-.41,0,.16,.72,.18,"#394547");box(leg,0,-.79,.042,.19,.13,.28,"#3b3938");p.add(leg);limbs.push(leg);}
    if(delivery){box(p,0,1.00,.32,.43,.29,.35,"#bf935e");box(p,0,1.151,.32,.068,.006,.35,"#ead1a0");}
  }
  return {group:p,limbs};
}
export function createProperty(canvas, interactive=true) {
  const renderer=new T.WebGLRenderer({canvas,antialias:true,alpha:false,preserveDrawingBuffer:!interactive,powerPreference:"low-power"});
  renderer.setPixelRatio(interactive?Math.min(devicePixelRatio,1.6):1);
  renderer.outputColorSpace=T.SRGBColorSpace;renderer.toneMapping=T.ACESFilmicToneMapping;renderer.toneMappingExposure=1.28;
  renderer.shadowMap.enabled=true;renderer.shadowMap.type=T.PCFSoftShadowMap;
  const scene=new T.Scene();scene.background=new T.Color("#26383c");scene.fog=new T.FogExp2("#283c40",.016);
  const sky=new T.HemisphereLight("#dfebf3","#929278",2.15);scene.add(sky);
  const sun=new T.DirectionalLight("#ffe4b2",3.2);sun.position.set(-13,19,12);sun.castShadow=true;
  Object.assign(sun.shadow.camera,{left:-17,right:17,top:17,bottom:-17,near:.5,far:60});sun.shadow.mapSize.set(interactive?1024:1024,1024);sun.shadow.bias=-.0004;scene.add(sun);
  const ground=solid(scene,new T.PlaneGeometry(260,260),"#314344",0,-1.06,0);ground.rotation.x=-Math.PI/2;ground.receiveShadow=true;
  const grid=new T.GridHelper(120,80,"#566765","#46595a");grid.position.y=-1.04;scene.add(grid);
  const staticObjects=new T.Group();scene.add(staticObjects);house(staticObjects);lot(staticObjects);bake(staticObjects);
  const overview=new T.PerspectiveCamera(36,1,.1,180);
  const home=()=>{overview.position.set(-21,16.5,24);overview.lookAt(0,.75,.1);};home();
  const orbit=interactive?new OrbitControls(overview,canvas):null;
  if(orbit){orbit.target.set(0,.75,.1);orbit.enablePan=false;orbit.minDistance=18;orbit.maxDistance=48;orbit.maxPolarAngle=Math.PI*.47;orbit.minPolarAngle=.25;orbit.enableDamping=false;orbit.update();}
  const fixed={},markers=new T.Group();scene.add(markers);
  for(const c of cameras){const cam=new T.PerspectiveCamera(c.fov,1,.1,100);cam.position.set(...c.position);cam.lookAt(...c.target);cam.updateMatrixWorld();fixed[c.id]=cam;
    const base=V(...c.position),forward=V(...c.target).sub(base).setY(0).normalize(),side=V(forward.z,0,-forward.x);
    const end=base.clone().addScaledVector(forward,4).setY(.08),a=end.clone().addScaledVector(side,1.65),b=end.clone().addScaledVector(side,-1.65);
    const points=[base,a,b,base];const line=new T.Line(new T.BufferGeometry().setFromPoints(points),new T.LineBasicMaterial({color:"#ccf097",transparent:true,opacity:.66}));markers.add(line);
    const panel=new T.BufferGeometry().setFromPoints([base,a,b]);markers.add(new T.Mesh(panel,new T.MeshBasicMaterial({color:"#c6e98b",side:T.DoubleSide,transparent:true,opacity:.065,depthWrite:false})));
    ell(markers,...c.position,.13,.13,.13,"#cefa77");
  }
  const people={delivery:actor(false,true),visitor:actor(false,false),wildlife:actor(true,false)};
  for(const {group} of Object.values(people)){scene.add(group);group.traverse(m=>{if(m.isMesh)m.castShadow=true;});}
  const occluders=[new T.Box3(V(-4.9,0,-3.90),V(2.5,3.55,1.2)),new T.Box3(V(2.13,0,-3.65),V(6.42,2.76,1.75))];
  let aspect=1;
  return {
    resize(w,h){if(w<=0||h<=0)return;aspect=w/h;renderer.setSize(w,h,false);for(const cam of [overview,...Object.values(fixed)]){cam.aspect=aspect;cam.updateProjectionMatrix();}},
    onOrbit(fn){orbit?.addEventListener("change",fn);},
    reset(){home();if(orbit){orbit.target.set(0,.75,.1);orbit.update();}},
    draw(s,t,view="overview",showCoverage=true) {
      const a=subjectAt(s,t), chosen=people[s.id];for(const v of Object.values(people))v.group.visible=v===chosen;
      chosen.group.position.set(a.x,.09,a.z);chosen.group.rotation.y=a.yaw;
      chosen.limbs.forEach((l,i)=>l.rotation.x=a.moving?Math.sin(t*6.5+i*Math.PI)*.36:0);
      const dusk=s.id==="delivery";sky.intensity=dusk?2.15:1.18;sun.intensity=dusk?3.2:1.2;sun.color.set(dusk?"#ffe4b2":"#a8c9f7");
      scene.background.set(dusk?"#31464a":"#23363c");scene.fog.color.copy(scene.background);
      const cam=view==="overview"?overview:fixed[view];markers.visible=view==="overview"&&showCoverage;
      if(orbit)orbit.enabled=view==="overview";
      if(cam===overview){overview.fov=aspect<1.25?Math.min(66,36*1.25/aspect):36;overview.updateProjectionMatrix();}
      cam.updateMatrixWorld();renderer.render(scene,cam);
      const sensor=fixed[view==="overview"?s.camera:view], height=s.id==="wildlife"?.83:1.85;
      const center=V(a.x,height*.55,a.z), ray=new T.Ray(sensor.position,center.clone().sub(sensor.position).normalize());
      const blocked=occluders.some(bounds=>{const hit=ray.intersectBox(bounds,new T.Vector3());return hit&&hit.distanceTo(sensor.position)<center.distanceTo(sensor.position);});
      const screen=center.clone().project(sensor);
      const visible=!blocked && Math.abs(screen.x)<1 && Math.abs(screen.y)<1 && Math.abs(screen.z)<1;
      const coord=(world)=>{const v=world.project(cam);return [(v.x+1)*50,(1-v.y)*50];};
      const foot=coord(V(a.x,.03,a.z)),head=coord(V(a.x,height+.12,a.z));
      return {visible,inZone:a.inZone,foot,head};
    },
    dispose(){orbit?.dispose();scene.traverse(obj=>{obj.geometry?.dispose();if(obj.material)obj.material.dispose?.();});for(const m of materials.values())m.dispose();materials.clear();renderer.dispose();renderer.forceContextLoss();}
  };
}
