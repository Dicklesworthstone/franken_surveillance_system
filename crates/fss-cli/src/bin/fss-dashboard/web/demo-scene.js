// Synthetic architectural display fixture only. Never selected after a failed real read.
import {lookAt} from './spatial-model.js';
export function makeDemoScene(metadata) {
  const vertices=[], triangles=[];
  const materials=[
    ['Lawn','terrain',[.30,.43,.34]], ['Limestone facade','structure',[.82,.79,.68]],
    ['Graphite standing seam','roof',[.32,.39,.41]], ['Poured concrete','path',[.62,.64,.61]],
    ['Cedar','structure',[.60,.43,.27]], ['Canopy','vegetation',[.29,.47,.34]],
    ['Trunk','vegetation',[.38,.32,.24]], ['Boundary','boundary',[.53,.56,.48]],
    ['Pool water','water',[.24,.59,.64]], ['Glazing','structure',[.27,.45,.49]],
    ['Travertine','path',[.79,.77,.67]], ['Lawn stripe','terrain',[.32,.45,.36]],
    ['Window mullions','structure',[.16,.24,.27]], ['Leaf light','vegetation',[.40,.54,.36]],
    ['Leaf shade','vegetation',[.25,.40,.30]], ['Soffit','roof',[.76,.76,.69]],
    ['Warm glass','structure',[.64,.65,.51]], ['Pool glint','water',[.43,.72,.72]],
    ['Roof seam','roof',[.43,.48,.49]], ['Island edge','terrain',[.40,.44,.40]],
    ['Roof cap','roof',[.39,.44,.45]], ['Soil','terrain',[.27,.31,.27]],
    ['Gravel','path',[.54,.54,.47]], ['Outdoor seating','structure',[.78,.77,.66]],
  ].map(([name,role,color])=>({name,role,color}));
  const poly=(points,m)=>{const start=vertices.length;vertices.push(...points);for(let i=1;i<points.length-1;i++)triangles.push([start,start+i,start+i+1,m]);};
  const box=(x,y,z,w,d,h,m)=>{
    const a=[[x-w/2,y-d/2,z],[x+w/2,y-d/2,z],[x+w/2,y+d/2,z],[x-w/2,y+d/2,z]],b=a.map(p=>[p[0],p[1],z+h]);
    poly(b,m);poly([...a].reverse(),m);for(let i=0;i<4;i++)poly([a[i],a[(i+1)%4],b[(i+1)%4],b[i]],m);
  };
  const roof=(x,y,z,w,d,h)=>{
    const a=[x-w/2,y-d/2,z],b=[x+w/2,y-d/2,z],c=[x+w/2,y+d/2,z],e=[x-w/2,y+d/2,z],r1=[x,y-d/2,z+h],r2=[x,y+d/2,z+h];
    poly([a,r1,r2,e],2);poly([r1,b,c,r2],2);poly([a,b,r1],15);poly([e,r2,c],15);
    for(let offset=-w/2+.35;offset<w/2;offset+=.55){
      const zl=z+h*(1-Math.abs(offset-.012)/(w/2))+.018,zr=z+h*(1-Math.abs(offset+.012)/(w/2))+.018;
      poly([[x+offset-.012,y-d/2,zl],[x+offset+.012,y-d/2,zr],[x+offset+.012,y+d/2,zr],[x+offset-.012,y+d/2,zl]],18);
    }
    box(x,y,z+h,.09,d+.08,.035,20);
  };
  const crown=(x,y,z,rx,ry,rz,seed=0)=>{
    const segments=9,rings=5;const pts=[];
    for(let j=0;j<=rings;j++)for(let i=0;i<segments;i++){const lat=j*Math.PI/rings,lon=i*2*Math.PI/segments+(j%2)*.10;pts.push([x+Math.cos(lon)*Math.sin(lat)*rx,y+Math.sin(lon)*Math.sin(lat)*ry,z+Math.cos(lat)*rz]);}
    for(let j=0;j<rings;j++)for(let i=0;i<segments;i++)poly([pts[j*segments+i],pts[j*segments+(i+1)%segments],pts[(j+1)*segments+(i+1)%segments],pts[(j+1)*segments+i]],[5,13,14][(i+j+seed)%3]);
  };
  const tree=(x,y,s,seed)=>{box(x,y,.02,1.7*s,1.7*s,.025,21);box(x,y,0,.20*s,.20*s,2.3*s,6);crown(x,y,2.55*s,1.15*s,1.1*s,1.5*s,seed);crown(x-.48*s,y+.08*s,2.3*s,.65*s,.62*s,.8*s,seed+1);};
  box(0,1,-.42,34.4,30.4,.36,19);box(0,1,-.06,34,30,.06,0);
  for(let x=-16;x<16;x+=4)box(x+.9,1,.002,1.8,29.5,.003,11);
  box(10,-3,.015,6.5,22,.025,3);for(let y=-13;y<7;y+=2.7)box(10,y,.044,6.4,.026,.006,22);
  box(-.5,-3.5,.025,17,2.5,.05,10);box(-10,2,.025,2,19,.035,3);
  box(-2,4,.0,11,11,3.35,1);box(-2,4,.02,11.1,11.1,.17,10);
  box(-2,4,3.33,11.4,11.4,.13,15);roof(-2,4,3.46,11.8,11.8,2.05);
  box(7,5,0,6,8,2.9,1);box(7,5,2.88,6.4,8.4,.16,15);roof(7,5,3.04,6.6,8.6,1.08);
  // Front glazing is split by independent mullions and shallow reflected bands.
  for(const x of[-6,-2,2]){
    box(x,-1.565,1.05,2.35,.08,1.8,12);box(x,-1.616,1.12,2.19,.027,1.65,9);
    box(x,-1.635,1.12,.045,.04,1.65,12);box(x,-1.635,1.95,2.18,.03,.035,16);
  }
  for(const y of[1,5,8]){box(-7.56,y,.85,.08,2.25,2,12);box(-7.615,y,.92,.02,2.10,1.83,9);box(-7.63,y,.92,.03,.04,1.83,12);}
  box(7,.95,.16,4.6,.13,2.23,12);box(7,.867,.22,4.4,.04,2.08,4);
  for(let z=.4;z<2.3;z+=.22)box(7,.839,z,4.35,.02,.018,1);
  box(-.25,-1.63,0,.95,.12,2.5,4);box(-.61,-1.71,1.18,.06,.08,.28,12);
  for(let z=.6;z<3.3;z+=.46)box(-2,-1.52,z,10.9,.024,.012,10);
  box(-5,-2.5,.07,6,2,.16,10);for(let y=-3.4;y<-1.6;y+=.26)box(-5,y,.239,5.95,.025,.009,4);
  // Terrace, pool and a light pergola. All are authored geometry, never real property assets.
  box(-11,10,.025,6,4.7,.14,10);box(-11,10,.17,5.2,3.8,.04,8);
  for(let i=0;i<7;i++)box(-11+(i%2)*.4,8.5+i*.45,.211,4.7,.025,.004,17);
  for(const y of[7,12.8]){box(-11,y,.09,4.8,.8,.30,23);box(-11,y+.27,.39,4.8,.2,.35,23);}
  box(-10,-5,.02,4.3,4.5,.09,22);
  for(const x of[-11.8,-8.2])for(const y of[-7,-3])box(x,y,.1,.16,.16,2.65,4);
  for(let y=-7;y<=-3;y+=.4)box(-10,y,2.74,4.0,.12,.13,4);
  box(-10,-5,.12,1.4,1.6,.6,23);
  for(let y=-11.8;y<-4;y+=1.5)box(-3,y,.024,1.7,.88,.055,10);
  for(const[x,y,s,i]of[[-14.3,-10,1.15,0],[-14.3,-4.5,.85,1],[-14.2,1,1,2],[-14,13,1.05,0],[14,13,1.1,2],[14.4,7.5,.9,1],[14.5,1.5,1.0,0],[-5,13,.8,1],[4,13,.85,2],[14,-10.5,.85,0]])tree(x,y,s,i);
  for(let x=-16;x<17;x+=2)for(const y of[-13,15]){if(y===-13&&x>=6&&x<=12)continue;box(x,y,0,.13,.13,1.1,7);for(const z of[.35,.68,1])box(x+.87,y,z,1.85,.09,.08,7);}
  for(let y=-12;y<15;y+=2)for(const x of[-16,16]){box(x,y,0,.13,.13,1.1,7);for(const z of[.35,.68,1])box(x,y+.87,z,.09,1.85,.08,7);}
  const cam=(i,label,position,target)=>({id:`sensor:demo:camera-${i}`,label,kind:'camera',status:'available',knowledge:'observed',basis:'Synthetic camera pose; not a calibration certificate',position,pose:lookAt(position,target),intrinsics:{width:1280,height:720,fx:780,fy:780,cx:640,cy:360,imageDomain:'undistorted_pinhole'},frame:null,reading:null});
  const sensors=[cam(1,'North gate',[1,10.15,3.25],[-3,14,.5]),cam(2,'Front approach',[-5,-1.85,3.1],[1,-9,.6]),cam(3,'Service entry',[9,.70,2.8],[10,-6,.3]),cam(4,'West courtyard',[-7.8,5,3],[-12,3,.3])];
  for(const[id,label,kind,position,value,units]of[['motion','West motion','motion',[-14,0,1.2],1,'motion'],['contact','Service gate','contact',[10,-13,1],0,'open'],['temp','Courtyard climate','temperature',[-10,9,1],18.4,'°C']])sensors.push({id:`sensor:demo:${id}`,label,kind,status:'available',knowledge:'observed',basis:'Synthetic sensor fixture',position,pose:null,intrinsics:null,frame:null,reading:{value,unit:units,observedAtUnixMs:'1789398500000'}});
  const placements=[];
  for(const[i,knowledge,severity,shape,positions,radii]of[[1,'inferred','high','person',[[1,-9,.06]],[1.7,1.1,.4]],[2,'observed','critical','person',[[10,-4,.06]],[.5,.5,.15]],[3,'conflicted','medium','unknown',[[-12,3,.06],[-12,5.5,.06]],[.8,.8,.3]],[5,'unknown','medium','unknown',[],[0,0,0]],[6,'inferred','medium','animal',[[-10,-9,.06]],[2,1.2,.3]],[8,'observed','low','person',[[-7,11,.06]],[.5,.5,.1]],[9,'stale','high','unknown',[[-3,-6,.06]],[1,1,.2]]]){
    const event=metadata.events.find(e=>e.id===`event:demo:${String(i).padStart(3,'0')}`);if(!event)continue;
    placements.push({eventId:event.id,revisionDigest:event.revisionDigest,knowledge,severity,shape,basis:'Synthetic spatial hypothesis; glyphs are not reconstructed pose or identity',observedAtUnixMs:'1789398490000',validForMs:60000,hypotheses:positions.map(position=>({position,radii}))});
  }
  return {format:'fss.operator_scene.v1',site:metadata.site,frame:'frame:synthetic-property:z-up',scale:{kind:'measured',metresPerUnit:1,error:0},ledgerRoot:metadata.ledgerRoot,mesh:{vertices,triangles,materials},sensors,placements};
}
