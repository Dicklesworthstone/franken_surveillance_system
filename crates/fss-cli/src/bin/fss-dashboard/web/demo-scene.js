// Conspicuously synthetic display fixture. Never selected after a failed real read.
import {lookAt} from './spatial-model.js';
export function makeDemoScene(metadata){
 const vertices=[],triangles=[];
 const materials=[['Lawn','terrain',[.14,.26,.22]],['Facade','structure',[.59,.64,.61]],['Standing seam roof','roof',[.24,.35,.41]],['Pavers','path',[.37,.43,.44]],['Warm interior','structure',[.77,.63,.43]],['Evergreen','vegetation',[.17,.36,.28]],['Tree bark','vegetation',[.30,.28,.22]],['Boundary','boundary',[.43,.50,.50]],['Pool','water',[.18,.51,.59]],['Windows','structure',[.17,.34,.41]],['Stone','path',[.57,.60,.55]]].map(([name,role,color])=>({name,role,color}));
 const poly=(points,m)=>{const start=vertices.length;vertices.push(...points);for(let i=1;i<points.length-1;i++)triangles.push([start,start+i,start+i+1,m]);};
 const box=(x,y,z,w,d,h,m)=>{const a=[[x-w/2,y-d/2,z],[x+w/2,y-d/2,z],[x+w/2,y+d/2,z],[x-w/2,y+d/2,z]],b=a.map(p=>[p[0],p[1],z+h]);poly(b,m);for(let i=0;i<4;i++)poly([a[i],a[(i+1)%4],b[(i+1)%4],b[i]],m);};
 const roof=(x,y,z,w,d,h)=>{const a=[x-w/2,y-d/2,z],b=[x+w/2,y-d/2,z],c=[x+w/2,y+d/2,z],e=[x-w/2,y+d/2,z],r1=[x,y-d/2,z+h],r2=[x,y+d/2,z+h];poly([a,r1,r2,e],2);poly([r1,b,c,r2],2);poly([a,b,r1],1);poly([e,r2,c],1);};
 const tree=(x,y,s)=>{box(x,y,0,.2*s,.2*s,1.8*s,6);for(const[z,r]of[[1.1,1.3],[1.8,1.1],[2.5,.8]])for(let i=0;i<7;i++){const a=i*Math.PI*2/7,b=(i+1)*Math.PI*2/7;poly([[x+Math.cos(a)*r*s,y+Math.sin(a)*r*s,z*s],[x+Math.cos(b)*r*s,y+Math.sin(b)*r*s,z*s],[x,y,(z+1.5)*s]],5);}};
 box(0,1,-.25,34,30,.25,0);box(10,-3,.015,6.5,22,.04,3);box(-.5,-4,.02,17,2,.05,3);box(-10,2,.02,2,19,.04,3);
 box(-2,4,0,11,11,3.4,1);roof(-2,4,3.4,11.8,11.8,2.4);box(7,5,0,6,8,2.8,1);roof(7,5,2.8,6.5,8.5,1.3);
 box(-5,-2,.1,6,2,.2,10);box(7,.95,.1,4,.12,2.15,9);
 for(const x of[-6,-2,2])box(x,-1.56,1.2,2.1,.1,1.5,9);for(const y of[1,5,8])box(-7.56,y,1.2,.1,2.1,1.45,9);
 box(-11,10,.03,6,4,.12,10);box(-11,10,.17,5.3,3.3,.04,8);for(let y=-11;y<-4;y+=2)box(-3,y,.02,1.7,1.1,.08,10);
 for(const[x,y,s]of[[-14,-10,1.2],[-14,-5,.9],[-14,1,1],[-14,13,1.05],[14,13,1.2],[14,9,.9],[14,4,1],[-5,13,.8],[4,13,.9],[14,-11,.9]])tree(x,y,s);
 for(let x=-16;x<17;x+=2)for(const y of[-13,15]){if(y===-13&&x>=6&&x<=12)continue;box(x,y,0,.12,.12,1.25,7);box(x+.8,y,.9,1.6,.09,.08,7);box(x+.8,y,.4,1.6,.09,.08,7);}
 for(let y=-12;y<15;y+=2)for(const x of[-16,16]){box(x,y,0,.12,.12,1.25,7);box(x,y+.8,.9,.09,1.6,.08,7);}
 const cam=(i,label,position,target)=>({id:`sensor:demo:camera-${i}`,label,kind:'camera',status:'available',knowledge:'observed',basis:'Synthetic camera pose; not a calibration certificate',position,pose:lookAt(position,target),intrinsics:{width:1280,height:720,fx:900,fy:900,cx:640,cy:360,imageDomain:'undistorted_pinhole'},frame:null,reading:null});
 const sensors=[cam(1,'North gate',[1,14,3],[1,4,0]),cam(2,'Front approach',[-5,-1.8,3],[0,-10,0]),cam(3,'Service entry',[9,.8,2.8],[10,-8,0]),cam(4,'West courtyard',[-7.8,5,3],[-12,1,0])];
 for(const[id,label,kind,position,value,unit]of[['motion','West motion','motion',[-14,0,1.2],1,'motion'],['contact','Service gate','contact',[10,-13,1],0,'open'],['temp','Courtyard climate','temperature',[-10,9,1],18.4,'°C']])sensors.push({id:`sensor:demo:${id}`,label,kind,status:'available',knowledge:'observed',basis:'Synthetic sensor fixture',position,pose:null,intrinsics:null,frame:null,reading:{value,unit,observedAtUnixMs:'1789398500000'}});
 const placements=[];
 for(const[i,knowledge,severity,shape,positions,radii]of[[1,'inferred','high','person',[[1,-9,.06]],[1.7,1.1,.4]],[2,'observed','critical','person',[[10,-4,.06]],[.5,.5,.15]],[3,'conflicted','medium','unknown',[[-12,3,.06],[-12,5.5,.06]],[.8,.8,.3]],[5,'unknown','medium','unknown',[],[0,0,0]],[6,'inferred','medium','animal',[[-10,-6,.06]],[2,1.2,.3]],[8,'observed','low','person',[[-7,11,.06]],[.5,.5,.1]],[9,'stale','high','unknown',[[-3,-6,.06]],[1,1,.2]]]){
   const id=`event:demo:${String(i).padStart(3,'0')}`,event=metadata.events.find(e=>e.id===id);if(!event)continue;
   placements.push({eventId:id,revisionDigest:event.revisionDigest,knowledge,severity,shape,basis:'Synthetic spatial hypothesis; glyphs are not reconstructed pose or identity',observedAtUnixMs:'1789398490000',validForMs:60000,hypotheses:positions.map(position=>({position,radii}))});
 }
 return{format:'fss.operator_scene.v1',site:metadata.site,frame:'frame:synthetic-property:z-up',scale:{kind:'measured',metresPerUnit:1,error:0},ledgerRoot:metadata.ledgerRoot,mesh:{vertices,triangles,materials},sensors,placements};
}
