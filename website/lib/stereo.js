import {conditions,frameRate,passAt} from "./pass.js";
export const imageSize=[896,504];
export const cameraRig={
  garden:{position:[4.8,2.8,2.6],target:[.15,.85,0],fov:47},
  patio:{position:[-4.65,2.05,3],target:[-.15,1.03,0],fov:48}
};
export const moments=[{frame:24,label:"In flight"},{frame:28,label:"Near the floor"},{frame:38,label:"After the bounce"}];
const add=(a,b)=>a.map((x,i)=>x+b[i]),sub=(a,b)=>a.map((x,i)=>x-b[i]);
const scale=(a,n)=>a.map(x=>x*n),dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
const unit=a=>scale(a,1/Math.hypot(...a));
const cross=(a,b)=>[a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]];
export function optics(id){
 const {position,target,fov}=cameraRig[id];
 const forward=unit(sub(target,position)),right=unit(cross(forward,[0,1,0])),up=cross(right,forward);
 return {position,forward,right,up,focal:imageSize[1]/(2*Math.tan(fov*Math.PI/360))};
}
export function project(id,point){
 const c=optics(id),d=sub(point,c.position),k=c.focal/dot(d,c.forward);
 return [imageSize[0]/2+k*dot(d,c.right),imageSize[1]/2-k*dot(d,c.up)];
}
function bearing(id,[x,y]){
 const c=optics(id);
 return unit(add(c.forward,add(scale(c.right,(x-imageSize[0]/2)/c.focal),scale(c.up,(imageSize[1]/2-y)/c.focal))));
}
export function referenceAt(time){
 const {x,y}=passAt(conditions[0],time).ball,point=[x,y,0];
 return {point,marks:Object.fromEntries(Object.keys(cameraRig).map(id=>[id,project(id,point)]))};
}
export const referenceFrame=frame=>referenceAt(frame/frameRate);
export function reconstruct(marks){
 const rays=Object.entries(cameraRig).flatMap(([id,{position}])=>marks[id]?[{id,origin:position,direction:bearing(id,marks[id])}]:[]);
 if(rays.length<2)return {status:"waiting",rays};
 const [a,b]=rays,offset=sub(a.origin,b.origin),cos=dot(a.direction,b.direction),den=1-cos*cos;
 if(den<1e-6)return {status:"weak",rays};
 const u=dot(a.direction,offset),v=dot(b.direction,offset);
 const t=(cos*v-u)/den,s=(v-cos*u)/den;
 if(t<=0||s<=0)return {status:"behind",rays};
 const ends=[add(a.origin,scale(a.direction,t)),add(b.origin,scale(b.direction,s))];
 const point=scale(add(...ends),.5),miss=Math.hypot(...sub(...ends));
 const residual=Math.max(...rays.map(r=>Math.hypot(...sub(project(r.id,point),marks[r.id]))));
 return {status:residual>4?"disagrees":"fit",rays,ends,point,miss,residual};
}
