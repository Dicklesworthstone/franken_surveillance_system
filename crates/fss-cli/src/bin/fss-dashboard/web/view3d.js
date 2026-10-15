import {add,sub,mul,dot,cross,unit,center,lookAt,project,transform,frustum,cameraMatrix,sceneBounds} from './spatial-model.js';

const SVG='http://www.w3.org/2000/svg';
const svg=(tag,attrs={},text)=>{const e=document.createElementNS(SVG,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=text;return e;};
const COLORS={low:[.36,.74,.76],medium:[.98,.73,.36],high:[1,.42,.29],critical:[1,.27,.32],unrated:[.73,.70,.89],camera:[.39,.80,.93],sensor:[.60,.85,.65],stale:[.57,.62,.68]};
const VS=`attribute vec3 aPosition; attribute vec4 aColor; uniform mat4 uMatrix; varying vec4 vColor; void main(){gl_Position=uMatrix*vec4(aPosition,1.0);vColor=aColor;}`;
const FS=`precision mediump float; varying vec4 vColor; void main(){gl_FragColor=vColor;}`;
function shader(gl,type,source){const s=gl.createShader(type);gl.shaderSource(s,source);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS))throw Error('Graphics shader unavailable');return s;}
function program(gl){const p=gl.createProgram(),v=shader(gl,gl.VERTEX_SHADER,VS),f=shader(gl,gl.FRAGMENT_SHADER,FS);gl.attachShader(p,v);gl.attachShader(p,f);gl.linkProgram(p);gl.deleteShader(v);gl.deleteShader(f);if(!gl.getProgramParameter(p,gl.LINK_STATUS))throw Error('Graphics program unavailable');return p;}
function hex(c){return '#'+c.map(n=>Math.round(Math.min(1,Math.max(0,n))*255).toString(16).padStart(2,'0')).join('');}
export class PropertyView {
  constructor(host,{interactive=true,onSelect=()=>{},overlay=true}={}){
    this.host=host;this.onSelect=onSelect;this.interactive=interactive;this.overlayEnabled=overlay;
    this.canvas=document.createElement('canvas');this.canvas.setAttribute('aria-label','Interactive three-dimensional property model');this.canvas.tabIndex=interactive?0:-1;
    this.overlay=svg('svg',{class:'world-labels','aria-label':'Positioned cameras, sensors, and unresolved event localizations'});
    host.replaceChildren(this.canvas,this.overlay);
    this.gl=this.canvas.getContext('webgl',{alpha:false,antialias:true,preserveDrawingBuffer:false});
    if(this.gl){const gl=this.gl;this.program=program(gl);this.buffer=gl.createBuffer();this.pos=gl.getAttribLocation(this.program,'aPosition');this.color=gl.getAttribLocation(this.program,'aColor');this.matrix=gl.getUniformLocation(this.program,'uMatrix');}
    else this.ctx=this.canvas.getContext('2d');
    host.dataset.renderer=this.gl?'webgl':'canvas-fallback';
    this.layers={roof:true,frusta:true,threats:true,grid:true};this.angle=-.95;this.elevation=.73;this.zoom=1;this.target=null;this.activeCamera=null;this.selected=null;this.frame=0;this.destroyed=false;this.lost=false;
    this.resize=new ResizeObserver(()=>this.invalidate());this.resize.observe(host);
    this.canvas.addEventListener('webglcontextlost',e=>{e.preventDefault();this.lost=true;host.setAttribute('data-graphics-state','lost');this.overlay.replaceChildren(svg('text',{x:20,y:40,fill:'#efc38b'},'Graphics context lost. Reload the view; event lists remain available.'));});
    this.canvas.addEventListener('webglcontextrestored',()=>{this.lost=false;const gl=this.gl;this.program=program(gl);this.buffer=gl.createBuffer();this.pos=gl.getAttribLocation(this.program,'aPosition');this.color=gl.getAttribLocation(this.program,'aColor');this.matrix=gl.getUniformLocation(this.program,'uMatrix');host.removeAttribute('data-graphics-state');this.invalidate();});
    if(interactive)this.controls();
  }
  controls(){
    let drag=null,moved=false;
    this.canvas.addEventListener('pointerdown',e=>{if(!this.scene)return;drag={x:e.clientX,y:e.clientY,angle:this.angle,elevation:this.elevation,target:[...this.target],pan:e.shiftKey||e.button===2};moved=false;this.canvas.setPointerCapture(e.pointerId);});
    this.canvas.addEventListener('pointermove',e=>{if(!drag)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;moved ||= Math.hypot(dx,dy)>3;this.activeCamera=null;
      if(drag.pan){const r=this.bounds.radius*this.zoom/450;this.target=add(drag.target,[(-Math.sin(this.angle)*dx+Math.cos(this.angle)*dy)*r,(Math.cos(this.angle)*dx+Math.sin(this.angle)*dy)*r,0]);}
      else{this.angle=drag.angle-dx*.006;this.elevation=Math.max(.08,Math.min(1.56,drag.elevation+dy*.005));}this.invalidate();});
    this.canvas.addEventListener('pointerup',e=>{if(!moved&&this.hit){const r=this.canvas.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;const hit=[...this.hit].reverse().find(h=>Math.hypot(h.x-x,h.y-y)<24);if(hit)this.onSelect(hit.kind,hit.id);}drag=null;});
    this.canvas.addEventListener('pointercancel',()=>drag=null);this.canvas.addEventListener('contextmenu',e=>e.preventDefault());
    this.canvas.addEventListener('wheel',e=>{e.preventDefault();this.activeCamera=null;this.zoom=Math.max(.18,Math.min(4,this.zoom*Math.exp(e.deltaY*.001)));this.invalidate();},{passive:false});
    this.canvas.addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','+','=','-','0'].includes(e.key))return;e.preventDefault();this.activeCamera=null;if(e.key==='ArrowLeft')this.angle-=.12;if(e.key==='ArrowRight')this.angle+=.12;if(e.key==='ArrowUp')this.elevation=Math.min(1.56,this.elevation+.1);if(e.key==='ArrowDown')this.elevation=Math.max(.08,this.elevation-.1);if(['+','='].includes(e.key))this.zoom=Math.max(.18,this.zoom*.85);if(e.key==='-')this.zoom=Math.min(4,this.zoom/ .85);if(e.key==='0')this.reset();this.invalidate();});
  }
  setScene(scene,threats=[]){const same=this.scene?.frame===scene.frame;this.scene=scene;this.threats=threats;this.bounds=sceneBounds(scene);if(!same||!this.target)this.target=[...this.bounds.center];this.invalidate();}
  reset(mode='orbit'){if(!this.scene)return;this.activeCamera=null;this.target=[...this.bounds.center];this.zoom=1;this.angle=-.95;this.elevation=mode==='top'?1.56:.73;this.invalidate();}
  fromCamera(sensor){this.activeCamera=sensor;this.invalidate();}
  setLayer(key,value){this.layers[key]=value;this.invalidate();}
  select(kind,id){this.selected={kind,id};this.invalidate();}
  focus(p){this.activeCamera=null;this.target=[...p];this.zoom=.48;this.invalidate();}
  invalidate(){if(this.destroyed||this.frame||this.lost)return;this.frame=requestAnimationFrame(()=>{this.frame=0;this.draw();});}
  view(width,height){
    if(this.activeCamera?.pose){const c=this.activeCamera,k=c.intrinsics,scale=Math.min(width/k.width,height/k.height);return{pose:c.pose,k:{...k,width,height,fx:k.fx*scale,fy:k.fy*scale,cx:(width-k.width*scale)/2+k.cx*scale,cy:(height-k.height*scale)/2+k.cy*scale}};}
    const r=this.bounds.radius*this.zoom*1.65,eye=add(this.target,[r*Math.cos(this.elevation)*Math.cos(this.angle),r*Math.cos(this.elevation)*Math.sin(this.angle),r*Math.sin(this.elevation)]);
    const focal=Math.min(width,height)*1.35;return{pose:lookAt(eye,this.target),k:{width,height,fx:focal,fy:focal,cx:width/2,cy:height*.48}};
  }
  geometry(){
    const opaque=[],translucent=[],lines=[],gridLines=[];
    const triangle=(a,b,c,color,alpha=1,lit=true)=>{
      let light=1;if(lit){const n=cross(sub(b,a),sub(c,a)),l=Math.hypot(...n);light=l>.000001?.55+.45*Math.abs(dot(mul(n,1/l),[.36,-.48,.8])):.7;}
      const rgba=[...color.map(v=>v*light),alpha];const to=alpha<1?translucent:opaque;for(const p of[a,b,c])to.push(...p,...rgba);
    };
    const line=(a,b,color,alpha=1)=>{lines.push(...a,...color,alpha,...b,...color,alpha);};
    const box=(p,size,color,alpha=1,wire=false)=>{
      const v=[];for(let z=0;z<2;z++)for(let y=0;y<2;y++)for(let x=0;x<2;x++)v.push(add(p,[(x-.5)*size[0],(y-.5)*size[1],z*size[2]]));
      const faces=[[0,1,3,2],[4,6,7,5],[0,4,5,1],[2,3,7,6],[0,2,6,4],[1,5,7,3]];
      for(const[a,b,c,d]of faces){if(wire){line(v[a],v[b],color,alpha);line(v[b],v[c],color,alpha);line(v[c],v[d],color,alpha);line(v[d],v[a],color,alpha);}else{triangle(v[a],v[b],v[c],color,alpha);triangle(v[a],v[c],v[d],color,alpha);}}
    };
    const ring=(p,radii,color,alpha=1,dashed=false,vertical=0)=>{let prev=null;for(let i=0;i<=64;i++){const a=i*Math.PI/32;let d=[Math.cos(a)*radii[0],Math.sin(a)*radii[1],0];if(vertical===1)d=[d[0],0,Math.sin(a)*radii[2]];if(vertical===2)d=[0,d[1],Math.cos(a)*radii[2]];const v=add(p,d);if(prev&&(!dashed||i%4<2))line(prev,v,color,alpha);prev=v;}};
    const capsule=(p,height,color,wire,alpha=1)=>{
      // Generic glyph, not reconstructed body pose or identity.
      const radii=[.16,.25,.19,.11],zs=[.2,.5,1.15,1.38];const v=[];
      for(let j=0;j<4;j++)for(let i=0;i<8;i++){const a=i*Math.PI/4;v.push(add(p,[Math.cos(a)*radii[j],Math.sin(a)*radii[j],zs[j]*height/1.7]));}
      for(let j=0;j<3;j++)for(let i=0;i<8;i++){const a=j*8+i,b=j*8+(i+1)%8,c=b+8,d=a+8;if(wire){line(v[a],v[b],color,alpha);line(v[a],v[d],color,alpha);}else{triangle(v[a],v[b],v[c],color,alpha);triangle(v[a],v[c],v[d],color,alpha);}}
      const c=add(p,[0,0,height-.18]),top=add(c,[0,0,.2]),bottom=add(c,[0,0,-.2]);
      for(let i=0;i<8;i++){const a=add(c,[.16*Math.cos(i*Math.PI/4),.16*Math.sin(i*Math.PI/4),0]),b=add(c,[.16*Math.cos((i+1)*Math.PI/4),.16*Math.sin((i+1)*Math.PI/4),0]);if(wire){line(a,b,color,alpha);line(a,top,color,alpha);}else{triangle(a,b,top,color,alpha);triangle(b,a,bottom,color,alpha);}}
      for(const dx of[-.12,.12])line(add(p,[dx,0,.27]),add(p,[dx,.03,0]),color,alpha);
    };
    const mesh=this.scene.mesh;
    for(const t of mesh.triangles){const m=mesh.materials[t[3]];if(!this.layers.roof&&m.role==='roof')continue;triangle(mesh.vertices[t[0]],mesh.vertices[t[1]],mesh.vertices[t[2]],m.color);}
    if(this.layers.grid){const gridStart=lines.length;const r=this.bounds.radius,step=Math.pow(10,Math.floor(Math.log10(r/10)));const max=Math.min(80,Math.ceil(r*1.5/step));const [x,y]=this.bounds.center;for(let i=-max;i<=max;i++){line([x-max*step,y+i*step,-.06],[x+max*step,y+i*step,-.06],[.16,.24,.28],.55);line([x+i*step,y-max*step,-.06],[x+i*step,y+max*step,-.06],[.16,.24,.28],.55);}gridLines.push(...lines.splice(gridStart));}
    for(const sensor of this.scene.sensors){if(sensor.id===this.activeCamera?.id)continue;const p=sensor.pose?center(sensor.pose):sensor.position;if(!p||sensor.knowledge==='redacted')continue;const color=sensor.status==='offline'?COLORS.stale:sensor.kind==='camera'?COLORS.camera:COLORS.sensor;
      if(sensor.kind==='camera'&&sensor.pose){const c=frustum(sensor.pose,sensor.intrinsics,Math.min(7,this.bounds.radius*.3)),short=frustum(sensor.pose,sensor.intrinsics,.5);
        for(let i=0;i<4;i++){line(p,short[i],color);line(short[i],short[(i+1)%4],color);if(this.layers.frusta){line(p,c[i],color,.45);line(c[i],c[(i+1)%4],color,.3);triangle(p,c[i],c[(i+1)%4],color,.05,false);}}
        box(add(p,[0,0,-.12]),[.32,.32,.24],color);line(p,add(p,[0,0,-.8]),color,.5);
      }else{box(p,[.28,.28,.28],color);ring(p,[.5,.5,0],color,.6);}
    }
    if(this.layers.threats)for(const threat of this.threats){const color=threat.knowledge==='stale'?COLORS.stale:COLORS[threat.severity];const uncertain=threat.knowledge!=='observed';
      for(let hi=0;hi<threat.hypotheses.length;hi++){const h=threat.hypotheses[hi],p=h.position,alpha=hi===0?1:.6;
        if(threat.shape==='person')capsule(p,1.7,color,uncertain,alpha);
        else if(threat.shape==='vehicle')box(p,[1.8,3.5,1.4],color,alpha,uncertain);
        else if(threat.shape==='animal'){box(add(p,[0,0,.35]),[.65,1,.4],color,alpha,uncertain);box(add(p,[0,-.6,.4]),[.38,.38,.35],color,alpha,uncertain);}
        else{const top=add(p,[0,0,1.2]);for(const d of[[.35,0,.6],[0,.35,.6],[-.35,0,.6],[0,-.35,.6]]){line(p,add(p,d),color,alpha);line(add(p,d),top,color,alpha);}}
        const radii=h.radii;ring(add(p,[0,0,.04]),[Math.max(.45,radii[0]),Math.max(.45,radii[1]),radii[2]],color,.8,uncertain);
        if(radii[2]>0){ring(add(p,[0,0,.06]),radii,color,.3,true,1);ring(add(p,[0,0,.06]),radii,color,.3,true,2);}
        if(threat.knowledge==='conflicted')ring(add(p,[0,0,.08]),[Math.max(.6,radii[0]+.18),Math.max(.6,radii[1]+.18),0],[.74,.57,1],.9,true);
        if(this.selected?.id===threat.id)ring(add(p,[0,0,.02]),[Math.max(.8,radii[0]+.4),Math.max(.8,radii[1]+.4),0],[1,1,1]);
      }
    }
    return{opaque,translucent,lines,gridLines};
  }
  draw(){
    if(!this.scene||this.lost||this.destroyed)return;
    const w=Math.round(this.host.clientWidth),h=Math.round(this.host.clientHeight);if(w<2||h<2)return;
    const dpr=this.gl?Math.min(devicePixelRatio||1,2):1;this.canvas.width=w*dpr;this.canvas.height=h*dpr;
    const{pose,k}=this.view(w,h),geometry=this.geometry();
    if(this.gl){const gl=this.gl;gl.viewport(0,0,this.canvas.width,this.canvas.height);gl.clearColor(.035,.060,.078,1);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);gl.useProgram(this.program);gl.uniformMatrix4fv(this.matrix,false,cameraMatrix(pose,k,.025,Math.max(2000,this.bounds.radius*12)));
      gl.bindBuffer(gl.ARRAY_BUFFER,this.buffer);gl.enableVertexAttribArray(this.pos);gl.vertexAttribPointer(this.pos,3,gl.FLOAT,false,28,0);gl.enableVertexAttribArray(this.color);gl.vertexAttribPointer(this.color,4,gl.FLOAT,false,28,12);
      const draw=(vertices,mode)=>{if(!vertices.length)return;gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(vertices),gl.DYNAMIC_DRAW);gl.drawArrays(mode,0,vertices.length/7);};
      gl.disable(gl.BLEND);gl.depthMask(true);draw(geometry.gridLines,gl.LINES);draw(geometry.opaque,gl.TRIANGLES);
      gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE_MINUS_SRC_ALPHA);gl.depthMask(false);draw(geometry.translucent,gl.TRIANGLES);draw(geometry.lines,gl.LINES);gl.depthMask(true);
    }else if(this.ctx){ this.software(geometry,pose,k,w,h); }

    this.overlay.setAttribute('viewBox',`0 0 ${w} ${h}`);this.overlay.replaceChildren();this.hit=[];
    if(!this.overlayEnabled)return;
    const labels=[];
    for(const s of this.scene.sensors){if(s.id===this.activeCamera?.id)continue;const p=s.pose?center(s.pose):s.position;if(p&&s.knowledge!=='redacted')labels.push({p:add(p,[0,0,.45]),kind:'sensor',id:s.id,label:s.label,state:s.status,color:COLORS.camera});}
    if(this.layers.threats)for(const t of this.threats)for(let i=0;i<t.hypotheses.length;i++)labels.push({p:add(t.hypotheses[i].position,[0,0,2.1]),kind:'threat',id:t.id,label:t.kind.replaceAll('_',' ')+(t.hypotheses.length>1?` · H${i+1}`:''),state:t.knowledge,color:t.knowledge==='stale'?COLORS.stale:COLORS[t.severity]});
    const occupied=[];
    for(const item of labels){const p=project(pose,k,item.p);if(!p||p[0]<0||p[0]>w||p[1]<0||p[1]>h)continue;this.hit.push({x:p[0],y:p[1],...item});
      const g=svg('g',{class:'world-label',tabindex:0,role:'button','aria-label':`${item.label}; ${item.state}; ${item.kind}`});
      const color=hex(item.color),label=item.label.length>27?item.label.slice(0,25)+'…':item.label,width=Math.max(108,Math.min(210,label.length*6.2+22));
      let x=Math.max(4,Math.min(w-width-4,p[0]-width/2)),y=Math.max(5,p[1]-26);
      for(const offset of[0,-42,42,-84,84,-126,126]){const yy=Math.max(5,Math.min(h-40,p[1]-26+offset));if(!occupied.some(b=>x<b.x+b.width+3&&x+width+3>b.x&&yy<b.y+39&&yy+39>b.y)){y=yy;break;}}
      occupied.push({x,y,width});
      g.append(svg('line',{x1:Math.max(x+8,Math.min(x+width-8,p[0])),x2:p[0],y1:y+27,y2:p[1]+8,stroke:color,'stroke-opacity':.65}));
      g.append(svg('rect',{x,y,width,height:36,rx:7,fill:'#111e2c','fill-opacity':.94,stroke:color,'stroke-opacity':this.selected?.id===item.id?1:.5}));
      g.append(svg('circle',{cx:x+9,cy:y+12,r:2.3,fill:color}));g.append(svg('text',{x:x+17,y:y+15,class:'world-label-title'},label));g.append(svg('text',{x:x+17,y:y+28,class:'world-label-status'},item.state.toUpperCase()));
      const choose=()=>this.onSelect(item.kind,item.id);g.addEventListener('click',choose);g.addEventListener('keydown',e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();choose();}});this.overlay.append(g);
    }
  }
  software(geometry,pose,k,w,h){
    // Depth-buffered reference rasterizer for browsers without WebGL. Painter sorting alone
    // is incorrect for intersecting property faces and would place ground on top of roofs.
    const image=this.ctx.createImageData(w,h),pixels=image.data,depth=new Float32Array(w*h);depth.fill(Infinity);
    for(let i=0;i<pixels.length;i+=4){pixels[i]=9;pixels[i+1]=16;pixels[i+2]=25;pixels[i+3]=255;}
    const blend=(index,color,alpha)=>{const at=index*4;for(let c=0;c<3;c++)pixels[at+c]=pixels[at+c]*(1-alpha)+color[c]*255*alpha;};
    const point=c=>[k.fx*c[0]/c[2]+k.cx,k.fy*c[1]/c[2]+k.cy,c[2]];
    const near=.025;
    const clip=poly=>{const out=[];for(let i=0;i<poly.length;i++){const a=poly[i],b=poly[(i+1)%poly.length],ai=a[2]>=near,bi=b[2]>=near;if(ai)out.push(a);if(ai!==bi)out.push(add(a,mul(sub(b,a),(near-a[2])/(b[2]-a[2]))));}return out;};
    const triangle=(a,b,c,color,alpha,write)=>{
      const area=(b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]);if(Math.abs(area)<1e-10)return;
      const x0=Math.max(0,Math.floor(Math.min(a[0],b[0],c[0]))),x1=Math.min(w-1,Math.ceil(Math.max(a[0],b[0],c[0]))),y0=Math.max(0,Math.floor(Math.min(a[1],b[1],c[1]))),y1=Math.min(h-1,Math.ceil(Math.max(a[1],b[1],c[1])));
      for(let y=y0;y<=y1;y++)for(let x=x0;x<=x1;x++){const xx=x+.5,yy=y+.5,wa=((b[0]-xx)*(c[1]-yy)-(b[1]-yy)*(c[0]-xx))/area,wb=((c[0]-xx)*(a[1]-yy)-(c[1]-yy)*(a[0]-xx))/area,wc=1-wa-wb;if(wa<0||wb<0||wc<0)continue;const z=1/(wa/a[2]+wb/b[2]+wc/c[2]),index=y*w+x;if(z<=depth[index]+1e-5){blend(index,color,alpha);if(write)depth[index]=z;}}
    };
    const triangles=(arr,write)=>{const faces=[];for(let i=0;i<arr.length;i+=21){const poly=clip([0,7,14].map(n=>transform(pose,arr.slice(i+n,i+n+3))));for(let j=1;j<poly.length-1;j++)faces.push({p:[poly[0],poly[j],poly[j+1]].map(point),color:arr.slice(i+3,i+6),alpha:arr[i+6]});}if(!write)faces.sort((a,b)=>b.p.reduce((n,p)=>n+p[2],0)-a.p.reduce((n,p)=>n+p[2],0));for(const f of faces)triangle(...f.p,f.color,f.alpha,write);};
    const lines=arr=>{for(let i=0;i<arr.length;i+=14){let a=transform(pose,arr.slice(i,i+3)),b=transform(pose,arr.slice(i+7,i+10));if(a[2]<near&&b[2]<near)continue;if(a[2]<near)a=add(a,mul(sub(b,a),(near-a[2])/(b[2]-a[2])));if(b[2]<near)b=add(b,mul(sub(a,b),(near-b[2])/(a[2]-b[2])));a=point(a);b=point(b);const steps=Math.min(5000,Math.max(1,Math.ceil(Math.hypot(b[0]-a[0],b[1]-a[1]))));for(let j=0;j<=steps;j++){const t=j/steps,x=Math.round(a[0]+(b[0]-a[0])*t),y=Math.round(a[1]+(b[1]-a[1])*t);if(x<0||y<0||x>=w||y>=h)continue;const z=1/((1-t)/a[2]+t/b[2]),index=y*w+x;if(z<depth[index]+.025)blend(index,arr.slice(i+3,i+6),arr[i+6]);}}};
    triangles(geometry.opaque,true);lines(geometry.gridLines);triangles(geometry.translucent,false);lines(geometry.lines);this.ctx.putImageData(image,0,0);
  }
  dispose(){this.destroyed=true;this.resize.disconnect();cancelAnimationFrame(this.frame);if(this.gl&&!this.lost){this.gl.deleteBuffer(this.buffer);this.gl.deleteProgram(this.program);}this.host.replaceChildren();}
}
