// First-party presentation renderer. Rendering never establishes visibility or source custody.
import {add,sub,mul,dot,cross,unit,center,lookAt,project,transform,frustum,cameraMatrix,sceneBounds} from './spatial-model.js';
const SVG='http://www.w3.org/2000/svg';
const svg=(tag,attrs={},text)=>{const e=document.createElementNS(SVG,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=text;return e;};
const COLORS={low:[.47,.85,.87],medium:[1,.77,.39],high:[1,.48,.30],critical:[1,.39,.34],unrated:[.77,.72,.95],camera:[.57,.85,.91],sensor:[.70,.88,.72],stale:[.65,.69,.73]};
const SUN=unit([-.65,-.8,1.45]);
const HEX=c=>'#'+c.map(v=>Math.round(Math.min(1,Math.max(0,v))*255).toString(16).padStart(2,'0')).join('');
const VS=`attribute vec3 aPosition;attribute vec4 aColor;uniform mat4 uMatrix;uniform mat4 uLight;varying vec4 vColor;varying vec4 vShadow;void main(){gl_Position=uMatrix*vec4(aPosition,1.);vShadow=uLight*vec4(aPosition,1.);vColor=aColor;}`;
const FS=`precision highp float;varying vec4 vColor;varying vec4 vShadow;uniform sampler2D uShadow;uniform float uShade;float unpack(vec4 c){return dot(c,vec4(1.,1./255.,1./65025.,1./16581375.));}void main(){float shade=1.;if(uShade>.5){vec3 p=vShadow.xyz/vShadow.w*.5+.5;if(p.x>0.&&p.x<1.&&p.y>0.&&p.y<1.&&p.z>0.&&p.z<1.){float n=0.;for(int x=-1;x<=1;x++){for(int y=-1;y<=1;y++){float d=unpack(texture2D(uShadow,p.xy+vec2(float(x),float(y))/1024.));n+=p.z-.0007>d?1.:0.;}}shade=1.-n/9.*.34;}}gl_FragColor=vec4(vColor.rgb*shade,vColor.a);}`;
const SHADOW_VS=`attribute vec3 aPosition;uniform mat4 uMatrix;void main(){gl_Position=uMatrix*vec4(aPosition,1.);}`;
const SHADOW_FS=`precision highp float;void main(){vec4 c=fract(gl_FragCoord.z*vec4(1.,255.,65025.,16581375.));c-=c.yzww*vec4(1./255.,1./255.,1./255.,0.);gl_FragColor=c;}`;
function shader(gl,type,source){const s=gl.createShader(type);gl.shaderSource(s,source);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS)){gl.deleteShader(s);throw Error('Graphics shader unavailable');}return s;}
function program(gl,vs,fs){const p=gl.createProgram(),v=shader(gl,gl.VERTEX_SHADER,vs),f=shader(gl,gl.FRAGMENT_SHADER,fs);gl.attachShader(p,v);gl.attachShader(p,f);gl.linkProgram(p);gl.deleteShader(v);gl.deleteShader(f);if(!gl.getProgramParameter(p,gl.LINK_STATUS)){gl.deleteProgram(p);throw Error('Graphics program unavailable');}return p;}
function lightMatrix(bounds){
  const radius=bounds.radius,pose=lookAt(add(bounds.center,mul(SUN,radius*3)),bounds.center),r=pose.rotation,t=pose.translation;
  const extent=radius*1.08,near=radius*.1,far=radius*6,s=[1/extent,-1/extent,2/(far-near)];
  return new Float32Array([r[0][0]*s[0],r[1][0]*s[1],r[2][0]*s[2],0,r[0][1]*s[0],r[1][1]*s[1],r[2][1]*s[2],0,r[0][2]*s[0],r[1][2]*s[1],r[2][2]*s[2],0,t[0]*s[0],t[1]*s[1],t[2]*s[2]-(far+near)/(far-near),1]);
}
function pointInBox(a,b){return a.x<b.x+b.w+5&&a.x+a.w+5>b.x&&a.y<b.y+b.h+5&&a.y+a.h+5>b.y;}
export class PropertyView {
  constructor(host,{interactive=true,onSelect=()=>{},overlay=true,onView=()=>{},software=false}={}){
    this.host=host;this.onSelect=onSelect;this.onView=onView;this.overlayEnabled=overlay;this.interactive=interactive;
    this.canvas=document.createElement('canvas');this.canvas.setAttribute('aria-label','Interactive 3D property. Arrow keys orbit, plus/minus zoom, 0 fits the scene.');this.canvas.tabIndex=interactive?0:-1;
    this.overlay=svg('svg',{class:'world-labels','aria-label':'Positioned cameras, sensors and event hypotheses'});host.replaceChildren(this.canvas,this.overlay);
    this.gl=software?null:this.canvas.getContext('webgl',{alpha:true,antialias:true,premultipliedAlpha:false});
    try{if(this.gl)this.initGL();}catch{this.releaseGL();this.gl=null;const old=this.canvas;this.canvas=old.cloneNode();old.replaceWith(this.canvas);}
    this.ctx=this.gl?null:this.canvas.getContext('2d');
    host.dataset.renderer=this.gl?'webgl':'canvas-fallback';
    this.layers={roof:true,frusta:true,threats:true,grid:false,labels:false};this.lens='context';this.angle=-1.03;this.elevation=.74;this.zoom=1;
    this.target=null;this.activeCamera=null;this.selected=null;this.frame=0;this.destroyed=false;this.lost=false;this.animation=null;this.cache=null;this.shadowDirty=true;
    this.resize=new ResizeObserver(()=>this.invalidate());this.resize.observe(host);
    this.canvas.addEventListener('webglcontextlost',e=>{e.preventDefault();if(this.destroyed)return;this.lost=true;this.host.dataset.graphicsState='lost';this.overlay.replaceChildren(svg('text',{x:20,y:35,fill:'#efc38b'},'Graphics context lost. Reload to restore; event inventory remains available.'));});
    this.canvas.addEventListener('webglcontextrestored',()=>{if(this.destroyed)return;try{this.initGL();this.lost=false;this.shadowDirty=true;delete this.host.dataset.graphicsState;this.invalidate();}catch{this.lost=true;}});
    if(interactive)this.controls();
  }
  initGL(){
    const gl=this.gl;this.program=program(gl,VS,FS);this.buffer=gl.createBuffer();this.pos=gl.getAttribLocation(this.program,'aPosition');this.color=gl.getAttribLocation(this.program,'aColor');
    this.matrix=gl.getUniformLocation(this.program,'uMatrix');this.light=gl.getUniformLocation(this.program,'uLight');this.shade=gl.getUniformLocation(this.program,'uShade');this.sampler=gl.getUniformLocation(this.program,'uSampler');
    this.sampler=gl.getUniformLocation(this.program,'uShadow');
    this.shadowProgram=program(gl,SHADOW_VS,SHADOW_FS);this.shadowPos=gl.getAttribLocation(this.shadowProgram,'aPosition');this.shadowMatrix=gl.getUniformLocation(this.shadowProgram,'uMatrix');
    this.shadowTexture=gl.createTexture();gl.bindTexture(gl.TEXTURE_2D,this.shadowTexture);gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA,1024,1024,0,gl.RGBA,gl.UNSIGNED_BYTE,null);
    gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.NEAREST);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MAG_FILTER,gl.NEAREST);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_S,gl.CLAMP_TO_EDGE);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_T,gl.CLAMP_TO_EDGE);
    this.depth=gl.createRenderbuffer();gl.bindRenderbuffer(gl.RENDERBUFFER,this.depth);gl.renderbufferStorage(gl.RENDERBUFFER,gl.DEPTH_COMPONENT16,1024,1024);
    this.fbo=gl.createFramebuffer();gl.bindFramebuffer(gl.FRAMEBUFFER,this.fbo);gl.framebufferTexture2D(gl.FRAMEBUFFER,gl.COLOR_ATTACHMENT0,gl.TEXTURE_2D,this.shadowTexture,0);gl.framebufferRenderbuffer(gl.FRAMEBUFFER,gl.DEPTH_ATTACHMENT,gl.RENDERBUFFER,this.depth);
    this.hasShadows=gl.checkFramebufferStatus(gl.FRAMEBUFFER)===gl.FRAMEBUFFER_COMPLETE;gl.bindFramebuffer(gl.FRAMEBUFFER,null);
  }
  controls(){
    let drag=null,moved=false;
    this.canvas.addEventListener('pointerdown',e=>{if(!this.scene)return;this.animation=null;drag={x:e.clientX,y:e.clientY,angle:this.angle,elevation:this.elevation,target:[...this.target],pan:e.shiftKey||e.button===2};moved=false;this.canvas.setPointerCapture(e.pointerId);});
    this.canvas.addEventListener('pointermove',e=>{if(!drag)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;moved ||= Math.hypot(dx,dy)>3;if(this.activeCamera){this.activeCamera=null;this.cache=null;}
      if(drag.pan){const scale=this.bounds.radius*this.zoom/Math.max(250,this.host.clientHeight);this.target=add(drag.target,[(Math.sin(this.angle)*dx-Math.cos(this.angle)*dy)*scale,(-Math.cos(this.angle)*dx-Math.sin(this.angle)*dy)*scale,0]);}
      else{this.angle=drag.angle-dx*.005;this.elevation=Math.max(.08,Math.min(1.565,drag.elevation+dy*.004));}this.invalidate();});
    this.canvas.addEventListener('pointerup',e=>{if(!moved){const r=this.canvas.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;const hit=this.hit?.find(h=>Math.hypot(h.x-x,h.y-y)<22);if(hit)this.onSelect(hit.kind,hit.id,hit.hypothesis);}drag=null;});
    this.canvas.addEventListener('pointercancel',()=>drag=null);this.canvas.addEventListener('contextmenu',e=>e.preventDefault());
    this.canvas.addEventListener('wheel',e=>{e.preventDefault();this.animation=null;if(this.activeCamera){this.activeCamera=null;this.cache=null;}this.zoom=Math.max(.18,Math.min(4,this.zoom*Math.exp(e.deltaY*.001)));this.invalidate();},{passive:false});
    this.canvas.addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','+','=','-','0'].includes(e.key))return;e.preventDefault();e.stopPropagation();this.animation=null;if(this.activeCamera){this.activeCamera=null;this.cache=null;}
      if(e.key==='ArrowLeft')this.angle-=.12;if(e.key==='ArrowRight')this.angle+=.12;if(e.key==='ArrowUp')this.elevation=Math.min(1.565,this.elevation+.1);if(e.key==='ArrowDown')this.elevation=Math.max(.08,this.elevation-.1);
      if(['+','='].includes(e.key))this.zoom=Math.max(.18,this.zoom*.85);if(e.key==='-')this.zoom=Math.min(4,this.zoom/.85);if(e.key==='0')this.reset();this.invalidate();});
  }
  changed(){this.cache=null;this.shadowDirty=true;this.invalidate();}
  setScene(scene,threats=[]){
    const same=this.scene?.frame===scene.frame,cameraId=this.activeCamera?.id;this.animation=null;this.scene=scene;this.threats=threats;this.bounds=sceneBounds(scene);
    if(!same||!this.target)this.target=[this.bounds.center[0],this.bounds.center[1],this.bounds.center[2]*.25];
    this.activeCamera=same&&cameraId?scene.sensors.find(s=>s.id===cameraId&&s.pose&&s.knowledge!=='redacted'&&s.status!=='redacted')??null:null;this.cache=null;this.shadowDirty=true;this.invalidate();
  }
  clear(){cancelAnimationFrame(this.frame);this.frame=0;this.animation=null;this.scene=null;this.threats=[];this.activeCamera=null;this.target=null;this.selected=null;this.cache=null;this.hit=[];this.canvas.width=this.canvas.width;this.overlay.replaceChildren();}
  move(target,zoom,angle=this.angle,elevation=this.elevation){
    this.activeCamera=null;this.cache=null;
    if(!this.interactive||matchMedia('(prefers-reduced-motion: reduce)').matches){this.target=[...target];this.zoom=zoom;this.angle=angle;this.elevation=elevation;this.animation=null;}
    else this.animation={start:performance.now(),from:[...this.target,this.zoom,this.angle,this.elevation],to:[...target,zoom,angle,elevation]};this.invalidate();
  }
  reset(mode='orbit'){if(this.scene)this.move([this.bounds.center[0],this.bounds.center[1],this.bounds.center[2]*.25],1,-1.03,mode==='top'?1.565:.74);}
  fromCamera(sensor){if(!sensor.pose||sensor.knowledge==='redacted'||sensor.status==='redacted')return;this.animation=null;this.activeCamera=sensor;this.changed();}
  setLayer(key,value){if(!(key in this.layers))return;this.layers[key]=value;this.changed();}
  setLens(lens){this.lens=lens==='uncertainty'?'uncertainty':'context';this.changed();}
  select(kind,id,hypothesis=0){this.selected={kind,id,hypothesis};this.changed();}
  focus(p){if(this.scene)this.move(add(p,[0,0,.8]),.49);}
  invalidate(){if(this.destroyed||this.frame||this.lost)return;this.frame=requestAnimationFrame(()=>{this.frame=0;this.draw();});}
  view(width,height){
    if(this.activeCamera?.pose){const c=this.activeCamera,k=c.intrinsics,scale=Math.min(width/k.width,height/k.height);return{pose:c.pose,k:{...k,width,height,fx:k.fx*scale,fy:k.fy*scale,cx:(width-k.width*scale)/2+k.cx*scale,cy:(height-k.height*scale)/2+k.cy*scale}};}
    const r=this.bounds.radius*this.zoom*2.10,eye=add(this.target,[r*Math.cos(this.elevation)*Math.cos(this.angle),r*Math.cos(this.elevation)*Math.sin(this.angle),r*Math.sin(this.elevation)]);
    const focal=Math.min(width,height)*1.48;return{pose:lookAt(eye,this.target),k:{width,height,fx:focal,fy:focal,cx:width/2,cy:height*.52}};
  }
  geometry(){
    if(this.cache)return this.cache;
    const opaque=[],translucent=[],lines=[],gridLines=[];
    const triangle=(a,b,c,color,alpha=1,lit=true)=>{
      let light=1;if(lit){const n=cross(sub(b,a),sub(c,a)),l=Math.hypot(...n);light=l>1e-9?.67+.31*Math.abs(dot(mul(n,1/l),SUN)):.8;}
      const rgba=[...color.map(v=>Math.min(1,v*light)),alpha],to=alpha<1?translucent:opaque;for(const p of[a,b,c])to.push(...p,...rgba);
    };
    const line=(a,b,color,alpha=1)=>{lines.push(...a,...color,alpha,...b,...color,alpha);};
    const box=(p,size,color,alpha=1,wire=false)=>{
      const v=[];for(let z=0;z<2;z++)for(let y=0;y<2;y++)for(let x=0;x<2;x++)v.push(add(p,[(x-.5)*size[0],(y-.5)*size[1],z*size[2]]));
      for(const[a,b,c,d]of[[0,1,3,2],[4,6,7,5],[0,4,5,1],[2,3,7,6],[0,2,6,4],[1,5,7,3]]){if(wire){line(v[a],v[b],color,alpha);line(v[b],v[c],color,alpha);line(v[c],v[d],color,alpha);line(v[d],v[a],color,alpha);}else{triangle(v[a],v[b],v[c],color,alpha);triangle(v[a],v[c],v[d],color,alpha);}}
    };
    const ring=(p,r,color,alpha=1,dashed=false,vertical=0)=>{let prev=null;for(let i=0;i<=64;i++){const a=i*Math.PI/32;let d=[Math.cos(a)*r[0],Math.sin(a)*r[1],0];if(vertical===1)d=[d[0],0,Math.sin(a)*r[2]];if(vertical===2)d=[0,d[1],Math.cos(a)*r[2]];const v=add(p,d);if(prev&&(!dashed||i%4<2))line(prev,v,color,alpha);prev=v;}};
    const disc=(p,r,color,alpha)=>{for(let i=0;i<48;i++){const a=i*Math.PI/24,b=(i+1)*Math.PI/24;triangle(p,add(p,[Math.cos(a)*r[0],Math.sin(a)*r[1],0]),add(p,[Math.cos(b)*r[0],Math.sin(b)*r[1],0]),color,alpha,false);}};
    const person=(p,color,wire)=>{
      // Generic symbolic glyph, not measured body geometry or identity.
      const radius=[.14,.24,.21,.11],z=[.38,.65,1.18,1.40],v=[];
      for(let j=0;j<4;j++)for(let i=0;i<8;i++){const a=i*Math.PI/4;v.push(add(p,[Math.cos(a)*radius[j],Math.sin(a)*radius[j],z[j]]));}
      for(let j=0;j<3;j++)for(let i=0;i<8;i++){const a=j*8+i,b=j*8+(i+1)%8,c=b+8,d=a+8;if(wire){line(v[a],v[b],color);line(v[a],v[d],color);}else{triangle(v[a],v[b],v[c],color);triangle(v[a],v[c],v[d],color);}}
      const c=add(p,[0,0,1.57]),top=add(c,[0,0,.19]),bottom=add(c,[0,0,-.17]);
      for(let i=0;i<8;i++){const a=add(c,[.145*Math.cos(i*Math.PI/4),.145*Math.sin(i*Math.PI/4),0]),b=add(c,[.145*Math.cos((i+1)*Math.PI/4),.145*Math.sin((i+1)*Math.PI/4),0]);if(wire){line(a,b,color);line(a,top,color);}else{triangle(a,b,top,color);triangle(b,a,bottom,color);}}
      for(const dx of[-.13,.13])box(add(p,[dx,0,0]),[.12,.14,.47],color,1,wire);
      line(add(p,[-.28,0,1.12]),add(p,[-.36,0,.64]),color);line(add(p,[.28,0,1.12]),add(p,[.36,0,.64]),color);
    };
    for(const t of this.scene.mesh.triangles){const m=this.scene.mesh.materials[t[3]];if(!this.layers.roof&&m.role==='roof')continue;let color=m.color;if(this.lens==='uncertainty'){const gray=dot(color,[.22,.65,.13]);color=color.map(v=>(v*.25+gray*.75)*.69);}triangle(this.scene.mesh.vertices[t[0]],this.scene.mesh.vertices[t[1]],this.scene.mesh.vertices[t[2]],color);}
    const worldCount=opaque.length;
    if(this.layers.grid){const n=lines.length,r=this.bounds.radius,step=Math.pow(10,Math.floor(Math.log10(r/8))),max=Math.min(36,Math.ceil(r*1.4/step)),[x,y]=this.bounds.center;
      const minZ=this.scene.mesh.vertices.reduce((z,p)=>Math.min(z,p[2]),0)-.02;
      for(let i=-max;i<=max;i++){line([x-max*step,y+i*step,minZ],[x+max*step,y+i*step,minZ],[.37,.50,.52],.14);line([x+i*step,y-max*step,minZ],[x+i*step,y+max*step,minZ],[.37,.50,.52],.14);}gridLines.push(...lines.splice(n));}
    for(const sensor of this.scene.sensors){if(sensor.id===this.activeCamera?.id)continue;const p=sensor.pose?center(sensor.pose):sensor.position;if(!p||sensor.knowledge==='redacted'||sensor.status==='redacted')continue;
      const color=sensor.status==='offline'?COLORS.stale:sensor.kind==='camera'?COLORS.camera:COLORS.sensor,selected=this.selected?.kind==='sensor'&&this.selected.id===sensor.id;
      if(sensor.kind==='camera'&&sensor.pose){const c=frustum(sensor.pose,sensor.intrinsics,Math.min(8,this.bounds.radius*.32)),small=frustum(sensor.pose,sensor.intrinsics,.44);
        for(let i=0;i<4;i++){line(p,small[i],color);line(small[i],small[(i+1)%4],color);if(this.layers.frusta){line(p,c[i],color,selected?.8:.3);line(c[i],c[(i+1)%4],color,selected?.65:.2);triangle(p,c[i],c[(i+1)%4],color,selected?.09:.023,false);}}
        box(add(p,[0,0,-.14]),[.30,.30,.24],color);line(p,add(p,[0,0,-.5]),color,.6);
      }else{box(p,[.25,.25,.28],color);ring(p,[.38,.38,0],color,.7);}
    }
    if(this.layers.threats)for(const t of this.threats){const color=t.knowledge==='stale'?COLORS.stale:COLORS[t.severity]??COLORS.unrated,wire=t.knowledge!=='observed';
      for(let hi=0;hi<t.hypotheses.length;hi++){const h=t.hypotheses[hi],p=h.position,selected=this.selected?.kind==='threat'&&this.selected.id===t.id;
        if(t.shape==='person')person(p,color,wire);
        else if(t.shape==='vehicle')box(p,[1.8,3.5,1.4],color,1,wire);
        else if(t.shape==='animal'){box(add(p,[0,0,.32]),[.5,.9,.37],color,1,wire);box(add(p,[0,-.50,.4]),[.31,.35,.30],color,1,wire);for(const dx of[-.2,.2])for(const dy of[-.30,.3])line(add(p,[dx,dy,0]),add(p,[dx,dy,.38]),color);}
        else{const v=[[.4,0,.6],[0,.4,.6],[-.4,0,.6],[0,-.4,.6]].map(d=>add(p,d)),top=add(p,[0,0,1.25]);for(let i=0;i<4;i++){line(p,v[i],color);line(v[i],top,color);line(v[i],v[(i+1)%4],color);}}
        // Envelope radii are rendered exactly. A separate selection ring is UI, not uncertainty.
        ring(add(p,[0,0,.025]),h.radii,color,.85,wire);disc(add(p,[0,0,.018]),h.radii,color,this.lens==='uncertainty'?.16:.06);
        if(h.radii[2]>0){ring(p,h.radii,color,this.lens==='uncertainty'?.8:.34,true,1);ring(p,h.radii,color,this.lens==='uncertainty'?.8:.34,true,2);}
        if(t.knowledge==='conflicted')ring(add(p,[0,0,.03]),[h.radii[0]+.15,h.radii[1]+.15,0],[.75,.66,.96],.9,true);
        if(selected){ring(add(p,[0,0,.015]),[Math.max(.65,h.radii[0]+.35),Math.max(.65,h.radii[1]+.35),0],[.88,.96,.94],.9,true);if(this.selected.hypothesis===hi)ring(add(p,[0,0,.018]),[.35,.35,0],[.97,1,1],.9);}
      }
    }
    this.cache={opaque:new Float32Array(opaque),translucent:new Float32Array(translucent),lines:new Float32Array(lines),gridLines:new Float32Array(gridLines),worldCount};return this.cache;
  }
  draw(){
    if(!this.scene||this.lost||this.destroyed)return;
    if(this.animation){const a=this.animation,t=Math.min(1,(performance.now()-a.start)/380),ease=1-(1-t)**3,v=a.from.map((n,i)=>n+(a.to[i]-n)*ease);this.target=v.slice(0,3);this.zoom=v[3];this.angle=v[4];this.elevation=v[5];if(t===1)this.animation=null;}
    const w=Math.round(this.host.clientWidth),h=Math.round(this.host.clientHeight);if(w<2||h<2)return;
    const dpr=this.gl?Math.min(devicePixelRatio||1,1.75):Math.min(1,Math.sqrt(500000/(w*h)));
    const cw=Math.max(1,Math.round(w*dpr)),ch=Math.max(1,Math.round(h*dpr));if(this.canvas.width!==cw||this.canvas.height!==ch){this.canvas.width=cw;this.canvas.height=ch;}
    const view=this.view(w,h),geometry=this.geometry();
    if(this.gl)this.drawGL(geometry,view.pose,view.k);
    else if(this.ctx){const k={...view.k,width:cw,height:ch,fx:view.k.fx*dpr,fy:view.k.fy*dpr,cx:view.k.cx*dpr,cy:view.k.cy*dpr};this.software(geometry,view.pose,k,cw,ch);}
    this.labels(view.pose,view.k,w,h);
    this.onView({angle:this.angle,elevation:this.elevation,activeCamera:this.activeCamera,visible:this.hit?.length??0,limited:this.labelLimited??0});
    if(this.animation)this.invalidate();
  }
  drawGL(geometry,pose,k){
    const gl=this.gl,lm=lightMatrix(this.bounds),draw=(vertices,mode)=>{if(!vertices.length)return;gl.bufferData(gl.ARRAY_BUFFER,vertices,gl.DYNAMIC_DRAW);gl.drawArrays(mode,0,vertices.length/7);};
    gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);gl.bindBuffer(gl.ARRAY_BUFFER,this.buffer);
    if(this.hasShadows&&this.shadowDirty){
      gl.bindFramebuffer(gl.FRAMEBUFFER,this.fbo);gl.viewport(0,0,1024,1024);gl.clearColor(1,1,1,1);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.disable(gl.BLEND);gl.depthMask(true);
      gl.useProgram(this.shadowProgram);gl.uniformMatrix4fv(this.shadowMatrix,false,lm);gl.enableVertexAttribArray(this.shadowPos);gl.vertexAttribPointer(this.shadowPos,3,gl.FLOAT,false,28,0);draw(geometry.opaque.subarray(0,geometry.worldCount),gl.TRIANGLES);this.shadowDirty=false;
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER,null);gl.viewport(0,0,this.canvas.width,this.canvas.height);gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);
    gl.useProgram(this.program);gl.uniformMatrix4fv(this.matrix,false,cameraMatrix(pose,k,.025,Math.max(2000,this.bounds.radius*12)));gl.uniformMatrix4fv(this.light,false,lm);gl.activeTexture(gl.TEXTURE0);gl.bindTexture(gl.TEXTURE_2D,this.shadowTexture);gl.uniform1i(this.sampler,0);
    gl.enableVertexAttribArray(this.pos);gl.vertexAttribPointer(this.pos,3,gl.FLOAT,false,28,0);gl.enableVertexAttribArray(this.color);gl.vertexAttribPointer(this.color,4,gl.FLOAT,false,28,12);
    gl.disable(gl.BLEND);gl.depthMask(true);gl.uniform1f(this.shade,this.hasShadows?1:0);draw(geometry.opaque,gl.TRIANGLES);
    gl.uniform1f(this.shade,0);gl.enable(gl.BLEND);gl.blendFunc(gl.SRC_ALPHA,gl.ONE_MINUS_SRC_ALPHA);gl.depthMask(false);draw(geometry.gridLines,gl.LINES);draw(geometry.translucent,gl.TRIANGLES);draw(geometry.lines,gl.LINES);gl.depthMask(true);
  }
  labels(pose,k,w,h){
    this.overlay.setAttribute('viewBox',`0 0 ${w} ${h}`);this.overlay.replaceChildren();this.hit=[];this.labelLimited=0;if(!this.overlayEnabled)return;
    const items=[];let cameras=0,others=0;
    for(const s of this.scene.sensors){const ordinal=s.kind==='camera'?`C${++cameras}`:`S${++others}`,p=s.pose?center(s.pose):s.position;if(!p||s.id===this.activeCamera?.id||s.knowledge==='redacted'||s.status==='redacted')continue;items.push({p:add(p,[0,0,.32]),kind:'sensor',id:s.id,label:s.label,state:s.status,code:ordinal,color:s.status==='offline'?COLORS.stale:COLORS.camera});}
    if(this.layers.threats)this.threats.forEach((t,n)=>t.hypotheses.forEach((hypothesis,i)=>items.push({p:add(hypothesis.position,[0,0,2.0]),kind:'threat',id:t.id,hypothesis:i,label:t.kind.replaceAll('_',' '),state:t.knowledge,code:String(n+1).padStart(2,'0')+(t.hypotheses.length>1?`·H${i+1}`:''),color:t.knowledge==='stale'?COLORS.stale:COLORS[t.severity]??COLORS.unrated})));
    // Selected hypotheses get first choice of label positions, but others remain in the inventory.
    items.sort((a,b)=>Number(b.id===this.selected?.id)-Number(a.id===this.selected?.id));const occupied=[];
    for(const item of items){const p=project(pose,k,item.p);if(!p||p[0]<8||p[0]>w-8||p[1]<75||p[1]>h-42){this.labelLimited++;continue;}const selected=this.selected?.id===item.id,expanded=selected||this.layers.labels;
      const code=item.code,full=item.label.length>26?item.label.slice(0,24)+'…':item.label,label=full[0].toUpperCase()+full.slice(1),box={x:p[0],y:p[1],w:expanded?Math.min(195,Math.max(145,label.length*6.2+35)):code.length>3?52:32,h:expanded?42:27};
      box.x=Math.max(5,Math.min(w-box.w-5,p[0]-box.w/2));box.y=p[1]-box.h;
      let found=false;for(const offset of[0,-32,32,-64,64,-96,96]){const y=Math.max(82,Math.min(h-75,box.y+offset)),candidate={...box,y};if(!occupied.some(b=>pointInBox(candidate,b))){box.y=y;found=true;break;}}
      if((!found&&!selected)||occupied.length>=80){this.labelLimited++;continue;}occupied.push(box);
      this.hit.push({x:p[0],y:p[1],...item});const color=HEX(item.color),g=svg('g',{class:'world-label',role:'button',tabindex:0,'aria-label':`${code}: ${item.label}; position ${item.state}${item.hypothesis===undefined?'':`; hypothesis ${item.hypothesis+1}`}`});
      g.append(svg('title',{},`${item.id}\n${item.label} · ${item.state}\nMarker is an x-ray annotation, not a visibility claim.`));
      g.append(svg('line',{x1:Math.max(box.x+8,Math.min(box.x+box.w-8,p[0])),y1:box.y+box.h,x2:p[0],y2:p[1]+10,stroke:color,'stroke-opacity':selected?.85:.45}));
      g.append(svg('circle',{cx:p[0],cy:p[1]+10,r:2.2,fill:color}));
      g.append(svg('rect',{x:box.x,y:box.y,width:box.w,height:box.h,rx:expanded?8:7,class:'label-body',stroke:color}));
      if(expanded){g.append(svg('rect',{x:box.x+1,y:box.y+9,width:2,height:23,rx:1,fill:color}));g.append(svg('text',{x:box.x+10,y:box.y+17,class:'world-label-title'},label));g.append(svg('text',{x:box.x+10,y:box.y+31,class:'world-label-status'},`${code} · ${item.state.toUpperCase()}`));}
      else g.append(svg('text',{x:box.x+box.w/2,y:box.y+17,'text-anchor':'middle',class:'marker-number',fill:color},code));
      const choose=()=>this.onSelect(item.kind,item.id,item.hypothesis??0);g.addEventListener('click',choose);g.addEventListener('keydown',e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();choose();}});this.overlay.append(g);
    }
  }
  softwareShadow(geometry){
    if(geometry.softwareShadow)return geometry.softwareShadow;
    const size=384,depth=new Float32Array(size*size);depth.fill(Infinity);const matrix=lightMatrix(this.bounds);
    const light=p=>{const out=[];for(let row=0;row<3;row++)out.push(matrix[row]*p[0]+matrix[4+row]*p[1]+matrix[8+row]*p[2]+matrix[12+row]);return[(out[0]+1)*.5*size,(1-out[1])*.5*size,(out[2]+1)*.5];};
    const arr=geometry.opaque;
    for(let i=0;i<geometry.worldCount;i+=21){const[a,b,c]=[0,7,14].map(n=>light(arr.subarray(i+n,i+n+3))),area=(b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]);if(Math.abs(area)<1e-10)continue;
      const x0=Math.max(0,Math.floor(Math.min(a[0],b[0],c[0]))),x1=Math.min(size-1,Math.ceil(Math.max(a[0],b[0],c[0]))),y0=Math.max(0,Math.floor(Math.min(a[1],b[1],c[1]))),y1=Math.min(size-1,Math.ceil(Math.max(a[1],b[1],c[1])));
      for(let y=y0;y<=y1;y++)for(let x=x0;x<=x1;x++){const xx=x+.5,yy=y+.5,wa=((b[0]-xx)*(c[1]-yy)-(b[1]-yy)*(c[0]-xx))/area,wb=((c[0]-xx)*(a[1]-yy)-(c[1]-yy)*(a[0]-xx))/area,wc=1-wa-wb;if(wa<0||wb<0||wc<0)continue;const z=wa*a[2]+wb*b[2]+wc*c[2],at=y*size+x;if(z<depth[at])depth[at]=z;}
    }
    geometry.softwareShadow={depth,size,light};return geometry.softwareShadow;
  }
  software(geometry,pose,k,w,h){
    // Bounded depth-buffered fallback, including near clipping and perspective-correct depth.
    const image=this.ctx.createImageData(w,h),pixels=image.data,depth=new Float32Array(w*h);depth.fill(Infinity);
    for(let y=0;y<h;y++)for(let x=0;x<w;x++){const glow=Math.max(0,1-Math.hypot((x/w-.47)*1.2,(y/h-.42)*1.1)),i=(y*w+x)*4;pixels[i]=24+24*glow;pixels[i+1]=35+30*glow;pixels[i+2]=42+29*glow;pixels[i+3]=255;}
    const blend=(index,color,alpha)=>{const at=index*4;for(let c=0;c<3;c++)pixels[at+c]=pixels[at+c]*(1-alpha)+color[c]*255*alpha;};
    const shadow=this.softwareShadow(geometry);
    const point=c=>[k.fx*c[0]/c[2]+k.cx,k.fy*c[1]/c[2]+k.cy,c[2],...c.slice(3)],near=.025;
    const clip=poly=>{const out=[];for(let i=0;i<poly.length;i++){const a=poly[i],b=poly[(i+1)%poly.length],ai=a[2]>=near,bi=b[2]>=near;if(ai)out.push(a);if(ai!==bi)out.push(add(a,mul(sub(b,a),(near-a[2])/(b[2]-a[2]))));}return out;};
    const triangle=(a,b,c,color,alpha,write)=>{
      const area=(b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]);if(Math.abs(area)<1e-10)return;
      const x0=Math.max(0,Math.floor(Math.min(a[0],b[0],c[0]))),x1=Math.min(w-1,Math.ceil(Math.max(a[0],b[0],c[0]))),y0=Math.max(0,Math.floor(Math.min(a[1],b[1],c[1]))),y1=Math.min(h-1,Math.ceil(Math.max(a[1],b[1],c[1])));
      for(let y=y0;y<=y1;y++)for(let x=x0;x<=x1;x++){const xx=x+.5,yy=y+.5,wa=((b[0]-xx)*(c[1]-yy)-(b[1]-yy)*(c[0]-xx))/area,wb=((c[0]-xx)*(a[1]-yy)-(c[1]-yy)*(a[0]-xx))/area,wc=1-wa-wb;if(wa<0||wb<0||wc<0)continue;const z=1/(wa/a[2]+wb/b[2]+wc/c[2]),index=y*w+x;if(z<=depth[index]+1e-5){
          let shade=1;
          if(write&&a.length>3){const sx=Math.round((wa*a[3]/a[2]+wb*b[3]/b[2]+wc*c[3]/c[2])*z),sy=Math.round((wa*a[4]/a[2]+wb*b[4]/b[2]+wc*c[4]/c[2])*z),sz=(wa*a[5]/a[2]+wb*b[5]/b[2]+wc*c[5]/c[2])*z;
            if(sx>0&&sx<shadow.size-1&&sy>0&&sy<shadow.size-1){const at=sy*shadow.size+sx;let hits=0;for(const offset of[0,-1,1,-shadow.size,shadow.size])if(sz-.002>shadow.depth[at+offset])hits++;shade=1-hits*.055;}}
          blend(index,shade===1?color:color.map(v=>v*shade),alpha);if(write)depth[index]=z;
        }}
    };
    const triangles=(arr,write)=>{const faces=[];for(let i=0;i<arr.length;i+=21){const poly=clip([0,7,14].map(n=>{const p=arr.slice(i+n,i+n+3);return [...transform(pose,p),...shadow.light(p)];}));for(let j=1;j<poly.length-1;j++)faces.push({p:[poly[0],poly[j],poly[j+1]].map(point),color:arr.slice(i+3,i+6),alpha:arr[i+6]});}if(!write)faces.sort((a,b)=>b.p.reduce((n,p)=>n+p[2],0)-a.p.reduce((n,p)=>n+p[2],0));for(const f of faces)triangle(...f.p,f.color,f.alpha,write);};
    const lines=arr=>{for(let i=0;i<arr.length;i+=14){let a=transform(pose,arr.slice(i,i+3)),b=transform(pose,arr.slice(i+7,i+10));if(a[2]<near&&b[2]<near)continue;if(a[2]<near)a=add(a,mul(sub(b,a),(near-a[2])/(b[2]-a[2])));if(b[2]<near)b=add(b,mul(sub(a,b),(near-b[2])/(a[2]-b[2])));a=point(a);b=point(b);const steps=Math.min(5000,Math.max(1,Math.ceil(Math.hypot(b[0]-a[0],b[1]-a[1]))));for(let j=0;j<=steps;j++){const t=j/steps,x=Math.round(a[0]+(b[0]-a[0])*t),y=Math.round(a[1]+(b[1]-a[1])*t);if(x<0||y<0||x>=w||y>=h)continue;const z=1/((1-t)/a[2]+t/b[2]),index=y*w+x;if(z<depth[index]+.025)blend(index,arr.slice(i+3,i+6),arr[i+6]);}}};
    triangles(geometry.opaque,true);lines(geometry.gridLines);triangles(geometry.translucent,false);lines(geometry.lines);this.ctx.putImageData(image,0,0);
  }
  releaseGL(){const gl=this.gl;if(!gl)return;for(const name of['buffer'])if(this[name])gl.deleteBuffer(this[name]);for(const name of['program','shadowProgram'])if(this[name])gl.deleteProgram(this[name]);if(this.shadowTexture)gl.deleteTexture(this.shadowTexture);if(this.depth)gl.deleteRenderbuffer(this.depth);if(this.fbo)gl.deleteFramebuffer(this.fbo);}
  dispose(){this.destroyed=true;this.animation=null;this.resize.disconnect();cancelAnimationFrame(this.frame);this.cache=null;this.scene=null;this.threats=[];this.hit=[];this.activeCamera=null;this.releaseGL();this.gl?.getExtension('WEBGL_lose_context')?.loseContext();this.host.replaceChildren();}
}
