"use client";
import {useEffect,useRef,useState} from "react";
import {createProperty} from "../lib/property";

export default function Viewport({scenario,time,view,cones,reset,playing}) {
  const surface=useRef(null), stage=useRef(null), current=useRef(null), frame=useRef(null);
  const [ready,setReady]=useState(false),[failed,setFailed]=useState(false);
  useEffect(()=>{
    current.current={scenario,time,view,cones};
    frame.current?.();
  },[scenario,time,view,cones]);
  useEffect(()=>{
    const canvas=surface.current, parent=canvas.parentElement;
    let model;
    const lost=(e)=>{e.preventDefault();setFailed(true);setReady(false);};
    canvas.addEventListener("webglcontextlost",lost);
    try{model=createProperty(canvas);}catch{setFailed(true);return ()=>canvas.removeEventListener("webglcontextlost",lost);}
    stage.current=model;
    const draw=()=>{const v=current.current;if(!v)return;const o=model.draw(v.scenario,v.time,v.view,v.cones);
      const marks=parent.querySelector(".trackbox");
      const height=Math.abs(o.foot[1]-o.head[1]);
      marks.hidden=v.view==="overview"||!o.visible;
      marks.style.left=(o.foot[0])+"%"; marks.style.top=Math.min(o.head[1],o.foot[1])+"%";
      marks.style.height=height+"%";marks.style.width=Math.max(2,height*(v.scenario.id==="wildlife"?.98:.35)*parent.clientHeight/parent.clientWidth)+"%";
    };
    frame.current=draw;model.onOrbit(draw);
    const size=()=>{model.resize(parent.clientWidth,parent.clientHeight);draw();};
    const ro=new ResizeObserver(size);ro.observe(parent);size();setReady(true);
    return ()=>{ro.disconnect();frame.current=null;stage.current=null;canvas.removeEventListener("webglcontextlost",lost);model.dispose();};
  },[]);
  useEffect(()=>{stage.current?.reset();frame.current?.();},[reset]);
  const video=useRef(null);
  useEffect(()=>{if(video.current && Math.abs(video.current.currentTime-time)>.23)video.current.currentTime=time;},[time,failed,scenario]);
  return <div className="viewport-surface" style={{backgroundImage:'url(/films/'+(view==="overview"?"property":scenario.id)+'.jpg)'}}>
    <canvas ref={surface} aria-label={view==="overview"?"Interactive 3D model of Juniper House. Drag to orbit or choose a fixed camera below.":"Virtual camera image of Juniper House"} style={{opacity:ready?1:0}}/>
    {failed&&<><video ref={video} src={'/films/'+scenario.id+'.mp4'} poster={'/films/'+scenario.id+'.jpg'} muted playsInline preload="auto"/><span className="fallback">WebGL unavailable · recorded {scenario.camera} view</span></>}
    <div className="trackbox" hidden><span>{scenario.kind} · simulated</span></div>
  </div>;
}
