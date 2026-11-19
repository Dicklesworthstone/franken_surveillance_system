import { ImageResponse } from "next/og";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { cache } from "react";
import { exhibits } from "./exhibits";
import { fieldData } from "./field-data";

const row={display:"flex"}, column={...row,flexDirection:"column"},abs={...row,position:"absolute"};
const paper="#f3ecdd", forest="#112d24";
const local=file=>readFile(path.join(process.cwd(),file));
const jpeg=cache(async file=>"data:image/jpeg;base64,"+(await local(file)).toString("base64"));
const font=cache(async()=>Promise.all([
 ["Instrument","normal","@fontsource/instrument-serif/files/instrument-serif-latin-400-normal.woff"],
 ["Instrument","italic","@fontsource/instrument-serif/files/instrument-serif-latin-400-italic.woff"],
 ["Mono","normal","@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff"],
].map(async([name,style,file])=>({name,style,weight:400,data:await local("node_modules/"+file)}))));
const mono=(text,styles={})=><div style={{...row,fontFamily:"Mono",fontSize:16,letterSpacing:.7,...styles}}>{text}</div>;
function Brand(){return <div style={{...row,alignItems:"center",gap:12}}>
 <svg width="32" height="32" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" strokeWidth="1.8"/><circle cx="16" cy="16" r="8" fill="none" stroke="currentColor" strokeWidth="2"/><circle cx="16" cy="16" r="3" fill="currentColor"/><path d="M16 1V6M26 16H31M16 26V31M1 16H6" stroke="currentColor" strokeWidth="2"/></svg>
 {mono("FRANKEN SURVEILLANCE",{fontSize:19,letterSpacing:.8})}</div>}
const labelFor = {
 "poster-room":"Juniper House cover collection",home:"A residential digital twin", "motion-study":"A courier in motion", "film-archive":"The night recordings",
 "camera-inputs":"Consumer camera optics","event-ledger":"Inside the immutable ledger","belief-lab":"Evidence and uncertainty","agent-console":"The agent workspace","owner-response":"Owner-controlled actions",
 "digital-twin":"Property survey",courtyard:"The courtyard study","stereo-bench":"The stereo bench","camera-wall":"The camera wall","camera-fusion":"The doorstep case","field-method":"Reading a recording"
};
const covers={
 home:["art/juniper-model.jpg","Three cameras. One site.","ARCHITECTURAL ILLUSTRATION"],
 "motion-study":["art/arrival.jpg","A parcel, a release, a rebound.","DELIVERY STUDY  /  COVER ILLUSTRATION"],
 "film-archive":["art/night-garden.jpg","Nine films across three encounters.","NIGHT GARDEN  /  COVER ILLUSTRATION"],
};
const objects={
 "camera-inputs":["art/camera-optics.jpg","#dce9db","#1d482f","RTSP  /  HTTP MJPEG  /  FILE IMPORT"],
 "event-ledger":["art/ledger-glass.jpg","#072927","#adf3d4","CONTENT-ADDRESSED PUBLICATION"],
 "belief-lab":["art/instruments/prism.jpg","#ebe6f0","#513659","SHARED SOURCE"],
 "agent-console":["art/instruments/folio.jpg","#1b363b","#b4e3de","ONE SESSION  /  HANDOFF AND RESUME"],
 "owner-response":["art/instruments/bell.jpg","#ede2cc","#713e2b","NOTIFICATION PLAN"],
 "poster-room":["art/instruments/film.jpg","#352723","#fbddbe","OPEN GRAPH  /  X CARD EDITIONS"],
 "digital-twin":["art/site-plan.jpg","#dce2d5","#244b37","THREE FIXED CAMERA POSES"]
};
const sheets={
 courtyard:[["public/court/arc.jpg","Ball flight"],["public/court/hands.jpg","At the receiver"]],
 "stereo-bench":[["public/stereo/sightlines.jpg","Calibrated sightlines"],["public/court/garden.jpg","Garden camera"]],
 "camera-wall":[["public/wall/delivery.jpg","Delivery reel"],["public/wall/wildlife.jpg","Garden reel"]],
 "camera-fusion":[["public/field/porch.jpg","Porch entry"],["public/field/drive.jpg","Driveway entry"]],
 "field-method":[["public/motion/pose.jpg","Authored scene"],["public/motion/porch-sample.jpg","Native input"]],
};
function Headline({lines,accent,size=106}){
 return <div style={{...column,fontSize:size,lineHeight:1,letterSpacing:-3}}>
 {lines.map((l,i)=><div key={l} style={{...row,fontStyle:i?"italic":"normal",color:i?accent:undefined}}>{l}</div>)}</div>
}
async function Cover({slug,h}){
 const [file,dek,credit]=covers[slug];
 return <div style={{...column,width:1200,height:h,backgroundColor:"#10251c",position:"relative",color:"#fff4dc"}}>
 <img src={await jpeg(file)} width={1200} height={h} alt="" style={{...abs,top:0,left:0,objectFit:"cover"}}/>
 <div style={{...abs,left:0,top:0,width:1200,height:h,backgroundImage:"linear-gradient(90deg,rgba(6,21,16,.83) 0%,rgba(6,21,16,.64) 30%,rgba(6,21,16,0) 68%)"}}/>
 <div style={{...column,position:"relative",padding:"40px 50px 34px",justifyContent:"space-between",height:h}}>
 <Brand/><div style={column}>{mono(labelFor[slug].toUpperCase(),{marginBottom:14,color:"#c5dbc0"})}<Headline lines={exhibits[slug].lines} accent="#ffd096" size={117}/><div style={{...row,fontFamily:"Instrument",fontSize:31,marginTop:10}}>{dek}</div></div>
 {mono(credit,{fontSize:13})}</div></div>
}
async function ObjectPlate({slug,h}){
 const [file,bg,ink,caption]=objects[slug];
 const light=!["event-ledger","agent-console","poster-room"].includes(slug);
 let note=caption;
 const field=fieldData();
 if(slug==="belief-lab")note=field.belief.shared.interval.map(n=>(n/10000).toFixed(1)).join("–")+"%  /  SHARED-SOURCE FIXTURE";
 if(slug==="owner-response")note=field.agent.alert.outcome.toUpperCase()+"  /  NOTIFICATION PLAN";
 if(slug==="event-ledger")note=field.ledger.objects.length+" VERIFIED OBJECTS  /  DOORSTEP";
 return <div style={{...row,position:"relative",height:h,width:1200,backgroundColor:bg,color:ink}}>
 <div style={{...column,width:595,height:h,padding:"40px 0 40px 47px",justifyContent:"space-between"}}>
 <Brand/><div style={column}>{mono(labelFor[slug].toUpperCase(),{marginBottom:22})}<Headline lines={exhibits[slug].lines} accent={light?"#925437":"#f0bd8e"} size={102}/></div>
 <div style={{...column,borderTop:"1px solid "+ink,paddingTop:13,width:500}}>{mono(note,{fontSize:15})}</div></div>
 <div style={{...column,width:605,alignItems:"center",justifyContent:"center",padding:"23px 27px 23px 7px"}}>
 <div style={{...row,backgroundColor:light?"#fffbf0":"#e6e1cd",padding:9,transform:"rotate(2deg)"}}>
 <img src={await jpeg(file)} width={530} height={h-100} alt="" style={{...row,objectFit:"cover"}}/></div></div></div>
}
async function ContactSheet({slug,h}){
 const info=exhibits[slug],field=fieldData();
 const captions={
  courtyard:"ONE PASS  /  TWO FIXED CAMERAS","stereo-bench":"TWO RAYS  /  ONE RECONSTRUCTION",
  "camera-wall":"FOUR VIEWS  /  ONE CLOCK","camera-fusion":Math.round(field.association.distance*100)+" CM APART  /  "+field.association.delta+" MS WORST CASE",
  "field-method":"SCENE RENDER  /  IMPORTED CAMERA FRAME"
 };
 const bg=slug==="camera-wall"?"#172d33":slug==="courtyard"?"#e8cabb":paper,fg=slug==="camera-wall"?paper:forest;
 return <div style={{...column,width:1200,height:h,backgroundColor:bg,color:fg,padding:"30px 43px 25px",justifyContent:"space-between"}}>
 <div style={{...row,alignItems:"center",justifyContent:"space-between"}}><Brand/>{mono(labelFor[slug].toUpperCase(),{fontSize:16})}</div>
 <div style={{...row,alignItems:"baseline",fontSize:81,lineHeight:1.1,letterSpacing:-2,marginTop:4}}><div style={row}>{info.lines[0]}</div><div style={{...row,fontStyle:"italic",color:slug==="camera-wall"?"#ffc89a":"#93543a",marginLeft:14}}>{info.lines[1]}</div></div>
 <div style={{...row,gap:12}}>{await Promise.all(sheets[slug].map(async([file,label],i)=><div key={label} style={{...column,width:i?412:688}}>
 <img src={await jpeg(file)} width={i?412:688} height={h-265} alt="" style={{...row,objectFit:"cover",border:"1px solid "+fg}}/>
 {mono(label.toUpperCase(),{marginTop:7,fontSize:14})}</div>))}</div>
 {mono(captions[slug],{paddingTop:9,borderTop:"1px solid "+fg,fontSize:16})}</div>
}
const raster=cache(async(slug,height)=>{
 const props={slug,h:height};
 const artwork=covers[slug]?await Cover(props):objects[slug]?await ObjectPlate(props):await ContactSheet(props);
 const response=new ImageResponse(<div style={{...row,fontFamily:"Instrument",width:1200,height}}>{artwork}</div>,{width:1200,height,fonts:await font()});
 return Buffer.from(await response.arrayBuffer());
});

// A real .png suffix survives a static host's MIME detection; the bytes name
// their own URL, including when only a fixture, font or composition changes.
export async function imageMeta(slug, height) {
  const bytes = await raster(slug, height);
  return [
    {
      id:
        createHash("sha256").update(bytes).digest("hex").slice(0, 20) + ".png",
      alt: exhibits[slug].title + ". " + exhibits[slug].description,
      size: { width: 1200, height },
      contentType: "image/png",
    },
  ];
}
export async function imageBody(slug, height) {
  return new Response(await raster(slug, height), {
    headers: { "Content-Type": "image/png" },
  });
}
