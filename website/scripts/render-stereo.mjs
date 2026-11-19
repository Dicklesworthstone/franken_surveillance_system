import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile,writeFile,rename } from "node:fs/promises";
import {join} from "node:path";
import {encodeFilm} from "./render-motion.mjs";
import {cameraRig,moments,optics,referenceFrame,imageSize} from "../lib/stereo.js";
import {clipSeconds,frameRate} from "../lib/pass.js";

export async function renderStereo(render,dir){
 const out="public/stereo",files=[];
 const add=name=>{files.push(name);return join(dir,name)};
 const hash=async path=>"sha256:"+createHash("sha256").update(await readFile(path)).digest("hex");
 const cameras={};
 for(const id of Object.keys(cameraRig)){
   const film="public/court/"+id+".mp4";
   cameras[id]={...optics(id),film:"/court/"+id+".mp4",digest:await hash(film)};
   for(const {frame} of moments){
     execFileSync("ffmpeg",["-nostdin","-v","error","-i",film,"-vf","select=eq(n\\,"+frame+")","-frames:v","1","-threads","1",add(id+"-"+frame+".png")]);
   }
 }
 async function* frames(){for(let i=0;i<clipSeconds*frameRate;i++){
   const {jpeg}=await render("film",i/frameRate,"stereo",896,504);
   yield Buffer.from(jpeg,"base64");
 }}
 await encodeFilm(add("sightlines.mp4"),frameRate,frames());
 const still=await render("film",1,"stereo",1408,792);
 await writeFile(add("sightlines.jpg"),Buffer.from(still.jpeg,"base64"));
 const index={imageSize,fps:frameRate,coordinates:"Three.js right-handed Y-up, metres",cameras,
 floor:{width:20,depth:12,y:-.002},moments:moments.map(m=>({...m,...referenceFrame(m.frame)})),files:{}};
 for(const name of files)index.files[name]=await hash(join(dir,name));
 await writeFile(add("capture.json"),JSON.stringify(index,null,2)+"\n");
 for(const name of files)await rename(join(dir,name),join(out,name));
 console.log("Rendered stereo film, paired source frames and camera geometry.");
}
