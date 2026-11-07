#!/usr/bin/env python3
"""Feed complete masked camera-event frames to a pinned Rust parser in memory.

The trace is passive and time-bounded. Raw bytes live only in pipes and process
memory. Output consists of aggregate labels, bounded alphabetic protocol
function names, and top-level field names and types, never payload values.
No TLS read is independently attributed to an individual socket here.
"""
import collections
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

if len(sys.argv)!=4: raise SystemExit("expected controller PID, parser path, and parser SHA-256")
try: pid=int(sys.argv[1])
except ValueError: raise SystemExit("invalid controller PID")
if pid<2: raise SystemExit("invalid controller PID")
path,expected=sys.argv[2:]
if not re.fullmatch(r"[a-f0-9]{64}",expected): raise SystemExit("invalid parser SHA-256")
with open(path,"rb") as executable:
    if hashlib.sha256(executable.read()).hexdigest()!=expected: raise SystemExit("parser hash mismatch")
if not os.path.exists(f"/proc/{pid}/root/usr/bin/node"): raise SystemExit("controller process missing")
if os.readlink(f"/proc/{pid}/exe") != "/usr/bin/node": raise SystemExit("controller process is not the expected node binary")
program=r'''config = { max_strlen = 256; }
uprobe:/proc/2303589/root/usr/bin/node:SSL_read /pid == 2303589/ { @ptr[tid] = arg1; }
uretprobe:/proc/2303589/root/usr/bin/node:SSL_read /pid == 2303589 && @ptr[tid]/ {
  $p=@ptr[tid]; $n=retval;
  if ($n >= 6 && $n <= 4096) {
    $a=*(uint8*)uptr($p); $b=*(uint8*)uptr($p+1);
    if (($a & 15)==2 && ($b & 128)) {
      @seq[tid]++; $seq=@seq[tid];
      for ($i : 0..18) {
        $off=$i*240;
        if ($off < $n) {
          $size=$n-$off; if ($size>240) { $size=240; }
          printf("C %d %d %d %d |%rh\n",tid,$seq,$n,$i,buf(uptr($p+$off),$size));
        }
      }
    }
  }
  delete(@ptr[tid]);
}
interval:s:30 { clear(@ptr); clear(@seq); exit(); }'''
program=program.replace("2303589",str(pid))
native=subprocess.Popen([path],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
trace=subprocess.Popen(["sudo","-n","timeout","60s","bpftrace","-e",program],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
assert native.stdin is not None and native.stdout is not None and trace.stdout is not None
pending={};counts=collections.Counter();accepted=0
safe_shape_keys=("eventType","edgeType","descriptors","audioType","soundType","classification","type","confidence","confidenceLevel","event","events","smartAudio","data","value","score","level","state","detected","timestamp","start","end","audio")
def shape(value):
    if value is None: return "null"
    if isinstance(value,bool): return "boolean"
    if isinstance(value,(int,float)): return "number"
    if isinstance(value,str): return "string"
    if isinstance(value,list): return "array_empty" if not value else "array_nonempty"
    if isinstance(value,dict): return "object_empty" if not value else "object_nonempty"
    return "unsupported"
for line in trace.stdout:
    if not line.startswith("C "): continue
    try:
        label,hexdata=line.rstrip().split("|",1)
        _,tid,seq,total,index=label.split();tid=int(tid);seq=int(seq);total=int(total);index=int(index)
        chunk=bytes.fromhex(hexdata);key=(tid,seq)
        if not (6<=total<=4096 and 0<=index<18 and len(chunk)<=240): counts["invalid_chunk"]+=1;continue
        if len(pending)>=32 and key not in pending: counts["capacity_refusal"]+=1;continue
        entry=pending.setdefault(key,{"total":total,"chunks":{}})
        if entry["total"]!=total or index in entry["chunks"]: counts["chunk_conflict"]+=1;pending.pop(key,None);continue
        entry["chunks"][index]=chunk
        needed=(total+239)//240
        if len(entry["chunks"])!=needed: continue
        raw=b"".join(entry["chunks"].get(i,b"") for i in range(needed));pending.pop(key,None)
        if len(raw)!=total:
            counts["incomplete_read"]+=1
            counts[f"chunk_size_{min(map(len,entry['chunks'].values()))}_{max(map(len,entry['chunks'].values()))}"]+=1
            continue
        size=raw[1]&127;offset=2
        if size==126: size=struct.unpack_from(">H",raw,offset)[0];offset+=2
        elif size==127: size=struct.unpack_from(">Q",raw,offset)[0];offset+=8
        mask=raw[offset:offset+4];offset+=4
        if offset+size!=len(raw): counts["not_one_complete_frame"]+=1;continue
        message=bytes(b^mask[i%4] for i,b in enumerate(raw[offset:]))
        try: obj=json.loads(message)
        except (UnicodeDecodeError,json.JSONDecodeError): counts["non_json"]+=1;continue
        if not isinstance(obj,dict) or obj.get("from")!="ubnt_avclient" or obj.get("to")!="UniFiVideo" or not isinstance(obj.get("functionName"),str) or not obj["functionName"].startswith("Event"):
            counts["other_envelope"]+=1;continue
        name=obj["functionName"]
        if re.fullmatch(r"Event[A-Za-z]{1,40}",name): counts[f"protocol_function:{name}"]+=1
        else: counts["protocol_function_redacted"]+=1
        if name=="EventSmartAudio":
            payload=obj.get("payload")
            counts[f"smart_audio_payload:{shape(payload)}"]+=1
            if isinstance(payload,dict):
                for key in safe_shape_keys:
                    if key in payload: counts[f"smart_audio_field:{key}:{shape(payload[key])}"]+=1
                for key,value in payload.items():
                    if re.fullmatch(r"[a-z][A-Za-z]{0,30}",key): counts[f"smart_audio_top_key:{key}:{shape(value)}"]+=1
                    else: counts["smart_audio_top_key_redacted"]+=1
        if accepted>=32: counts["parser_limit"]+=1;continue
        native.stdin.write(struct.pack(">I",len(message))+message);native.stdin.flush();accepted+=1
        del obj,message,raw
    except (ValueError,TypeError,struct.error,BrokenPipeError): counts["parse_refused"]+=1
trace_status=trace.wait();native.stdin.close()
native_output=native.stdout.read(512).decode("ascii","replace").strip();native_status=native.wait()
print("trace_exit",trace_status,"parser_exit",native_status,"incomplete_chunk_groups",len(pending))
for key in sorted(counts): print(key,counts[key])
print(native_output)
if trace_status or native_status: sys.exit(1)
