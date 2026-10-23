import socket, struct, sys, time, threading
import sys
IF_IP=sys.argv[1] if len(sys.argv)>1 else "192.168.4.160"; GW=sys.argv[2] if len(sys.argv)>2 else "192.168.4.1"
NAMES={b"s3-us-west-2.amazonaws.com", b"aws-iot.wyzecam.com",
       b"d1fk93tz4plczb.cloudfront.net", b"d2h8pzxcxn71bo.cloudfront.net",
       b"a24rq1e5m4mtei.iot.us-west-2.amazonaws.com", b"wyze-upgrade-service.wyzecam.com"}
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",53))
end=time.time()+3600
def parse_name(q):
    labels=[]
    i=12
    while q[i]:
        n=q[i]; labels.append(q[i+1:i+1+n]); i+=n+1
    return b".".join(labels).lower(), i+1
while time.time()<end:
    s.settimeout(1.0)
    try: data,addr=s.recvfrom(1500)
    except socket.timeout: continue
    try:
        name,i=parse_name(data); qtype=struct.unpack(">H",data[i:i+2])[0]
    except Exception: continue
    if qtype==1 and name in NAMES:
        hdr=data[:2]+b"\x81\x80"+data[4:6]+b"\x00\x01\x00\x00\x00\x00"
        ans=b"\xc0\x0c"+struct.pack(">HHIH",1,1,60,4)+socket.inet_aton(IF_IP)
        s.sendto(hdr+data[12:i+4]+ans,addr)
        print("answered",name.decode(),"->",IF_IP,flush=True)
    else:
        try:
            u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(1.5); u.sendto(data,(GW,53))
            r,_=u.recvfrom(1500); s.sendto(r,addr); u.close()
        except Exception: pass
