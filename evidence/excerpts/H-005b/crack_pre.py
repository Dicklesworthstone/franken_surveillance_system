import hashlib,json,sys
cap=json.load(open('capture.json')); pre_s=sys.argv[1]
cn=cap["cnonce"]; nonce=cap["nonce"]; target=cap["device_confirm"][:64]
pre=cn.encode(); nb=nonce.encode(); sha=hashlib.sha256
width=int(sys.argv[4]) if len(sys.argv)>4 else 0
for i in range(int(sys.argv[2]),int(sys.argv[3])):
    pw=(pre_s+str(i).zfill(width)).encode()
    if sha(pre+sha(pw).hexdigest().upper().encode()+nb).hexdigest().upper()==target:
        print("FOUND",pw.decode()); break
else: print("not found")
