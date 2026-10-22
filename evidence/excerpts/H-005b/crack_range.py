import hashlib,json,sys
cap=json.load(open('capture.json')); cn=cap["cnonce"]; nonce=cap["nonce"]; target=cap["device_confirm"][:64]
pre=cn.encode(); nb=nonce.encode()
sha=hashlib.sha256
for i in range(int(sys.argv[1]),int(sys.argv[2])):
    pw=str(i).encode()
    if sha(pre+sha(pw).hexdigest().upper().encode()+nb).hexdigest().upper()==target:
        print("FOUND",i); break
else: print("not found")
