import sys
sufs = ["1","12","123","1234","12345","123456","!","@","2024","2025","2026","69","99","07","321"]
w = sys.stdout.write
for line in open('/tmp/ry2.txt','rb'):
    p = line.rstrip(b'\r\n')
    if not p: continue
    w(p.decode('latin-1')+"\n")
    w(p.capitalize().decode('latin-1')+"\n")
    for s in sufs:
        w(p.decode('latin-1')+s+"\n")
