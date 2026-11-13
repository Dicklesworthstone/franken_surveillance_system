#!/bin/bash
# ota_sim.sh — run an OTA payload's upgraderun.sh against fakes, on the build host.
#
# The Wyze route ships a shell payload that `assis` extracts and runs as root. It can therefore be
# exercised with no SoC emulation at all: a fake /proc/mtd with the stock map, fake block devices,
# an image over HTTP and receivers on the backup ports. This proves the *contract* (map check,
# backup streaming, digest, write order, bootloader-last) before any camera is touched.
#
# Endianness/arch of the busybox is emulated with qemu-user, so the real payload binary is used.
#
#   ota_sim.sh <host> <capsule.tar> <img.bin> [qemu]
set -u
H=${1:?host}; TAR=${2:?capsule tar}; IMG=${3:?image}; QEMU=${4:-qemu-mipsel}
R=/tmp/otasim
SIZES="0x80000 0x280000 0x5C0000 0x5C0000 0x100000 0x80000"
NAMES="uboot boot system back cfg provisioning"

ssh -o BatchMode=yes "$H" 'pkill -f "nc -l -p" 2>/dev/null; rm -rf /tmp/otasim; mkdir -p /tmp/otasim/Upgrade /tmp/otasim/dev /tmp/otasim/http'
scp -q -o BatchMode=yes "$TAR" "$H:$R/capsule.tar"
scp -q -o BatchMode=yes "$IMG" "$H:$R/http/img.bin"
ssh -o BatchMode=yes "$H" "cd $R && tar xf capsule.tar && chmod +x Upgrade/*"
# busybox under qemu, and every absolute path the payload expects
# busybox picks its applet by argv[0], so the wrapper must NOT be named busybox
ssh -o BatchMode=yes "$H" "printf '#!/bin/sh\nexec $QEMU $R/Upgrade/busybox \"\$@\"\n' > $R/bb.sh && chmod +x $R/bb.sh"
ssh -o BatchMode=yes "$H" "cd $R && sed -i 's|/proc/mtd|$R/fake_mtd|g; s|/dev/mtdblock|$R/dev/mtdblock|g; s|^BB=.*|BB=$R/bb.sh|; s|/bin/busybox|$R/bb.sh|g; s|^HOST=.*|HOST=127.0.0.1|; s|^BEACON_HOST=.*|BEACON_HOST=127.0.0.1|; s|^IMG_URL=.*|IMG_URL=\"http://127.0.0.1:8080/img.bin\"|' Upgrade/upgraderun.sh"
ssh -o BatchMode=yes "$H" "python3 - <<'PY'
sizes=[0x80000,0x280000,0x5C0000,0x5C0000,0x100000,0x80000]
names='uboot boot system back cfg provisioning'.split()
lines=['dev:    size   erasesize  name']
for i,(s,n) in enumerate(zip(sizes,names)):
    lines.append('mtd%d: %08x 00010000 \"%s\"' % (i,s,n))
    open('/tmp/otasim/dev/mtdblock%d'%i,'wb').write(b'\xff'*s)
open('/tmp/otasim/fake_mtd','w').write('\n'.join(lines)+'\n')
PY"
ssh -o BatchMode=yes "$H" "touch $R/http/fss-ran; cd $R/http && setsid nohup python3 -m http.server 8080 >/tmp/otasim/http.log 2>&1 & 
for p in 444 445 446 447 448 449; do setsid nohup timeout 300 nc -l -p \$p > $R/backup_\$p.bin 2>/dev/null & done"
sleep 4
ssh -o BatchMode=yes "$H" "cd $R && sh Upgrade/upgraderun.sh > $R/run.log 2>&1; echo rc=\$?; tail -6 $R/run.log"
ssh -o BatchMode=yes "$H" "cd $R && python3 - <<'PY'
img=open('http/img.bin','rb').read(); off=0; ok=True
for i,s in enumerate([0x80000,0x280000,0x5C0000,0x5C0000,0x100000,0x80000]):
    d=open('/tmp/otasim/dev/mtdblock%d'%i,'rb').read()
    m = d == img[off:off+s]; ok = ok and m
    print('mtd%d %d match=%s' % (i, s, m)); off+=s
print('ALL', ok)
PY"
