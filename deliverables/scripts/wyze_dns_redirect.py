"""Answer the camera's DNS for the OTA/broker names, from the address the camera queried.

The camera asks several resolvers at once (8.8.8.8, 8.8.4.4, 208.67.x, the gateway). The public
addresses are aliased on the interface, and this script binds one socket per alias with
SO_REUSEPORT, so a reply leaves with the queried address as its source. A strict resolver discards
a reply from any other address, which is why IP_SENDSRCADDR alone was not enough.

  wyze_dns_redirect.py [IF_IP]
"""
import select, socket, struct, sys, time

IF_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.160"
SOURCES = [IF_IP, "8.8.8.8", "8.8.4.4", "208.67.220.123", "208.67.222.123"]
# wyze-upgrade-service is NOT intercepted: the device uploads upgrade status there and our forge
# only serves files, so a spoofed answer breaks the status report and the cloud job never clears.
NAMES = {b"s3-us-west-2.amazonaws.com", b"aws-iot.wyzecam.com",
         b"a24rq1e5m4mtei.iot.us-west-2.amazonaws.com",
         b"api.wyzecam.com"}

socks = {}
for src in SOURCES:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        s.bind((src, 53))
    except OSError as exc:
        print("bind", src, "failed:", exc, flush=True)
        continue
    socks[s] = src
end = time.time() + 86400


def parse_name(q):
    labels, i = [], 12
    while q[i]:
        n = q[i]
        labels.append(q[i + 1:i + 1 + n])
        i += n + 1
    return b".".join(labels).lower(), i + 1


while time.time() < end:
    ready, _, _ = select.select(list(socks), [], [], 1.0)
    for s in ready:
        try:
            data, addr = s.recvfrom(1500)
        except OSError:
            continue
        try:
            name, i = parse_name(data)
            qtype = struct.unpack(">H", data[i:i + 2])[0]
        except Exception:
            continue
        print("rx", addr, "via", socks[s], name.decode(errors="replace"), flush=True)
        if qtype == 1 and (name in NAMES or name.endswith(b".iot.us-west-2.amazonaws.com")):
            hdr = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00"
            ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(IF_IP)
            s.sendto(hdr + data[12:i + 4] + ans, addr)
            print("answered", name.decode(), "->", IF_IP, flush=True)
        else:
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.settimeout(1.5)
                u.sendto(data, ("1.1.1.1", 53))
                r, _ = u.recvfrom(1500)
                s.sendto(r, addr)
                u.close()
            except Exception:
                pass
