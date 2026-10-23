#!/usr/bin/env python3
"""Point ota.frankenfs.com at a given LAN address (Cloudflare API).

The camera validates TLS against the public chain, so the descriptor host must be our own name. That
name must resolve to the host that serves the capsule, and the answer changes with the network:
192.168.4.160 on Aardvark, 192.168.60.1 on the AP. TTL is 120, so a flip settles in ~2 minutes.

Token/zone come from the acme.sh cert config; nothing is printed.

  ota_dns.py show
  ota_dns.py set 192.168.60.1
"""
import json
import os
import sys
import urllib.request

CONF = os.path.expanduser("~/.acme.sh/ota.frankenfs.com_ecc/ota.frankenfs.com.conf")
NAME = "ota.frankenfs.com"
API = "https://api.cloudflare.com/client/v4"


def creds():
    vals = {}
    with open(CONF) as fh:
        for line in fh:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip().strip("'\"")
    return vals["CF_Token"], vals["CF_Zone_ID"]


def call(path, method="GET", body=None, token=None):
    req = urllib.request.Request(f"{API}{path}", method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data, timeout=20) as r:
        return json.loads(r.read())


def record(token, zone):
    res = call(f"/zones/{zone}/dns_records?name={NAME}&type=A", token=token)
    if not res.get("success") or not res["result"]:
        raise SystemExit(f"lookup failed: {res.get('errors')}")
    return res["result"][0]


def main():
    token, zone = creds()
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    if sys.argv[1] == "show":
        rec = record(token, zone)
        print(f"{rec['name']} -> {rec['content']} (ttl {rec['ttl']}, proxied={rec['proxied']})")
        return 0
    if sys.argv[1] == "set" and len(sys.argv) > 2:
        ip = sys.argv[2]
        rec = record(token, zone)
        res = call(f"/zones/{zone}/dns_records/{rec['id']}", "PATCH",
                   {"content": ip, "ttl": 120}, token)
        if not res.get("success"):
            raise SystemExit(f"patch failed: {res.get('errors')}")
        print(f"{NAME} -> {res['result']['content']} (ttl {res['result']['ttl']})")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
