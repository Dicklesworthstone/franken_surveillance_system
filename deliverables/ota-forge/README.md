# OTA TLS forgery via the eMudhra intermediate compromise

The Wyze Cam v4 Trusts `emSign ECC Root CA - G3` (cert #133 of the 138 in its
`/system/local/cacert.pem`) and does not check revocation or Certificate Transparency. Eight eMudhra
intermediate keys from April 2025 are recoverable because they are tiny integers; the DV one is 156.

`em-dv-g3b.key.pem` is that key. `forge-leaf.pem` is a leaf for `s3-us-west-2.amazonaws.com` signed
with it, chaining through `EM DV TLS CA - G3B` -> `emSign Root TLS CA - G3` -> the trusted root.

Proof with the camera's own bundle and a libcurl client:

```
openssl verify -CAfile <camera cacert.pem> -untrusted forge-chain.pem forge-leaf.pem   # OK
curl --cacert <camera cacert.pem> --resolve s3-us-west-2.amazonaws.com:9443:127.0.0.1 \
     https://s3-us-west-2.amazonaws.com:9443/    # HTTP 200, ssl_verify=0
```

Therefore the OTA host can be impersonated on the LAN with DNS control alone — no cloud shadow and
no URL allowlist problem. Revocation is irrelevant here (the camera never fetches CRLs); it stops
working only if a firmware update replaces the CA bundle, and by then our firmware is installed.

Remaining requirements: control of the camera's DNS for that name, a listener on port 443, and a
capsule whose MD5 matches whatever the push carries.

Rebuild the chain with:

```
openssl s_client -connect dv-g3b-emudhra.we-have-a-problem.com:443 -showcerts </dev/null
```
