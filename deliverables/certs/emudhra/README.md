# Forged certificates from the eMudhra intermediate compromise (Oct 2026)

Eight eMudhra intermediate CA keys were generated with a **tiny P-384 scalar** — the whole key is the
integer `d`, so it is recovered from the certificate by counting (`d = 156` for `EM DV TLS CA - G3B`,
found in 0.02 s). Anything can be signed under it. The intermediates are revoked, but firmware CA
bundles are static and do not check CRL/OCSP, so they still verify.

Chain used here is the **Sectigo cross-sign to `AAA Certificate Services`**, because the Wyze v4
bundle (`/system/local/cacert.pem`, 138 roots) contains that root (`CN=AAA Certificate Services`,
index 10) and does **not** contain the self-signed `emSign Root TLS CA - G3`. The other chain
(`emSign ECC Root CA - G3`) is also in the bundle at index 133 but needs a root the bundle lacks.

Verified against the **device's own bundle**:

```
openssl verify -CAfile <device cacert.pem> -untrusted dv-ca-aaa-cross.pem -verify_hostname aws-iot.wyzecam.com fleet.pem
# -> OK   (and for s3-us-west-2.amazonaws.com)
openssl s_client -connect 127.0.0.1:8443 -servername aws-iot.wyzecam.com \
  -CAfile <device cacert.pem> -verify_hostname aws-iot.wyzecam.com
# -> Verification: OK / Verify return code: 0 (ok)
```

Files: `ev-ca.key.pem` + `ev-ca-aaa-cross.pem` (**primary** — the EV intermediate; its published key is
literally `AAAA…`, and it matches the cert's SPKI hash `e0254c7f…`), `dv-ca.key.pem` +
`dv-ca-aaa-cross.pem` (the DV one we recovered ourselves, `d=156`, kept as a cross-check), and `mint.py`
(re-mints a leaf; default SANs cover the fleet hosts). Leaf keys and validity are throwaway — mint,
don't archive.

All eight keys are published at `github.com/Fluepke/emudrahahahahaha` (one `.key`/`.pem` per
intermediate); only the `-aaa-` chains work with the Wyze bundle, because `emSign Root TLS CA - G3` is
self-signed and absent from it while `AAA Certificate Services` is present.

Caveats: no CT enforcement on these clients, so unlogged leaves are fine; a client that *does* check
CRL/OCSP would reject the chain, and the leaf must be served **with** the intermediate in the chain
(the device has only the root).

Serve it with `deliverables/scripts/wyze_forge_serve.py` (binds :443, appends the intermediate, serves a
directory). Something must still resolve the SAN host to the host running it — that is the remaining
wiring, not the certificate.

Source: https://emudhra.we-have-a-problem.com/ , Mozilla bug 2083449 (`d` is "below 256"), all eight
keys at github.com/Fluepke/emudrahahahahaha.
