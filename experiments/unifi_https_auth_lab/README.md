# UniFi task-owned authenticated HTTPS laboratory

This isolated Linux laboratory drives the camera's local HTTPS login and
read-only status API through a task-owned Asupersync 0.5 TCP transport and a
separately resolved `rustls`/`rustls-rustcrypto` TLS stack. It performs at most
one login and one status request per run; it does not issue camera-setting or
controller commands, and has no retry loop. The task checks explicit network,
adapter-authentication and status grants, limits response framing through
Asupersync's HTTP/1 decoder, and emits only HTTP outcomes and status-object
presence flags. The tool does not read credentials before the certificate pin
and TLS handshake signature match.

The credential is read from an existing owner-selected private Linux file,
using bounded input, regular-file, permission and no-follow checks; the file
identity is revalidated around its use. Credentials, cookies and response
bodies are not printed or intentionally persisted by this lab. Request and
response buffers are cleared on a best-effort basis, but the HTTP decoder,
JSON parser, TLS library, allocator and operating system can retain copies;
this is **not** a guaranteed secret-zeroization claim. The synchronous file
read also is not a production nonblocking secret service.

The certificate pin was observed on the same network and is not independent
physical-device authentication. The verifier does not validate hostname,
certificate dates or chain; the experimental provider has ambient entropy
calls and is not admitted for production. Successful camera login authenticates
the credential to the responding endpoint; it does not by itself prove the
endpoint's independent physical identity. Login creates a camera session; this
lab does not establish how the camera expires that session. It is not an
automatic enrollment service, native controller, or video recorder.

On 2026-11-05, a separate Python TLS loopback fixture on `trj` verified one
login and one status request using disposable synthetic credentials, checked
the cookie and sequence, and found none of its test secrets in process output.
Three Rust tests on `hz3` covered cookie rejection, strict status JSON and
private-file revocation/permissions. The isolated lockfile SHA-256 was
`ea46b39794c6acd829c598491364cad56408453ec0d9c57f92b7a4c9bba08248`.
The final stripped Linux executable,
SHA-256 `331908ddbb6b385eba4a8ed398b00a6c51ce5c02d17a8fa58b8b8e3e6f221a49`,
then ran on `trj` against the owner's G4: changed-certificate and different
valid-key controls were rejected before a deliberately nonexistent credential
path could be read, and the matching TLS 1.3 case returned HTTP 200 for both
login and status with board, firmware and controller objects present. A prior
build also completed one live read-only login and status; thus two successful
camera sessions were created during this work. The recorder and its upload and
discovery timers were active afterward.

Run the fixture with a disposable P-256 certificate and private key:

```text
cargo test --locked --manifest-path experiments/unifi_https_auth_lab/Cargo.toml
python3 experiments/unifi_https_auth_lab/fixture.py BIN CERT_DER CERT_PEM KEY_PEM
```

The lab binary accepts `CERT_DER PRIVATE_IPV4 tls13 match SCOPE_DIGEST
CREDENTIAL_FILE 443 --owner-authorized`. The digest must identify the exact
owner authorization; it does not independently prove that authorization or the
camera identity. Loopback-only test endpoints may use another port.
