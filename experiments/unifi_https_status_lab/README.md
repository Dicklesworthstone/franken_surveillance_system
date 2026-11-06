# UniFi task-owned HTTPS status probe

This standalone laboratory builds on `../unifi_tls_owned_lab`: it runs an
Asupersync 0.5 task and FSS metered TCP transport with an experimental rustls
provider and a caller-supplied, same-network observed camera certificate. In
`match` mode only, after a matching certificate and a verified TLS handshake
signature, it sends a single credential-free `GET /api/1.1/status`. It reads
only a bounded HTTP/1 status line for output, discards the response on close,
and does not send credentials or change settings. The request and TLS records
are metered; transport overhead below TCP is not. A mismatch or different valid
public key must stop before the HTTP request.

The certificate pin is not independent device identity. The verifier ignores
hostname, dates and certificate chain, and the selected provider is not
admitted for production, has ambient entropy calls and advises against
production use. This is not an authenticated status response, a full HTTP
framing implementation, a native controller, or a recorder. The workspace has a distinct package name and is isolated from the main
workspace dependency resolution.

```text
cargo test --locked --manifest-path experiments/unifi_https_status_lab/Cargo.toml
cargo run --locked --manifest-path experiments/unifi_https_status_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 match sha256:SCOPE_DIGEST --owner-authorized
```

The scope digest must identify an owner authorization for this exact read-only
request. Use `mismatch` or `bad-key` to test rejection, and `tls12` to exercise
the restricted TLS 1.2 lab verifier.

On 2026-11-05, the stripped Linux executable SHA-256
`0fe7e10973ac41d5a1ec3e28080482ec2fac813b545ab9d576d6049547088d58`
ran on `trj` against the owner's G4 using the previously observed certificate.
The isolated lockfile SHA-256 was
`963e432ec7835d8494627fec3aa90d3b562ff5d2e106cb11a4129fda764c333f`.
For both TLS 1.2 and TLS 1.3, the matching case received HTTP 401; both the
changed-certificate and valid-wrong-key cases rejected the handshake before
the HTTP request. All six task receipts completed. The recorder and its upload
and discovery timers remained active. This establishes a direct, credential-free
application response, with the pin and provider limitations above; it does not
establish a fully parsed response, authenticated device, login, or video.
