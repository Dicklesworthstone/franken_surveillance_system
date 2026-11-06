# UniFi Asupersync TLS interoperability lab

This standalone experiment adapts rustls's sans-I/O TLS engine to the pinned
Asupersync 0.5.0 TCP runtime. It makes one credential-free TLS connection to an
explicitly owner-authorized private IPv4 address, limits handshake bytes and
iterations, and applies connect, handshake and close timeouts. It sends no HTTP
request, credentials, WebSocket data, or camera setting changes.

The experiment is not linked into FSS. It does not use FSS `TaskCx`, canonical
network/entropy accounting, a durable session owner, or a qualified TLS
provider. Its raw certificate pin is the complete observed certificate; the
custom verifier deliberately does not check hostname, dates, or certificate
chain. A certificate observed on the same network is not independent proof of
camera identity. Never use this verifier for production or send it credentials.
The provider's upstream explicitly warns against production use.

Like the neighboring `unifi_tls_v1_lab`, it extracts SPKI from the pinned X.509
v1 certificate and verifies only ECDSA P-256/SHA-256 handshake signatures. For
TLS 1.2, the lab uses rustls's TLS 1.3 raw-public-key signature helper on the
TLS 1.2 handshake message after restricting the scheme to P-256/SHA-256. This
is not a general TLS 1.2 signature verifier. The `bad-key` case substitutes a
valid, different P-256 public key; `mismatch` changes the expected certificate.

```sh
cargo build --locked --manifest-path experiments/unifi_tls_async_lab/Cargo.toml
cargo run --locked --manifest-path experiments/unifi_tls_async_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 mismatch --owner-authorized
cargo run --locked --manifest-path experiments/unifi_tls_async_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 bad-key --owner-authorized
cargo run --locked --manifest-path experiments/unifi_tls_async_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 match --owner-authorized
```

Repeat with `tls12` for the other protocol version. Both the exact TLS provider
revision and dependencies are pinned by the standalone lockfile. The lab uses
its own dependency resolution, which is not necessarily the FSS workspace's
lockfile closure. Success is interoperability evidence only.
