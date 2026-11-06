# UniFi X.509 v1 TLS interoperability lab

This standalone experiment tests a credential-free TLS handshake against one
explicitly owner-authorized private IPv4 endpoint. It sends no HTTP requests,
credentials, WebSocket frames, or camera configuration changes. It is not
linked into FSS and must not be used as a production client or trust policy.

The tested G4 Instant presents a self-signed X.509 version 1 certificate.
Rustls's ordinary certificate-based handshake-signature helper rejected that
certificate as `UnsupportedCertVersion`. This experiment parses the exact
observed certificate with RustCrypto `x509-cert`, extracts its SPKI, compares
the complete certificate to the supplied observed pin, and uses rustls's raw
public-key verification helper for ECDSA P-256/SHA-256. It supports that one
signature scheme only. For TLS 1.2 it uses the same P-256/SHA-256 raw-key
signature verifier on the message passed by rustls; it does not claim general
TLS 1.2 signature-scheme coverage.

The verifier does not validate certificate dates, hostname, issuance chain, or
how the pin was obtained. An observed same-network certificate is not proof of
camera identity and an attacker present during observation can defeat this
experiment. Never send credentials or real application data through this lab.
The selected upstream provider explicitly says it is not for production and
uses ambient system entropy. No dependency or certificate admission is implied.

Build with the repository's pinned toolchain and this standalone lockfile:

```sh
cargo build --locked --manifest-path experiments/unifi_tls_v1_lab/Cargo.toml
```

Supply an independently obtained DER certificate file and the owner's private
IPv4 address. A `match` run only proves consistency with that input pin; it
cannot authenticate where the pin came from. `mismatch` changes the expected
certificate; `bad-key` substitutes the valid public P-256 generator point and
requires signature verification to fail.

```sh
cargo run --locked --manifest-path experiments/unifi_tls_v1_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 mismatch --owner-authorized
cargo run --locked --manifest-path experiments/unifi_tls_v1_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 bad-key --owner-authorized
cargo run --locked --manifest-path experiments/unifi_tls_v1_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 match --owner-authorized
```

Repeat with `tls12` to test that protocol version. No public network addresses
are accepted. The exact `rustls-rustcrypto` Git revision and all dependencies
are pinned in `Cargo.lock`; check the active dependency graph and security
advisories before any separate qualification effort.
