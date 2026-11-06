# UniFi task-owned TLS interoperability lab

This isolated experiment drives rustls through Asupersync and compiles the
actual FSS `unifi_direct/metered.rs` transport source against `fss-core` and
`fss-runtime`. A scoped `AdapterNet` grant and canonical owned task cover the
single connection; a successful result requires a completed task receipt.
The meter wraps the raw TCP stream beneath TLS, accounting for stream bytes
with conservative reservations. It does not account for IP or link overhead.

This is a credential-free handshake test only. It sends no HTTP, WebSocket,
camera commands, or credentials. It is not the FSS production controller or
an authenticated adoption implementation. The caller supplies an explicit
owner-authorization flag and a SHA-256 digest of a local scope statement;
those inputs are test evidence, not an independently verified identity system.

The same-network observed certificate is not independent proof of camera
identity. The verifier ignores hostname, dates and chain, and the upstream
RustCrypto TLS provider warns against production use. No provider, entropy
source, certificate trust policy, or dependency closure is admitted for
production by this experiment. The standalone lockfile resolves dependencies
separately from the main workspace. See `../unifi_tls_async_lab/README.md` for
the restricted P-256 signature verification and negative cases.

```sh
cargo build --locked --manifest-path experiments/unifi_tls_owned_lab/Cargo.toml
cargo run --locked --manifest-path experiments/unifi_tls_owned_lab/Cargo.toml -- CERT_DER PRIVATE_IPV4 tls13 mismatch sha256:SCOPE_DIGEST --owner-authorized
```

Use `bad-key` and `match` in addition to `mismatch`, then repeat for `tls12`.
Provide the actual 64-character lowercase digest in place of `SCOPE_DIGEST`.
