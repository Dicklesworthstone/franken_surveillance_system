# Encrypted pack recovery from a remote manifest

`fss archive restore` can recover an encrypted pack after its local plaintext file
and local archive manifest have been lost. Retain the `manifest_object_key` and
`manifest_digest` from the successful upload result in an independent trusted
record. Recovery also needs the current key-envelope catalog, its vault-backed
KEK, and scoped S3 credentials.

## Restore the remote root

```sh
fss archive restore \
  --packs-dir /absolute/path/offline-restored-packs \
  --manifest-object-key fss-cold/v1/manifests/pack-00000001-000000000001.manifest.fssc \
  --expected-manifest sha256:INDEPENDENT_MANIFEST_DIGEST_FROM_UPLOAD \
  --key-catalog /absolute/path/keys.fskc \
  --peer 127.0.0.1:9000 --host s3.local --region us-east-1 \
  --bucket fss-cold-bucket \
  --vault-dir /absolute/path/vault \
  --passphrase-file /absolute/path/private-passphrase-file \
  --kek-secret-id secret:kek:site-1 \
  --s3-secret-id secret:s3:cold-1 \
  --access-key-id S3_ACCESS_KEY_ID \
  --site site:archive-e2e --json
```

Use the upload result's domain-separated `manifest_digest` for
`--expected-manifest`. The independent pin authenticates every canonical
manifest field, including the pack identity, key-envelope identity, plaintext
digest, ciphertext digest and length, and ciphertext object key.

The current transport requires an explicitly approved local or private socket
address. It signs both reads with SigV4 and uses the supplied host, bucket and
vault scope. Keep the destination offline while restoring packfiles, then reopen
the ordinary pack store to rebuild its derived object index.

## Verification and bounds

Recovery performs one signed manifest GET with a 16 KiB response-body ceiling.
It checks the returned object key, canonical format, embedded integrity digest,
and independent manifest pin before requesting any ciphertext. Invalid pins
and empty or oversized key strings refuse before contact. A malformed,
substituted, oversized, missing or mismatched remote manifest stops recovery.

After root verification, the existing cold restore owner reads the selected
ciphertext with its 256 MiB ceiling. The declared ciphertext size is checked
before that request. The owner verifies exact ciphertext bytes and SHA-256,
authenticates every AEAD frame using the current key catalog and vault KEK,
checks the original plaintext length and SHA-256, and verifies every sealed pack
record before atomic local publication. A current cryptographic-erasure tombstone
continues to refuse decryption. The CLI checks cancellation after metadata recovery
and before the ciphertext download.

The normal successful path makes two signed GET requests. There is one bounded
metadata buffer in addition to the existing bounded ciphertext and plaintext
buffers. The metadata read creates no local file. On any metadata, ciphertext,
AEAD or plaintext verification failure, restoration publishes no packfile.

## Operator result

The existing `fss.pack_archive_response.v1` result includes the restored pack
path, object count, plaintext identity and manifest identity. Recovery adds the
following provenance fields.

| Field | Remote-root recovery | Local-file restoration |
|---|---|---|
| `manifest_source` | `remote_object` | `local_file` |
| `manifest_object_key` | The explicitly requested root object key | `null` |
| `manifest_pin_verified` | `true` | `false` |
| `manifest_download_limit_bytes` | `16384` | `0` |

Local-file restoration uses `--manifest-file FILE`. The parser requires exactly
one manifest source. Remote mode requires both the object key and independent
pin, and rejects duplicate source or pin options. Local manifests retain their
existing canonical integrity checks.

## Recovery material and verification scope

Keep the key catalog and vault recovery material under the site's existing
backup and erasure policy. A root manifest contains key identities and wrapped
envelope digests. Actual decryption still depends on the currently authorized
wrapped DEK. Losing that recovery material or erasing that DEK prevents recovery
of the encrypted pack.

The native contract exercises single-PUT and multipart pack uploads, deletion of
local manifests, recovery of both remote roots, exact object restoration, invalid
pins, a valid but different root, corrupted and oversized manifest responses, and
pre-network ciphertext-size refusal. The process contract exercises the unified
CLI with its vault, loss of the source pack and local manifest, independent-pin
refusal, malformed/missing remote roots, authenticated metadata with an incorrect
plaintext identity, exact successful restoration, and erased-key refusal.

Run the focused contracts with the pinned toolchain.

```sh
cargo test --locked --offline -p fss-pack --test crypto_archive_contract
cargo test --locked --offline -p fss-cli --test vault_notify_archive_cli_e2e fss_archive_cli_
cargo test --locked --offline -p fss-cli --test vault_notify_archive_cli_e2e remote_archive_restore_
```
