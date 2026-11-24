#![forbid(unsafe_code)]
//! First-party pure-Rust RFC 8446 TLS 1.3 client & loopback server transport
//! (`TLS_CHACHA20_POLY1305_SHA256`, `x25519`, `ed25519`, `Zeroizing` key erasure).

use core::fmt;
use std::io::{self, Read, Write};
use std::net::IpAddr;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use fss_core::{Sha256Hasher, TimestampNs, sha256};
use fss_vault::{
    EntropySource, constant_time_eq, hkdf_sha256_expand, hkdf_sha256_extract, hmac_sha256,
};
use zeroize::Zeroizing;

use super::ed25519::Ed25519SigningKey;
use super::x509::{
    ERR_NOTIFY_TLS_CERT_001, TlsTrustPolicy, VerifiedPeerCert, X509Error, verify_certificate_chain,
};
use super::x25519::{X25519PublicKey, X25519SecretKey};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const CIPHER_CHACHA20_POLY1305_SHA256: [u8; 2] = [0x13, 0x03];
const GROUP_X25519: [u8; 2] = [0x00, 0x1d];
const SIG_ED25519: [u8; 2] = [0x08, 0x07];
const TLS_13_VERSION: [u8; 2] = [0x03, 0x04];
const LEGACY_VERSION: [u8; 2] = [0x03, 0x03];

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Maximum TLS 1.3 plaintext fragment length (RFC 8446 §5.1).
pub const MAX_TLS_PLAINTEXT_LEN: usize = 16_384;
/// Maximum TLS 1.3 ciphertext fragment length (RFC 8446 §5.2).
pub const MAX_TLS_CIPHERTEXT_LEN: usize = MAX_TLS_PLAINTEXT_LEN + 256;
/// Maximum cumulative handshake message buffer size (64 KiB).
pub const MAX_TLS_HANDSHAKE_BYTES: usize = 64 * 1024;

/// Errors returned during RFC 8446 TLS 1.3 handshakes or encrypted record I/O.
#[derive(Debug)]
pub enum Tls13Error {
    /// Certificate chain, pin, hostname, expiry, or `CertificateVerify` refusal.
    Certificate(X509Error),
    /// Protocol framing, cipher negotiation, AEAD authentication, or `Finished` verification failure.
    Protocol(String),
    /// Peer sent a TLS alert record (`level`, `description`).
    PeerAlert {
        /// TLS alert level (`1` = warning, `2` = fatal).
        level: u8,
        /// TLS alert description code.
        description: u8,
    },
    /// Underlying socket or stream I/O error.
    Io(io::Error),
    /// Explicit entropy failure.
    EntropyFailed,
    /// Configured byte budget or record sequence counter exhausted.
    BudgetExceeded(&'static str),
}

impl Tls13Error {
    /// Returns `ERR-NOTIFY-TLS-CERT-001` for certificate/signature errors, else `None`.
    #[must_use]
    pub const fn cert_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Certificate(_) => Some(ERR_NOTIFY_TLS_CERT_001),
            _ => None,
        }
    }

    /// Returns `true` if the underlying error was a socket timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Io(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
    }
}

impl fmt::Display for Tls13Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(err) => write!(f, "{err}"),
            Self::Protocol(msg) => write!(f, "TLS 1.3 protocol error: {msg}"),
            Self::PeerAlert { level, description } => {
                write!(f, "TLS 1.3 peer alert ({level}, {description})")
            }
            Self::Io(err) => write!(f, "TLS 1.3 transport I/O error: {:?}", err.kind()),
            Self::EntropyFailed => f.write_str("TLS 1.3 entropy source failed"),
            Self::BudgetExceeded(detail) => write!(f, "TLS 1.3 budget exceeded: {detail}"),
        }
    }
}

impl std::error::Error for Tls13Error {}
impl From<io::Error> for Tls13Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
impl From<X509Error> for Tls13Error {
    fn from(err: X509Error) -> Self {
        Self::Certificate(err)
    }
}

struct TrafficCipher {
    key: Zeroizing<[u8; 32]>,
    iv: Zeroizing<[u8; 12]>,
    seq: u64,
}

impl TrafficCipher {
    fn from_secret(secret: &[u8; 32]) -> Result<Self, Tls13Error> {
        let mut key = Zeroizing::new([0_u8; 32]);
        let mut iv = Zeroizing::new([0_u8; 12]);
        key.copy_from_slice(&hkdf_expand_label(secret, b"key", &[], 32)?);
        iv.copy_from_slice(&hkdf_expand_label(secret, b"iv", &[], 12)?);
        Ok(Self { key, iv, seq: 0 })
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], Tls13Error> {
        let seq = self.seq;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(Tls13Error::BudgetExceeded("TLS sequence overflow"))?;
        let mut nonce = *self.iv;
        for (slot, b) in nonce[4..12].iter_mut().zip(seq.to_be_bytes()) {
            *slot ^= b;
        }
        Ok(nonce)
    }

    fn encrypt_record(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Tls13Error> {
        if plaintext.len() > MAX_TLS_PLAINTEXT_LEN {
            return Err(Tls13Error::BudgetExceeded("TLS plaintext record too large"));
        }
        let ct_len = plaintext.len() + 17;
        let header = [
            CONTENT_APPLICATION_DATA,
            LEGACY_VERSION[0],
            LEGACY_VERSION[1],
            (ct_len >> 8) as u8,
            ct_len as u8,
        ];
        let mut inner = Zeroizing::new(Vec::with_capacity(plaintext.len() + 1));
        inner.extend_from_slice(plaintext);
        inner.push(content_type);
        let nonce = self.next_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| Tls13Error::Protocol("AEAD init failed".to_owned()))?;
        let ct = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .map_err(|_| Tls13Error::Protocol("AEAD encrypt failed".to_owned()))?;
        let mut rec = Vec::with_capacity(5 + ct.len());
        rec.extend_from_slice(&header);
        rec.extend_from_slice(&ct);
        Ok(rec)
    }

    fn decrypt_record(
        &mut self,
        header: &[u8; 5],
        ciphertext: &[u8],
    ) -> Result<(u8, Zeroizing<Vec<u8>>), Tls13Error> {
        if ciphertext.len() < 17 || ciphertext.len() > MAX_TLS_CIPHERTEXT_LEN {
            return Err(Tls13Error::Protocol(
                "invalid TLS ciphertext length".to_owned(),
            ));
        }
        let nonce = self.next_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| Tls13Error::Protocol("AEAD init failed".to_owned()))?;
        let mut plain = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| Tls13Error::Protocol("TLS AEAD decrypt failed".to_owned()))?,
        );
        while plain.last() == Some(&0) {
            plain.pop();
        }
        let ct = plain
            .pop()
            .ok_or_else(|| Tls13Error::Protocol("empty inner TLS plaintext".to_owned()))?;
        Ok((ct, plain))
    }
}

/// Authenticated RFC 8446 TLS 1.3 connection over any `Read + Write` stream.
pub struct Tls13Stream<S: Read + Write> {
    inner: S,
    send_cipher: TrafficCipher,
    recv_cipher: TrafficCipher,
    read_buf: Zeroizing<Vec<u8>>,
    read_pos: usize,
    peer_cert: Option<VerifiedPeerCert>,
    eof_received: bool,
}

impl<S: Read + Write> Tls13Stream<S> {
    /// Performs a full RFC 8446 TLS 1.3 client handshake with strict X.509 verification.
    pub fn connect_client(
        mut stream: S,
        server_name: &str,
        trust: &TlsTrustPolicy,
        now: TimestampNs,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, Tls13Error> {
        let mut client_random = [0_u8; 32];
        entropy
            .fill_bytes(&mut client_random)
            .map_err(|_| Tls13Error::EntropyFailed)?;
        let client_sk =
            X25519SecretKey::generate(entropy).map_err(|_| Tls13Error::EntropyFailed)?;
        let ch_msg = build_client_hello(&client_random, server_name, &client_sk.public_key());

        let mut transcript = Sha256Hasher::new();
        transcript.update(&ch_msg);
        write_plaintext_record(&mut stream, CONTENT_HANDSHAKE, &ch_msg)?;
        stream.flush()?;

        let mut hs_buf = HandshakeReader::new();
        let sh_msg = hs_buf.read_msg(&mut stream, None, HS_SERVER_HELLO)?;
        let server_pk = parse_server_hello(&sh_msg[4..])?;
        transcript.update(&sh_msg);
        let shared = client_sk
            .diffie_hellman(&server_pk)
            .map_err(|_| Tls13Error::Protocol("X25519 low-order server key share".to_owned()))?;
        drop(client_sk);

        let (hs_secret, c_hs, s_hs) =
            derive_handshake_secrets(&shared, &transcript_digest(&transcript)?)?;
        let mut send_hs = TrafficCipher::from_secret(&c_hs)?;
        let mut recv_hs = TrafficCipher::from_secret(&s_hs)?;

        let ee_msg = hs_buf.read_msg(&mut stream, Some(&mut recv_hs), HS_ENCRYPTED_EXTENSIONS)?;
        transcript.update(&ee_msg);

        let cert_msg = hs_buf.read_msg(&mut stream, Some(&mut recv_hs), HS_CERTIFICATE)?;
        let chain_der = parse_certificate_message(&cert_msg[4..])?;
        let verified_cert = verify_certificate_chain(&chain_der, trust, server_name, now)?;
        transcript.update(&cert_msg);
        let cert_hash = transcript_digest(&transcript)?;

        let cv_msg = hs_buf.read_msg(&mut stream, Some(&mut recv_hs), HS_CERTIFICATE_VERIFY)?;
        let cv_sig = parse_certificate_verify(&cv_msg[4..])?;
        verified_cert
            .leaf_public_key
            .verify(&build_cert_verify_content(&cert_hash), &cv_sig)
            .map_err(|_| {
                Tls13Error::Certificate(X509Error {
                    detail: "TLS CertificateVerify invalid".to_owned(),
                })
            })?;
        transcript.update(&cv_msg);
        let cv_hash = transcript_digest(&transcript)?;

        let sf_msg = hs_buf.read_msg(&mut stream, Some(&mut recv_hs), HS_FINISHED)?;
        if sf_msg.len() != 36
            || !constant_time_eq(&sf_msg[4..36], &*compute_finished_mac(&s_hs, &cv_hash)?)
        {
            return Err(Tls13Error::Protocol(
                "server Finished MAC mismatch".to_owned(),
            ));
        }
        transcript.update(&sf_msg);
        let sf_hash = transcript_digest(&transcript)?;
        let (c_ap, s_ap) = derive_app_secrets(&hs_secret, &sf_hash)?;

        let cf_msg = wrap_handshake(HS_FINISHED, &*compute_finished_mac(&c_hs, &sf_hash)?);
        stream.write_all(&send_hs.encrypt_record(CONTENT_HANDSHAKE, &cf_msg)?)?;
        stream.flush()?;

        Ok(Self {
            inner: stream,
            send_cipher: TrafficCipher::from_secret(&c_ap)?,
            recv_cipher: TrafficCipher::from_secret(&s_ap)?,
            read_buf: Zeroizing::new(Vec::new()),
            read_pos: 0,
            peer_cert: Some(verified_cert),
            eof_received: false,
        })
    }

    /// Performs a full RFC 8446 TLS 1.3 server handshake (used for loopback E2E servers).
    pub fn accept_server(
        mut stream: S,
        cert_chain_der: &[Vec<u8>],
        leaf_signing_key: &Ed25519SigningKey,
        entropy: &mut dyn EntropySource,
    ) -> Result<Self, Tls13Error> {
        let mut hs_buf = HandshakeReader::new();
        let ch_msg = hs_buf.read_msg(&mut stream, None, HS_CLIENT_HELLO)?;
        let (session_id, client_pk) = parse_client_hello(&ch_msg[4..])?;

        let mut transcript = Sha256Hasher::new();
        transcript.update(&ch_msg);

        let mut server_random = [0_u8; 32];
        entropy
            .fill_bytes(&mut server_random)
            .map_err(|_| Tls13Error::EntropyFailed)?;
        let server_sk =
            X25519SecretKey::generate(entropy).map_err(|_| Tls13Error::EntropyFailed)?;
        let sh_msg = build_server_hello(&server_random, &session_id, &server_sk.public_key());
        transcript.update(&sh_msg);
        write_plaintext_record(&mut stream, CONTENT_HANDSHAKE, &sh_msg)?;

        let shared = server_sk
            .diffie_hellman(&client_pk)
            .map_err(|_| Tls13Error::Protocol("X25519 low-order client key share".to_owned()))?;
        drop(server_sk);

        let (hs_secret, c_hs, s_hs) =
            derive_handshake_secrets(&shared, &transcript_digest(&transcript)?)?;
        let mut send_hs = TrafficCipher::from_secret(&s_hs)?;
        let mut recv_hs = TrafficCipher::from_secret(&c_hs)?;

        let ee_msg = wrap_handshake(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]);
        transcript.update(&ee_msg);
        let cert_msg = build_certificate_message(cert_chain_der);
        transcript.update(&cert_msg);
        let cv_sig =
            leaf_signing_key.sign(&build_cert_verify_content(&transcript_digest(&transcript)?));
        let cv_msg = wrap_handshake(
            HS_CERTIFICATE_VERIFY,
            &[&SIG_ED25519[..], &[0x00, 0x40], &cv_sig].concat(),
        );
        transcript.update(&cv_msg);
        let sf_msg = wrap_handshake(
            HS_FINISHED,
            &*compute_finished_mac(&s_hs, &transcript_digest(&transcript)?)?,
        );
        transcript.update(&sf_msg);
        let sf_hash = transcript_digest(&transcript)?;

        for msg in [&ee_msg, &cert_msg, &cv_msg, &sf_msg] {
            stream.write_all(&send_hs.encrypt_record(CONTENT_HANDSHAKE, msg)?)?;
        }
        stream.flush()?;

        let (c_ap, s_ap) = derive_app_secrets(&hs_secret, &sf_hash)?;
        let cf_msg = hs_buf.read_msg(&mut stream, Some(&mut recv_hs), HS_FINISHED)?;
        if cf_msg.len() != 36
            || !constant_time_eq(&cf_msg[4..36], &*compute_finished_mac(&c_hs, &sf_hash)?)
        {
            return Err(Tls13Error::Protocol(
                "client Finished MAC mismatch".to_owned(),
            ));
        }
        Ok(Self {
            inner: stream,
            send_cipher: TrafficCipher::from_secret(&s_ap)?,
            recv_cipher: TrafficCipher::from_secret(&c_ap)?,
            read_buf: Zeroizing::new(Vec::new()),
            read_pos: 0,
            peer_cert: None,
            eof_received: false,
        })
    }

    /// Returns the verified peer certificate details for client connections.
    #[must_use]
    pub const fn verified_peer_cert(&self) -> Option<&VerifiedPeerCert> {
        self.peer_cert.as_ref()
    }

    /// Encrypts and writes all application bytes in RFC 8446 bounded fragments.
    pub fn write_application_data(&mut self, data: &[u8]) -> Result<(), Tls13Error> {
        for chunk in data.chunks(MAX_TLS_PLAINTEXT_LEN) {
            let record = self
                .send_cipher
                .encrypt_record(CONTENT_APPLICATION_DATA, chunk)?;
            self.inner.write_all(&record)?;
        }
        self.inner.flush()?;
        Ok(())
    }

    /// Reads decrypted application bytes into `buf`, returning `0` on clean `close_notify`.
    pub fn read_application_data(&mut self, buf: &mut [u8]) -> Result<usize, Tls13Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.read_pos >= self.read_buf.len() {
            if self.eof_received {
                return Ok(0);
            }
            self.read_buf.clear();
            self.read_pos = 0;
            let (outer, header, payload) = read_raw_record(&mut self.inner)?;
            if outer != CONTENT_APPLICATION_DATA {
                return Err(Tls13Error::Protocol(format!(
                    "unexpected record type {outer}"
                )));
            }
            let (inner_type, plain) = self.recv_cipher.decrypt_record(&header, &payload)?;
            match inner_type {
                CONTENT_APPLICATION_DATA => self.read_buf.extend_from_slice(&plain),
                CONTENT_ALERT if plain.len() == 2 && plain[0] == 1 && plain[1] == 0 => {
                    self.eof_received = true;
                    return Ok(0);
                }
                CONTENT_ALERT if plain.len() == 2 => {
                    return Err(Tls13Error::PeerAlert {
                        level: plain[0],
                        description: plain[1],
                    });
                }
                CONTENT_HANDSHAKE => {}
                other => {
                    return Err(Tls13Error::Protocol(format!(
                        "unexpected inner type {other}"
                    )));
                }
            }
        }
        let take = (self.read_buf.len() - self.read_pos).min(buf.len());
        buf[..take].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
        self.read_pos += take;
        Ok(take)
    }

    /// Sends an encrypted TLS 1.3 `close_notify` alert and flushes the stream.
    pub fn close_notify(&mut self) -> Result<(), Tls13Error> {
        let rec = self
            .send_cipher
            .encrypt_record(CONTENT_ALERT, &[1_u8, 0_u8])?;
        self.inner.write_all(&rec)?;
        self.inner.flush()?;
        Ok(())
    }

    /// Borrows the underlying transport stream.
    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.inner
    }
}

struct HandshakeReader {
    buf: Vec<u8>,
}

impl HandshakeReader {
    const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn read_msg<S: Read + Write>(
        &mut self,
        stream: &mut S,
        mut cipher: Option<&mut TrafficCipher>,
        expected_type: u8,
    ) -> Result<Vec<u8>, Tls13Error> {
        loop {
            if self.buf.len() >= 4 {
                let len = (usize::from(self.buf[1]) << 16)
                    | (usize::from(self.buf[2]) << 8)
                    | usize::from(self.buf[3]);
                let total = 4 + len;
                if total > MAX_TLS_HANDSHAKE_BYTES {
                    return Err(Tls13Error::BudgetExceeded(
                        "handshake message exceeds 64 KiB",
                    ));
                }
                if self.buf.len() >= total {
                    let tail = self.buf.split_off(total);
                    let msg = core::mem::replace(&mut self.buf, tail);
                    if msg.first().copied() != Some(expected_type) {
                        return Err(Tls13Error::Protocol(format!(
                            "expected handshake type {expected_type}"
                        )));
                    }
                    return Ok(msg);
                }
            }
            let (outer, header, payload) = read_raw_record(stream)?;
            if outer == CONTENT_CHANGE_CIPHER_SPEC {
                continue;
            }
            let (inner_type, bytes) = if let Some(c) = cipher.as_deref_mut() {
                if outer != CONTENT_APPLICATION_DATA {
                    return Err(Tls13Error::Protocol(
                        "expected encrypted handshake record".to_owned(),
                    ));
                }
                let (t, p) = c.decrypt_record(&header, &payload)?;
                (t, p.to_vec())
            } else {
                (outer, payload)
            };
            if inner_type == CONTENT_ALERT && bytes.len() == 2 {
                return Err(Tls13Error::PeerAlert {
                    level: bytes[0],
                    description: bytes[1],
                });
            }
            if inner_type != CONTENT_HANDSHAKE {
                return Err(Tls13Error::Protocol(format!(
                    "unexpected handshake content {inner_type}"
                )));
            }
            if self.buf.len().saturating_add(bytes.len()) > MAX_TLS_HANDSHAKE_BYTES {
                return Err(Tls13Error::BudgetExceeded(
                    "handshake buffer exceeded 64 KiB",
                ));
            }
            self.buf.extend_from_slice(&bytes);
        }
    }
}

fn write_plaintext_record<S: Write>(
    stream: &mut S,
    ct: u8,
    payload: &[u8],
) -> Result<(), Tls13Error> {
    if payload.len() > MAX_TLS_PLAINTEXT_LEN {
        return Err(Tls13Error::BudgetExceeded("plaintext TLS record too large"));
    }
    let len = payload.len() as u16;
    stream.write_all(&[
        ct,
        LEGACY_VERSION[0],
        LEGACY_VERSION[1],
        (len >> 8) as u8,
        len as u8,
    ])?;
    stream.write_all(payload)?;
    Ok(())
}

fn read_raw_record<S: Read>(stream: &mut S) -> Result<(u8, [u8; 5], Vec<u8>), Tls13Error> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len == 0 || len > MAX_TLS_CIPHERTEXT_LEN {
        return Err(Tls13Error::Protocol(format!(
            "invalid TLS record length {len}"
        )));
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload)?;
    Ok((header[0], header, payload))
}

fn transcript_digest(hasher: &Sha256Hasher) -> Result<[u8; 32], Tls13Error> {
    hasher
        .clone()
        .finalize()
        .map_err(|_| Tls13Error::Protocol("transcript SHA-256 overflow".to_owned()))
}

pub(crate) fn hkdf_expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Tls13Error> {
    let mut info = Zeroizing::new(Vec::with_capacity(10 + label.len() + context.len()));
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_sha256_expand(secret, &info, length)
        .map_err(|_| Tls13Error::Protocol("HKDF-Expand-Label failed".to_owned()))
}

fn derive_secret(
    secret: &[u8; 32],
    label: &[u8],
    hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Tls13Error> {
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(&hkdf_expand_label(secret, label, hash, 32)?);
    Ok(out)
}

type HandshakeSecrets = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

fn derive_handshake_secrets(
    shared: &[u8; 32],
    ch_sh: &[u8; 32],
) -> Result<HandshakeSecrets, Tls13Error> {
    let empty = sha256(&[]);
    let early = hkdf_sha256_extract(&[0_u8; 32], &[0_u8; 32]);
    let hs = hkdf_sha256_extract(&*derive_secret(&early, b"derived", &empty)?, shared);
    let c_hs = derive_secret(&hs, b"c hs traffic", ch_sh)?;
    let s_hs = derive_secret(&hs, b"s hs traffic", ch_sh)?;
    Ok((hs, c_hs, s_hs))
}

type AppSecrets = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn derive_app_secrets(hs: &[u8; 32], sf_hash: &[u8; 32]) -> Result<AppSecrets, Tls13Error> {
    let master = hkdf_sha256_extract(&*derive_secret(hs, b"derived", &sha256(&[]))?, &[0_u8; 32]);
    Ok((
        derive_secret(&master, b"c ap traffic", sf_hash)?,
        derive_secret(&master, b"s ap traffic", sf_hash)?,
    ))
}

fn compute_finished_mac(
    secret: &[u8; 32],
    hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Tls13Error> {
    let fk = hkdf_expand_label(secret, b"finished", &[], 32)?;
    Ok(Zeroizing::new(hmac_sha256(&fk, hash)))
}

fn build_cert_verify_content(transcript_hash: &[u8; 32]) -> Vec<u8> {
    [
        &[0x20_u8; 64][..],
        b"TLS 1.3, server CertificateVerify\x00",
        transcript_hash,
    ]
    .concat()
}

fn wrap_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&[
        msg_type,
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
    ]);
    out.extend_from_slice(body);
    out
}

fn push_ext(buf: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    buf.extend_from_slice(&ext_type.to_be_bytes());
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
}

fn build_client_hello(
    random: &[u8; 32],
    server_name: &str,
    key_share: &X25519PublicKey,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(200);
    body.extend_from_slice(&LEGACY_VERSION);
    body.extend_from_slice(random);
    body.extend_from_slice(&[
        0,
        0,
        2,
        CIPHER_CHACHA20_POLY1305_SHA256[0],
        CIPHER_CHACHA20_POLY1305_SHA256[1],
        1,
        0,
    ]);
    let mut exts = Vec::with_capacity(128);
    if !server_name.is_empty() && server_name.parse::<IpAddr>().is_err() {
        let nb = server_name.as_bytes();
        let mut sni = Vec::with_capacity(5 + nb.len());
        sni.extend_from_slice(&((3 + nb.len()) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        sni.extend_from_slice(nb);
        push_ext(&mut exts, EXT_SERVER_NAME, &sni);
    }
    push_ext(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
    push_ext(&mut exts, EXT_SUPPORTED_GROUPS, &[0, 2, 0x00, 0x1d]);
    push_ext(&mut exts, EXT_SIGNATURE_ALGORITHMS, &[0, 2, 0x08, 0x07]);
    let ks = [
        &[0, 36, GROUP_X25519[0], GROUP_X25519[1], 0, 32][..],
        key_share.as_bytes(),
    ]
    .concat();
    push_ext(&mut exts, EXT_KEY_SHARE, &ks);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    wrap_handshake(HS_CLIENT_HELLO, &body)
}

fn build_server_hello(
    random: &[u8; 32],
    session_id: &[u8],
    key_share: &X25519PublicKey,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(120);
    body.extend_from_slice(&LEGACY_VERSION);
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[
        CIPHER_CHACHA20_POLY1305_SHA256[0],
        CIPHER_CHACHA20_POLY1305_SHA256[1],
        0,
    ]);
    let mut exts = Vec::with_capacity(52);
    push_ext(&mut exts, EXT_SUPPORTED_VERSIONS, &TLS_13_VERSION);
    let ks = [
        &[GROUP_X25519[0], GROUP_X25519[1], 0, 32][..],
        key_share.as_bytes(),
    ]
    .concat();
    push_ext(&mut exts, EXT_KEY_SHARE, &ks);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    wrap_handshake(HS_SERVER_HELLO, &body)
}

fn parse_client_hello(body: &[u8]) -> Result<(Vec<u8>, X25519PublicKey), Tls13Error> {
    if body.len() < 38 {
        return Err(Tls13Error::Protocol("truncated ClientHello".to_owned()));
    }
    let mut pos = 34;
    let sid_len = usize::from(body[pos]);
    pos += 1;
    let sid = body
        .get(pos..pos + sid_len)
        .ok_or_else(|| Tls13Error::Protocol("bad sid".to_owned()))?
        .to_vec();
    pos += sid_len;
    let cs_len = usize::from(read_u16(body, &mut pos)?);
    let cs = body
        .get(pos..pos + cs_len)
        .ok_or_else(|| Tls13Error::Protocol("bad ciphers".to_owned()))?;
    if !cs
        .as_chunks::<2>()
        .0
        .contains(&CIPHER_CHACHA20_POLY1305_SHA256)
    {
        return Err(Tls13Error::Protocol(
            "missing TLS_CHACHA20_POLY1305_SHA256".to_owned(),
        ));
    }
    pos += cs_len;
    let comp_len = usize::from(
        *body
            .get(pos)
            .ok_or_else(|| Tls13Error::Protocol("bad comp".to_owned()))?,
    );
    pos += 1 + comp_len;
    let ext_len = usize::from(read_u16(body, &mut pos)?);
    let exts = body
        .get(pos..pos + ext_len)
        .ok_or_else(|| Tls13Error::Protocol("bad exts".to_owned()))?;
    let (mut has_tls13, mut pk, mut ep) = (false, None, 0);
    while ep < exts.len() {
        let et = read_u16(exts, &mut ep)?;
        let el = usize::from(read_u16(exts, &mut ep)?);
        let ed = exts
            .get(ep..ep + el)
            .ok_or_else(|| Tls13Error::Protocol("bad ext".to_owned()))?;
        ep += el;
        if et == EXT_SUPPORTED_VERSIONS && ed.len() >= 3 {
            has_tls13 = ed[1..].as_chunks::<2>().0.contains(&TLS_13_VERSION);
        } else if et == EXT_KEY_SHARE && ed.len() >= 2 {
            let mut kp = 2;
            while kp + 4 <= ed.len() {
                let grp = [ed[kp], ed[kp + 1]];
                let kl = usize::from(u16::from_be_bytes([ed[kp + 2], ed[kp + 3]]));
                kp += 4;
                if grp == GROUP_X25519 && kl == 32 && kp + 32 <= ed.len() {
                    let mut raw = [0_u8; 32];
                    raw.copy_from_slice(&ed[kp..kp + 32]);
                    pk = Some(X25519PublicKey(raw));
                }
                kp += kl;
            }
        }
    }
    if !has_tls13 {
        return Err(Tls13Error::Protocol("client lacks TLS 1.3".to_owned()));
    }
    Ok((
        sid,
        pk.ok_or_else(|| Tls13Error::Protocol("client lacks X25519 key_share".to_owned()))?,
    ))
}

fn parse_server_hello(body: &[u8]) -> Result<X25519PublicKey, Tls13Error> {
    if body.len() < 38 || body[2..34] == HRR_RANDOM {
        return Err(Tls13Error::Protocol(
            "invalid ServerHello or unsupported HRR".to_owned(),
        ));
    }
    let mut pos = 35 + usize::from(body[34]);
    if body.get(pos..pos + 2) != Some(&CIPHER_CHACHA20_POLY1305_SHA256) {
        return Err(Tls13Error::Protocol(
            "unsupported server cipher suite".to_owned(),
        ));
    }
    pos += 3;
    let ext_len = usize::from(read_u16(body, &mut pos)?);
    let exts = body
        .get(pos..pos + ext_len)
        .ok_or_else(|| Tls13Error::Protocol("bad SH exts".to_owned()))?;
    let (mut ok_v, mut pk, mut ep) = (false, None, 0);
    while ep < exts.len() {
        let et = read_u16(exts, &mut ep)?;
        let el = usize::from(read_u16(exts, &mut ep)?);
        let ed = exts
            .get(ep..ep + el)
            .ok_or_else(|| Tls13Error::Protocol("bad SH ext".to_owned()))?;
        ep += el;
        if et == EXT_SUPPORTED_VERSIONS && ed == TLS_13_VERSION {
            ok_v = true;
        } else if et == EXT_KEY_SHARE
            && ed.len() == 36
            && ed[0..2] == GROUP_X25519
            && ed[2..4] == [0, 32]
        {
            let mut raw = [0_u8; 32];
            raw.copy_from_slice(&ed[4..36]);
            pk = Some(X25519PublicKey(raw));
        }
    }
    if !ok_v {
        return Err(Tls13Error::Protocol(
            "server did not select TLS 1.3".to_owned(),
        ));
    }
    pk.ok_or_else(|| Tls13Error::Protocol("missing server X25519 key_share".to_owned()))
}

fn build_certificate_message(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for cert in chain {
        let len = cert.len() as u32;
        entries.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
        entries.extend_from_slice(cert);
        entries.extend_from_slice(&[0, 0]);
    }
    let ll = entries.len() as u32;
    let mut body = vec![
        0,
        ((ll >> 16) & 0xff) as u8,
        ((ll >> 8) & 0xff) as u8,
        (ll & 0xff) as u8,
    ];
    body.extend_from_slice(&entries);
    wrap_handshake(HS_CERTIFICATE, &body)
}

fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>, Tls13Error> {
    if body.len() < 4 || body[0] != 0 {
        return Err(Tls13Error::Protocol("bad Certificate msg".to_owned()));
    }
    let ll = (usize::from(body[1]) << 16) | (usize::from(body[2]) << 8) | usize::from(body[3]);
    let list = body
        .get(4..4 + ll)
        .ok_or_else(|| Tls13Error::Protocol("truncated Certificate list".to_owned()))?;
    let (mut certs, mut pos) = (Vec::new(), 0);
    while pos < list.len() {
        if pos + 3 > list.len() {
            return Err(Tls13Error::Protocol("truncated cert entry".to_owned()));
        }
        let clen = (usize::from(list[pos]) << 16)
            | (usize::from(list[pos + 1]) << 8)
            | usize::from(list[pos + 2]);
        pos += 3;
        let cert = list
            .get(pos..pos + clen)
            .ok_or_else(|| Tls13Error::Protocol("truncated cert DER".to_owned()))?;
        pos += clen;
        let ext_len = usize::from(read_u16(list, &mut pos)?);
        if pos + ext_len > list.len() {
            return Err(Tls13Error::Protocol("truncated cert ext".to_owned()));
        }
        pos += ext_len;
        certs.push(cert.to_vec());
    }
    Ok(certs)
}

fn parse_certificate_verify(body: &[u8]) -> Result<[u8; 64], Tls13Error> {
    if body.len() != 68 || body[0..2] != SIG_ED25519 || body[2..4] != [0x00, 0x40] {
        return Err(Tls13Error::Certificate(X509Error {
            detail: "CertificateVerify must be Ed25519".to_owned(),
        }));
    }
    let mut sig = [0_u8; 64];
    sig.copy_from_slice(&body[4..68]);
    Ok(sig)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, Tls13Error> {
    let s = data
        .get(*pos..*pos + 2)
        .ok_or_else(|| Tls13Error::Protocol("truncated TLS u16".to_owned()))?;
    *pos += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}
