//! Minimal DTLS 1.2 client for `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256`
//! (0xCCAC), X25519 key exchange, PSK identity `AUTHPWD_admin` — sans-IO.
//!
//! The caller owns the datagram transport: feed received datagrams in, pull
//! outgoing datagrams out. No sockets, no clocks except injected, no panics.
//!
//! Wire details (RFC 6347, RFC 5489, RFC 7905; live-verified against OpenSSL
//! `s_server` and owner Wyze cameras via the Python reference):
//!   * record header: type(1) version(2)=FE FD epoch(2) seq(6) len(2) — 13 B
//!   * handshake header: type(1) length(3) message_seq(2) frag_off(3) frag_len(3)
//!   * nonce = IV XOR (0x00*4 || epoch[2] || seq[6])  (RFC 7905 §2;
//!     the right-padded variant is available for stacks that deviate)
//!   * AAD = epoch || seq || type || version || plaintext_len
//!   * premaster = u16|Z || u16|PSK  (RFC 5489 §2)
//!   * PRF = TLS 1.2 SHA-256 (RFC 5246 §5); Finished verify_data = 12 B

use crate::chacha::{aead_decrypt, aead_encrypt};
use crate::digest::{hmac_sha256, Sha256};
use crate::x25519::{x25519, x25519_base};

/// DTLS 1.2 version bytes (FE FD).
pub const DTLS12: [u8; 2] = [0xFE, 0xFD];
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

pub(crate) const HT_CLIENT_HELLO: u8 = 1;
pub(crate) const HT_SERVER_HELLO: u8 = 2;
pub(crate) const HT_HELLO_VERIFY_REQUEST: u8 = 3;
pub(crate) const HT_SERVER_KEY_EXCHANGE: u8 = 12;
pub(crate) const HT_SERVER_HELLO_DONE: u8 = 14;
pub(crate) const HT_CLIENT_KEY_EXCHANGE: u8 = 16;
pub(crate) const HT_FINISHED: u8 = 20;

pub(crate) const CIPHER_ECDHE_PSK_CHACHA20_POLY1305: u16 = 0xCCAC;
pub(crate) const GROUP_X25519: u16 = 0x001D;

/// PSK identity used by TUTK AV sessions.
pub const PSK_IDENTITY: &[u8] = b"AUTHPWD_admin";

/// Errors from the DTLS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtlsError {
    /// Malformed input at some protocol layer.
    Malformed(&'static str),
    /// A timeout budget expired.
    Timeout(&'static str),
    /// The peer sent an alert (level, description).
    Alert(u8, u8),
    /// Server Finished verify_data mismatch.
    VerifyMismatch,
    /// The server selected something unsupported.
    Unsupported(&'static str),
}

impl core::fmt::Display for DtlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed: {what}"),
            Self::Timeout(what) => write!(f, "timeout: {what}"),
            Self::Alert(l, d) => write!(f, "dtls alert level={l} desc={d}"),
            Self::VerifyMismatch => write!(f, "server Finished verify_data mismatch"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl std::error::Error for DtlsError {}

/// TLS 1.2 PRF with SHA-256 (RFC 5246 §5).
#[must_use]
pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label);
    full_seed.extend_from_slice(seed);
    let mut out = Vec::with_capacity(out_len);
    let mut a = full_seed.clone();
    while out.len() < out_len {
        a = hmac_sha256(secret, &a).to_vec();
        let mut round_input = a.clone();
        round_input.extend_from_slice(&full_seed);
        out.extend_from_slice(&hmac_sha256(secret, &round_input));
    }
    out.truncate(out_len);
    out
}

/// Pack one DTLS record.
#[must_use]
pub fn pack_record(content_type: u8, epoch: u16, seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + payload.len());
    out.push(content_type);
    out.extend_from_slice(&DTLS12);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// One parsed record from a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Content type.
    pub content_type: u8,
    /// Epoch.
    pub epoch: u16,
    /// 48-bit sequence number.
    pub seq: u64,
    /// Payload bytes (owned for lifetimes simplicity).
    pub payload: Vec<u8>,
}

/// Split a datagram into records.
pub fn parse_records(datagram: &[u8]) -> Result<Vec<Record>, DtlsError> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 13 <= datagram.len() {
        let ct = datagram[off];
        let epoch = u16::from_be_bytes([datagram[off + 3], datagram[off + 4]]);
        let mut seq = [0u8; 8];
        seq[2..].copy_from_slice(&datagram[off + 5..off + 11]);
        let seq = u64::from_be_bytes(seq);
        let length = u16::from_be_bytes([datagram[off + 11], datagram[off + 12]]) as usize;
        let end = off + 13 + length;
        if end > datagram.len() {
            return Err(DtlsError::Malformed("record overruns datagram"));
        }
        out.push(Record {
            content_type: ct,
            epoch,
            seq,
            payload: datagram[off + 13..end].to_vec(),
        });
        off = end;
    }
    Ok(out)
}

/// Pack one handshake message (single fragment).
#[must_use]
pub fn pack_handshake(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&body.len().to_be_bytes()[5..]);
    out.extend_from_slice(&message_seq.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&body.len().to_be_bytes()[5..]);
    out.extend_from_slice(body);
    out
}

/// Reassembles (possibly fragmented) DTLS handshake messages.
#[derive(Default)]
pub struct HandshakeReassembler {
    frags: std::collections::BTreeMap<u16, (u8, usize, std::collections::BTreeMap<usize, Vec<u8>>)>,
    done: std::collections::BTreeMap<u16, (u8, Vec<u8>)>,
}

impl HandshakeReassembler {
    /// New empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one record's handshake payload.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        let mut off = 0;
        while off + 12 <= data.len() {
            let mtype = data[off];
            let mlen = u32::from_be_bytes([0, data[off + 1], data[off + 2], data[off + 3]]) as usize;
            let mseq = u16::from_be_bytes([data[off + 4], data[off + 5]]);
            let foff = u32::from_be_bytes([0, data[off + 6], data[off + 7], data[off + 8]]) as usize;
            let flen = u32::from_be_bytes([0, data[off + 9], data[off + 10], data[off + 11]]) as usize;
            if off + 12 + flen > data.len() {
                return Err(DtlsError::Malformed("truncated handshake fragment"));
            }
            let frag = &data[off + 12..off + 12 + flen];
            if foff + flen > mlen {
                return Err(DtlsError::Malformed("handshake fragment overruns declared length"));
            }
            off += 12 + flen;
            if self.done.contains_key(&mseq) {
                continue;
            }
            let slot = self.frags.entry(mseq).or_insert_with(|| (mtype, mlen, Default::default()));
            if slot.0 != mtype || slot.1 != mlen {
                return Err(DtlsError::Malformed("inconsistent handshake fragment header"));
            }
            slot.2.insert(foff, frag.to_vec());
            if slot.2.values().map(Vec::len).sum::<usize>() == mlen {
                let mut body = vec![0u8; mlen];
                for (fo, part) in &slot.2 {
                    body[*fo..*fo + part.len()].copy_from_slice(part);
                }
                if let Some((t, _, _)) = self.frags.remove(&mseq) {
                    self.done.insert(mseq, (t, body));
                }
            }
        }
        if off != data.len() {
            return Err(DtlsError::Malformed("trailing garbage in handshake record"));
        }
        Ok(())
    }

    /// Take an assembled message by sequence.
    pub fn take(&mut self, msg_seq: u16) -> Option<(u8, Vec<u8>)> {
        self.done.remove(&msg_seq)
    }

    /// Sorted list of complete message sequences.
    #[must_use]
    pub fn complete_seqs(&self) -> Vec<u16> {
        self.done.keys().copied().collect()
    }
}

fn record_nonce(iv: &[u8; 12], epoch: u16, seq: u64) -> [u8; 12] {
    let mut seq64 = [0u8; 8];
    seq64[..2].copy_from_slice(&epoch.to_be_bytes());
    seq64[2..].copy_from_slice(&seq.to_be_bytes()[2..]);
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = iv[i] ^ if i < 4 { 0 } else { seq64[i - 4] };
    }
    out
}

fn record_aad(epoch: u16, seq: u64, content_type: u8, plain_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes()[2..]);
    out.push(content_type);
    out.extend_from_slice(&DTLS12);
    out.extend_from_slice(&(plain_len as u16).to_be_bytes());
    out
}

/// Sans-IO ECDHE_PSK DTLS 1.2 client state machine.
pub struct DtlsClient {
    psk: Vec<u8>,
    identity: Vec<u8>,
    state: State,
    client_random: [u8; 32],
    eph_secret: [u8; 32],
    epoch0_seq: u64,
    send_seq: u64,
    c_key: [u8; 32],
    s_key: [u8; 32],
    c_iv: [u8; 12],
    s_iv: [u8; 12],
    transcript: Vec<u8>,
    outgoing: std::collections::VecDeque<Vec<u8>>,
    server_hello: Option<ServerHello>,
    server_ske: Option<ServerKeyExchange>,
    master: Option<Vec<u8>>,
    expected_server_verify: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SendClientHello,
    WaitServerFlight,
    WaitServerFinished,
    Established,
    Failed,
}

struct ServerHello {
    random: [u8; 32],
    cipher: u16,
}

struct ServerKeyExchange {
    public: [u8; 32],
}

impl DtlsClient {
    /// New client with the owner-supplied PSK and two independent 32-byte
    /// secrets from the caller's CSPRNG: the ClientHello `client_random`
    /// (public on the wire) and the `eph_secret` X25519 ephemeral private key
    /// (never leaves the client). They must be independent: reusing
    /// `client_random` as the ephemeral would expose the ECDH shared secret
    /// to any passive observer. The PSK is never logged or persisted here.
    #[must_use]
    pub fn new(psk: &[u8], client_random: [u8; 32], eph_secret: [u8; 32]) -> Option<Self> {
        if psk.is_empty() {
            return None;
        }
        Some(Self {
            psk: psk.to_vec(),
            identity: PSK_IDENTITY.to_vec(),
            state: State::SendClientHello,
            client_random,
            eph_secret,
            epoch0_seq: 0,
            send_seq: 0,
            c_key: [0; 32],
            s_key: [0; 32],
            c_iv: [0; 12],
            s_iv: [0; 12],
            transcript: Vec::new(),
            outgoing: Default::default(),
            server_hello: None,
            server_ske: None,
            master: None,
            expected_server_verify: None,
        })
    }

    /// Whether the handshake completed.
    #[must_use]
    pub fn established(&self) -> bool {
        self.state == State::Established
    }

    /// Take the next outgoing datagram, if any.
    pub fn poll_send(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    fn client_hello(&self, cookie: &[u8]) -> Vec<u8> {
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x000Au16.to_be_bytes()); // supported_groups
        exts.extend_from_slice(&4u16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&GROUP_X25519.to_be_bytes());
        exts.extend_from_slice(&0x000Bu16.to_be_bytes()); // ec_point_formats
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&[1, 0]);
        let mut body = Vec::with_capacity(64 + cookie.len());
        body.extend_from_slice(&DTLS12);
        body.extend_from_slice(&self.client_random);
        body.push(0); // session id: empty
        body.push(cookie.len() as u8);
        body.extend_from_slice(cookie);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&CIPHER_ECDHE_PSK_CHACHA20_POLY1305.to_be_bytes());
        body.extend_from_slice(&[1, 0]); // compression: null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        pack_handshake(HT_CLIENT_HELLO, 0, &body)
    }

    fn send_client_hello(&mut self, cookie: &[u8]) {
        let msg = self.client_hello(cookie);
        self.transcript.clear();
        self.transcript.extend_from_slice(&msg);
        let rec = pack_record(CT_HANDSHAKE, 0, self.epoch0_seq, &msg);
        self.epoch0_seq += 1;
        self.outgoing.push_back(rec);
        self.state = State::WaitServerFlight;
    }

    /// Kick off the handshake (queues the first ClientHello).
    pub fn start(&mut self) {
        if self.state == State::SendClientHello {
            self.send_client_hello(&[]);
        }
    }

    fn encrypt(&mut self, content_type: u8, plain: &[u8]) -> Vec<u8> {
        let nonce = record_nonce(&self.c_iv, 1, self.send_seq);
        let aad = record_aad(1, self.send_seq, content_type, plain.len());
        let (ct, tag) = aead_encrypt(&self.c_key, &nonce, &aad, plain);
        let mut sealed = ct;
        sealed.extend_from_slice(&tag);
        let rec = pack_record(content_type, 1, self.send_seq, &sealed);
        self.send_seq += 1;
        rec
    }

    fn decrypt(&self, content_type: u8, seq: u64, payload: &[u8]) -> Result<Vec<u8>, DtlsError> {
        if payload.len() < 16 {
            return Err(DtlsError::Malformed("ciphertext shorter than tag"));
        }
        let (ct, tag) = payload.split_at(payload.len() - 16);
        let nonce = record_nonce(&self.s_iv, 1, seq);
        let aad = record_aad(1, seq, content_type, ct.len());
        let mut t = [0u8; 16];
        t.copy_from_slice(tag);
        aead_decrypt(&self.s_key, &nonce, &aad, ct, &t)
            .ok_or(DtlsError::Malformed("record AEAD open failed"))
    }

    fn parse_server_hello(body: &[u8]) -> Result<ServerHello, DtlsError> {
        if body.len() < 38 {
            return Err(DtlsError::Malformed("ServerHello too short"));
        }
        if body[0..2] != DTLS12 {
            return Err(DtlsError::Unsupported("server version"));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&body[2..34]);
        let sid_len = body[34] as usize;
        let p = 35 + sid_len;
        if body.len() < p + 3 {
            return Err(DtlsError::Malformed("ServerHello truncated after session id"));
        }
        let cipher = u16::from_be_bytes([body[p], body[p + 1]]);
        if body[p + 2] != 0 {
            return Err(DtlsError::Unsupported("non-null compression"));
        }
        Ok(ServerHello { random, cipher })
    }

    fn parse_server_key_exchange(body: &[u8]) -> Result<ServerKeyExchange, DtlsError> {
        // ECDHE_PSK (RFC 5489 §2): psk_identity_hint<0..2^16-1> then ECDH params.
        let parse_hint_first = |b: &[u8]| -> Result<[u8; 32], DtlsError> {
            if b.len() < 2 {
                return Err(DtlsError::Malformed("SKE too short"));
            }
            let hint_len = u16::from_be_bytes([b[0], b[1]]) as usize;
            let p = 2 + hint_len;
            if b.len() < p + 4 {
                return Err(DtlsError::Malformed("SKE truncated"));
            }
            if b[p] != 3 {
                return Err(DtlsError::Unsupported("curve type"));
            }
            let curve = u16::from_be_bytes([b[p + 1], b[p + 2]]);
            if curve != GROUP_X25519 {
                return Err(DtlsError::Unsupported("curve"));
            }
            let plen = b[p + 3] as usize;
            if b.len() < p + 4 + plen || plen != 32 {
                return Err(DtlsError::Malformed("SKE bad point"));
            }
            let mut public = [0u8; 32];
            public.copy_from_slice(&b[p + 4..p + 4 + 32]);
            Ok(public)
        };
        let parse_params_first = |b: &[u8]| -> Result<[u8; 32], DtlsError> {
            if b.len() < 4 + 32 {
                return Err(DtlsError::Malformed("SKE too short"));
            }
            if b[0] != 3 {
                return Err(DtlsError::Unsupported("curve type"));
            }
            let curve = u16::from_be_bytes([b[1], b[2]]);
            if curve != GROUP_X25519 {
                return Err(DtlsError::Unsupported("curve"));
            }
            let plen = b[3] as usize;
            if b.len() < 4 + plen + 2 || plen != 32 {
                return Err(DtlsError::Malformed("SKE bad point"));
            }
            let mut public = [0u8; 32];
            public.copy_from_slice(&b[4..4 + 32]);
            Ok(public)
        };
        let public = parse_hint_first(body)
            .or_else(|_| parse_params_first(body))?;
        Ok(ServerKeyExchange { public })
    }

    /// Feed one received datagram. Drives the state machine; outgoing records
    /// appear via [`poll_send`].
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), DtlsError> {
        match self.state {
            State::Failed | State::Established => return Ok(()),
            _ => {}
        }
        let records = parse_records(datagram)?;
        match self.state {
            State::WaitServerFlight => self.handle_server_flight(records),
            State::WaitServerFinished => self.handle_server_finished(records),
            _ => Ok(()),
        }
    }

    fn handle_server_flight(&mut self, records: Vec<Record>) -> Result<(), DtlsError> {
        let mut reasm = HandshakeReassembler::new();
        let mut seen = std::collections::BTreeSet::new();
        for rec in records {
            if rec.content_type == CT_ALERT {
                if rec.payload.len() >= 2 {
                    return Err(DtlsError::Alert(rec.payload[0], rec.payload[1]));
                }
                return Err(DtlsError::Malformed("alert"));
            }
            if rec.content_type != CT_HANDSHAKE || rec.epoch != 0 {
                continue;
            }
            reasm.feed(&rec.payload)?;
            for mseq in reasm.complete_seqs() {
                if seen.contains(&mseq) {
                    reasm.take(mseq);
                    continue;
                }
                let (mtype, body) = match reasm.take(mseq) {
                    Some(v) => v,
                    None => continue,
                };
                if mtype == HT_HELLO_VERIFY_REQUEST {
                    if body.len() < 3 {
                        return Err(DtlsError::Malformed("HelloVerifyRequest"));
                    }
                    let clen = body[2] as usize;
                    if body.len() < 3 + clen {
                        return Err(DtlsError::Malformed("HelloVerifyRequest cookie"));
                    }
                    let cookie = body[3..3 + clen].to_vec();
                    self.transcript.clear();
                    self.send_client_hello(&cookie);
                    return Ok(());
                }
                seen.insert(mseq);
                self.transcript.extend_from_slice(&pack_handshake(mtype, mseq, &body));
                match mtype {
                    HT_SERVER_HELLO => {
                        self.server_hello = Some(Self::parse_server_hello(&body)?);
                    }
                    HT_SERVER_KEY_EXCHANGE => {
                        self.server_ske = Some(Self::parse_server_key_exchange(&body)?);
                    }
                    HT_SERVER_HELLO_DONE => {
                        return self.finish_client_side();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn finish_client_side(&mut self) -> Result<(), DtlsError> {
        let sh = match &self.server_hello {
            Some(v) => v,
            None => return Err(DtlsError::Malformed("no ServerHello in flight")),
        };
        let ske = match &self.server_ske {
            Some(v) => v,
            None => return Err(DtlsError::Malformed("no ServerKeyExchange in flight")),
        };
        if sh.cipher != CIPHER_ECDHE_PSK_CHACHA20_POLY1305 {
            return Err(DtlsError::Unsupported("cipher"));
        }
        let shared = x25519(&self.eph_secret, &ske.public);
        let mut premaster = Vec::with_capacity(4 + shared.len() + self.psk.len());
        premaster.extend_from_slice(&(shared.len() as u16).to_be_bytes());
        premaster.extend_from_slice(&shared);
        premaster.extend_from_slice(&(self.psk.len() as u16).to_be_bytes());
        premaster.extend_from_slice(&self.psk);
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&sh.random);
        let master = prf(&premaster, b"master secret", &seed, 48);
        let mut kseed = Vec::with_capacity(64);
        kseed.extend_from_slice(&sh.random);
        kseed.extend_from_slice(&self.client_random);
        let kb = prf(&master, b"key expansion", &kseed, 88);
        self.c_key.copy_from_slice(&kb[0..32]);
        self.s_key.copy_from_slice(&kb[32..64]);
        self.c_iv.copy_from_slice(&kb[64..76]);
        self.s_iv.copy_from_slice(&kb[76..88]);

        let mut cke_body = Vec::with_capacity(3 + self.identity.len() + 33);
        cke_body.extend_from_slice(&(self.identity.len() as u16).to_be_bytes());
        cke_body.extend_from_slice(&self.identity);
        cke_body.push(32u8);
        let client_pub = x25519_base(&self.eph_secret);
        cke_body.extend_from_slice(&client_pub);
        let cke_msg = pack_handshake(HT_CLIENT_KEY_EXCHANGE, 1, &cke_body);
        self.transcript.extend_from_slice(&cke_msg);

        let client_verify = prf(&master, b"client finished",
                                &Sha256::digest(&self.transcript), 12);
        let fin_msg = pack_handshake(HT_FINISHED, 2, &client_verify);

        let cke_rec = pack_record(CT_HANDSHAKE, 0, self.epoch0_seq, &cke_msg);
        let ccs_rec = pack_record(CT_CHANGE_CIPHER_SPEC, 0, self.epoch0_seq + 1, &[1]);
        self.epoch0_seq += 2;
        self.master = Some(master.clone());
        self.outgoing.push_back(cke_rec);
        self.outgoing.push_back(ccs_rec);
        let fin_rec = self.encrypt(CT_HANDSHAKE, &fin_msg);
        self.outgoing.push_back(fin_rec);
        self.transcript.extend_from_slice(&fin_msg);
        self.expected_server_verify = Some(prf(
            &master,
            b"server finished",
            &Sha256::digest(&self.transcript),
            12,
        ));
        self.state = State::WaitServerFinished;
        Ok(())
    }

    fn handle_server_finished(&mut self, records: Vec<Record>) -> Result<(), DtlsError> {
        let mut reasm = HandshakeReassembler::new();
        for rec in records {
            match rec.content_type {
                CT_ALERT => {
                    let payload = if rec.epoch == 1 {
                        self.decrypt(CT_ALERT, rec.seq, &rec.payload)?
                    } else {
                        rec.payload.clone()
                    };
                    if payload.len() >= 2 {
                        return Err(DtlsError::Alert(payload[0], payload[1]));
                    }
                    return Err(DtlsError::Malformed("alert"));
                }
                CT_CHANGE_CIPHER_SPEC => {}
                CT_HANDSHAKE => {
                    if rec.epoch != 1 {
                        continue;
                    }
                    let plain = self.decrypt(CT_HANDSHAKE, rec.seq, &rec.payload)?;
                    reasm.feed(&plain)?;
                    for mseq in reasm.complete_seqs() {
                        let (mtype, body) = match reasm.take(mseq) {
                            Some(v) => v,
                            None => continue,
                        };
                        if mtype != HT_FINISHED {
                            continue;
                        }
                        let expected = match &self.expected_server_verify {
                            Some(v) => v,
                            None => return Err(DtlsError::Malformed("no expected verify")),
                        };
                        if &body != expected {
                            self.state = State::Failed;
                            return Err(DtlsError::VerifyMismatch);
                        }
                        self.state = State::Established;
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Queue one application-data datagram (post-handshake).
    pub fn send_appdata(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        if !self.established() {
            return Err(DtlsError::Malformed("handshake not complete"));
        }
        let rec = self.encrypt(CT_APPLICATION_DATA, data);
        self.outgoing.push_back(rec);
        Ok(())
    }

    /// Decrypt one application-data datagram (post-handshake).
    pub fn recv_appdata(&mut self, datagram: &[u8]) -> Result<Vec<u8>, DtlsError> {
        if !self.established() {
            return Err(DtlsError::Malformed("handshake not complete"));
        }
        let mut app = Vec::new();
        for rec in parse_records(datagram)? {
            match rec.content_type {
                CT_APPLICATION_DATA if rec.epoch == 1 => {
                    app.extend_from_slice(&self.decrypt(CT_APPLICATION_DATA, rec.seq, &rec.payload)?);
                }
                CT_ALERT => {
                    let payload = if rec.epoch == 1 {
                        self.decrypt(CT_ALERT, rec.seq, &rec.payload)?
                    } else {
                        rec.payload.clone()
                    };
                    if payload.len() >= 2 {
                        return Err(DtlsError::Alert(payload[0], payload[1]));
                    }
                    return Err(DtlsError::Malformed("alert"));
                }
                _ => {}
            }
        }
        Ok(app)
    }

    /// Queue a close_notify alert.
    pub fn close(&mut self) {
        if self.established() {
            let rec = self.encrypt(CT_ALERT, &[1, 0]);
            self.outgoing.push_back(rec);
        }
    }
}
