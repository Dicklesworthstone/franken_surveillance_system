#![forbid(unsafe_code)]
//! Strict bounded X.509 v3 DER certificate parser, PEM bundle loader, Ed25519 certificate
//! generator, and fail-closed chain/pin/hostname/validity verifier (`ERR-NOTIFY-TLS-CERT-001`).

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fss_core::{ContentDigest, TimestampNs};

use super::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};

/// Stable error code for all X.509 / TLS certificate verification refusals.
pub const ERR_NOTIFY_TLS_CERT_001: &str = "ERR-NOTIFY-TLS-CERT-001";
/// Maximum DER byte size accepted for a single certificate (32 KiB).
pub const MAX_CERT_DER_BYTES: usize = 32 * 1024;
/// Maximum certificates allowed in a presented peer chain.
pub const MAX_CERT_CHAIN_LEN: usize = 4;
/// Maximum PEM root bundle input size (256 KiB).
pub const MAX_PEM_BUNDLE_BYTES: usize = 256 * 1024;
/// Maximum SAN entries parsed per certificate.
pub const MAX_SAN_ENTRIES: usize = 64;

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// Typed certificate parsing or verification error (always maps to [`ERR_NOTIFY_TLS_CERT_001`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509Error {
    /// Stable refusal detail (never includes secret keys or raw tokens).
    pub detail: String,
}

impl X509Error {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Stable FSS error code for all X.509 verification refusals.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        ERR_NOTIFY_TLS_CERT_001
    }
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ERR_NOTIFY_TLS_CERT_001}: {}", self.detail)
    }
}

impl std::error::Error for X509Error {}

/// Parsed Subject Alternative Name entry from extension `2.5.29.17`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SanEntry {
    /// DNS hostname entry (`dNSName [2]`), stored lower-cased.
    DnsName(String),
    /// IP address entry (`iPAddress [7]`).
    IpAddress(IpAddr),
}

/// Parsed, verified-structure X.509 v3 certificate supporting Ed25519 SPKI and signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedX509Cert {
    /// Raw DER encoding of `tbsCertificate` covered by the issuer signature.
    pub tbs_der: Vec<u8>,
    /// Raw DER encoding of `issuer` Name for exact chain matching.
    pub issuer_der: Vec<u8>,
    /// Raw DER encoding of `subject` Name for exact chain matching.
    pub subject_der: Vec<u8>,
    /// Subject Common Name (`2.5.4.3`), if present.
    pub subject_cn: Option<String>,
    /// Parsed Subject Alternative Name entries (`2.5.29.17`).
    pub san_entries: Vec<SanEntry>,
    /// Whether `BasicConstraints` (`2.5.29.19`) sets `cA = TRUE`.
    pub is_ca: bool,
    /// Certificate validity start (`notBefore`) as Unix epoch seconds.
    pub not_before_unix_s: i64,
    /// Certificate validity end (`notAfter`) as Unix epoch seconds.
    pub not_after_unix_s: i64,
    /// Raw DER encoding of `SubjectPublicKeyInfo`.
    pub spki_der: Vec<u8>,
    /// SHA-256 digest of `spki_der` for SPKI pinning and delivery receipts.
    pub spki_sha256: ContentDigest,
    /// Ed25519 subject public verifying key.
    pub public_key: Ed25519VerifyingKey,
    /// Raw 64-byte Ed25519 issuer signature over `tbs_der`.
    pub signature: [u8; 64],
}

/// Explicit trust anchor policy for TLS 1.3 peer certificate verification (no bypass option).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsTrustPolicy {
    /// Pinned trusted CA certificates in DER form (also accepts self-signed pinned leaves).
    pub trusted_ca_certs_der: Vec<Vec<u8>>,
    /// Pinned exact leaf `SubjectPublicKeyInfo` SHA-256 digests.
    pub pinned_leaf_spki_sha256: Vec<ContentDigest>,
}

impl TlsTrustPolicy {
    /// Creates a trust policy pinned to one or more DER root/CA certificates.
    #[must_use]
    pub fn from_ca_certs_der(certs_der: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_ca_certs_der: certs_der,
            pinned_leaf_spki_sha256: Vec::new(),
        }
    }

    /// Creates a trust policy parsed from a bounded PEM root bundle.
    pub fn from_pem_bundle(pem: &str) -> Result<Self, X509Error> {
        let certs = parse_pem_certificates(pem)?;
        if certs.is_empty() {
            return Err(X509Error::new(
                "PEM root bundle contained zero certificates",
            ));
        }
        Ok(Self::from_ca_certs_der(certs))
    }

    /// Creates a trust policy pinned directly to a leaf SPKI SHA-256 digest.
    #[must_use]
    pub fn from_pinned_leaf_spki(spki_sha256: ContentDigest) -> Self {
        Self {
            trusted_ca_certs_der: Vec::new(),
            pinned_leaf_spki_sha256: vec![spki_sha256],
        }
    }

    /// Adds an additional pinned leaf SPKI SHA-256 digest.
    #[must_use]
    pub fn with_pinned_leaf_spki(mut self, spki_sha256: ContentDigest) -> Self {
        self.pinned_leaf_spki_sha256.push(spki_sha256);
        self
    }
}

/// Verified peer certificate identity returned by [`verify_certificate_chain`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPeerCert {
    /// Leaf certificate's Ed25519 verifying key used to verify TLS 1.3 `CertificateVerify`.
    pub leaf_public_key: Ed25519VerifyingKey,
    /// SHA-256 digest of the leaf certificate's `SubjectPublicKeyInfo`.
    pub leaf_spki_sha256: ContentDigest,
    /// SHA-256 digest of the leaf certificate DER bytes.
    pub leaf_cert_sha256: ContentDigest,
    /// Matched SNI hostname or IP string.
    pub verified_server_name: String,
}

/// Parses one DER-encoded X.509 v3 Ed25519 certificate under strict size and syntax bounds.
pub fn parse_x509_der(der: &[u8]) -> Result<ParsedX509Cert, X509Error> {
    if der.is_empty() || der.len() > MAX_CERT_DER_BYTES {
        return Err(X509Error::new(
            "certificate DER length empty or exceeds 32 KiB",
        ));
    }
    let mut root = DerReader::new(der);
    let cert_body = root.read_tlv(0x30)?;
    root.ensure_empty()?;

    let mut cert = DerReader::new(cert_body);
    let tbs_raw = cert.read_tlv_with_header(0x30)?;
    verify_ed25519_alg_id(cert.read_tlv(0x30)?)?;
    let sig_bits = cert.read_bit_string()?;
    cert.ensure_empty()?;
    if sig_bits.len() != 64 {
        return Err(X509Error::new(
            "Ed25519 certificate signature must be 64 bytes",
        ));
    }
    let mut signature = [0_u8; 64];
    signature.copy_from_slice(sig_bits);

    let mut tbs_wrap = DerReader::new(tbs_raw);
    let mut tbs = DerReader::new(tbs_wrap.read_tlv(0x30)?);
    let mut ver_reader = DerReader::new(tbs.read_tlv(0xa0)?);
    if ver_reader.read_tlv(0x02)? != [0x02] {
        return Err(X509Error::new("only X.509 v3 certificates are supported"));
    }
    ver_reader.ensure_empty()?;
    let _serial = tbs.read_tlv(0x02)?;
    verify_ed25519_alg_id(tbs.read_tlv(0x30)?)?;
    let issuer_der = tbs.read_tlv_with_header(0x30)?.to_vec();
    let (not_before_unix_s, not_after_unix_s) = parse_validity(tbs.read_tlv(0x30)?)?;
    let subject_raw = tbs.read_tlv_with_header(0x30)?;
    let subject_cn = extract_common_name(subject_raw)?;
    let spki_raw = tbs.read_tlv_with_header(0x30)?;
    let public_key = parse_ed25519_spki(spki_raw)?;
    let spki_sha256 = ContentDigest::sha256(spki_raw);

    let mut san_entries = Vec::new();
    let mut is_ca = false;
    while !tbs.is_empty() {
        let (tag, content) = tbs.read_any_tlv()?;
        if tag == 0xa3 {
            let mut ext_seq = DerReader::new(content);
            let exts_body = ext_seq.read_tlv(0x30)?;
            ext_seq.ensure_empty()?;
            parse_extensions(exts_body, &mut san_entries, &mut is_ca)?;
        }
    }
    Ok(ParsedX509Cert {
        tbs_der: tbs_raw.to_vec(),
        issuer_der,
        subject_der: subject_raw.to_vec(),
        subject_cn,
        san_entries,
        is_ca,
        not_before_unix_s,
        not_after_unix_s,
        spki_der: spki_raw.to_vec(),
        spki_sha256,
        public_key,
        signature,
    })
}

/// Strictly verifies a peer's DER certificate chain against `trust`, `expected_hostname`, and `now`.
pub fn verify_certificate_chain(
    chain_der: &[Vec<u8>],
    trust: &TlsTrustPolicy,
    expected_hostname: &str,
    now: TimestampNs,
) -> Result<VerifiedPeerCert, X509Error> {
    if chain_der.is_empty() || chain_der.len() > MAX_CERT_CHAIN_LEN {
        return Err(X509Error::new(
            "peer certificate chain empty or exceeds max length",
        ));
    }
    if trust.trusted_ca_certs_der.is_empty() && trust.pinned_leaf_spki_sha256.is_empty() {
        return Err(X509Error::new(
            "TLS trust policy has no trusted CA roots or SPKI pins",
        ));
    }
    if expected_hostname.is_empty() || expected_hostname.len() > 253 {
        return Err(X509Error::new("invalid expected TLS server hostname"));
    }
    let now_s = i64::try_from(now.0.div_euclid(1_000_000_000))
        .map_err(|_| X509Error::new("timestamp outside valid Unix seconds range"))?;

    let mut chain = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        let cert = parse_x509_der(der)?;
        if now_s < cert.not_before_unix_s || now_s > cert.not_after_unix_s {
            return Err(X509Error::new(format!(
                "certificate expired or not yet valid at unix_s={now_s}"
            )));
        }
        chain.push(cert);
    }
    let leaf = &chain[0];
    if !matches_hostname(leaf, expected_hostname) {
        return Err(X509Error::new(format!(
            "certificate SAN/CN does not match '{expected_hostname}'"
        )));
    }
    if !trust.pinned_leaf_spki_sha256.is_empty()
        && !trust.pinned_leaf_spki_sha256.contains(&leaf.spki_sha256)
    {
        return Err(X509Error::new(
            "leaf SPKI SHA-256 does not match pinned digest",
        ));
    }
    if !trust.trusted_ca_certs_der.is_empty() {
        let mut roots = Vec::with_capacity(trust.trusted_ca_certs_der.len());
        for root_der in &trust.trusted_ca_certs_der {
            let root = parse_x509_der(root_der)?;
            if now_s >= root.not_before_unix_s && now_s <= root.not_after_unix_s {
                roots.push(root);
            }
        }
        if roots.is_empty() {
            return Err(X509Error::new(
                "no currently valid CA roots in trust policy",
            ));
        }
        verify_chain_to_roots(&chain, &roots)?;
    }
    Ok(VerifiedPeerCert {
        leaf_public_key: leaf.public_key,
        leaf_spki_sha256: leaf.spki_sha256,
        leaf_cert_sha256: ContentDigest::sha256(&chain_der[0]),
        verified_server_name: expected_hostname.to_ascii_lowercase(),
    })
}

fn verify_chain_to_roots(
    chain: &[ParsedX509Cert],
    roots: &[ParsedX509Cert],
) -> Result<(), X509Error> {
    let leaf = &chain[0];
    if roots.iter().any(|r| {
        r.subject_der == leaf.subject_der
            && r.spki_sha256 == leaf.spki_sha256
            && r.public_key.verify(&leaf.tbs_der, &leaf.signature).is_ok()
    }) {
        return Ok(());
    }
    for pair in chain.windows(2) {
        let (child, issuer) = (&pair[0], &pair[1]);
        if !issuer.is_ca || child.issuer_der != issuer.subject_der {
            return Err(X509Error::new(
                "certificate chain issuer/CA constraint failed",
            ));
        }
        issuer
            .public_key
            .verify(&child.tbs_der, &child.signature)
            .map_err(|_| X509Error::new("intermediate certificate signature invalid"))?;
    }
    let top = chain
        .last()
        .ok_or_else(|| X509Error::new("empty certificate chain"))?;
    if roots.iter().any(|r| {
        r.is_ca
            && top.issuer_der == r.subject_der
            && r.public_key.verify(&top.tbs_der, &top.signature).is_ok()
    }) {
        return Ok(());
    }
    Err(X509Error::new(
        "certificate chain not signed by any trusted CA root",
    ))
}

fn matches_hostname(cert: &ParsedX509Cert, expected: &str) -> bool {
    if let Ok(ip) = expected.parse::<IpAddr>() {
        return cert
            .san_entries
            .iter()
            .any(|e| matches!(e, SanEntry::IpAddress(a) if *a == ip));
    }
    let target = expected.to_ascii_lowercase();
    if !cert.san_entries.is_empty() {
        return cert.san_entries.iter().any(|e| match e {
            SanEntry::DnsName(pat) => dns_pattern_matches(pat, &target),
            SanEntry::IpAddress(_) => false,
        });
    }
    cert.subject_cn
        .as_deref()
        .is_some_and(|cn| dns_pattern_matches(&cn.to_ascii_lowercase(), &target))
}

fn dns_pattern_matches(pattern: &str, hostname: &str) -> bool {
    if pattern == hostname {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    if suffix.is_empty() || suffix.contains('*') || !suffix.contains('.') {
        return false;
    }
    hostname
        .strip_suffix(suffix)
        .and_then(|p| p.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

/// Decodes one or more `-----BEGIN CERTIFICATE-----` blocks from a PEM bundle.
pub fn parse_pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, X509Error> {
    if pem.len() > MAX_PEM_BUNDLE_BYTES {
        return Err(X509Error::new("PEM bundle exceeds 256 KiB bound"));
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let (mut certs, mut rest) = (Vec::new(), pem);
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after
            .find(END)
            .ok_or_else(|| X509Error::new("unterminated PEM block"))?;
        let clean: String = after[..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = decode_base64_strict(&clean)?;
        if der.is_empty() || der.len() > MAX_CERT_DER_BYTES {
            return Err(X509Error::new("PEM certificate DER length out of bounds"));
        }
        certs.push(der);
        if certs.len() > 64 {
            return Err(X509Error::new("PEM bundle exceeds 64-certificate limit"));
        }
        rest = &after[end + END.len()..];
    }
    Ok(certs)
}

/// Parameters for generating a standards-compliant DER X.509 v3 Ed25519 certificate.
#[derive(Clone, Debug)]
pub struct CertBuilderParams<'a> {
    /// Positive serial number.
    pub serial: u64,
    /// Issuer Common Name.
    pub issuer_cn: &'a str,
    /// Subject Common Name.
    pub subject_cn: &'a str,
    /// DNS Subject Alternative Names.
    pub san_dns: &'a [&'a str],
    /// IP Subject Alternative Names.
    pub san_ips: &'a [IpAddr],
    /// Validity start in Unix seconds.
    pub not_before_unix_s: i64,
    /// Validity end in Unix seconds.
    pub not_after_unix_s: i64,
    /// Whether this certificate is a CA (`BasicConstraints cA=TRUE`).
    pub is_ca: bool,
}

/// Builds and signs a DER-encoded X.509 v3 Ed25519 certificate.
#[must_use]
pub fn build_ed25519_x509_der(
    params: &CertBuilderParams<'_>,
    subject_key: &Ed25519VerifyingKey,
    issuer_signing_key: &Ed25519SigningKey,
) -> Vec<u8> {
    let version = der_tlv(0xa0, &der_tlv(0x02, &[0x02]));
    let serial = der_tlv(0x02, &encode_positive_u64_der(params.serial.max(1)));
    let alg_id = der_tlv(0x30, &der_tlv(0x06, OID_ED25519));
    let issuer = der_cn_name(params.issuer_cn);
    let validity = der_tlv(
        0x30,
        &[
            encode_generalized_time(params.not_before_unix_s),
            encode_generalized_time(params.not_after_unix_s),
        ]
        .concat(),
    );
    let subject = der_cn_name(params.subject_cn);
    let spki = der_tlv(
        0x30,
        &[
            alg_id.clone(),
            der_tlv(0x03, &[&[0x00][..], subject_key.as_bytes()].concat()),
        ]
        .concat(),
    );

    let ca_flag: &[u8] = if params.is_ca {
        &[0x01, 0x01, 0xff]
    } else {
        &[]
    };
    let mut exts = der_extension(OID_BASIC_CONSTRAINTS, true, &der_tlv(0x30, ca_flag));
    if !params.san_dns.is_empty() || !params.san_ips.is_empty() {
        let mut san_inner = Vec::new();
        for dns in params.san_dns {
            san_inner.extend_from_slice(&der_tlv(0x82, dns.as_bytes()));
        }
        for ip in params.san_ips {
            match ip {
                IpAddr::V4(v4) => san_inner.extend_from_slice(&der_tlv(0x87, &v4.octets())),
                IpAddr::V6(v6) => san_inner.extend_from_slice(&der_tlv(0x87, &v6.octets())),
            }
        }
        exts.extend_from_slice(&der_extension(OID_SAN, false, &der_tlv(0x30, &san_inner)));
    }
    let extensions = der_tlv(0xa3, &der_tlv(0x30, &exts));
    let tbs = der_tlv(
        0x30,
        &[
            version,
            serial,
            alg_id.clone(),
            issuer,
            validity,
            subject,
            spki,
            extensions,
        ]
        .concat(),
    );
    let sig = issuer_signing_key.sign(&tbs);
    der_tlv(
        0x30,
        &[tbs, alg_id, der_tlv(0x03, &[&[0x00][..], &sig].concat())].concat(),
    )
}

/// Encodes a DER certificate into PEM (`-----BEGIN CERTIFICATE-----`).
#[must_use]
pub fn encode_cert_pem(der: &[u8]) -> String {
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in super::encode_base64_std(der).as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn verify_ed25519_alg_id(body: &[u8]) -> Result<(), X509Error> {
    let mut r = DerReader::new(body);
    let oid = r.read_tlv(0x06)?;
    r.ensure_empty()?;
    if oid != OID_ED25519 {
        return Err(X509Error::new(
            "unsupported X.509 algorithm OID (Ed25519 required)",
        ));
    }
    Ok(())
}

fn parse_ed25519_spki(spki_raw: &[u8]) -> Result<Ed25519VerifyingKey, X509Error> {
    let mut wrap = DerReader::new(spki_raw);
    let mut inner = DerReader::new(wrap.read_tlv(0x30)?);
    wrap.ensure_empty()?;
    verify_ed25519_alg_id(inner.read_tlv(0x30)?)?;
    let key_bits = inner.read_bit_string()?;
    inner.ensure_empty()?;
    let key: [u8; 32] = key_bits
        .try_into()
        .map_err(|_| X509Error::new("Ed25519 SPKI key must be 32 bytes"))?;
    Ed25519VerifyingKey::from_bytes(key).map_err(|_| X509Error::new("invalid Ed25519 SPKI key"))
}

fn extract_common_name(name_der: &[u8]) -> Result<Option<String>, X509Error> {
    let mut wrap = DerReader::new(name_der);
    let mut rdns = DerReader::new(wrap.read_tlv(0x30)?);
    let mut cn = None;
    while !rdns.is_empty() {
        let mut attrs = DerReader::new(rdns.read_tlv(0x31)?);
        while !attrs.is_empty() {
            let mut attr = DerReader::new(attrs.read_tlv(0x30)?);
            let oid = attr.read_tlv(0x06)?;
            let (tag, bytes) = attr.read_any_tlv()?;
            if oid == OID_COMMON_NAME && matches!(tag, 0x0c | 0x13 | 0x16) {
                cn = Some(
                    std::str::from_utf8(bytes)
                        .map_err(|_| X509Error::new("invalid UTF-8 CN"))?
                        .to_owned(),
                );
            }
        }
    }
    Ok(cn)
}

fn parse_extensions(
    exts_body: &[u8],
    san_entries: &mut Vec<SanEntry>,
    is_ca: &mut bool,
) -> Result<(), X509Error> {
    let mut reader = DerReader::new(exts_body);
    while !reader.is_empty() {
        let mut ext = DerReader::new(reader.read_tlv(0x30)?);
        let oid = ext.read_tlv(0x06)?;
        if ext.peek_tag() == Some(0x01) {
            let _ = ext.read_tlv(0x01)?;
        }
        let octets = ext.read_tlv(0x04)?;
        ext.ensure_empty()?;
        if oid == OID_SAN {
            let mut sw = DerReader::new(octets);
            let mut entries = DerReader::new(sw.read_tlv(0x30)?);
            sw.ensure_empty()?;
            while !entries.is_empty() {
                if san_entries.len() >= MAX_SAN_ENTRIES {
                    return Err(X509Error::new("exceeds max SAN count"));
                }
                let (tag, val) = entries.read_any_tlv()?;
                match tag {
                    0x82 => san_entries.push(SanEntry::DnsName(
                        std::str::from_utf8(val)
                            .map_err(|_| X509Error::new("non-UTF-8 SAN"))?
                            .to_ascii_lowercase(),
                    )),
                    0x87 if val.len() == 4 => san_entries.push(SanEntry::IpAddress(IpAddr::V4(
                        Ipv4Addr::new(val[0], val[1], val[2], val[3]),
                    ))),
                    0x87 if val.len() == 16 => {
                        let mut oct = [0_u8; 16];
                        oct.copy_from_slice(val);
                        san_entries.push(SanEntry::IpAddress(IpAddr::V6(Ipv6Addr::from(oct))));
                    }
                    0x87 => return Err(X509Error::new("invalid SAN iPAddress length")),
                    _ => {}
                }
            }
        } else if oid == OID_BASIC_CONSTRAINTS {
            let mut bw = DerReader::new(octets);
            let mut bc = DerReader::new(bw.read_tlv(0x30)?);
            bw.ensure_empty()?;
            if bc.peek_tag() == Some(0x01) {
                let flag = bc.read_tlv(0x01)?;
                if flag.len() != 1 {
                    return Err(X509Error::new("malformed BasicConstraints cA"));
                }
                *is_ca = flag[0] != 0;
            }
        }
    }
    Ok(())
}

fn parse_validity(body: &[u8]) -> Result<(i64, i64), X509Error> {
    let mut r = DerReader::new(body);
    let (nb, na) = (parse_x509_time(&mut r)?, parse_x509_time(&mut r)?);
    r.ensure_empty()?;
    if na < nb {
        return Err(X509Error::new("certificate notAfter precedes notBefore"));
    }
    Ok((nb, na))
}

fn parse_x509_time(reader: &mut DerReader<'_>) -> Result<i64, X509Error> {
    let (tag, bytes) = reader.read_any_tlv()?;
    let s = std::str::from_utf8(bytes).map_err(|_| X509Error::new("non-ASCII X.509 timestamp"))?;
    let (year, rest) = match tag {
        0x17 if s.len() == 13 && s.ends_with('Z') => {
            let yy = parse_2d(&s[0..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..12])
        }
        0x18 if s.len() == 15 && s.ends_with('Z') => (
            s[0..4]
                .parse::<i64>()
                .map_err(|_| X509Error::new("invalid year"))?,
            &s[4..14],
        ),
        _ => return Err(X509Error::new("unsupported X.509 time format")),
    };
    let (m, d, h, min, sec) = (
        parse_2d(&rest[0..2])?,
        parse_2d(&rest[2..4])?,
        parse_2d(&rest[4..6])?,
        parse_2d(&rest[6..8])?,
        parse_2d(&rest[8..10])?,
    );
    if !(1..=12).contains(&m)
        || !(1..=31).contains(&d)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return Err(X509Error::new("out-of-range X.509 date field"));
    }
    Ok(days_from_civil(year, m, d) * 86_400 + h * 3_600 + min * 60 + sec)
}

fn parse_2d(s: &str) -> Result<i64, X509Error> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(X509Error::new("non-digit X.509 time"));
    }
    s.parse().map_err(|_| X509Error::new("invalid X.509 time"))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + day - 1;
    era * 146_097 + doe - 719_468
}

fn encode_generalized_time(unix_s: i64) -> Vec<u8> {
    let (days, sod) = (unix_s.div_euclid(86_400), unix_s.rem_euclid(86_400));
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    );
    der_tlv(0x18, text.as_bytes())
}

fn der_cn_name(cn: &str) -> Vec<u8> {
    let atv = der_tlv(
        0x30,
        &[der_tlv(0x06, OID_COMMON_NAME), der_tlv(0x0c, cn.as_bytes())].concat(),
    );
    der_tlv(0x30, &der_tlv(0x31, &atv))
}

fn der_extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut inner = der_tlv(0x06, oid);
    if critical {
        inner.extend_from_slice(&der_tlv(0x01, &[0xff]));
    }
    inner.extend_from_slice(&der_tlv(0x04, value));
    der_tlv(0x30, &inner)
}

fn encode_positive_u64_der(value: u64) -> Vec<u8> {
    let raw = value.to_be_bytes();
    let slice = &raw[raw.iter().position(|&b| b != 0).unwrap_or(7)..];
    let mut out = Vec::with_capacity(slice.len() + 1);
    if (slice[0] & 0x80) != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(slice);
    out
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(tag);
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() < 256 {
        out.extend_from_slice(&[0x81, body.len() as u8]);
    } else if body.len() < 65_536 {
        out.push(0x82);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    } else {
        let len = body.len() as u32;
        out.extend_from_slice(&[
            0x83,
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);
    }
    out.extend_from_slice(body);
    out
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }
    fn ensure_empty(&self) -> Result<(), X509Error> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(X509Error::new("trailing DER bytes"))
        }
    }
    fn read_any_tlv(&mut self) -> Result<(u8, &'a [u8]), X509Error> {
        let (_, tag, content) = self.read_tlv_inner()?;
        Ok((tag, content))
    }
    fn read_tlv(&mut self, expected: u8) -> Result<&'a [u8], X509Error> {
        let (_, tag, content) = self.read_tlv_inner()?;
        if tag != expected {
            return Err(X509Error::new(format!("unexpected DER tag 0x{tag:02x}")));
        }
        Ok(content)
    }
    fn read_tlv_with_header(&mut self, expected: u8) -> Result<&'a [u8], X509Error> {
        let (full, tag, _) = self.read_tlv_inner()?;
        if tag != expected {
            return Err(X509Error::new(format!("unexpected DER tag 0x{tag:02x}")));
        }
        Ok(full)
    }
    fn read_bit_string(&mut self) -> Result<&'a [u8], X509Error> {
        let content = self.read_tlv(0x03)?;
        if content.is_empty() || content[0] != 0 {
            return Err(X509Error::new("invalid DER BIT STRING"));
        }
        Ok(&content[1..])
    }
    fn read_tlv_inner(&mut self) -> Result<(&'a [u8], u8, &'a [u8]), X509Error> {
        let start = self.pos;
        let tag = *self
            .data
            .get(self.pos)
            .ok_or_else(|| X509Error::new("truncated DER tag"))?;
        let first = *self
            .data
            .get(self.pos + 1)
            .ok_or_else(|| X509Error::new("truncated DER len"))?;
        self.pos += 2;
        let len = if (first & 0x80) == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 {
                return Err(X509Error::new("unsupported DER length encoding"));
            }
            let mut acc = 0_usize;
            for _ in 0..count {
                let b = *self
                    .data
                    .get(self.pos)
                    .ok_or_else(|| X509Error::new("truncated DER len"))?;
                self.pos += 1;
                acc = (acc << 8) | usize::from(b);
            }
            acc
        };
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| X509Error::new("DER length overflow"))?;
        let content = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| X509Error::new("truncated DER value"))?;
        self.pos = end;
        Ok((&self.data[start..end], tag, content))
    }
}

fn decode_base64_strict(input: &str) -> Result<Vec<u8>, X509Error> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(X509Error::new("invalid base64 length in PEM block"));
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.as_chunks::<4>().0 {
        let (a, b) = (b64_val(chunk[0])?, b64_val(chunk[1])?);
        let (p2, p3) = (chunk[2] == b'=', chunk[3] == b'=');
        if p2 && !p3 {
            return Err(X509Error::new("malformed PEM base64 padding"));
        }
        let (c, d) = (
            if p2 { 0 } else { b64_val(chunk[2])? },
            if p3 { 0 } else { b64_val(chunk[3])? },
        );
        out.push((a << 2) | (b >> 4));
        if !p2 {
            out.push((b << 4) | (c >> 2));
        }
        if !p3 {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn b64_val(byte: u8) -> Result<u8, X509Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(X509Error::new("invalid base64 byte in PEM")),
    }
}
