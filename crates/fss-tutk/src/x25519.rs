//! X25519 Elliptic-Curve Diffie-Hellman (RFC 7748), first-party.
//!
//! Faithful port of the public-domain TweetNaCl `crypto_scalarmult`
//! (base-2^16 `gf` limbs, carry-based) — small, auditable, and verified
//! against the RFC 7748 §5.2 vectors in this crate's test suite.

/// Field element: 16 limbs of base 2^16.
type Gf = [i64; 16];

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(out: &mut [u8; 32], n: &Gf) {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m: Gf = [0; 16];
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut out: Gf = [0; 16];
    for i in 0..16 {
        out[i] = (n[2 * i] as i64) | ((n[2 * i + 1] as i64) << 8);
    }
    out[15] &= 0x7fff;
    out
}

fn add(a: &Gf, b: &Gf) -> Gf {
    let mut o: Gf = [0; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn sub(a: &Gf, b: &Gf) -> Gf {
    let mut o: Gf = [0; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn mul(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut out: Gf = [0; 16];
    out.copy_from_slice(&t[..16]);
    car25519(&mut out);
    car25519(&mut out);
    out
}

fn sqr(a: &Gf) -> Gf {
    mul(a, a)
}

fn inv25519(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = sqr(&c);
        if a != 2 && a != 4 {
            c = mul(&c, i);
        }
    }
    c
}

const A24: Gf = [121665, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// X25519(n, u) — Montgomery ladder in the RFC 7748 §5 pseudocode form
/// (oracle-verified against the cryptography package and the RFC vectors).
#[must_use]
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[31] = (k[31] & 127) | 64;
    k[0] &= 248;
    let x1 = unpack25519(point);
    let mut x2: Gf = [0; 16];
    x2[0] = 1;
    let mut z2: Gf = [0; 16];
    let mut x3 = x1;
    let mut z3: Gf = [0; 16];
    z3[0] = 1;
    let mut swap = 0i64;
    for t in (0..=254).rev() {
        let kt = ((k[t >> 3] >> (t & 7)) & 1) as i64;
        swap ^= kt;
        sel25519(&mut x2, &mut x3, swap);
        sel25519(&mut z2, &mut z3, swap);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = sqr(&a);
        let b = sub(&x2, &z2);
        let bb = sqr(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = sqr(&add(&da, &cb));
        z3 = mul(&x1, &sqr(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul(&A24, &e)));
    }
    sel25519(&mut x2, &mut x3, swap);
    sel25519(&mut z2, &mut z3, swap);
    let out_gf = mul(&x2, &inv25519(&z2));
    let mut out = [0u8; 32];
    pack25519(&mut out, &out_gf);
    out
}

/// X25519 base-point multiplication (public key from a 32-byte secret).
#[must_use]
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn gf_ops_match_python_clone() {
        let x = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let y = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6c0ab1c4c");
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&x);
        let mut yb = [0u8; 32];
        yb.copy_from_slice(&y);
        let xg = unpack25519(&xb);
        let yg = unpack25519(&yb);
        let mut out = [0u8; 32];
        pack25519(&mut out, &mul(&xg, &yg));
        assert_eq!(hex(&out), "47d4bd46c676f43eee7e07da44f1ffb6656106cb7ace00722eeeae5c65a4e051", "mul");
        pack25519(&mut out, &sqr(&xg));
        assert_eq!(hex(&out), "581409f3383b3d900fc0102b4d0d600a07756955d93a920d036aea4272265213", "sqr");
        pack25519(&mut out, &inv25519(&xg));
        assert_eq!(hex(&out), "03279bd555cf9329dc17dc18a89e564f0bfb98f1623cb1e0389a43419bfc4c21", "inv");
        pack25519(&mut out, &xg);
        assert_eq!(hex(&out), "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44", "pack");
    }

    #[test]
    fn ladder_intermediate_state() {
        let s = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6c0ab1c4c");
        let mut k = [0u8; 32];
        k.copy_from_slice(&s);
        let mut pt = [0u8; 32];
        pt.copy_from_slice(&u);
        k[31] = (k[31] & 127) | 64;
        k[0] &= 248;
        let x1 = unpack25519(&pt);
        let mut x2: Gf = [0; 16];
        x2[0] = 1;
        let mut z2: Gf = [0; 16];
        let mut x3 = x1;
        let mut z3: Gf = [0; 16];
        z3[0] = 1;
        let mut swap = 0i64;
        for t in (251..=254).rev() {
            let kt = ((k[t >> 3] >> (t & 7)) & 1) as i64;
            swap ^= kt;
            sel25519(&mut x2, &mut x3, swap);
            sel25519(&mut z2, &mut z3, swap);
            swap = kt;
            let a = add(&x2, &z2);
            let aa = sqr(&a);
            let b = sub(&x2, &z2);
            let bb = sqr(&b);
            let e = sub(&aa, &bb);
            let c = add(&x3, &z3);
            let d = sub(&x3, &z3);
            let da = mul(&d, &a);
            let cb = mul(&c, &b);
            x3 = sqr(&add(&da, &cb));
            z3 = mul(&x1, &sqr(&sub(&da, &cb)));
            x2 = mul(&aa, &bb);
            z2 = mul(&e, &add(&aa, &mul(&A24, &e)));
        }
        assert_eq!(x2[0] & 0xffff, 0xb27e, "x2[0]");
        assert_eq!(x2[1] & 0xffff, 0x88eb, "x2[1]");
        assert_eq!(x2[2] & 0xffff, 0xa407, "x2[2]");
        assert_eq!(z2[0] & 0xffff, 0x3ef4, "z2[0]");
        assert_eq!(z2[1] & 0xffff, 0xef17, "z2[1]");
        assert_eq!(z2[2] & 0xffff, 0x52a6, "z2[2]");
        assert_eq!(x3[0] & 0xffff, 0xa070, "x3[0]");
        assert_eq!(x3[1] & 0xffff, 0x43b8, "x3[1]");
        assert_eq!(x3[2] & 0xffff, 0x481b, "x3[2]");
        assert_eq!(z3[0] & 0xffff, 0x43f2, "z3[0]");
        assert_eq!(z3[1] & 0xffff, 0xa76a, "z3[1]");
        assert_eq!(z3[2] & 0xffff, 0xa2a6, "z3[2]");
    }
}
