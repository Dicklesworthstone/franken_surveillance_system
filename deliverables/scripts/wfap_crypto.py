#!/usr/bin/env python3
"""
wfap_crypto.py -- host-side reimplementation of the Wyze WFAP BLE session protocol.

Reversed statically from libwyze_wfap-lib.so (AArch64, symbols present).
Every constant below is tied to a symbol / instruction address; see
/tmp/wfap_crypto_NOTES.md.

Two independent cipher suites live in the library:

  method 1 (cmd 0xF0)  : toy 32-bit modular-exponentiation key agreement + XXTEA
  method 2 (cmd 0xF4)  : ephemeral P-256 ECDH -> HKDF-SHA256(info=b"enc") -> AES-128-GCM
  method 4 (cmd 0xF8..) : authenticated variant of method 2, plus a per-message
                         HKDF schedule with direction-specific info strings

The library only ever runs one of them per connection (talk+0xa4, the
"selected handshake method"); 0xF0 is the only *plaintext* command type, and
every other type is wrapped by the selected cipher.

Frame (wfap_serialize_message_send, 0x274f4):

    off 0 : (cipher_flag & 3) << 4 | seq_nibble      cipher_flag 0=clear 1=XXTEA 2=AES-GCM
    off 1 : cmdType
    off 2 : (last_fragment_index << 4) | fragment_index
    off 3 : chunk length (<= mtu-4, <= 255)
    off 4 : ciphertext chunk

Payload wrapper for AES-GCM (wfap_crypto_service_encrypt_payload, 0x216ac):

    ciphertext || tag(16) || nonce(16)          nonce = rand(12) || counter_be32

Method 4 additionally prefixes the plaintext with

    b"WF3R" | 0x01 | role_byte | 0x00 | 0x00

before encryption; the receiver checks and strips those 8 bytes
(0x226d4..0x227bc).

Per-message key (method 4, 0x24bac):

    HKDF-SHA256(salt = session_salt(16),
                ikm  = app_nonce(32 ASCII hex chars),
                info = "wfap-v3/traffic/app-to-firmware/v1"  (role 1, app -> device)
                     | "wfap-v3/traffic/firmware-to-app/v1"  (role 2, device -> app),
                L    = 16)

Session material for method 4 comes from *two* stacked ECDH runs:

    1. HKDF-SHA256(salt = local_salt XOR peer_salt,
                   ikm  = ECDH_z,
                   info = b"enc", L = 16)          -> session_salt
    2. per-message derivation above

and the app must present the account's 65-byte P-256 public key (Java
Center.user_id) plus, for the authenticated variant, a 32-byte pre-auth
secret / cloud credential.  See the notes file: the device supplies the
32-character nonce in TLV 0x0303.
"""

import base64
import hashlib
import hmac
import os
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# constants (addresses are file/vaddr offsets in libwyze_wfap-lib.so)
# --------------------------------------------------------------------------

CMD_DH_EXCHANGE = 0xF0          # WFAP_EnableEncrypt, 0x1ca34 (proto 1)
CMD_ECDH_EXCHANGE = 0xF4        # WFAP_EnableEncryptECDH_AES128GCM, 0x1cc44 (proto 2)
CMD_AUTH_REQ = 0xF8             # dispatch table 0xb075
CMD_AUTH_RSP = 0xF9             # 0x17fa4 helper builds this
CMD_GET_AUTH_PARAMS_REQ = 0xFA  # WFAP_EnableEncryptAUTH_ECDH_AES128GCM, 0x1cf84
CMD_GET_AUTH_PARAMS_RSP = 0xFB  # 0x18650
CMD_APP_AUTH_REQ = 0xFC
CMD_APP_AUTH_RSP = 0xFD         # 0x1a08c
CMD_SET_SSID = 0x82             # WpkBleHandle.TYPE_82, TLV tag 10

TAG_SSID = 0x000A               # WpkBleChangeWifiControlFragment2.dealWifiMsg
TAG_ECDH_PUBKEY = 0x00F2        # wfap_codec_decode_ecdh_pubkey_payload, 0x27478
TAG_AUTH_FLAG = 0x00FF          # 0x17fb0
TAG_APP_PUBKEY = 0x0301         # 0x17fe8 / 0x196fc
TAG_APP_SALT = 0x0302           # 0x18058
TAG_DEV_NONCE = 0x0303          # 0x191b8
TAG_DEV_ID = 0x0304             # 0x19174
TAG_DEV_PUBKEY = 0x0306
TAG_DEV_SALT = 0x0305
TAG_AUTH_MODE = 0x030E
TAG_SECRET_PRESENT = 0x030D     # 0x1cf98 (1 byte) and 0x19698

HANDSHAKE_METHODS = {0xF0: 1, 0xF4: 2, 0xF8: 4, 0xF9: 4, 0xFA: 4,
                     0xFB: 4, 0xFC: 4, 0xFD: 4, 0xFE: 4}

WF3R = b"WF3R"                  # 0x2232c: 0x4657 / 0x5233
WF3R_VERSION = 0x01

INFO_KEY_AGREEMENT = b"enc"     # 0x1df00: 0x01636e65, HKDF-Expand info
INFO_APP_TO_DEV = b"wfap-v3/traffic/app-to-firmware/v1"     # 0xb3c7
INFO_DEV_TO_APP = b"wfap-v3/traffic/firmware-to-app/v1"     # 0xb3ea

ROLE_APP = 1
ROLE_DEVICE = 2

FLAG_CLEAR = 0
FLAG_XXTEA = 1
FLAG_GCM = 2

DEFAULT_MTU = 244               # MTUAlign, 0x26ba0 (cap); chunk = mtu - 4


class WfapError(Exception):
    pass


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

DELTA = 0x9E3779B9


def _to_u32(data):
    pad = (-len(data)) % 4
    data = data + b"\x00" * pad
    return list(struct.unpack("<%dI" % (len(data) // 4), data))


def _from_u32(words):
    return struct.pack("<%dI" % len(words), *[w & 0xFFFFFFFF for w in words])


def xxtea_encrypt_block(block8, key16):
    """wfap_xxtea_encrypt, 0x283a0 -- single 2-word block, 16-byte key."""
    if len(block8) != 8:
        raise WfapError("xxtea block must be 8 bytes")
    v = _to_u32(block8)
    k = _to_u32(key16)
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    y = v[0]
    for _ in range(rounds):
        total = (total + DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            mx = (((v[(p - 1) % n] >> 5) ^ (y << 2)) +
                  ((y >> 3) ^ (v[(p - 1) % n] << 4))) & 0xFFFFFFFF
            mx ^= ((total ^ y) + (k[(p & 3) ^ e] ^ v[(p - 1) % n])) & 0xFFFFFFFF
            v[p] = (v[p] + mx) & 0xFFFFFFFF
    return _from_u32(v)


def xxtea_decrypt_block(block8, key16):
    """wfap_xxtea_decrypt, 0x2868c."""
    if len(block8) != 8:
        raise WfapError("xxtea block must be 8 bytes")
    v = _to_u32(block8)
    k = _to_u32(key16)
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & 0xFFFFFFFF
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, -1, -1):
            y = v[(p - 1) % n]
            mx = (((v[(p - 1) % n] >> 5) ^ (y << 2)) +
                  ((y >> 3) ^ (v[(p - 1) % n] << 4))) & 0xFFFFFFFF
            mx ^= ((total ^ y) + (k[(p & 3) ^ e] ^ v[(p - 1) % n])) & 0xFFFFFFFF
            v[p] = (v[p] - mx) & 0xFFFFFFFF
        total = (total - DELTA) & 0xFFFFFFFF
    return _from_u32(v)


def xxtea_key_from_u32(key_u32):
    """key schedule at 0x28a48 -> vsnprintf("%x", 16) (fmt string 0x76e6)."""
    return ("%x" % key_u32).encode()[:15].ljust(16, b"\x00")


def hkdf_sha256(ikm, salt, info, length):
    """wfap_crypto_hkdf_sha256, 0x1f310 (RFC 5869, SHA-256)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def modpow(base, exp, mod):
    """wfap_dh_context_generate_shared_secret, 0x24e78 (square-and-multiply mod 2^32-59)."""
    if mod == 0:
        return 0
    if exp == 1:
        return base % mod
    half = modpow(base, exp >> 1, mod)
    r = (half * half) % mod
    if exp & 1:
        r = (r * base) % mod
    return r


def _dh_base(peer):
    """0x24e08: base = peer + 59, unless that overflows uint32."""
    return peer + 0x3B if peer + 0x3B <= 0xFFFFFFFF else peer


def tlv(tag, value):
    """wfap_codec_tlv_write_header, 0x272a4: tag BE16 | length BE16 | value."""
    return struct.pack(">HH", tag, len(value)) + value


def parse_tlv(data):
    out = []
    off = 0
    while off + 4 <= len(data):
        tag, ln = struct.unpack_from(">HH", data, off)
        off += 4
        if off + ln > len(data):
            raise WfapError("truncated TLV")
        out.append((tag, data[off:off + ln]))
        off += ln
    if off != len(data):
        raise WfapError("trailing bytes after TLV stream")
    return out


def tlv_find(data, tag):
    for t, v in parse_tlv(data):
        if t == tag:
            return v
    return None


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------

class Session:
    """One WFAP talk.  role=ROLE_APP for a host, ROLE_DEVICE to emulate a camera."""

    def __init__(self, role=ROLE_APP, mtu=DEFAULT_MTU, rng=None):
        self.role = role
        self.mtu = mtu
        self.chunk = min(max(mtu - 4, 1), 0xFF)
        self.seq = 0
        self.flag = FLAG_CLEAR
        self.method = 0

        self._rng = rng or os.urandom
        self._priv = None
        self._local_salt = None
        self._peer_pub = None
        self._peer_salt = None

        self.gcm_key = None          # method 2 session key
        self.session_salt = None     # method 4 session salt (talk+0x119)
        self.app_nonce = None        # 32 ASCII bytes (talk+0x19b)
        self.tx_counter = 0          # talk+0x130
        self.rx_counter = 0          # talk+0x12c
        self.established = False
        self.replay = True

    # -- helpers ---------------------------------------------------------

    def _rand(self, n):
        b = self._rng(n)
        if len(b) != n:
            raise WfapError("rng returned wrong length")
        return b

    def _nonce(self, counter):
        n = bytearray(self._rand(12) + struct.pack(">I", counter & 0xFFFFFFFF))
        if not any(n):
            n[0] = 1
        return bytes(n)

    def _direction_info(self, for_rx=False):
        # 0x24ccc / 0x2263c: sender uses its own role's info; the receiver
        # derives with the *peer* role's info (talk+0x19a vs. the local role).
        app_side = (self.role == ROLE_DEVICE) if for_rx else (self.role == ROLE_APP)
        return INFO_APP_TO_DEV if app_side else INFO_DEV_TO_APP

    def _message_key(self, for_rx=False):
        if not self.session_salt or not self.app_nonce:
            raise WfapError("no session salt / app nonce")
        return hkdf_sha256(self.app_nonce, self.session_salt,
                           self._direction_info(for_rx), 16)

    # -- key agreement ---------------------------------------------------

    def new_keypair(self):
        self._priv = ec.generate_private_key(ec.SECP256R1())
        pub = self._pub_bytes()
        self._local_salt = self._rand(16)
        return pub

    def _pub_bytes(self):
        return self._priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def _ecdh(self, peer_pub):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
        return self._priv.exchange(ec.ECDH(), pub)

    # -- method 1: 0xF0 --------------------------------------------------

    def handshake_frame_proto1(self):
        """WFAP_EnableEncrypt, 0x1ca34: 4-byte LE random + 4 zero bytes."""
        self.method = 1
        if not getattr(self, "_dh_value", None):
            self._dh_value = struct.unpack("<I", self._rand(4))[0] or 1
        pub = getattr(self, "_dh_pub", None)
        if pub is None:
            pub = self._dh_pub = modpow(5, self._dh_value, 0xFFFFFFFF - 0x3A) or 1
        self.tx_counter = 0
        self.rx_counter = 0
        return CMD_DH_EXCHANGE, struct.pack("<II", pub, 0)

    def accept_proto1(self, payload):
        """wfap_dh_handle_pubkey_exchange, 0x1d1c8: peer value used as base."""
        if len(payload) != 8:
            raise WfapError("0xF0 payload must be 8 bytes")
        if not getattr(self, "_dh_value", None):
            self._dh_value = struct.unpack("<I", self._rand(4))[0] or 1
        peer = struct.unpack_from("<I", payload, 0)[0]
        key = modpow(_dh_base(peer), self._dh_value, 0xFFFFFFFF - 0x3A)
        if key == 0:                       # 0x24e44
            key = 1
        self._xxtea_key = xxtea_key_from_u32(key)
        self.method = 1
        self.established = True

    # -- method 2: 0xF4 --------------------------------------------------

    def handshake_frame_proto2(self):
        """WFAP_EnableEncryptECDH_AES128GCM, 0x1cc40: TLV 0xF2 = salt||pubkey."""
        self.method = 2
        if self._priv is None:
            self.new_keypair()
        return CMD_ECDH_EXCHANGE, tlv(TAG_ECDH_PUBKEY, self._local_salt + self._pub_bytes())

    def accept_proto2(self, payload):
        """wfap_ecdh_handle_pubkey_exchange, 0x1d290 -> wfap_ecdh_hkdf_context_*."""
        val = tlv_find(payload, TAG_ECDH_PUBKEY)
        if val is None or len(val) < 0x11:
            raise WfapError("bad 0xF2 TLV")
        peer_salt, peer_pub = val[:16], val[16:]
        if not self._priv:
            self.new_keypair()
        z = self._ecdh(peer_pub)
        salt = bytes(a ^ b for a, b in zip(self._local_salt, peer_salt))
        self.gcm_key = hkdf_sha256(z, salt, INFO_KEY_AGREEMENT, 16)
        self.method = 2
        self.established = True

    # -- method 4 handshake ---------------------------------------------

    def handshake_frames(self, secret_present=False, user_pubkey=None):
        """Frames that must be sent before anything else (WFAP_EnableEncryptAUTH, 0x1cd68).

        Returns [(cmd, payload), ...] that the host writes in order and then
        waits for the device's replies (see NOTES).
        """
        self.method = 4
        if self._priv is None:
            self.new_keypair()
        out = []
        val = bytes([1 if secret_present else 0])          # 0x30D, 0x1cf98
        body = tlv(TAG_SECRET_PRESENT, val)
        if user_pubkey:                                    # 0x301, 0x1cfb4
            if len(user_pubkey) != 0x41:
                raise WfapError("account public key must be 65 bytes")
            body += tlv(TAG_APP_PUBKEY, user_pubkey)
        out.append((CMD_GET_AUTH_PARAMS_REQ, body))
        return out

    def accept_auth_params(self, payload):
        """Handle the device's 0xFB (wfap_v3_handle_get_auth_params_rsp, 0x19090)."""
        dev_id = tlv_find(payload, TAG_DEV_ID)
        nonce = tlv_find(payload, TAG_DEV_NONCE)
        peer_salt = tlv_find(payload, TAG_DEV_SALT)
        peer_pub = tlv_find(payload, TAG_DEV_PUBKEY)
        if dev_id is None or len(dev_id) > 0x40 or b"\x00" in dev_id:
            raise WfapError("bad 0x304 device id")
        if nonce is None or len(nonce) != 32:
            raise WfapError("bad 0x303 nonce")
        if any(c not in b"0123456789abcdef" for c in nonce):   # 0x19220-0x19270
            raise WfapError("nonce must be 32 lowercase hex chars")
        if peer_salt is None or len(peer_salt) != 16:
            raise WfapError("bad 0x305 salt")
        if peer_pub is None or not peer_pub:
            raise WfapError("bad 0x306 public key")

        self.device_id = dev_id
        self.app_nonce = nonce                      # talk+0x19b
        z = self._ecdh(peer_pub)
        salt = bytes(a ^ b for a, b in zip(self._local_salt, peer_salt))
        self.session_salt = hkdf_sha256(z, salt, INFO_KEY_AGREEMENT, 16)

    def follow_up_frame(self):
        """Second 0xFA the app sends after deriving (0x19694): 0x30D=0 + 0x301=ephemeral pubkey."""
        return CMD_GET_AUTH_PARAMS_REQ, tlv(TAG_SECRET_PRESENT, b"\x00") + tlv(TAG_APP_PUBKEY, self._pub_bytes())

    # -- payload cipher --------------------------------------------------

    def encrypt_payload(self, plaintext):
        """wfap_crypto_service_encrypt_for_send, 0x21ea0."""
        if self.method == 1:
            key = self._xxtea_key
            out = b""
            for i in range(0, len(plaintext), 8):
                block = plaintext[i:i + 8]
                out += xxtea_encrypt_block(block.ljust(8, b"\x00"), key)
            return out

        self.tx_counter = (self.tx_counter + 1) & 0xFFFFFFFF      # 0x21808
        if self.tx_counter == 0xFFFFFFFF:
            raise WfapError("tx counter exhausted")
        counter = self.tx_counter
        if self.method == 4:
            key = self._message_key()                            # 0x221c0
            body = WF3R + bytes([WF3R_VERSION, self.role, 0, 0]) + plaintext
        else:
            if self.gcm_key is None:
                raise WfapError("no session key")
            key = self.gcm_key                                   # 0x223d8
            body = plaintext
        nonce = self._nonce(counter)
        blob = AESGCM(key).encrypt(nonce, body, None)
        return blob + nonce

    def decrypt_payload(self, blob):
        """wfap_crypto_service_decrypt_after_receive, 0x22430."""
        if self.method == 1:
            if len(blob) % 8:
                raise WfapError("xxtea payload not block aligned")
            return b"".join(xxtea_decrypt_block(blob[i:i + 8], self._xxtea_key)
                            for i in range(0, len(blob), 8))

        if len(blob) < 0x20:
            raise WfapError("cipher payload too short")
        nonce, tag = blob[-16:], blob[-32:-16]
        counter = struct.unpack(">I", nonce[-4:])[0]             # 0x21cc0
        if self.replay and counter != 0 and counter <= self.rx_counter:
            raise WfapError("replay: counter %d <= %d" % (counter, self.rx_counter))

        if self.method == 4:
            key = self._message_key(for_rx=True)
        else:
            key = self.gcm_key
        if key is None:
            raise WfapError("no session key")
        body = AESGCM(key).decrypt(nonce, blob[:-32] + tag, None)

        if self.method == 4:
            if len(body) < 8 or body[:4] != WF3R or body[4] != WF3R_VERSION:
                raise WfapError("bad WF3R header")
            expected_role = ROLE_APP if self.role == ROLE_DEVICE else ROLE_DEVICE
            if body[5] != expected_role or body[6] != 0 or body[7] != 0:
                raise WfapError("bad WF3R header fields")
            body = body[8:]
        self.rx_counter = counter
        return body

    # -- framing ---------------------------------------------------------

    def frame(self, cmd, plaintext=b"", encrypt=None):
        """Serialize one message into MTU-sized BLE writes."""
        if encrypt is None:
            encrypt = self.method != 0 and self.established
        if encrypt and cmd != CMD_DH_EXCHANGE:
            flag = FLAG_XXTEA if self.method == 1 else FLAG_GCM
            body = self.encrypt_payload(plaintext)
        else:
            flag = FLAG_CLEAR
            body = plaintext

        nchunks = max(1, (len(body) + self.chunk - 1) // self.chunk)
        if nchunks > 16:
            raise WfapError("too many fragments (%d)" % nchunks)
        frames = []
        for idx in range(nchunks):
            chunk = body[idx * self.chunk:(idx + 1) * self.chunk]
            head = bytes([(flag & 3) << 4 | (self.seq & 0x0F),
                          cmd,
                          ((nchunks - 1) << 4) | idx,
                          len(chunk)])
            frames.append(head + chunk)
        self.seq = (self.seq + 1) & 0x0F
        return frames

    @staticmethod
    def parse_frames(frames):
        """Reassemble a full message from raw BLE notifications."""
        if not frames:
            raise WfapError("no frames")
        first = frames[0]
        if len(first) < 4:
            raise WfapError("short header")
        flag = (first[0] >> 4) & 3
        cmd = first[1]
        total = first[2] >> 4
        body = b""
        for i, f in enumerate(frames):
            if len(f) < 4:
                raise WfapError("short header")
            if (f[0] & 0x0F) != (first[0] & 0x0F) or f[1] != cmd:
                raise WfapError("sequence/cmd mismatch")
            idx = f[2] & 0x0F
            if idx != i or (f[2] >> 4) != total:
                raise WfapError("fragment mismatch")
            ln = f[3]
            if len(f) != 4 + ln:
                raise WfapError("length mismatch")
            body += f[4:]
        return flag, cmd, body


# --------------------------------------------------------------------------
# module-level convenience API (default session)
# --------------------------------------------------------------------------

_default = None


def session():
    global _default
    if _default is None:
        _default = Session()
    return _default


def handshake_frames(proto=4, **kw):
    """Outgoing (cmd, payload) pairs for the selected handshake method."""
    s = session()
    if proto == 1:
        return [s.handshake_frame_proto1()]
    if proto == 2:
        return [s.handshake_frame_proto2()]
    if proto == 4:
        return s.handshake_frames(**kw)
    raise WfapError("unsupported handshake protocol %r" % (proto,))


def encrypt(payload, cmd=CMD_SET_SSID):
    """Encrypt `payload` and return the raw BLE frame list."""
    return session().frame(cmd, payload)


def decrypt(frames):
    """Decrypt a raw BLE frame list, returning (cmd, plaintext)."""
    s = session()
    flag, cmd, body = Session.parse_frames(frames)
    if flag == FLAG_CLEAR:
        return cmd, body
    return cmd, s.decrypt_payload(body)


def ssid_payload(ssid, password=""):
    """TLV tag 10: "s=<b64>&p=<b64>" (createTlvValue0x82)."""
    val = "s=" + base64.b64encode(ssid.encode()).decode()
    if password:
        val += "&p=" + base64.b64encode(password.encode()).decode()
    return tlv(TAG_SSID, val.encode())


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def _selftest():
    ok = 0

    def check(name, cond):
        nonlocal ok
        if not cond:
            raise AssertionError("FAIL " + name)
        ok += 1
        print("ok %d - %s" % (ok, name))

    # --- XXTEA / modpow ------------------------------------------------
    key = xxtea_key_from_u32(0xDEADBEEF)
    check("xxtea key schedule", key == b"deadbeef" + b"\x00" * 8)
    blk = bytes(range(8))
    check("xxtea round trip", xxtea_decrypt_block(xxtea_encrypt_block(blk, key), key) == blk)
    check("modpow 3^5 mod (2^32-59)",
          modpow(3, 5, 0xFFFFFFFF - 0x3A) == pow(3, 5, 0xFFFFFFFF - 0x3A))

    # --- HKDF vs RFC 5869 test case 1 ----------------------------------
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    out = hkdf_sha256(ikm, salt, info, 42)
    check("hkdf rfc5869 #1",
          out.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                       "34007208d5b887185865")

    # --- TLV ------------------------------------------------------------
    check("tlv encode", tlv(0x0A, b"ab") == b"\x00\x0a\x00\x02ab")
    check("tlv parse", parse_tlv(b"\x00\x0a\x00\x02ab") == [(0x0A, b"ab")])

    # --- method 2 round trip, both directions ---------------------------
    a = Session(role=ROLE_APP)
    d = Session(role=ROLE_DEVICE)
    cmd, p = a.handshake_frame_proto2()
    check("proto2 cmd", cmd == 0xF4)
    check("proto2 payload tag 0xF2", p[0:2] == b"\x00\xf2" and p[2:4] == b"\x00\x51")
    d.accept_proto2(p)
    cmd, p2 = d.handshake_frame_proto2()
    a.accept_proto2(p2)
    check("proto2 shared key", a.gcm_key == d.gcm_key and len(a.gcm_key) == 16)

    plain = ssid_payload("MyNet", "hunter2")
    frames = a.frame(CMD_SET_SSID, plain)
    check("proto2 no WF3R header", b"WF3R" not in frames[0])
    flag, c, body = Session.parse_frames(frames)
    check("proto2 flag=2", flag == FLAG_GCM and c == CMD_SET_SSID)
    got = d.decrypt_payload(body)
    check("proto2 decrypt", got == plain)
    check("proto2 plaintext", tlv_find(got, TAG_SSID) ==
          b"s=" + base64.b64encode(b"MyNet") + b"&p=" + base64.b64encode(b"hunter2"))

    # reply direction uses the same key but its own counter
    r_frame = d.frame(0x83, tlv(2, b"\x00"))
    _, rc, rbody = Session.parse_frames(r_frame)
    check("proto2 reply", a.decrypt_payload(rbody) == tlv(2, b"\x00"))

    # replay
    check("replay rejected", _raises(lambda: d.decrypt_payload(body)))

    # tamper
    bad = bytearray(rbody)
    bad[0] ^= 0xFF
    d.rx_counter = 0
    check("tamper rejected", _raises(lambda: d.decrypt_payload(bytes(bad))))

    # --- method 4 schedule ---------------------------------------------
    app = Session(role=ROLE_APP)
    dev = Session(role=ROLE_DEVICE)
    secret = 0x11223344
    dev._xxtea_key = None
    dev.method = 4
    app.method = 4
    salt = bytes(range(16))
    nonce = b"0123456789abcdef0123456789abcdef"
    for s in (app, dev):
        s.session_salt = salt
        s.app_nonce = nonce
        s.established = True
    k_app = app._message_key()
    k_dev = dev._message_key()
    check("method4 direction keys differ", k_app != k_dev)
    check("method4 app key vector",
          k_app.hex() == hkdf_sha256(nonce, salt, INFO_APP_TO_DEV, 16).hex())

    f = app.frame(CMD_SET_SSID, plain)
    _, _, blob = Session.parse_frames(f)
    check("method4 header present in plaintext", b"WF3R" in AESGCM(k_app).decrypt(
        blob[-16:], blob[:-32] + blob[-32:-16], None))
    check("method4 device decrypt", dev.decrypt_payload(blob) == plain)
    check("method4 next counter", app.tx_counter == 1 and dev.rx_counter == 1)

    # --- fragmentation --------------------------------------------------
    big = Session(role=ROLE_APP)
    big.method = 2
    big.established = True
    big.gcm_key = b"\x00" * 16
    body = bytes(range(256)) * 3
    fl = big.frame(0x82, body)
    check("fragmented >1", len(fl) > 1)
    flag2, c2, joined = Session.parse_frames(fl)
    check("fragment reassembly", big.decrypt_payload(joined) == body)
    check("frag header shape", fl[0][2] == ((len(fl) - 1) << 4) | 0 and
          fl[-1][2] >> 4 == fl[-1][2] & 0x0F)

    # --- method 1 -------------------------------------------------------
    x = Session(role=ROLE_APP)
    y = Session(role=ROLE_DEVICE)
    cmd, p = x.handshake_frame_proto1()
    check("proto1 cmd", cmd == 0xF0 and len(p) == 8)
    check("proto1 public == 5^r", struct.unpack_from("<I", p)[0] ==
          modpow(5, x._dh_value, 0xFFFFFFFF - 0x3A))
    peer_for_y = struct.unpack_from("<I", p)[0]
    y.accept_proto1(p)
    check("proto1 device key formula",
          y._xxtea_key == xxtea_key_from_u32(
              modpow(_dh_base(peer_for_y), y._dh_value, 0xFFFFFFFF - 0x3A) or 1))
    cmd, p = y.handshake_frame_proto1()
    x.accept_proto1(p)
    # the library's agreement is asymmetric (see NOTES); share the key
    y._xxtea_key = x._xxtea_key
    fl = x.frame(0x82, b"hello world!")
    _, _, ct = Session.parse_frames(fl)
    check("proto1 padded to 8", len(ct) % 8 == 0)
    check("proto1 round trip", y.decrypt_payload(ct).startswith(b"hello world!"))

    print("\n%d checks passed" % ok)
    return 0


def _raises(fn):
    try:
        fn()
    except Exception:
        return True
    return False


def _demo(proto):
    s = session()
    for cmd, payload in handshake_frames(proto):
        for f in s.frame(cmd, payload, encrypt=False):
            print("tx %02x %s" % (cmd, f.hex()))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    if "--demo" in sys.argv:
        _demo(int(sys.argv[sys.argv.index("--demo") + 1]))
        sys.exit(0)
    print(__doc__)
