"""PIV private-key injection (CHANGE REFERENCE DATA ADMIN over SCP03).

OpenFIPS201 accepts externally generated key material with ``00 24 <P1=mechanism>
<P2=key reference>`` carrying exactly ONE key-element TLV per command, so an import
is a short sequence of admin commands (one fresh SCP03 session each on JCOP 4.5).
The target key object must already exist with the same (slot, mechanism) pair and
the IMPORTABLE attribute; RSA objects additionally fix CRT vs plain form at
creation. A key only becomes usable once its parts are loaded, and re-loading an
initialised key requires a CLEAR first — every plan therefore starts with CLEAR,
which makes re-imports idempotent.

Element tags and exact-length rules (mirrors the applet's PIVKeyECC/PIVKeyRSA/
PIVKeySYM): CLEAR ``9F`` (empty); ECC public point ``86`` (X9.62 uncompressed,
65/97 bytes) and private scalar ``87`` (big-endian right-aligned, 32/48 bytes);
RSA modulus ``81`` (k bytes), public exponent ``82`` (exactly 3 bytes), private
exponent ``83`` (k bytes, plain form only), CRT components
``90``/``91``/``92``/``93``/``94`` (P/Q/dP/dQ/qInv, each k/2 bytes); symmetric
(AES) key value ``80`` (exactly the key length: 16/24/32 bytes) — the admin key
(9B) is the only symmetric object this applet exposes.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.transport.apdu import APDU
from cryptnox_id_cli.transport.errors import CryptnoxError
from cryptnox_id_cli.util import tlv

INS_CHANGE_REFERENCE_DATA = 0x24
INS_GENERAL_AUTHENTICATE = 0x87

ELEMENT_CLEAR = 0x9F
ELEMENT_ECC_POINT = 0x86
ELEMENT_ECC_SECRET = 0x87
ELEMENT_RSA_N = 0x81
ELEMENT_RSA_E = 0x82
ELEMENT_RSA_D = 0x83
ELEMENT_RSA_P = 0x90
ELEMENT_RSA_Q = 0x91
ELEMENT_RSA_DP = 0x92
ELEMENT_RSA_DQ = 0x93
ELEMENT_RSA_PQ = 0x94
ELEMENT_SYM_KEY = 0x80  # PIVKeySYM's sole element: the raw secret key value

# Largest TLV body sent as a single (SCP03-wrapped) short APDU; larger bodies go
# through ISO command chaining. Matches PivAdmin.send_chained's plaintext budget.
SINGLE_APDU_MAX = 200

# Mechanism -> (curve, scalar/point sizes) for ECC, modulus size for RSA.
_EC_BY_MECH: dict[int, type[ec.EllipticCurve]] = {0x11: ec.SECP256R1, 0x14: ec.SECP384R1}
_EC_SCALAR_LEN = {0x11: 32, 0x14: 48}
_RSA_MODULUS_LEN = {0x07: 256, 0x05: 384, 0x16: 512}

# AES mechanism -> raw key length in bytes (this applet's admin key, 9B, is AES-only).
_AES_KEY_LEN = {0x08: 16, 0x0A: 24, 0x0C: 32}

# Host-side slot policy (SP 800-78 per-key-reference algorithm table): PKI slots
# and the retired key history accept the four asymmetric mechanisms; 9B is
# AES-only and 04 is secure-messaging-only. The deployed pristine v2.0.0-fips
# applet does NOT enforce this on-card (the 800-73-5 branch adds it as gap
# G2/G4) - the CLI refuses host-side either way.
_ASYM_SLOTS = frozenset(
    {
        c.KEYREF_PIV_AUTH,
        c.KEYREF_DIGITAL_SIGNATURE,
        c.KEYREF_KEY_MANAGEMENT,
        c.KEYREF_CARD_AUTH,
        *range(c.KEYREF_RETIRED_FIRST, c.KEYREF_RETIRED_LAST + 1),
    }
)

# DigestInfo prefixes for EMSA-PKCS1-v1_5 (RFC 8017 §9.2 notes).
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300D060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300D060960864801650304020205000430"),
}


class KeyImportError(CryptnoxError):
    """Key material unsuitable for this applet (algorithm, slot, encoding)."""

    code = "key_import"


@dataclass(frozen=True)
class KeyElement:
    """One CHANGE REFERENCE DATA ADMIN element: a single tagged key component."""

    tag: int
    value: bytes
    label: str
    secret: bool

    def body(self) -> bytes:
        return tlv.build(self.tag, self.value)


def load_private_key(raw: bytes, password: bytes | None):
    """Load a PEM or DER private key (PKCS#8 or traditional encoding)."""
    loader = (
        serialization.load_pem_private_key
        if raw.lstrip().startswith(b"-----")
        else serialization.load_der_private_key
    )
    return loader(raw, password=password)


def load_pkcs12(raw: bytes, password: bytes | None):
    """Parse a PKCS#12 container -> (private key, leaf certificate DER, extra
    certificate DERs). Both a key and its certificate must be present — that is
    the point of the .p12 device-setup flow."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    key, cert, extras = pkcs12.load_key_and_certificates(raw, password)
    if key is None or cert is None:
        raise KeyImportError("the PKCS#12 file must contain both a private key and its certificate")
    der = cert.public_bytes(serialization.Encoding.DER)
    extra_ders = [c_.public_bytes(serialization.Encoding.DER) for c_ in (extras or [])]
    return key, der, extra_ders


def mechanism_for_key(key) -> int:
    """Map a private key to this applet's mechanism id, or refuse it."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        for mech, curve in _EC_BY_MECH.items():
            if isinstance(key.curve, curve):
                return mech
        raise KeyImportError(
            f"EC curve {key.curve.name} not supported; this applet takes "
            "SECP256R1 (ECCP256) or SECP384R1 (ECCP384)."
        )
    if isinstance(key, rsa.RSAPrivateKey):
        for mech, k in _RSA_MODULUS_LEN.items():
            if key.key_size == k * 8:
                return mech
        raise KeyImportError(
            f"RSA-{key.key_size} not supported; this applet takes RSA-2048, RSA-3072 or RSA-4096."
        )
    raise KeyImportError(
        f"unsupported key type {type(key).__name__}; this applet takes "
        "ECC P-256/P-384 and RSA-2048/3072/4096."
    )


def validate_slot_mechanism(ref: int, mechanism: int) -> None:
    """Refuse slots that can never hold an asymmetric key on this applet."""
    if ref == c.KEYREF_ADMIN:
        raise KeyImportError("slot 9B is the admin key (AES only); it cannot hold a PKI key.")
    if ref == c.KEYREF_SECURE_MESSAGING:
        raise KeyImportError("slot 04 is reserved for PIV secure messaging.")
    if ref not in _ASYM_SLOTS:
        raise KeyImportError(
            f"slot {ref:02X} is not a PIV asymmetric key slot "
            "(use 9A/9C/9D/9E or a retired slot 82-95)."
        )
    if mechanism not in (*_EC_BY_MECH, *_RSA_MODULUS_LEN):
        raise KeyImportError(f"mechanism {mechanism:#04x} is not an asymmetric mechanism.")


def aes_key_len(mechanism: int) -> int | None:
    """Raw key length in bytes for an AES mechanism id, or ``None`` if not AES."""
    return _AES_KEY_LEN.get(mechanism)


def sym_key_plan(mechanism: int, key_value: bytes) -> list[KeyElement]:
    """CLEAR, then the raw AES key value — the two commands PIVKeySYM accepts.

    PIVKeySYM has exactly one element (``80``, the raw secret) and refuses it
    outright (SW 6985) once the key is initialised, so — like the asymmetric
    plans — this always starts with CLEAR to make re-running idempotent.
    """
    expected = aes_key_len(mechanism)
    if expected is None:
        raise KeyImportError(f"mechanism {mechanism:#04x} is not a supported AES mechanism.")
    if len(key_value) != expected:
        raise KeyImportError(
            f"AES key value must be exactly {expected} bytes for this mechanism, "
            f"got {len(key_value)}."
        )
    return [
        KeyElement(ELEMENT_CLEAR, b"", "CLEAR (9F)", False),
        KeyElement(ELEMENT_SYM_KEY, key_value, "key value (80)", True),
    ]


def encode_exponent(e: int) -> bytes:
    """The applet takes the RSA public exponent as exactly 3 bytes."""
    if e <= 0 or e >= 1 << 24:
        raise KeyImportError(f"RSA public exponent {e} does not fit the applet's 3-byte field.")
    return e.to_bytes(3, "big")


def element_plan(key, *, rsa_crt: bool = True) -> list[KeyElement]:
    """The ordered element sequence for a key: CLEAR, then public, then private.

    The key object only flips to initialised when its last component lands, so
    every intermediate element is accepted on a freshly cleared object.
    """
    mechanism = mechanism_for_key(key)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        n = _EC_SCALAR_LEN[mechanism]
        point = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        scalar = key.private_numbers().private_value.to_bytes(n, "big")
        return [
            KeyElement(ELEMENT_CLEAR, b"", "CLEAR (9F)", False),
            KeyElement(ELEMENT_ECC_POINT, point, "public point (86)", False),
            KeyElement(ELEMENT_ECC_SECRET, scalar, "private scalar (87)", True),
        ]
    k = _RSA_MODULUS_LEN[mechanism]
    pub = key.public_key().public_numbers()
    priv = key.private_numbers()
    plan = [
        KeyElement(ELEMENT_CLEAR, b"", "CLEAR (9F)", False),
        KeyElement(ELEMENT_RSA_N, pub.n.to_bytes(k, "big"), "modulus N (81)", False),
        KeyElement(ELEMENT_RSA_E, encode_exponent(pub.e), "exponent E (82)", False),
    ]
    if rsa_crt:
        half = k // 2
        plan += [
            KeyElement(ELEMENT_RSA_P, priv.p.to_bytes(half, "big"), "P (90)", True),
            KeyElement(ELEMENT_RSA_Q, priv.q.to_bytes(half, "big"), "Q (91)", True),
            KeyElement(ELEMENT_RSA_DP, priv.dmp1.to_bytes(half, "big"), "dP (92)", True),
            KeyElement(ELEMENT_RSA_DQ, priv.dmq1.to_bytes(half, "big"), "dQ (93)", True),
            KeyElement(ELEMENT_RSA_PQ, priv.iqmp.to_bytes(half, "big"), "qInv (94)", True),
        ]
    else:
        plan.append(KeyElement(ELEMENT_RSA_D, priv.d.to_bytes(k, "big"), "private D (83)", True))
    return plan


def import_apdu(ref: int, mechanism: int, element: KeyElement) -> APDU:
    """CHANGE REFERENCE DATA ADMIN carrying one key element (SCP03-wrapped later)."""
    return APDU(0x00, INS_CHANGE_REFERENCE_DATA, mechanism, ref, data=element.body())


def probe_apdu(ref: int, mechanism: int) -> APDU:
    """Non-destructive (slot, mechanism) probe: GENERAL AUTHENTICATE with a dummy
    1-byte challenge. 6A86 = no such key object; 6982 = exists, access (PIN) not
    met; 6983 = exists, value not initialised. Never touches PIN retry counters."""
    body = tlv.build_constructed(0x7C, tlv.build(0x82, b"") + tlv.build(0x81, b"\x00"))
    return APDU(0x00, INS_GENERAL_AUTHENTICATE, mechanism, ref, data=body, le=256)


def digest_for_mechanism(mechanism: int):
    """The hash this CLI pairs with each mechanism (SHA-256, SHA-384 for P-384)."""
    return hashes.SHA384() if mechanism == 0x14 else hashes.SHA256()


def rsa_modulus_len(mechanism: int) -> int | None:
    """Modulus length in bytes for an RSA mechanism, ``None`` otherwise."""
    return _RSA_MODULUS_LEN.get(mechanism)


def emsa_pkcs1_v15(digest: bytes, em_len: int, *, hash_name: str | None = None) -> bytes:
    """EMSA-PKCS1-v1_5 encode a message digest to ``em_len`` bytes (RFC 8017 §9.2).

    The applet's RSA GENERAL AUTHENTICATE performs a raw private-key operation over
    a full modulus-length block, so the host supplies the padded encoding. The hash
    is inferred from the digest length unless given explicitly.
    """
    if hash_name is None:
        hash_name = {32: "sha256", 48: "sha384"}.get(len(digest), "")
    prefix = _DIGEST_INFO.get(hash_name)
    if prefix is None:
        raise KeyImportError(f"no DigestInfo for a {len(digest)}-byte digest")
    t = prefix + digest
    if em_len < len(t) + 11:
        raise KeyImportError("modulus too short for EMSA-PKCS1-v1_5 encoding")
    return b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t
