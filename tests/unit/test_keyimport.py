"""Key-injection wire grammar: element plans, exact lengths, APDUs, EMSA padding."""

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from cryptnox_id_cli.applets.piv import keyimport as ki

# A P-256 private value < 2^248: its 32-byte scalar must be left-padded with 0x00.
SMALL_P256_SCALAR = int.from_bytes(b"\x00" + b"\x11" * 31, "big")


@pytest.fixture(scope="module")
def p256_key():
    return ec.derive_private_key(SMALL_P256_SCALAR, ec.SECP256R1())


@pytest.fixture(scope="module")
def rsa2048_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ----------------------------------------------------------- mechanisms ---- #
def test_mechanism_inference(p256_key, rsa2048_key):
    assert ki.mechanism_for_key(p256_key) == 0x11
    assert ki.mechanism_for_key(ec.generate_private_key(ec.SECP384R1())) == 0x14
    assert ki.mechanism_for_key(rsa2048_key) == 0x07


def test_mechanism_rejects_unsupported():
    with pytest.raises(ki.KeyImportError):
        ki.mechanism_for_key(ec.generate_private_key(ec.SECP521R1()))
    with pytest.raises(ki.KeyImportError):
        ki.mechanism_for_key(ed25519.Ed25519PrivateKey.generate())


def test_slot_policy():
    for ref in (0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95):
        ki.validate_slot_mechanism(ref, 0x11)
    for ref in (0x9B, 0x04, 0x80, 0x7A):
        with pytest.raises(ki.KeyImportError):
            ki.validate_slot_mechanism(ref, 0x11)
    with pytest.raises(ki.KeyImportError):
        ki.validate_slot_mechanism(0x9C, 0x08)  # AES is not asymmetric


def test_encode_exponent():
    assert ki.encode_exponent(65537) == bytes.fromhex("010001")
    assert ki.encode_exponent(3) == bytes.fromhex("000003")
    with pytest.raises(ki.KeyImportError):
        ki.encode_exponent(1 << 24)


# ---------------------------------------------------------- element plans --- #
def test_ecc_p256_plan_exact(p256_key):
    plan = ki.element_plan(p256_key)
    assert [(el.tag, len(el.value)) for el in plan] == [(0x9F, 0), (0x86, 65), (0x87, 32)]
    point = plan[1].value
    assert point[0] == 0x04  # X9.62 uncompressed
    scalar = plan[2].value
    assert scalar[0] == 0x00  # right-aligned: small scalar keeps its leading zero
    assert int.from_bytes(scalar, "big") == SMALL_P256_SCALAR
    assert [el.secret for el in plan] == [False, False, True]


def test_ecc_p384_plan_lengths():
    plan = ki.element_plan(ec.generate_private_key(ec.SECP384R1()))
    assert [(el.tag, len(el.value)) for el in plan] == [(0x9F, 0), (0x86, 97), (0x87, 48)]


def test_rsa2048_crt_plan(rsa2048_key):
    plan = ki.element_plan(rsa2048_key)
    assert [el.tag for el in plan] == [0x9F, 0x81, 0x82, 0x90, 0x91, 0x92, 0x93, 0x94]
    assert [len(el.value) for el in plan] == [0, 256, 3, 128, 128, 128, 128, 128]
    assert plan[2].value == bytes.fromhex("010001")
    priv = rsa2048_key.private_numbers()
    by_tag = {el.tag: el.value for el in plan}
    assert int.from_bytes(by_tag[0x90], "big") == priv.p
    assert int.from_bytes(by_tag[0x91], "big") == priv.q
    assert int.from_bytes(by_tag[0x92], "big") == priv.dmp1
    assert int.from_bytes(by_tag[0x93], "big") == priv.dmq1
    assert int.from_bytes(by_tag[0x94], "big") == priv.iqmp
    # Public components are not secret; every private component is.
    assert [el.secret for el in plan] == [False, False, False, True, True, True, True, True]


def test_rsa2048_plain_plan(rsa2048_key):
    plan = ki.element_plan(rsa2048_key, rsa_crt=False)
    assert [(el.tag, len(el.value)) for el in plan] == [
        (0x9F, 0),
        (0x81, 256),
        (0x82, 3),
        (0x83, 256),
    ]
    assert int.from_bytes(plan[3].value, "big") == rsa2048_key.private_numbers().d


def test_chaining_threshold(rsa2048_key, p256_key):
    rsa_plan = {el.tag: el for el in ki.element_plan(rsa2048_key)}
    assert len(rsa_plan[0x81].body()) == 260  # 81 82 0100 + 256 -> chained
    assert len(rsa_plan[0x81].body()) > ki.SINGLE_APDU_MAX
    assert len(rsa_plan[0x90].body()) == 131  # 90 81 80 + 128 -> single APDU
    assert len(rsa_plan[0x90].body()) <= ki.SINGLE_APDU_MAX
    ecc_plan = ki.element_plan(p256_key)
    assert all(len(el.body()) <= ki.SINGLE_APDU_MAX for el in ecc_plan)


def test_sym_key_plan_lengths():
    assert ki.aes_key_len(0x08) == 16
    assert ki.aes_key_len(0x0A) == 24
    assert ki.aes_key_len(0x0C) == 32
    assert ki.aes_key_len(0x11) is None  # not AES

    plan = ki.sym_key_plan(0x0C, b"\x11" * 32)
    assert [(el.tag, len(el.value)) for el in plan] == [(0x9F, 0), (0x80, 32)]
    assert [el.secret for el in plan] == [False, True]


def test_sym_key_plan_rejects_wrong_length_or_mechanism():
    with pytest.raises(ki.KeyImportError):
        ki.sym_key_plan(0x0C, b"\x11" * 16)  # AES-256 wants 32 bytes
    with pytest.raises(ki.KeyImportError):
        ki.sym_key_plan(0x11, b"\x11" * 32)  # ECCP256 is not AES


# ------------------------------------------------------------------ APDUs --- #
def test_clear_apdu_golden(p256_key):
    clear = ki.element_plan(p256_key)[0]
    apdu = ki.import_apdu(0x9C, 0x11, clear)
    assert apdu.to_bytes().hex().upper() == "0024119C029F00"


def test_sym_key_apdu_golden():
    key_element = ki.sym_key_plan(0x0C, b"\x11" * 32)[1]
    apdu = ki.import_apdu(0x9B, 0x0C, key_element)
    assert apdu.to_bytes().hex().upper() == "00240C9B228020" + "11" * 32


def test_probe_apdu_golden():
    # 00 87 11 9C Lc=07 7C{82(empty) 81{00}} Le=00
    assert ki.probe_apdu(0x9C, 0x11).to_bytes().hex().upper() == "0087119C077C0582008101" + "0000"


# ------------------------------------------------------------- key loading --- #
def test_load_pem_der_pkcs8_traditional(p256_key):
    pem_pkcs8 = p256_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pem_trad = p256_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    der = p256_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    for raw in (pem_pkcs8, pem_trad, der):
        loaded = ki.load_private_key(raw, None)
        assert loaded.private_numbers().private_value == SMALL_P256_SCALAR


def test_load_encrypted_key(p256_key):
    enc = p256_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"hunter2"),
    )
    loaded = ki.load_private_key(enc, b"hunter2")
    assert loaded.private_numbers().private_value == SMALL_P256_SCALAR
    with pytest.raises(TypeError):  # encrypted, no password -> CLI resolves and retries
        ki.load_private_key(enc, None)
    with pytest.raises(ValueError):
        ki.load_private_key(enc, b"wrong")


# ----------------------------------------------------------------- PKCS#12 --- #
def _make_p12(key, password: bytes | None, with_cert: bool = True) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as h
    from cryptography.hazmat.primitives.serialization import pkcs12

    cert = None
    if with_cert:
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "p12 test")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(7)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, h.SHA256())
        )
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(b"t", key, cert, None, enc)


def test_load_pkcs12_with_and_without_password(p256_key):
    for password in (b"hunter2", None):
        key, cert_der, extras = ki.load_pkcs12(_make_p12(p256_key, password), password)
        assert key.private_numbers().private_value == SMALL_P256_SCALAR
        assert cert_der[:1] == b"\x30" and extras == []


def test_load_pkcs12_wrong_password_raises_value_error(p256_key):
    raw = _make_p12(p256_key, b"hunter2")
    with pytest.raises(ValueError):
        ki.load_pkcs12(raw, b"wrong")
    with pytest.raises(ValueError):  # missing password is indistinguishable -> CLI retries
        ki.load_pkcs12(raw, None)


def test_load_pkcs12_requires_certificate(p256_key):
    raw = _make_p12(p256_key, None, with_cert=False)
    with pytest.raises(ki.KeyImportError):
        ki.load_pkcs12(raw, None)


# --------------------------------------------------------------- EMSA pad --- #
def test_emsa_pkcs1_v15_matches_cryptography(rsa2048_key):
    import hashlib

    message = b"cryptnox import-key smoke"
    digest = hashlib.sha256(message).digest()
    em = ki.emsa_pkcs1_v15(digest, 256)
    assert len(em) == 256 and em[:2] == b"\x00\x01"
    priv = rsa2048_key.private_numbers()
    n = rsa2048_key.public_key().public_numbers().n
    raw_sig = pow(int.from_bytes(em, "big"), priv.d, n).to_bytes(256, "big")
    expected = rsa2048_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    assert raw_sig == expected


def test_emsa_rejects_unknown_digest_length():
    with pytest.raises(ki.KeyImportError):
        ki.emsa_pkcs1_v15(b"\x00" * 20, 256)  # SHA-1 not offered


# ------------------------------------------------- plain-channel chaining --- #
class _RecordingConn:
    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        self.frames.append(bytes(apdu))
        return [], 0x90, 0x00

    def get_atr(self) -> bytes:
        return b"\x3b\x00"

    def disconnect(self) -> None:
        pass


def test_transmit_chained_framing():
    from cryptnox_id_cli.transport.apdu import APDU
    from cryptnox_id_cli.transport.pcsc import CardSession

    conn = _RecordingConn()
    session = CardSession(conn)
    data = bytes(300)
    resp = session.transmit_chained(APDU(0x00, 0x87, 0x07, 0x9C, data=data, le=256), block_size=200)
    assert resp.ok
    assert len(conn.frames) == 2
    first, last = conn.frames
    # Non-final frame: chaining bit set, 200-byte block, no Le.
    assert (first[0], first[1], first[4]) == (0x10, 0x87, 200)
    assert first[5:] == data[:200]
    # Final frame: original CLA, remainder, Le appended.
    assert (last[0], last[4]) == (0x00, 100)
    assert last[5:-1] == data[200:] and last[-1] == 0x00
