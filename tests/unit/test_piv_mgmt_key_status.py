"""Admin key (9B) status: a non-destructive GENERAL AUTHENTICATE probe per AES
mechanism, same technique as ``keyimport.probe_apdu``'s pre-import existence
check. No retry counter is ever touched (9B has none).

The probe body shapes GENERAL AUTHENTICATE's "Internal Authenticate" case
(CHALLENGE with data, empty RESPONSE). For this applet's admin key - always a
ROLE_AUTHENTICATE symmetric key - that shape is invalid once existence/access/
initialised are behind it, so an initialised key answers 6985 deterministically
(verified against the applet source, PIV.java's generalAuthenticate/CASE 1).
"""

from __future__ import annotations

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import keyimport as ki
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.transport.pcsc import CardSession

AES128, AES192, AES256 = 0x08, 0x0A, 0x0C


class _DictConn:
    """Minimal RawConnection: maps command-APDU hex -> '<dataHex>|<swHex>'."""

    def __init__(self, exchanges: dict[str, str]) -> None:
        self._exchanges = {k.upper(): v for k, v in exchanges.items()}
        self.sent: list[str] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        spec = self._exchanges.get(key)
        if spec is None:
            return [], 0x6A, 0x82
        data_hex, sw_hex = spec.split("|")
        data = list(bytes.fromhex(data_hex)) if data_hex else []
        sw = bytes.fromhex(sw_hex)
        return data, sw[0], sw[1]

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B8580018073C821100E")

    def disconnect(self) -> None:  # pragma: no cover - nothing to release
        pass


def _probe_hex(mechanism: int) -> str:
    return ki.probe_apdu(c.KEYREF_ADMIN, mechanism).to_bytes().hex().upper()


def test_configured_on_first_mechanism_tried():
    conn = _DictConn({_probe_hex(AES128): "|6985"})  # existence+access+initialised all pass
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.ref == c.KEYREF_ADMIN
    assert status.mechanism == AES128
    assert status.configured is True
    assert conn.sent == [_probe_hex(AES128)]  # stops at the first match, no fallthrough


def test_not_configured():
    conn = _DictConn({_probe_hex(AES128): "|6983"})  # exists, value not initialised
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.mechanism == AES128
    assert status.configured is False


def test_falls_through_mechanisms_until_the_key_object_is_found():
    conn = _DictConn(
        {
            _probe_hex(AES128): "|6A86",  # no such key object at AES-128
            _probe_hex(AES192): "|6A86",  # nor AES-192
            _probe_hex(AES256): "|6985",  # this applet's admin key is AES-256, initialised
        }
    )
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.mechanism == AES256
    assert status.configured is True
    assert conn.sent == [_probe_hex(AES128), _probe_hex(AES192), _probe_hex(AES256)]


def test_no_admin_key_object_at_any_mechanism():
    conn = _DictConn({_probe_hex(m): "|6A86" for m in (AES128, AES192, AES256)})
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.mechanism is None
    assert status.configured is None


def test_access_rules_blocked_reports_unknown_not_a_guess():
    conn = _DictConn(
        {
            _probe_hex(AES128): "|6A86",
            _probe_hex(AES192): "|6A86",
            _probe_hex(AES256): "|6982",  # exists, access rules not satisfied
        }
    )
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.mechanism == AES256
    assert status.configured is None


def test_unclassified_sw_is_left_unknown_rather_than_assumed_configured():
    # A generic/unexpected SW (e.g. an unmatched command in a mock, or a status this
    # probe hasn't been mapped for) must not be silently read as "configured".
    conn = _DictConn(
        {
            _probe_hex(AES128): "|6A86",
            _probe_hex(AES192): "|6A86",
            _probe_hex(AES256): "|6A80",
        }
    )
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.mechanism == AES256
    assert status.configured is None


def test_to_dict_names_the_mechanism():
    conn = _DictConn(
        {
            _probe_hex(AES128): "|6A86",
            _probe_hex(AES192): "|6A86",
            _probe_hex(AES256): "|6985",
        }
    )
    status = PivApplet(CardSession(conn)).mgmt_key_status()
    assert status.to_dict() == {"ref": "9B", "mechanism": "AES-256", "configured": True}
