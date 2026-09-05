"""Read-only PIV applet operations over a :class:`CardSession`."""

from __future__ import annotations

from dataclasses import dataclass

from cryptnox_id_cli.applets.piv import constants as c
from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import objects as obj
from cryptnox_id_cli.applets.piv.apt import APTInfo, parse_apt
from cryptnox_id_cli.transport.apdu import APDU, Response
from cryptnox_id_cli.transport.errors import AppletNotFoundError, StatusWordError
from cryptnox_id_cli.transport.pcsc import CardSession


@dataclass(frozen=True)
class PinStatus:
    ref: int
    configured: bool
    blocked: bool
    verified: bool
    retries: int | None  # remaining tries (None if unknown / not configured)

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": f"{self.ref:02X}",
            "configured": self.configured,
            "blocked": self.blocked,
            "verified": self.verified,
            "retries_remaining": self.retries,
        }


def _pin_status_from_sw(ref: int, resp: Response) -> PinStatus:
    sw = resp.sw
    if sw == 0x9000:  # already verified in this session
        return PinStatus(ref, configured=True, blocked=False, verified=True, retries=None)
    if resp.sw1 == 0x63 and (resp.sw2 & 0xF0) == 0xC0:
        tries = resp.sw2 & 0x0F
        return PinStatus(ref, configured=True, blocked=tries == 0, verified=False, retries=tries)
    if sw == 0x6983:  # blocked
        return PinStatus(ref, configured=True, blocked=True, verified=False, retries=0)
    if sw in (0x6A88, 0x6A80, 0x6A82):  # reference not configured
        return PinStatus(ref, configured=False, blocked=False, verified=False, retries=None)
    # Unknown — report not-configured-ish but keep retries None.
    return PinStatus(ref, configured=False, blocked=False, verified=False, retries=None)


@dataclass(frozen=True)
class MgmtKeyStatus:
    ref: int
    mechanism: int | None  # AES mechanism id the key object was found at, or None
    configured: bool | None  # None: exists, but access rules blocked telling (rare)

    def to_dict(self) -> dict[str, object]:
        return {
            "ref": f"{self.ref:02X}",
            "mechanism": c.ALGORITHMS.get(self.mechanism) if self.mechanism is not None else None,
            "configured": self.configured,
        }


# AES-128/192/256 - the only mechanisms the admin key (9B) can hold on this applet.
_ADMIN_KEY_MECHANISMS = (0x08, 0x0A, 0x0C)


def _mgmt_key_status_from_sw(ref: int, mechanism: int, resp: Response) -> MgmtKeyStatus | None:
    """One mechanism's GENERAL AUTHENTICATE probe result, or None ("no key object
    at this mechanism - try the next one").

    The probe body (``keyimport.probe_apdu``) shapes a CHALLENGE-with-data plus an
    empty RESPONSE, i.e. GENERAL AUTHENTICATE's "Internal Authenticate" case. For a
    ROLE_AUTHENTICATE symmetric key - what this applet always makes the admin key -
    that shape is invalid once the existence/access/initialised preconditions are
    behind it, so it lands deterministically on SW 6985. That gives a clean four-way
    read: 6A86/6A88 no object, 6983 not initialised, 6982 access rules blocked the
    check itself, 6985 initialised. Anything else is left unclassified rather than
    assumed initialised.
    """
    if resp.sw in (0x6A86, 0x6A88):  # no key object at (ref, mechanism)
        return None
    if resp.sw == 0x6983:  # exists, value not initialised
        return MgmtKeyStatus(ref, mechanism, configured=False)
    if resp.sw == 0x6982:  # exists, but access rules blocked the check itself
        return MgmtKeyStatus(ref, mechanism, configured=None)
    if resp.sw == 0x6985:  # existence + access + initialised all passed
        return MgmtKeyStatus(ref, mechanism, configured=True)
    # Key object exists (we're past the 6A86/6A88 branch) but this SW isn't one of
    # the classified outcomes - report the mechanism without guessing further.
    return MgmtKeyStatus(ref, mechanism, configured=None)


def _pad_pin(pin: bytes) -> bytes:
    """PIV PINs are 8 bytes, padded with 0xFF."""
    if len(pin) > 8:
        raise ValueError("PIN must be at most 8 bytes")
    return bytes(pin) + b"\xff" * (8 - len(pin))


class PivApplet:
    """Thin, read-only PIV client. Mutating commands arrive in later phases."""

    def __init__(self, session: CardSession) -> None:
        self.session = session
        self._apt: APTInfo | None = None

    # -- selection ---------------------------------------------------------- #
    def select(self) -> APTInfo:
        resp = self.session.transmit(
            APDU(0x00, c.INS_SELECT, 0x04, 0x00, data=c.PIV_AID, le=256), context="SELECT PIV"
        )
        # On the multi-applet card, the first case-4 ISO SELECT issued right after a
        # DESFire native-command session is rejected with 6700 ("wrong length"); the
        # identical SELECT sent as case-3 (no Le) is accepted and still returns the
        # FCI. The composite StateDetector probes DESFire first, so without this the
        # PIV applet is mis-reported as Unknown over a contactless reader. Retry once
        # without Le. See docs/troubleshooting.md.
        if resp.sw == 0x6700:
            resp = self.session.transmit(
                APDU(0x00, c.INS_SELECT, 0x04, 0x00, data=c.PIV_AID), context="SELECT PIV (no Le)"
            )
        if resp.sw == 0x6A82:
            raise AppletNotFoundError("PIV applet not found on this card.")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="SELECT PIV")
        self._apt = parse_apt(resp.data)
        return self._apt

    def try_select(self) -> APTInfo | None:
        try:
            return self.select()
        except AppletNotFoundError:
            return None

    @property
    def apt(self) -> APTInfo | None:
        return self._apt

    # -- data objects ------------------------------------------------------- #
    def get_data(self, oid: bytes) -> Response:
        return self.session.transmit(obj.get_data_apdu(oid), context="GET DATA")

    def read_object(self, oid: bytes) -> bytes | None:
        """Return the unwrapped object content, or None if absent (6A82)."""
        resp = self.get_data(oid)
        if resp.sw == 0x6A82:
            return None
        if not resp.ok:
            # Access-gated objects (e.g. PIN-protected) may return 6982 — surface as absent-ish.
            if resp.sw in (0x6982, 0x6983):
                return None
            raise StatusWordError(resp.sw1, resp.sw2, context="GET DATA")
        return obj.unwrap(oid, resp.data)

    def object_present(self, oid: bytes) -> bool:
        """True if the object holds content (or exists but is access-gated).

        Two distinct "absent" cases per SP 800-73 4.1.1 (same clause in -4 and
        -5): a container never created at pre-personalization returns 6A82,
        while a created-but-unused container returns a zero-length object
        (9000). Both count as absent for every caller's purpose (status, slots,
        validate, quickstart).
        """
        resp = self.get_data(oid)
        if resp.sw in (0x6982, 0x6983):  # exists but access-gated still counts
            return True
        if not resp.ok:
            return False
        return bool(obj.unwrap(oid, resp.data))

    # -- PIN / PUK ---------------------------------------------------------- #
    def pin_status(self, ref: int = c.REF_PIV_PIN) -> PinStatus:
        """Non-decrementing status query (VERIFY with empty body)."""
        resp = self.session.transmit(APDU(0x00, c.INS_VERIFY, 0x00, ref), context="VERIFY (status)")
        return _pin_status_from_sw(ref, resp)

    def verify_pin(self, pin: bytes, ref: int = c.REF_PIV_PIN) -> Response:
        """Verify a PIN. NOTE: a wrong PIN decrements the retry counter."""
        self.session.redactor.register(pin)
        padded = _pad_pin(pin)
        self.session.redactor.register(padded)
        return self.session.transmit(
            APDU(0x00, c.INS_VERIFY, 0x00, ref, data=padded), context="VERIFY PIN"
        )

    def change_reference(self, old: bytes, new: bytes, ref: int = c.REF_PIV_PIN) -> Response:
        """Cardholder CHANGE REFERENCE DATA (INS 24, P1=00): swap a PIN or PUK value.

        Body is the current value then the new value, each 0xFF-padded to 8 bytes.
        A wrong ``old`` decrements the ref's retry counter (same as VERIFY). No admin
        channel: the cardholder proves knowledge of the current value in-band.
        """
        for secret in (old, new):
            self.session.redactor.register(secret)
        body = _pad_pin(old) + _pad_pin(new)
        self.session.redactor.register(body)
        return self.session.transmit(
            APDU(0x00, c.INS_CHANGE_REFERENCE_DATA, 0x00, ref, data=body),
            context="CHANGE REFERENCE DATA",
        )

    def unblock_pin(self, puk: bytes, new_pin: bytes, ref: int = c.REF_PIV_PIN) -> Response:
        """RESET RETRY COUNTER (INS 2C): unblock the PIN by proving the PUK.

        Body is the PUK then the new PIN, each 0xFF-padded to 8 bytes. Resets the
        PIN retry counter to its configured maximum. A wrong PUK decrements the PUK's
        own counter; if the PUK blocks too, the PIN is unrecoverable.
        """
        for secret in (puk, new_pin):
            self.session.redactor.register(secret)
        body = _pad_pin(puk) + _pad_pin(new_pin)
        self.session.redactor.register(body)
        return self.session.transmit(
            APDU(0x00, c.INS_RESET_RETRY, 0x00, ref, data=body),
            context="RESET RETRY COUNTER",
        )

    # -- management key (9B) ------------------------------------------------- #
    def mgmt_key_status(self, ref: int = c.KEYREF_ADMIN) -> MgmtKeyStatus:
        """Non-destructive status of the admin key (GENERAL AUTHENTICATE probe,
        empty challenge - same technique ``keyimport.probe_apdu`` uses to check
        an asymmetric slot before import; never touches a retry counter, since 9B
        has none). Tries each AES mechanism this applet supports until one
        resolves to an existing key object at this reference."""
        for mechanism in _ADMIN_KEY_MECHANISMS:
            resp = self.session.transmit(
                keyimport.probe_apdu(ref, mechanism), context="GENERAL AUTHENTICATE (status)"
            )
            status = _mgmt_key_status_from_sw(ref, mechanism, resp)
            if status is not None:
                return status
        return MgmtKeyStatus(ref, mechanism=None, configured=None)
