"""The ``piv`` command — PIV management and personalization.

Read-only inspection (info/status/slots/certs/objects), PIN operations, the SCP03
admin channel, and the ``perso`` namespace (PIN/PUK values, on-card key generation,
CSR / certificates, data objects, validate/smoke-test). Factory pre-personalization
lives under ``factory piv preperso``.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console

from cryptnox_id_cli import CLI_NAME, trust
from cryptnox_id_cli.applets.piv import constants as pivc
from cryptnox_id_cli.applets.piv import keyimport
from cryptnox_id_cli.applets.piv import perso as perso_mod
from cryptnox_id_cli.applets.piv import preperso as preperso_mod
from cryptnox_id_cli.applets.piv import profiles as prof_mod
from cryptnox_id_cli.applets.piv.admin import PivAdmin, scp_label
from cryptnox_id_cli.applets.piv.objects import (
    PIV_OBJECTS,
    extract_certificate,
    object_by_name,
    wrap_certificate,
)
from cryptnox_id_cli.applets.piv.piv import PivApplet
from cryptnox_id_cli.applets.piv.slots import PIV_SLOTS
from cryptnox_id_cli.cli.context import AppContext
from cryptnox_id_cli.crypto import csr as csr_mod
from cryptnox_id_cli.crypto import piv_objects, x509util
from cryptnox_id_cli.crypto.attestation import verify_attestation_chain
from cryptnox_id_cli.output.render import state_style
from cryptnox_id_cli.secrets.resolver import resolve_scp03_keys, resolve_secret
from cryptnox_id_cli.state import StateDetector
from cryptnox_id_cli.transport.errors import CryptnoxError, StatusWordError, describe_sw
from cryptnox_id_cli.util import tlv
from cryptnox_id_cli.util.hexutil import from_hex, to_hex

# Slots that carry a certificate container, and the object that holds it.
SLOT_CERT_OBJECT = {
    0x9A: "auth-cert",
    0x9C: "sign-cert",
    0x9D: "keymgmt-cert",
    0x9E: "card-auth-cert",
}


@click.group("piv")
def command() -> None:
    """Manage the PIV applet (status, PIN, certs, objects, personalization)."""


def _select(session: object) -> PivApplet:
    piv = PivApplet(session)  # type: ignore[arg-type]
    piv.select()
    return piv


# --------------------------------------------------------------------------- #
@command.command("info")
@click.pass_obj
def info(app: AppContext) -> None:
    """Show the PIV AID, label, URL and the algorithms/slots this applet exposes."""
    with app.open_session() as session:
        piv = _select(session)
        apt = piv.apt
    if apt is None:  # unreachable: _select() always parses the APT
        raise RuntimeError("card returned no PIV Application Property Template")
    supported = [pivc.ALGORITHMS[a] for a in sorted(pivc.SUPPORTED_ALGORITHMS)]
    note = "Values are read from the card; no FIPS/NIST/SP800-73 validation is claimed."
    payload = {
        "aid": apt.aid_hex,
        "label": apt.label,
        "url": apt.url,
        "supported_algorithms": supported,
        "slots": [{"ref": s.ref_hex, "name": s.name} for s in PIV_SLOTS],
        "note": note,
    }

    def human(c: Console) -> None:
        c.print("[bold]PIV applet[/bold]")
        c.print(f"  AID:   {apt.aid_hex}")
        c.print(f"  Label: {apt.label}")
        c.print(f"  URL:   {apt.url}")
        c.print(f"\n  Supported algorithms: {', '.join(supported)}")
        c.print(f"  Key slots: {', '.join(s.ref_hex for s in PIV_SLOTS)}")
        c.print(f"\n[dim]{note}[/dim]")

    app.out.result(payload, human)


@command.command("status")
@click.pass_obj
def status(app: AppContext) -> None:
    """Show PIV lifecycle state, PIN/PUK/management-key status and objects present."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
        mgmt_key = None
        if st.piv_apt is not None:
            with contextlib.suppress(CryptnoxError):
                mgmt_key = _select(session).mgmt_key_status()
    payload: dict[str, object] = {
        "state": st.piv.label,
        "reader": app.resolved_reader,
        "apt": st.piv_apt.to_dict() if st.piv_apt else None,
        "pin": st.piv_pin.to_dict() if st.piv_pin else None,
        "puk": st.piv_puk.to_dict() if st.piv_puk else None,
        "mgmt_key": mgmt_key.to_dict() if mgmt_key else None,
        "objects_present": st.piv_objects,
        "notes": st.notes,
    }

    def human(c: Console) -> None:
        c.print(f"[bold]PIV state:[/bold] {state_style(st.piv.label)}")
        if st.piv_pin:
            extra = f", {st.piv_pin.retries} tries left" if st.piv_pin.retries is not None else ""
            blocked = " [red](blocked)[/red]" if st.piv_pin.blocked else ""
            c.print(f"  PIN (80): {'set' if st.piv_pin.configured else 'not set'}{extra}{blocked}")
        if st.piv_puk:
            extra = f", {st.piv_puk.retries} tries left" if st.piv_puk.retries is not None else ""
            blocked = " [red](blocked)[/red]" if st.piv_puk.blocked else ""
            c.print(f"  PUK (81): {'set' if st.piv_puk.configured else 'not set'}{extra}{blocked}")
        if mgmt_key:
            mech_name = pivc.ALGORITHMS.get(mgmt_key.mechanism, "unknown mechanism")
            if mgmt_key.configured is True:
                c.print(f"  Management key (9B): [green]set[/green] ({mech_name})")
            elif mgmt_key.configured is False:
                c.print(f"  Management key (9B): [yellow]not set[/yellow] ({mech_name})")
            else:
                c.print("  Management key (9B): [dim]unknown[/dim] (could not tell from this probe)")
        elif st.piv_apt is not None:
            c.print("  Management key (9B): [dim]no admin key object found on this card[/dim]")
        if st.piv_objects:
            table = app.out.table("Object", "Present")
            for name, present in st.piv_objects.items():
                table.add_row(name, "[green]yes[/green]" if present else "[dim]no[/dim]")
            c.print(table)
        for note in st.notes:
            c.print(f"[yellow]*[/yellow] {note}")

    app.out.result(payload, human)


@command.command("discover")
@click.pass_obj
def discover(app: AppContext) -> None:
    """Read the PIV Discovery Object (PIN usage policy), if present."""
    with app.open_session() as session:
        piv = _select(session)
        data = piv.read_object(bytes([0x7E]))
    if data is None:
        app.out.result(
            {"present": False},
            lambda c: c.print("Discovery object: [yellow]not present[/yellow]"),
        )
        return
    nodes = tlv.parse(data)
    disc = tlv.find(nodes, 0x7E)
    scope = disc.children if (disc and disc.children) else nodes
    aid_node = tlv.find(scope, 0x4F)
    policy_node = tlv.find(scope, 0x5F2F)
    payload = {
        "present": True,
        "aid": to_hex(aid_node.value) if aid_node else None,
        "pin_policy": to_hex(policy_node.value) if policy_node else None,
    }

    def human(c: Console) -> None:
        c.print("Discovery object: [green]present[/green]")
        c.print(f"  AID: {payload['aid']}")
        c.print(f"  PIN usage policy: {payload['pin_policy']}")

    app.out.result(payload, human)


@command.command("slots")
@click.pass_obj
def slots(app: AppContext) -> None:
    """List PIV key slots and whether each cert-bearing slot has a certificate."""
    with app.open_session() as session:
        piv = _select(session)
        cert_present = {}
        for ref, obj_name in SLOT_CERT_OBJECT.items():
            obj = object_by_name(obj_name)
            cert_present[ref] = piv.object_present(obj.oid) if obj else False
    rows = []
    for s in PIV_SLOTS:
        has = None if s.ref not in SLOT_CERT_OBJECT else bool(cert_present.get(s.ref))
        rows.append({"ref": s.ref_hex, "name": s.name, "usage": s.usage, "certificate": has})

    def human(c: Console) -> None:
        table = app.out.table("Slot", "Name", "Usage", "Cert")
        for r in rows:
            cert = (
                "-"
                if r["certificate"] is None
                else ("[green]yes[/green]" if r["certificate"] else "[dim]no[/dim]")
            )
            table.add_row(str(r["ref"]), str(r["name"]), str(r["usage"]), cert)
        c.print(table)

    app.out.result({"slots": rows}, human)


# ------------------------------------------------------------------ certs --- #
@command.group("certs")
def certs() -> None:
    """Inspect and export PIV certificates."""


def _read_cert_der(piv: PivApplet, obj_name: str) -> bytes | None:
    obj = object_by_name(obj_name)
    if obj is None:
        return None
    val = piv.read_object(obj.oid)
    return extract_certificate(val) if val is not None else None


@certs.command("list")
@click.pass_obj
def certs_list(app: AppContext) -> None:
    """List certificate slots and summarise any certificate found."""
    with app.open_session() as session:
        piv = _select(session)
        out = []
        for ref, obj_name in SLOT_CERT_OBJECT.items():
            der = _read_cert_der(piv, obj_name)
            entry: dict[str, object] = {
                "slot": f"{ref:02X}",
                "object": obj_name,
                "present": der is not None,
            }
            if der is not None:
                try:
                    entry["certificate"] = x509util.describe_certificate(der)
                except Exception as exc:  # noqa: BLE001 - report parse failure, don't crash
                    entry["error"] = f"parse failed: {exc}"
            out.append(entry)

    def human(c: Console) -> None:
        table = app.out.table("Slot", "Object", "Present", "Subject", "Expires")
        for e in out:
            raw = e.get("certificate")
            cert = raw if isinstance(raw, dict) else {}
            table.add_row(
                str(e["slot"]),
                str(e["object"]),
                "[green]yes[/green]" if e["present"] else "[dim]no[/dim]",
                str(cert.get("subject", "-")),
                str(cert.get("not_after", "-")),
            )
        c.print(table)

    app.out.result({"certificates": out}, human)


@certs.command("export")
@click.option("--slot", required=True, help="Slot hex, e.g. 9A.")
@click.option("--out", "out_", required=True, type=click.Path(dir_okay=False))
@click.option("--der", is_flag=True, help="Write DER instead of PEM.")
@click.pass_obj
def certs_export(app: AppContext, slot: str, out_: str, der: bool) -> None:
    """Export a slot's certificate (PEM by default). Certificates are not secret."""
    ref = int(slot, 16)
    obj_name = SLOT_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    with app.open_session() as session:
        cert_der = _read_cert_der(_select(session), obj_name)
    if cert_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No certificate in slot {slot}.[/yellow]"),
        )
        return
    data = cert_der if der else x509util.to_pem(cert_der)
    Path(out_).write_bytes(data)
    fmt = "DER" if der else "PEM"
    app.out.result(
        {"present": True, "slot": slot, "out": out_, "format": fmt},
        lambda c: c.print(f"[green]Wrote {fmt} certificate to {out_}[/green]"),
    )


@certs.command("inspect")
@click.option("--slot", required=True, help="Slot hex, e.g. 9A.")
@click.pass_obj
def certs_inspect(app: AppContext, slot: str) -> None:
    """Show certificate details for a slot."""
    ref = int(slot, 16)
    obj_name = SLOT_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    with app.open_session() as session:
        cert_der = _read_cert_der(_select(session), obj_name)
    if cert_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No certificate in slot {slot}.[/yellow]"),
        )
        return
    desc = x509util.describe_certificate(cert_der)

    def human(c: Console) -> None:
        for key, value in desc.items():
            c.print(f"  {key}: {value}")

    app.out.result({"present": True, "slot": slot, "certificate": desc}, human)


# ------------------------------------------------------------ attestation --- #
# The factory/issuance-time PIV key-attestation leaf lives in the retired-slot-95
# certificate container (5FC120). Only slot 9C is attested in v1.
ATTESTATION_CERT_OBJECT = {0x9C: "attestation-cert"}


def _csr_spki(path: str) -> bytes:
    """SubjectPublicKeyInfo (DER) of the public key in a PEM or DER CSR."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = Path(path).read_bytes()
    try:
        req = x509.load_pem_x509_csr(raw)
    except ValueError:
        req = x509.load_der_x509_csr(raw)
    return req.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@command.command("export-attestation")
@click.option("--slot", default="9C", show_default=True, help="Attested slot (9C in v1).")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write the chain to FILE.")
@click.option("--der", is_flag=True, help="Write the leaf as DER (no chain) instead of PEM.")
@click.pass_obj
def export_attestation(app: AppContext, slot: str, out_: str | None, der: bool) -> None:
    """Export the on-card key-attestation leaf (PEM chain incl. bundled intermediates)."""
    ref = int(slot, 16)
    obj_name = ATTESTATION_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(
            f"slot {slot} carries no attestation certificate", param_hint="--slot"
        )
    with app.open_session() as session:
        leaf_der = _read_cert_der(_select(session), obj_name)
    if leaf_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No attestation certificate in slot {slot}.[/yellow]"),
        )
        return
    inter_ders: list[bytes] = []
    if der:
        data = leaf_der
    else:
        # Export the leaf's own chain, not the whole trust store: the bundled pool holds
        # sibling CAs that have nothing to do with this leaf. path_ders is [leaf, ...issuers].
        roots, pool = trust.load_anchors()
        path = verify_attestation_chain(leaf_der, pool, roots).path_ders
        # path is [leaf, ...issuers, anchor]; drop the leaf and the pinned root — a relying
        # party already holds the root, and shipping it invites trusting it from the file.
        inter_ders = [d for d in path[1:] if d not in set(roots)]
        data = b"".join([x509util.to_pem(leaf_der), *(x509util.to_pem(d) for d in inter_ders)])
    fmt = "DER" if der else "PEM"
    if out_:
        Path(out_).write_bytes(data)
    payload = {
        "present": True,
        "slot": slot,
        "format": fmt,
        "out": out_,
        "intermediates_bundled": len(inter_ders),
    }

    def human(c: Console) -> None:
        if out_:
            extra = f" (+{len(inter_ders)} intermediate)" if inter_ders else ""
            c.print(f"[green]Wrote {fmt} attestation to {out_}{extra}[/green]")
        else:
            c.print(to_hex(data) if der else data.decode())

    app.out.result(payload, human)


@command.command("verify-attestation")
@click.option("--slot", default="9C", show_default=True, help="Attested slot (9C in v1).")
@click.option(
    "--csr",
    "csr_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Also check the attested key matches this CSR's public key.",
)
@click.pass_obj
def verify_attestation(app: AppContext, slot: str, csr_file: str | None) -> None:
    """Validate the on-card attestation chain against the pinned Cryptnox root."""
    ref = int(slot, 16)
    obj_name = ATTESTATION_CERT_OBJECT.get(ref)
    if obj_name is None:
        raise click.BadParameter(
            f"slot {slot} carries no attestation certificate", param_hint="--slot"
        )
    csr_spki = _csr_spki(csr_file) if csr_file else None
    roots, inter_ders = trust.load_anchors()
    with app.open_session() as session:
        leaf_der = _read_cert_der(_select(session), obj_name)
    if leaf_der is None:
        app.out.result(
            {"present": False, "slot": slot},
            lambda c: c.print(f"[yellow]No attestation certificate in slot {slot}.[/yellow]"),
        )
        return
    result = verify_attestation_chain(leaf_der, inter_ders, roots, csr_spki=csr_spki)
    leaf_desc = x509util.describe_certificate(leaf_der)
    payload = {"present": True, "slot": slot, "leaf": leaf_desc, **result.to_dict()}

    def human(c: Console) -> None:
        verdict = "[green]verified[/green]" if result.verified else "[red]NOT verified[/red]"
        c.print(f"Attestation (slot {slot}): {verdict}")
        c.print(f"  subject: {leaf_desc['subject']}")
        if result.chain:
            c.print(f"  chain:   {' -> '.join(result.chain)}")
        if result.csr_match is not None:
            mark = "[green]yes[/green]" if result.csr_match else "[red]no[/red]"
            c.print(f"  CSR key match: {mark}")
        for reason in result.reasons:
            c.print(f"  [yellow]-[/yellow] {reason}")

    app.out.result(payload, human)


# ---------------------------------------------------------------- objects --- #
@command.group("objects")
def objects() -> None:
    """List and read PIV data objects."""


@objects.command("list")
@click.pass_obj
def objects_list(app: AppContext) -> None:
    """List PIV data objects and whether each is present."""
    with app.open_session() as session:
        piv = _select(session)
        rows = [
            {
                "name": o.name,
                "oid": o.oid_hex,
                "present": piv.object_present(o.oid),
                "mandatory": o.mandatory,
                "pin_protected": o.pin_protected,
            }
            for o in PIV_OBJECTS
        ]

    def human(c: Console) -> None:
        table = app.out.table("Object", "OID", "Present", "Mandatory", "PIN")
        for r in rows:
            table.add_row(
                str(r["name"]),
                str(r["oid"]),
                "[green]yes[/green]" if r["present"] else "[dim]no[/dim]",
                "yes" if r["mandatory"] else "-",
                "yes" if r["pin_protected"] else "-",
            )
        c.print(table)

    app.out.result({"objects": rows}, human)


@contextlib.contextmanager
def _transcript_hold(session):
    """Withhold the session's APDU transcript lines, then emit them re-masked.

    Lets the caller register a response payload with ``session.redactor`` after
    receiving it but before the lines reach the --apdu-log file or the --verbose
    trace, so PIN-gated cardholder data keeps the transcript's "secrets redacted"
    promise. (A first-class hook on CardSession would be the durable home for
    this; until then the emit seam is intercepted here.)
    """
    held: list[str] = []
    original = session._emit
    session._emit = held.append
    try:
        yield
    finally:
        session._emit = original
        for line in held:
            original(session.redactor.mask(line))


@objects.command("read")
@click.option("--object", "object_name", required=True, help="Object name, e.g. chuid.")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write raw bytes to FILE.")
@click.pass_obj
def objects_read(app: AppContext, object_name: str, out_: str | None) -> None:
    """Read a PIV data object (prints hex, or writes raw bytes with --out).

    PIN-gated objects (printed, fingerprints, facial) need the PIN verified
    first — without it, GET DATA returns 6982 and the object reads back as
    absent even when populated. Only prompts/consumes a PIN for those objects.
    """
    obj = object_by_name(object_name)
    if obj is None:
        names = ", ".join(o.name for o in PIV_OBJECTS)
        raise click.BadParameter(f"unknown object {object_name!r}. Known: {names}")
    with app.open_session() as session:
        piv = _select(session)
        if obj.pin_protected:
            secret = resolve_secret(
                redactor=app.redactor,
                env_var="CRYPTNOX_PIV_PIN",
                prompt_label="PIV PIN",
            )
            resp = piv.verify_pin(secret)
            _check_pin_verify(resp)
            # PIN-gated content (printed, fingerprints, facial) is cardholder data
            # the applet itself protects; it must not land in the "secrets redacted"
            # APDU transcript. Hold the GET DATA lines, register the payload, then
            # release them masked. Stdout still shows the content - the user asked
            # for it; the promise being kept is about --apdu-log/--verbose.
            with _transcript_hold(session):
                val = piv.read_object(obj.oid)
                shown = None if val is None else val.hex().upper()
                session.redactor.register(val)
        else:
            val = piv.read_object(obj.oid)
            shown = None if val is None else app.redactor.mask(val.hex().upper())
    if val is None:
        app.out.result(
            {"name": obj.name, "present": False},
            lambda c: c.print(f"Object {obj.name}: [yellow]not present[/yellow]"),
        )
        return
    if out_:
        Path(out_).write_bytes(val)
    payload = {
        "name": obj.name,
        "present": True,
        "length": len(val),
        "hex": None if out_ else shown,
        "out": out_,
    }

    def human(c: Console) -> None:
        if out_:
            c.print(f"[green]Wrote {len(val)} bytes to {out_}[/green]")
        else:
            c.print(f"{obj.name} ({len(val)} bytes): {payload['hex']}")

    app.out.result(payload, human)


# -------------------------------------------------------------------- pin --- #
@command.group("pin")
def pin() -> None:
    """PIN/PUK status and verification."""


@pin.command("status")
@click.pass_obj
def pin_status(app: AppContext) -> None:
    """Show PIN and PUK status (non-decrementing query)."""
    with app.open_session() as session:
        piv = _select(session)
        pin_st = piv.pin_status(pivc.REF_PIV_PIN)
        puk_st = piv.pin_status(pivc.REF_PUK)

    def human(c: Console) -> None:
        for label, st in (("PIN (80)", pin_st), ("PUK (81)", puk_st)):
            if not st.configured:
                c.print(f"  {label}: [dim]not configured[/dim]")
            elif st.blocked:
                c.print(f"  {label}: [red]blocked[/red]")
            else:
                tries = f"{st.retries} tries left" if st.retries is not None else "configured"
                c.print(f"  {label}: [green]{tries}[/green]")

    app.out.result({"pin": pin_st.to_dict(), "puk": puk_st.to_dict()}, human)


@pin.command("verify")
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_verify(app: AppContext, pin_value: str | None) -> None:
    """Verify the PIV PIN. A wrong PIN consumes one retry."""
    app.out.warn("a wrong PIN decrements the retry counter.")
    secret = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_PIN",
        prompt_label="PIV PIN",
        provided=pin_value,
    )
    with app.open_session() as session:
        resp = _select(session).verify_pin(secret)
    info = describe_sw(resp.sw1, resp.sw2)
    payload: dict[str, object] = {"verified": resp.ok, "sw": info.sw_hex(), "message": info.message}
    if not resp.ok and info.retries is not None:
        payload["retries_remaining"] = info.retries

    def human(c: Console) -> None:
        if resp.ok:
            c.print("[green]PIN verified.[/green]")
        else:
            c.print(f"[red]PIN not verified:[/red] {info.message} (SW={info.sw_hex()})")

    app.out.result(payload, human)


def _change_secret_result(
    app: AppContext, label: str, resp, *, blocked_hint: str | None = None
) -> None:
    info = describe_sw(resp.sw1, resp.sw2)
    payload: dict[str, object] = {"changed": resp.ok, "sw": info.sw_hex(), "message": info.message}
    blocked = not resp.ok and (resp.sw == 0x6983 or info.retries == 0)
    if not resp.ok and info.retries is not None:
        payload["retries_remaining"] = info.retries
    if blocked:
        payload["blocked"] = True
        if blocked_hint:
            payload["recovery"] = blocked_hint

    def human(c: Console) -> None:
        if resp.ok:
            c.print(f"[green]{label} changed.[/green]")
        else:
            c.print(f"[red]{label} not changed:[/red] {info.message} (SW={info.sw_hex()})")
            if blocked and blocked_hint:
                c.print(f"  [red]{blocked_hint}[/red]")

    app.out.result(payload, human)


@pin.command("change")
@click.option("--old-pin", help="(discouraged) current PIN on the CLI; prefer prompt/env.")
@click.option("--new-pin", help="(discouraged) new PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_change(app: AppContext, old_pin: str | None, new_pin: str | None) -> None:
    """Change the PIV PIN (cardholder). A wrong current PIN consumes one retry."""
    app.out.warn("a wrong current PIN decrements the retry counter.")
    old = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_PIN",
        prompt_label="Current PIV PIN",
        provided=old_pin,
    )
    new = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_NEW_PIN",
        prompt_label="New PIV PIN",
        provided=new_pin,
    )
    with app.open_session() as session:
        resp = _select(session).change_reference(old, new, pivc.REF_PIV_PIN)
    _change_secret_result(
        app,
        "PIN",
        resp,
        blocked_hint="PIN is now blocked. Recover it with `piv pin unblock` (needs the PUK).",
    )


@pin.command("unblock")
@click.option("--puk", "puk_value", help="(discouraged) PUK on the CLI; prefer prompt/env.")
@click.option("--new-pin", help="(discouraged) new PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def pin_unblock(app: AppContext, puk_value: str | None, new_pin: str | None) -> None:
    """Unblock a blocked PIV PIN via the PUK (RESET RETRY COUNTER, INS 2C)."""
    app.out.warn("a wrong PUK decrements the PUK counter; a blocked PUK is unrecoverable.")
    puk = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_PUK",
        prompt_label="PIV PUK",
        provided=puk_value,
    )
    new = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_NEW_PIN",
        prompt_label="New PIV PIN",
        provided=new_pin,
    )
    with app.open_session() as session:
        resp = _select(session).unblock_pin(puk, new, pivc.REF_PIV_PIN)
    _change_secret_result(
        app,
        "PIN",
        resp,
        blocked_hint="the PUK just used is now blocked - there is no recovery path.",
    )


@command.group("puk")
def puk() -> None:
    """PUK operations (the unblocking secret for the PIN)."""


@puk.command("change")
@click.option("--old-puk", help="(discouraged) current PUK on the CLI; prefer prompt/env.")
@click.option("--new-puk", help="(discouraged) new PUK on the CLI; prefer prompt/env.")
@click.pass_obj
def puk_change(app: AppContext, old_puk: str | None, new_puk: str | None) -> None:
    """Change the PIV PUK (cardholder). A wrong current PUK consumes one retry."""
    app.out.warn("a wrong current PUK decrements the retry counter.")
    old = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_PUK",
        prompt_label="Current PIV PUK",
        provided=old_puk,
    )
    new = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_NEW_PUK",
        prompt_label="New PIV PUK",
        provided=new_puk,
    )
    with app.open_session() as session:
        resp = _select(session).change_reference(old, new, pivc.REF_PUK)
    _change_secret_result(
        app, "PUK", resp, blocked_hint="PUK is now blocked - there is no recovery path."
    )


# ------------------------------------------------------------------ admin --- #
@command.group("admin")
def admin() -> None:
    """PIV administrative operations over SCP03 (vendor: OpenFIPS201)."""


@admin.command("status")
@click.option("--key-version", default=0, type=int, help="SCP03 key version (default 0).")
@click.pass_obj
def admin_status(app: AppContext, key_version: int) -> None:
    """Probe the SCP03 admin channel (read-only INITIALIZE UPDATE, no auth)."""
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        info = adm.initialize_update_probe(key_version=key_version)

    def human(c: Console) -> None:
        scp_id = info.get("scp_id")
        label = scp_label(scp_id)
        c.print(f"PIV admin secure channel ({label}):")
        if isinstance(scp_id, int):
            c.print(f"  SCP ID:      {scp_id:#04x} ({label})")
        c.print(f"  key version: {info.get('key_version')}")
        i_param = info.get("scp_i")
        if isinstance(i_param, int):
            c.print(f"  i-param:     {i_param:#04x}")
        c.print("  INITIALIZE UPDATE supported - run `piv admin authenticate` to open it.")

    app.out.result(info, human)


@admin.command("authenticate")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option("--key-version", default=0, type=int, help="SCP03 key version (default 0).")
@click.pass_obj
def admin_authenticate(app: AppContext, default_keys: bool, key_version: int) -> None:
    """Open the PIV admin channel (mutual auth, auto-detecting SCP02/SCP03) and self-test."""
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    security_level = 0x03  # C-MAC + C-ENC
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        adm.open(keys, key_version=key_version, security_level=security_level)
        scp_ver_label = scp_label(adm.scp_version)
        resp = adm.self_test_read()
    self_ok = resp.ok or resp.sw == 0x6A82
    payload: dict[str, object] = {
        "authenticated": True,
        "scp_version": scp_ver_label,
        "security_level": f"{security_level:#04x}",
        "self_test_sw": resp.sw_hex(),
        "self_test_ok": self_ok,
    }

    def human(c: Console) -> None:
        c.print(
            f"[green]{scp_ver_label} secure channel established[/green] (mutual authentication OK)."
        )
        c.print(f"  Security level: {security_level:#04x} (C-MAC + C-ENC)")
        verdict = "OK" if self_ok else "unexpected"
        c.print(f"  Admin round-trip (wrapped GET DATA): SW={resp.sw_hex()} -> {verdict}")

    app.out.result(payload, human)


# ------------------------------------------------------ legacy redirect --- #
@command.command(
    "preperso",
    hidden=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.pass_obj
def preperso_redirect(app: AppContext, args: tuple[str, ...]) -> None:
    """(moved) Pre-personalization is MANUFACTURING-ONLY; see `factory piv preperso`."""
    raise CryptnoxError(
        "Pre-personalization is a MANUFACTURING-ONLY operation and now lives under "
        f"`{CLI_NAME} factory piv preperso`. Re-run it there."
    )


# ------------------------------------------------------------------ perso --- #
@command.group("perso")
def perso() -> None:
    """PIV personalization: set PIN/PUK values, generate keys, write objects."""


@perso.command("generate-key")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    help="ECCP256/ECCP384/RSA2048/RSA3072/RSA4096.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--out", "out_", type=click.Path(dir_okay=False), help="Write public-key PEM to FILE."
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="If the slot has no key object for this (slot, algorithm) pair, create one "
    "first (PUT DATA ADMIN, non-finalized cards only) - same dev/eval fallback as "
    "`import-key --create-key-object`.",
)
@click.pass_obj
def perso_generate_key(
    app: AppContext,
    slot: str,
    algorithm: str,
    default_keys: bool,
    out_: str | None,
    create_key_object: bool,
) -> None:
    """Generate a key pair ON-CARD; the private key never leaves the card.

    Replaces any key already in the slot IRREVERSIBLY. When the slot's certificate
    container is occupied this asks for confirmation first (``--yes`` skips); a key
    without a certificate cannot be detected and is replaced without a prompt.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = int(slot, 16)
    alg = algorithm.upper()
    mech = perso_mod.ALGORITHMS.get(alg)
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        # Same rule quickstart applies: a certificate marks the slot as in use, so a
        # certified key is never replaced silently - the old private key is destroyed
        # irreversibly and every copy of that certificate goes orphan.
        cert_name = SLOT_CERT_OBJECT.get(ref)
        if cert_name is not None and _read_cert_der(_select(session), cert_name) is not None:
            app.out.warn(
                f"slot {slot} already holds a certificate; generating a new key DESTROYS "
                "the current private key irreversibly and orphans that certificate."
            )
            if not app.yes and not click.confirm(
                f"Replace the certified key in slot {slot}?", default=False
            ):
                raise click.Abort()
        adm = PivAdmin(session)
        if create_key_object:
            _select(session)
            probe = session.transmit(keyimport.probe_apdu(ref, mech), context=f"probe {slot}")
            if probe.sw == 0x6A86:
                _create_key_object(app, adm, keys, ref, mech, False, slot)
        public_key = _generate_key_on_card(adm, keys, ref, mech, label=slot)
    pem = perso_mod.public_key_pem(public_key)
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(der).hexdigest().upper()
    if out_:
        Path(out_).write_bytes(pem)
    payload = {
        "slot": slot,
        "algorithm": alg,
        "public_key_sha256": fingerprint,
        "out": out_,
        "public_key_pem": None if out_ else pem.decode(),
    }

    def human(c: Console) -> None:
        c.print(f"[green]Generated {alg} key in slot {slot}[/green] (on-card).")
        c.print(f"  Public key SHA-256: {fingerprint}")
        if out_:
            c.print(f"  Public key PEM -> {out_}")
        else:
            c.print(pem.decode().rstrip())

    app.out.result(payload, human)


# ------------------------------------------------- session-level helpers --- #
# Each opens a FRESH SCP03 session (JCOP 4.5 allows one application APDU per
# applet-directed secure-channel session) and performs one perso primitive.
def _set_verifier(adm: PivAdmin, keys, ref: int, padded: bytes, *, label: str):
    adm.select()
    adm.open(keys)
    return adm.send(perso_mod.set_verifier_value_apdu(ref, padded), context=f"SET {label}")


def _generate_key_on_card(adm: PivAdmin, keys, ref: int, mech: int, *, label: str):
    adm.select()
    adm.open(keys)
    resp = adm.send(perso_mod.generate_keypair_apdu(ref, mech), context=f"GENERATE {label}")
    if resp.sw == 0x6F00 and keyimport.rsa_modulus_len(mech):
        raise CryptnoxError(f"GENERATE key {label} failed (SW=6F00): {_IMPORT_SW_HINTS[0x6F00]}.")
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context=f"GENERATE key {label}")
    return perso_mod.parse_public_key(mech, resp.data)


def _import_cert_der(adm: PivAdmin, keys, ref: int, cert_der: bytes, *, label: str):
    obj = object_by_name(SLOT_CERT_OBJECT[ref])
    if obj is None:  # unreachable: SLOT_CERT_OBJECT values are built-in object names
        raise RuntimeError(f"unknown PIV object for slot {ref:02X}")
    adm.select()
    adm.open(keys)
    return adm.send_chained(
        perso_mod.INS_PUT_DATA,
        0x3F,
        0xFF,
        perso_mod.put_data_body(obj.oid, wrap_certificate(cert_der)),
        context=f"PUT DATA cert {label}",
    )


def _write_standard(adm: PivAdmin, keys, names: tuple[str, ...]) -> list[dict[str, object]]:
    generators: dict[str, Callable[[], bytes]] = {
        "chuid": piv_objects.generate_chuid,
        "ccc": piv_objects.generate_ccc,
    }
    results: list[dict[str, object]] = []
    for name in names:
        obj = object_by_name(name)
        if obj is None:  # unreachable: callers pass built-in object names
            raise RuntimeError(f"unknown PIV object {name!r}")
        adm.select()
        adm.open(keys)
        resp = adm.send(
            perso_mod.put_data_apdu(obj.oid, generators[name]()), context=f"PUT DATA {name}"
        )
        results.append(
            {"object": name, "ok": resp.ok, "sw": describe_sw(resp.sw1, resp.sw2).sw_hex()}
        )
    return results


def _check_pin_verify(resp) -> None:
    """Raise on a failed PIN verification, naming the PUK-unblock recovery path
    once the PIN is actually blocked rather than a generic status word.

    Only ``63C0`` (retry counter exhausted) proves a blocked PIN. ``6983`` is
    reported for a blocked verifier *and* when the PIN cannot be used for the
    operation at hand - e.g. a slot the profile never populated - so it must not
    assert a blocked PIN outright; saying so sent people to `pin unblock` for a
    card whose PIN was fine.
    """
    if resp.ok:
        return
    info = describe_sw(resp.sw1, resp.sw2)
    if info.retries == 0:
        raise CryptnoxError(
            f"PIN is blocked - 0 tries remaining (SW={info.sw_hex()}). Recover it with "
            "`piv pin unblock` (needs the PUK)."
        )
    if resp.sw == 0x6983:
        raise CryptnoxError(
            f"PIN verification refused (SW={info.sw_hex()}): either the PIN is blocked, or "
            "this PIN cannot be used for this operation (for example a key slot the card's "
            "profile never populated). Check `piv pin status` first - it does not consume a "
            "try - and if it reports 0 tries remaining, recover with `piv pin unblock` "
            "(needs the PUK)."
        )
    raise StatusWordError(resp.sw1, resp.sw2, context="VERIFY PIN")


def _sign_with_session(session, ref: int, mech: int, pin: bytes, build):
    """Verify the PIN and run ``build(signer)`` against an already-open session."""
    piv = _select(session)
    verified = piv.verify_pin(pin)
    _check_pin_verify(verified)

    def signer(digest: bytes) -> bytes:
        k = keyimport.rsa_modulus_len(mech)
        challenge = keyimport.emsa_pkcs1_v15(digest, k) if k else digest
        apdu = perso_mod.general_authenticate_sign_apdu(ref, mech, challenge)
        if len(apdu.data) > 0xFF:  # oversized body: plain-channel ISO chaining
            resp = session.transmit_chained(apdu, context="GENERAL AUTHENTICATE (sign)")
        else:
            resp = session.transmit(apdu, context="GENERAL AUTHENTICATE (sign)")
        if not resp.ok:
            raise StatusWordError(resp.sw1, resp.sw2, context="GENERAL AUTHENTICATE (sign)")
        return perso_mod.parse_sign_response(resp.data)

    return build(signer)


# Friendly diagnoses for CHANGE REFERENCE DATA ADMIN rejections during key import.
_IMPORT_SW_HINTS = {
    0x6A88: (
        "no key object with this (slot, mechanism) pair exists - the cryptnox-default "
        "profile creates ECC-P256 objects only; re-run pre-perso with a profile that "
        "defines it, or pass --create-key-object on a non-finalized card"
    ),
    0x6982: "the key object is not IMPORTABLE (or the admin channel is not accepted)",
    0x6A80: (
        "the card rejected this element - for RSA this usually means the key object's "
        "CRT attribute does not match; try the other --rsa-form"
    ),
    0x6700: "element too long for the transport (chaining should have engaged - report this)",
    0x6F00: (
        "the chip refuses this key size - its pre-issuance maximum-RSA configuration "
        "(DF2B) caps RSA below it, and that is factory-set before the card is secured"
    ),
}


def _load_private_key_file(app: AppContext, raw: bytes, password: str | None):
    """Load a private key, resolving a decryption password only if it is needed."""
    try:
        return keyimport.load_private_key(raw, password.encode() if password else None)
    except TypeError:
        # Encrypted key, no password given: env var or masked prompt.
        secret = resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_KEY_PASSWORD",
            prompt_label="Key file password",
            provided=None,
        )
        try:
            return keyimport.load_private_key(raw, secret)
        except ValueError as exc:
            raise CryptnoxError(f"could not decrypt the private key: {exc}") from exc
    except ValueError as exc:
        raise CryptnoxError(f"could not load the private key: {exc}") from exc


def _warn_key_file_permissions(app: AppContext, path: str) -> None:
    import os
    import stat

    if os.name == "nt":  # POSIX mode bits are meaningless on Windows
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        app.out.warn(f"{path} is group/world-readable; consider chmod 600.")


def _create_key_object(
    app: AppContext, adm: PivAdmin, keys, ref: int, mech: int, rsa_crt: bool, slot: str
) -> None:
    """Dev/eval fallback: create the missing (slot, mechanism) key object via PUT
    DATA ADMIN, copying modes/role from the builtin profile's slot template."""
    profile = prof_mod.builtin("cryptnox-default")
    template = next((k for k in profile.keys if k.ref == ref), None)
    if template is not None:
        contact, contactless, role = template.contact, template.contactless, template.role
    else:
        contact, contactless = preperso_mod.MODE_PIN, preperso_mod.MODE_NEVER
        if ref == pivc.KEYREF_DIGITAL_SIGNATURE:
            role = preperso_mod.ROLE_SIGN
        elif ref == pivc.KEYREF_KEY_MANAGEMENT or ref >= pivc.KEYREF_RETIRED_FIRST:
            role = preperso_mod.ROLE_KEY_ESTABLISH
        else:
            role = preperso_mod.ROLE_AUTHENTICATE
    attrs = preperso_mod.ATTR_IMPORTABLE
    if keyimport.rsa_modulus_len(mech) and rsa_crt:
        attrs |= preperso_mod.ATTR_RSA_CRT
    app.out.warn(
        "creating the key object (PUT DATA ADMIN) - a structural change normally "
        "done at pre-personalization."
    )
    op = preperso_mod.create_key(ref, contact, contactless, mech, role, attrs)
    adm.select()
    adm.open(keys)
    resp = adm.send(
        preperso_mod.put_data_admin_apdu(preperso_mod.build_bulk([op])),
        context=f"CREATE KEY {slot}",
    )
    if resp.sw == 0x6985:
        raise CryptnoxError(
            "the applet is finalized (SECURED): key objects can no longer be created. "
            "Import into an existing object, or reinstall the applet."
        )
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context=f"CREATE KEY {slot}")


def _execute_key_import(
    app: AppContext,
    session,
    adm: PivAdmin,
    keys,
    ref: int,
    mech: int,
    plan: list[keyimport.KeyElement],
    slot: str,
    *,
    create_key_object: bool,
    rsa_crt: bool,
) -> list[dict[str, object]]:
    """Probe for the (slot, mechanism) key object — optionally creating it — then
    send the element sequence, one fresh SCP03 session per element (JCOP 4.5)."""
    _select(session)
    probe = session.transmit(keyimport.probe_apdu(ref, mech), context=f"probe {slot}")
    if probe.sw == 0x6A86:
        if not create_key_object:
            alg_name = pivc.ALGORITHMS[mech]
            raise CryptnoxError(
                f"slot {slot} has no {alg_name} key object: {_IMPORT_SW_HINTS[0x6A88]}."
            )
        _create_key_object(app, adm, keys, ref, mech, rsa_crt, slot)

    results: list[dict[str, object]] = []
    for index, el in enumerate(plan, 1):
        adm.select()
        adm.open(keys)
        body = el.body()
        label = f"IMPORT {slot} [{el.label}] [{index}/{len(plan)}]"
        if len(body) > keyimport.SINGLE_APDU_MAX:
            resp = adm.send_chained(
                keyimport.INS_CHANGE_REFERENCE_DATA, mech, ref, body, context=label
            )
        else:
            resp = adm.send(keyimport.import_apdu(ref, mech, el), context=label)
        results.append({"element": el.label, "sw": resp.sw_hex(), "ok": resp.ok})
        if not resp.ok:
            hint = _IMPORT_SW_HINTS.get(resp.sw)
            app.out.warn(
                "the key is left uninitialised - that is safe; re-run the import "
                "(it starts with a CLEAR) or generate a key instead."
            )
            ctx = f"IMPORT {slot} [{el.label}]" + (f" - {hint}" if hint else "")
            raise StatusWordError(resp.sw1, resp.sw2, context=ctx)
    return results


def _post_import_smoke(
    app: AppContext, session, ref: int, mech: int, key, pin_value: str | None
) -> dict[str, object]:
    """Prove the imported key: verify the PIN, sign on-card, verify host-side
    against the key. A SIGN-incapable slot role reports a note, not a failure."""
    import hashlib
    import os

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

    modulus_len = keyimport.rsa_modulus_len(mech)
    pin_secret = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_PIN",
        prompt_label="PIV PIN",
        provided=pin_value,
    )
    piv = _select(session)
    verified = piv.verify_pin(pin_secret)
    _check_pin_verify(verified)
    message = os.urandom(32)
    hash_alg = keyimport.digest_for_mechanism(mech)
    digest = hashlib.new(hash_alg.name, message).digest()
    challenge = keyimport.emsa_pkcs1_v15(digest, modulus_len) if modulus_len else digest
    apdu = perso_mod.general_authenticate_sign_apdu(ref, mech, challenge)
    if len(apdu.data) > 0xFF:  # oversized body: plain-channel ISO chaining
        resp = session.transmit_chained(apdu, context="GENERAL AUTHENTICATE (smoke)")
    else:
        resp = session.transmit(apdu, context="GENERAL AUTHENTICATE (smoke)")
    if resp.sw == 0x6985:
        return {"signed": False, "note": "import OK; this slot's role cannot sign on this applet"}
    if not resp.ok:
        raise StatusWordError(resp.sw1, resp.sw2, context="GENERAL AUTHENTICATE (smoke)")
    signature = perso_mod.parse_sign_response(resp.data)
    public_key = key.public_key()
    try:
        if modulus_len:
            public_key.verify(signature, message, rsa_padding.PKCS1v15(), hash_alg)
        else:
            public_key.verify(signature, message, ec_mod.ECDSA(hash_alg))
    except InvalidSignature as exc:
        raise CryptnoxError(
            "the on-card signature does not verify against the imported key - wrong "
            "key material landed?"
        ) from exc
    return {"signed": True, "verified": True}


@perso.command("import-key")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9C.")
@click.option(
    "--key",
    "key_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Private key file (PEM or DER; PKCS#8 or traditional).",
)
@click.option(
    "--password",
    help="(discouraged) key-file password; prefer $CRYPTNOX_PIV_KEY_PASSWORD or the prompt.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--rsa-form",
    type=click.Choice(["crt", "plain"]),
    default="crt",
    show_default=True,
    help="RSA private-key element form; must match the key object's CRT attribute.",
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="Dev/eval: create the (slot, mechanism) key object first if it is missing "
    "(structural PUT DATA ADMIN; a finalized applet refuses this).",
)
@click.option(
    "--public-out",
    "public_out",
    type=click.Path(dir_okay=False),
    help="Write the derived public-key PEM to FILE.",
)
@click.option("--pin", "pin_value", help="(discouraged) PIN for the post-import signing check.")
@click.option("--no-smoke-test", is_flag=True, help="Skip the post-import signing check.")
@click.option("--dry-run", "dry_run", is_flag=True, help="Show the element plan; nothing is sent.")
@click.pass_obj
def perso_import_key(
    app: AppContext,
    slot: str,
    key_file: str,
    password: str | None,
    default_keys: bool,
    rsa_form: str,
    create_key_object: bool,
    public_out: str | None,
    pin_value: str | None,
    no_smoke_test: bool,
    dry_run: bool,
) -> None:
    """Import an EXTERNAL private key into a PIV slot (over SCP03).

    Use this for a key generated off-card. For an on-card RSA key, `generate-key`
    works on any slot that has a key object for that mechanism (profile-dependent:
    cryptnox-default provides ECC objects only, ms-logon adds RSA2048 on 9A).
    The key goes to the card one element per SCP03 session, starting with a CLEAR,
    so a re-run of the same import is safe.
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = int(slot, 16)
    key = _load_private_key_file(app, Path(key_file).read_bytes(), password)
    mech = keyimport.mechanism_for_key(key)
    keyimport.validate_slot_mechanism(ref, mech)
    alg_name = pivc.ALGORITHMS[mech]
    modulus_len = keyimport.rsa_modulus_len(mech)
    plan = keyimport.element_plan(key, rsa_crt=(rsa_form == "crt"))
    for el in plan:
        if el.secret:
            app.redactor.register(el.value)
    _warn_key_file_permissions(app, key_file)

    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(spki).hexdigest().upper()
    steps = [
        {
            "element": el.label,
            "bytes": len(el.body()),
            "chained": len(el.body()) > keyimport.SINGLE_APDU_MAX,
        }
        for el in plan
    ]

    if dry_run or app.dry_run:
        result = {
            "dry_run": True,
            "slot": slot,
            "algorithm": alg_name,
            "rsa_form": rsa_form if modulus_len else None,
            "elements": steps,
            "scp03_sessions": len(plan),
        }

        def human_dry(c: Console) -> None:
            c.print(f"[bold]DRY RUN[/bold] - import {alg_name} into slot {slot}:")
            for s in steps:
                via = "chained" if s["chained"] else "single APDU"
                c.print(f"    {s['element']}: {s['bytes']} bytes ({via}, own SCP03 session)")
            c.print("\n  [dim]Nothing was sent to the card.[/dim]")

        app.out.result(result, human_dry)
        return

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    smoke: dict[str, object] | None = None
    with app.open_session() as session:
        adm = PivAdmin(session)
        results = _execute_key_import(
            app,
            session,
            adm,
            keys,
            ref,
            mech,
            plan,
            slot,
            create_key_object=create_key_object,
            rsa_crt=(rsa_form == "crt"),
        )
        if not no_smoke_test:
            smoke = _post_import_smoke(app, session, ref, mech, key, pin_value)

    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if public_out:
        Path(public_out).write_bytes(pem)
    payload = {
        "slot": slot,
        "algorithm": alg_name,
        "rsa_form": rsa_form if modulus_len else None,
        "elements": results,
        "scp03_sessions": len(plan),
        "public_key_sha256": fingerprint,
        "public_out": public_out,
        "smoke_test": smoke,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Imported {alg_name} key into slot {slot}[/green] ({len(plan)} elements).")
        c.print(f"  Public key SHA-256: {fingerprint}")
        if public_out:
            c.print(f"  Public key PEM -> {public_out}")
        if smoke is None:
            c.print("  [dim]Smoke test skipped.[/dim]")
        elif smoke.get("signed"):
            c.print("  Smoke test: [green]signed on-card, verified against the key[/green].")
        else:
            c.print(f"  Smoke test: [yellow]{smoke.get('note')}[/yellow]")

    app.out.result(payload, human)


@perso.command("import-p12")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option(
    "--p12",
    "p12_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="PKCS#12 container (.p12/.pfx) holding the private key and its certificate.",
)
@click.option(
    "--password",
    help="(discouraged) container password; prefer $CRYPTNOX_PIV_P12_PASSWORD or the prompt.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--rsa-form",
    type=click.Choice(["crt", "plain"]),
    default="crt",
    show_default=True,
    help="RSA private-key element form; must match the key object's CRT attribute.",
)
@click.option(
    "--create-key-object",
    is_flag=True,
    help="Dev/eval: create the (slot, mechanism) key object first if it is missing "
    "(structural PUT DATA ADMIN; a finalized applet refuses this).",
)
@click.option("--pin", "pin_value", help="(discouraged) PIN for the post-import signing check.")
@click.option("--no-smoke-test", is_flag=True, help="Skip the post-import signing check.")
@click.option("--dry-run", "dry_run", is_flag=True, help="Show the plan; nothing is sent.")
@click.pass_obj
def perso_import_p12(
    app: AppContext,
    slot: str,
    p12_file: str,
    password: str | None,
    default_keys: bool,
    rsa_form: str,
    create_key_object: bool,
    pin_value: str | None,
    no_smoke_test: bool,
    dry_run: bool,
) -> None:
    """Import a PKCS#12 credential (private key + certificate) into a PIV slot.

    The one-command device-setup flow for credentials issued by a PKI (e.g. an
    AD CA for Windows logon / Remote Desktop): the key goes over SCP03 one
    element per session starting with a CLEAR, then the certificate lands in
    the slot's container. Extra CA certificates in the container are ignored
    (PIV containers hold the entity certificate only).
    """
    import hashlib

    from cryptography.hazmat.primitives import serialization

    ref = int(slot, 16)
    if ref not in SLOT_CERT_OBJECT:
        raise click.BadParameter(
            f"slot {slot} has no certificate container; import-p12 needs one "
            "(9A/9C/9D/9E). For a bare key use `piv perso import-key`.",
            param_hint="--slot",
        )
    raw = Path(p12_file).read_bytes()
    key, cert_der, extras = _load_p12_file(app, raw, password)
    mech = keyimport.mechanism_for_key(key)
    keyimport.validate_slot_mechanism(ref, mech)
    alg_name = pivc.ALGORITHMS[mech]
    modulus_len = keyimport.rsa_modulus_len(mech)

    # The container must actually pair: certificate public key == private key.
    from cryptography import x509

    cert_pub = x509.load_der_x509_certificate(cert_der).public_key()
    if cert_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise CryptnoxError(
            "the PKCS#12 certificate does not match its private key - refusing to "
            "import a mismatched pair."
        )

    plan = keyimport.element_plan(key, rsa_crt=(rsa_form == "crt"))
    for el in plan:
        if el.secret:
            app.redactor.register(el.value)
    _warn_key_file_permissions(app, p12_file)
    cert_desc = x509util.describe_certificate(cert_der)
    fingerprint = (
        hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        .hexdigest()
        .upper()
    )

    if dry_run or app.dry_run:
        steps = [
            {
                "element": el.label,
                "bytes": len(el.body()),
                "chained": len(el.body()) > keyimport.SINGLE_APDU_MAX,
            }
            for el in plan
        ]
        result = {
            "dry_run": True,
            "slot": slot,
            "algorithm": alg_name,
            "elements": steps,
            "certificate": cert_desc,
            "extra_certs_ignored": len(extras),
        }

        def human_dry(c: Console) -> None:
            c.print(f"[bold]DRY RUN[/bold] - import {alg_name} key + certificate into {slot}:")
            for s in steps:
                via = "chained" if s["chained"] else "single APDU"
                c.print(f"    {s['element']}: {s['bytes']} bytes ({via}, own SCP03 session)")
            c.print(f"    certificate ({cert_desc.get('subject')}): chained PUT DATA")
            if extras:
                c.print(f"    [dim]{len(extras)} chain certificate(s) ignored[/dim]")
            c.print("\n  [dim]Nothing was sent to the card.[/dim]")

        app.out.result(result, human_dry)
        return

    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    smoke: dict[str, object] | None = None
    with app.open_session() as session:
        adm = PivAdmin(session)
        results = _execute_key_import(
            app,
            session,
            adm,
            keys,
            ref,
            mech,
            plan,
            slot,
            create_key_object=create_key_object,
            rsa_crt=(rsa_form == "crt"),
        )
        cert_resp = _import_cert_der(adm, keys, ref, cert_der, label=slot)
        if not cert_resp.ok:
            raise StatusWordError(cert_resp.sw1, cert_resp.sw2, context=f"IMPORT cert {slot}")
        if not no_smoke_test:
            smoke = _post_import_smoke(app, session, ref, mech, key, pin_value)

    payload = {
        "slot": slot,
        "algorithm": alg_name,
        "rsa_form": rsa_form if modulus_len else None,
        "elements": results,
        "certificate": cert_desc,
        "extra_certs_ignored": len(extras),
        "public_key_sha256": fingerprint,
        "smoke_test": smoke,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Imported {alg_name} credential into slot {slot}[/green].")
        c.print(f"  Certificate: {cert_desc.get('subject')} (expires {cert_desc.get('not_after')})")
        if extras:
            c.print(f"  [dim]{len(extras)} chain certificate(s) ignored.[/dim]")
        if smoke is None:
            c.print("  [dim]Smoke test skipped.[/dim]")
        elif smoke.get("signed"):
            c.print("  Smoke test: [green]signed on-card, verified against the key[/green].")
        else:
            c.print(f"  Smoke test: [yellow]{smoke.get('note')}[/yellow]")

    app.out.result(payload, human)


def _load_p12_file(app: AppContext, raw: bytes, password: str | None):
    """Parse a PKCS#12 container, resolving the password only when needed.
    PKCS#12 cannot distinguish a wrong password from corrupt data, so the first
    passwordless attempt falling through to a prompt is the best we can do."""
    if password is not None:
        try:
            return keyimport.load_pkcs12(raw, password.encode())
        except ValueError as exc:
            raise CryptnoxError(f"could not open the PKCS#12 file: {exc}") from exc
    try:
        return keyimport.load_pkcs12(raw, None)
    except ValueError:
        secret = resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_P12_PASSWORD",
            prompt_label="PKCS#12 password",
            provided=None,
        )
        try:
            return keyimport.load_pkcs12(raw, secret)
        except ValueError as exc:
            raise CryptnoxError(
                f"could not open the PKCS#12 file (wrong password or corrupt data): {exc}"
            ) from exc


def _set_verifier_value(
    app: AppContext,
    ref: int,
    label: str,
    env_var: str,
    prompt_label: str,
    pin_value: str | None,
    default_keys: bool,
) -> None:
    app.out.warn(f"replaces the current {label} without needing its value (admin channel write).")
    secret = resolve_secret(
        redactor=app.redactor, env_var=env_var, prompt_label=prompt_label, provided=pin_value
    )
    padded = perso_mod.pad_pin(secret)
    app.redactor.register(padded)
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        resp = _set_verifier(PivAdmin(session), keys, ref, padded, label=label)
    info = describe_sw(resp.sw1, resp.sw2)
    app.out.result(
        {"ref": f"{ref:02X}", "set": resp.ok, "sw": info.sw_hex()},
        lambda c: c.print(
            f"[green]{label} set.[/green]"
            if resp.ok
            else f"[red]{label} not set:[/red] {info.message} (SW={info.sw_hex()})"
        ),
    )


@perso.command("set-pin")
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_set_pin(app: AppContext, pin_value: str | None, default_keys: bool) -> None:
    """Set the initial PIV PIN value (CHANGE REFERENCE DATA ADMIN over SCP03)."""
    _set_verifier_value(
        app, pivc.REF_PIV_PIN, "PIN", "CRYPTNOX_PIV_NEW_PIN", "New PIV PIN", pin_value, default_keys
    )


@perso.command("set-puk")
@click.option("--puk", "pin_value", help="(discouraged) PUK on the CLI; prefer prompt/env.")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_set_puk(app: AppContext, pin_value: str | None, default_keys: bool) -> None:
    """Set the initial PIV PUK value (CHANGE REFERENCE DATA ADMIN over SCP03)."""
    _set_verifier_value(
        app, pivc.REF_PUK, "PUK", "CRYPTNOX_PIV_NEW_PUK", "New PIV PUK", pin_value, default_keys
    )


# Friendly diagnoses for CHANGE REFERENCE DATA ADMIN rejections while setting 9B.
_MGMT_KEY_SW_HINTS = {
    0x6A88: (
        "no 9B key object at this mechanism - pass --algorithm matching whatever "
        "pre-perso gave the admin key object (cryptnox-default: AES256)"
    ),
    0x6982: "the key object is not IMPORTABLE (or the admin channel is not accepted)",
}


def _execute_sym_key_set(
    adm: PivAdmin, keys, ref: int, mech: int, plan: list[keyimport.KeyElement], label: str
) -> list[dict[str, object]]:
    """Send a symmetric-key element plan, one fresh SCP03 session per element
    (JCOP 4.5 allows one application APDU per applet-directed secure-channel
    session) — same shape as ``_execute_key_import``, minus the probe/create
    step: unlike an asymmetric slot, 9B's key object is expected to already
    exist from pre-perso, exactly like the PIN/PUK verifiers set-pin/set-puk
    assume."""
    results: list[dict[str, object]] = []
    for index, el in enumerate(plan, 1):
        adm.select()
        adm.open(keys)
        label_ctx = f"SET {label} [{el.label}] [{index}/{len(plan)}]"
        resp = adm.send(keyimport.import_apdu(ref, mech, el), context=label_ctx)
        results.append({"element": el.label, "sw": resp.sw_hex(), "ok": resp.ok})
        if not resp.ok:
            hint = _MGMT_KEY_SW_HINTS.get(resp.sw)
            ctx = f"SET {label} [{el.label}]" + (f" - {hint}" if hint else "")
            raise StatusWordError(resp.sw1, resp.sw2, context=ctx)
    return results


@perso.command("set-mgmt-key")
@click.option(
    "--algorithm",
    default="AES256",
    show_default=True,
    type=click.Choice(["AES128", "AES192", "AES256"], case_sensitive=False),
    help="Management key (9B) mechanism; must match what pre-perso gave the admin key object.",
)
@click.option(
    "--key",
    "key_value",
    help="(discouraged) management key as hex on the CLI; "
    "prefer env CRYPTNOX_PIV_MGMT_KEY or the prompt.",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_set_mgmt_key(
    app: AppContext, algorithm: str, key_value: str | None, default_keys: bool
) -> None:
    """Set the PIV management key (9B). Set it for standards-compliance/
    interoperability with tools that authenticate using 9B management key.
    """
    app.out.warn("replaces the current management key without needing its value (admin channel write).")
    mech = prof_mod.MECHANISMS[algorithm.upper()]
    expected_len = keyimport.aes_key_len(mech)
    secret = resolve_secret(
        redactor=app.redactor,
        env_var="CRYPTNOX_PIV_MGMT_KEY",
        prompt_label=f"New management key ({algorithm.upper()}, hex, {expected_len} bytes)",
        provided=key_value,
    )
    try:
        key_bytes = from_hex(secret.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise click.BadParameter(f"management key must be hex: {exc}") from exc
    app.redactor.register(key_bytes)
    plan = keyimport.sym_key_plan(mech, key_bytes)
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        adm = PivAdmin(session)
        results = _execute_sym_key_set(adm, keys, pivc.KEYREF_ADMIN, mech, plan, "management key")
    payload = {
        "ref": f"{pivc.KEYREF_ADMIN:02X}",
        "algorithm": algorithm.upper(),
        "set": True,
        "elements": results,
    }

    def human(c: Console) -> None:
        c.print(f"[green]Management key set.[/green] ({algorithm.upper()}, ref 9B)")

    app.out.result(payload, human)


def _resolve_asym_mech(algorithm: str) -> int:
    mech = perso_mod.ALGORITHMS.get(algorithm.upper())
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    return mech


def _load_spki(pubkey_file: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_public_key(Path(pubkey_file).read_bytes())
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _sign_on_card(
    app: AppContext,
    ref: int,
    mech: int,
    pin_value: str | None,
    build,
    *,
    pin_bytes: bytes | None = None,
):
    """Verify PIN, then run ``build(signer)`` where signer computes an on-card
    signature over a digest via GENERAL AUTHENTICATE.

    For RSA mechanisms the card performs a raw private-key operation over a full
    modulus-length block, so the digest is EMSA-PKCS1-v1_5 encoded here first; the
    resulting command exceeds a short APDU and goes out via ISO command chaining.
    """
    pin = (
        pin_bytes
        if pin_bytes is not None
        else resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_PIN",
            prompt_label="PIV PIN",
            provided=pin_value,
        )
    )
    with app.open_session() as session:
        return _sign_with_session(session, ref, mech, pin, build)


@perso.command("generate-csr")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--subject", required=True, help='e.g. "CN=John Doe,O=Cryptnox,C=CH"')
@click.option(
    "--public-key", "pubkey_file", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option("--out", "out_", type=click.Path(dir_okay=False))
@click.pass_obj
def perso_generate_csr(
    app: AppContext,
    slot: str,
    subject: str,
    pubkey_file: str,
    algorithm: str,
    pin_value: str | None,
    out_: str | None,
) -> None:
    """Generate a PKCS#10 CSR; the signature is computed ON-CARD by the slot key."""
    ref = int(slot, 16)
    mech = _resolve_asym_mech(algorithm)
    spki = _load_spki(pubkey_file)
    pem = _sign_on_card(
        app, ref, mech, pin_value, lambda s: csr_mod.build_csr(subject, spki, mech, s)
    )
    if out_:
        Path(out_).write_bytes(pem)
    app.out.result(
        {"slot": slot, "subject": subject, "out": out_, "csr_pem": None if out_ else pem.decode()},
        lambda c: c.print(
            f"[green]CSR written to {out_}[/green]" if out_ else pem.decode().rstrip()
        ),
    )


@perso.command("self-sign-cert")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--subject", required=True, help='e.g. "CN=Test User"')
@click.option(
    "--public-key", "pubkey_file", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--days", default=365, show_default=True, type=int)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.option("--out", "out_", type=click.Path(dir_okay=False))
@click.pass_obj
def perso_self_sign_cert(
    app: AppContext,
    slot: str,
    subject: str,
    pubkey_file: str,
    algorithm: str,
    days: int,
    pin_value: str | None,
    out_: str | None,
) -> None:
    """Build a self-signed certificate (DEV/TEST only), signed ON-CARD."""
    import datetime
    import secrets

    app.out.warn("Self-signed certificates are for development/testing only.")
    ref = int(slot, 16)
    mech = _resolve_asym_mech(algorithm)
    spki = _load_spki(pubkey_file)
    serial = int.from_bytes(secrets.token_bytes(8), "big") | 1
    not_before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    not_after = not_before + datetime.timedelta(days=days)
    pem = _sign_on_card(
        app,
        ref,
        mech,
        pin_value,
        lambda s: csr_mod.build_self_signed(
            subject,
            spki,
            mech,
            s,
            serial=serial,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
        ),
    )
    if out_:
        Path(out_).write_bytes(pem)
    app.out.result(
        {"slot": slot, "subject": subject, "out": out_, "cert_pem": None if out_ else pem.decode()},
        lambda c: c.print(
            f"[green]Self-signed cert written to {out_}[/green]" if out_ else pem.decode().rstrip()
        ),
    )


@perso.command("import-cert")
@click.option("--slot", required=True, help="Key slot hex, e.g. 9A.")
@click.option("--cert", "cert_file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_import_cert(app: AppContext, slot: str, cert_file: str, default_keys: bool) -> None:
    """Import an X.509 certificate into the slot's PIV container (over SCP03)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    ref = int(slot, 16)
    if ref not in SLOT_CERT_OBJECT:
        raise click.BadParameter(f"slot {slot} has no certificate container")
    raw = Path(cert_file).read_bytes()
    cert = (
        x509.load_pem_x509_certificate(raw)
        if raw.lstrip().startswith(b"-----")
        else x509.load_der_x509_certificate(raw)
    )
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        resp = _import_cert_der(
            PivAdmin(session),
            keys,
            ref,
            cert.public_bytes(serialization.Encoding.DER),
            label=slot,
        )
    info = describe_sw(resp.sw1, resp.sw2)
    app.out.result(
        {"slot": slot, "imported": resp.ok, "sw": info.sw_hex()},
        lambda c: c.print(
            f"[green]Certificate imported to slot {slot}.[/green]"
            if resp.ok
            else f"[red]Import failed:[/red] {info.message} (SW={info.sw_hex()})"
        ),
    )


def _emit_object(app: AppContext, name: str, data: bytes, out_: str | None) -> None:
    if out_:
        Path(out_).write_bytes(data)
    app.out.result(
        {
            "object": name,
            "length": len(data),
            "out": out_,
            "hex": None if out_ else data.hex().upper(),
        },
        lambda c: c.print(
            f"[green]{name}[/green] ({len(data)} bytes) -> {out_}"
            if out_
            else f"{name} ({len(data)} bytes): {data.hex().upper()}"
        ),
    )


@perso.command("generate-chuid")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_chuid(app: AppContext, out_: str | None) -> None:
    """Generate a minimal CHUID object (unsigned, dev/test)."""
    _emit_object(app, "chuid", piv_objects.generate_chuid(), out_)


@perso.command("generate-ccc")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_ccc(app: AppContext, out_: str | None) -> None:
    """Generate a minimal Card Capability Container object (dev/test)."""
    _emit_object(app, "ccc", piv_objects.generate_ccc(), out_)


@perso.command("generate-discovery")
@click.option("--out", "out_", type=click.Path(dir_okay=False), help="Write object bytes to FILE.")
@click.pass_obj
def perso_generate_discovery(app: AppContext, out_: str | None) -> None:
    """Generate the Discovery object (7E)."""
    _emit_object(app, "discovery", piv_objects.generate_discovery(), out_)


@perso.command("write-object")
@click.option("--object", "object_name", required=True, help="Object name, e.g. chuid.")
@click.option("--file", "file_", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_write_object(app: AppContext, object_name: str, file_: str, default_keys: bool) -> None:
    """Write a data object's content into its container (PUT DATA over SCP03)."""
    obj = object_by_name(object_name)
    if obj is None:
        raise click.BadParameter(f"unknown object {object_name!r}")
    app.out.warn(f"overwrites the {object_name} container's current content (admin channel write).")
    data = Path(file_).read_bytes()
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        adm = PivAdmin(session)
        adm.select()
        adm.open(keys)
        resp = adm.send(perso_mod.put_data_apdu(obj.oid, data), context=f"PUT DATA {object_name}")
    info = describe_sw(resp.sw1, resp.sw2)
    app.out.result(
        {"object": object_name, "written": resp.ok, "sw": info.sw_hex()},
        lambda c: c.print(
            f"[green]Wrote {object_name}.[/green]"
            if resp.ok
            else f"[red]Write failed:[/red] {info.message} (SW={info.sw_hex()})"
        ),
    )


@perso.command("write-standard-objects")
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.pass_obj
def perso_write_standard_objects(app: AppContext, default_keys: bool) -> None:
    """Generate and write the standard data objects (CHUID, CCC) into their containers."""
    app.out.warn(
        "overwrites the current content of the chuid and ccc containers (admin channel write)."
    )
    keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
    with app.open_session() as session:
        results = _write_standard(PivAdmin(session), keys, ("chuid", "ccc"))

    def human(c: Console) -> None:
        for r in results:
            mark = "[green]ok[/green]" if r["ok"] else f"[red]{r['sw']}[/red]"
            c.print(f"  {mark}  {r['object']}")

    app.out.result({"objects": results}, human)


@perso.command("smoke-test")
@click.option("--slot", default="9C", show_default=True, help="A SIGN-capable slot.")
@click.option("--algorithm", default="ECCP256", show_default=True)
@click.option("--pin", "pin_value", help="(discouraged) PIN on the CLI; prefer prompt/env.")
@click.pass_obj
def perso_smoke_test(app: AppContext, slot: str, algorithm: str, pin_value: str | None) -> None:
    """Fast post-perso check: verify the PIN and perform one on-card signature."""
    import os

    ref = int(slot, 16)
    mech = _resolve_asym_mech(algorithm)
    # Digest size must match the mechanism's hash (SHA-256=32, SHA-384=48); a fixed 32-byte
    # challenge makes the card reject ECCP384 with 6A80. Mirror the import/quickstart paths.
    digest = os.urandom(keyimport.digest_for_mechanism(mech).digest_size)
    signature = _sign_on_card(app, ref, mech, pin_value, lambda s: s(digest))
    app.out.result(
        {"slot": slot, "pin_verified": True, "signed": True, "signature_len": len(signature)},
        lambda c: c.print(
            f"[green]Smoke test OK[/green]: PIN verified and slot {slot} produced a "
            f"{len(signature)}-byte signature."
        ),
    )


@command.command("validate")
@click.option("--profile", default=None, help="Informational label for the report.")
@click.pass_obj
def validate(app: AppContext, profile: str | None) -> None:
    """Compatibility / consistency check (NOT a NIST/FIPS validation)."""
    with app.open_session() as session:
        st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
        piv = _select(session)
        certs_loaded = {
            ref: _read_cert_der(piv, name) is not None for ref, name in SLOT_CERT_OBJECT.items()
        }
    objs = st.piv_objects
    checks: list[dict[str, object]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    add("PIV applet selectable", st.piv_apt is not None, st.piv.label)
    add("PIN configured", bool(st.piv_pin and st.piv_pin.configured))
    add("PUK configured", bool(st.piv_puk and st.piv_puk.configured))
    add("CHUID present", bool(objs.get("chuid")))
    add("CCC present", bool(objs.get("ccc")))
    add("Discovery present", bool(objs.get("discovery")))
    for ref in SLOT_CERT_OBJECT:
        add(f"certificate {ref:02X} loaded", certs_loaded[ref])
    supported = ", ".join(pivc.ALGORITHMS[a] for a in sorted(pivc.SUPPORTED_ALGORITHMS))
    add("Supported algorithms reported", True, supported)
    payload = {
        "profile": profile,
        "checks": checks,
        "note": "Compatibility/consistency check only - NOT a NIST/FIPS/SP800-73 validation.",
    }

    def human(c: Console) -> None:
        table = app.out.table("Check", "Result", "Detail")
        for ch in checks:
            mark = "[green]pass[/green]" if ch["ok"] else "[yellow]absent[/yellow]"
            table.add_row(str(ch["check"]), mark, str(ch["detail"]))
        c.print(table)
        c.print(f"\n[dim]{payload['note']}[/dim]")

    app.out.result(payload, human)


# -------------------------------------------------------------- quickstart --- #
@dataclass(frozen=True)
class QuickstartOptions:
    slot: int
    mechanism: int
    cert_mode: str  # self-signed | csr | none
    include_preperso: bool


@dataclass(frozen=True)
class CardFacts:
    """What quickstart needs to know about the card before planning."""

    pin_configured: bool
    puk_configured: bool
    key_object_present: bool  # a (slot, mechanism) key object exists
    cert_present: bool
    chuid_present: bool
    ccc_present: bool


@dataclass(frozen=True)
class PlannedStep:
    step: str
    run: bool
    reason: str | None = None


def _plan_quickstart(facts: CardFacts, opts: QuickstartOptions) -> list[PlannedStep]:
    """Pure planner: which steps run for this card state. Raises when the card
    needs pre-personalization and the caller did not opt into it."""
    steps: list[PlannedStep] = []
    if not facts.key_object_present:
        if not opts.include_preperso:
            raise CryptnoxError(
                "the PIV structure (containers, verifiers, key objects) is missing on "
                f"this card. Lay it down first:\n  {CLI_NAME} factory piv preperso "
                "load-config --profile cryptnox-default\nor re-run quickstart with "
                "--include-preperso (dev/eval cards)."
            )
        steps.append(PlannedStep("preperso-load-config", True, "structure missing"))
    else:
        steps.append(PlannedStep("preperso-load-config", False, "structure present"))
    steps.append(
        PlannedStep(
            "set-pin",
            not facts.pin_configured,
            None if not facts.pin_configured else "PIN already set",
        )
    )
    steps.append(
        PlannedStep(
            "set-puk",
            not facts.puk_configured,
            None if not facts.puk_configured else "PUK already set",
        )
    )
    # A present certificate marks the slot as done: never silently replace a
    # certified key. Without a certificate the key is regenerated (nothing
    # references it yet).
    fresh_slot = not facts.cert_present
    steps.append(
        PlannedStep(
            "generate-key",
            fresh_slot,
            None if fresh_slot else "certificate present - keeping the existing key",
        )
    )
    if opts.cert_mode == "none":
        steps.append(PlannedStep("certificate", False, "--cert-mode none"))
    else:
        steps.append(
            PlannedStep("certificate", fresh_slot, None if fresh_slot else "already present")
        )
    steps.append(
        PlannedStep(
            "write-chuid",
            not facts.chuid_present,
            None if not facts.chuid_present else "already present",
        )
    )
    steps.append(
        PlannedStep(
            "write-ccc", not facts.ccc_present, None if not facts.ccc_present else "already present"
        )
    )
    steps.append(PlannedStep("smoke-test", True))
    return steps


def _pin_truth(piv: PivApplet, pin: bytes) -> tuple[str, int | None]:
    """Distinguish a set PIN from a created-but-valueless verifier, with one VERIFY.

    The status probe (empty VERIFY) cannot tell them apart: OpenFIPS201 answers
    63Cx with the retry counter for a verifier the pre-perso structure created even
    when no value was ever set, and only a real VERIFY reveals the difference -
    observed on hardware 2026-08-21. Returns:

    * ``("match", None)``     - PIN is set and the provided value is correct (9000)
    * ``("empty", None)``     - verifier exists but holds no value (6A88, no retry
      consumed - the applet rejects the reference, not the value)
    * ``("mismatch", tries)`` - PIN is set and the provided value is wrong (63Cx;
      one retry consumed - the same retry the certificate/smoke-test step would
      have consumed, since every quickstart path verifies the PIN at least once)
    """
    resp = piv.verify_pin(pin)
    if resp.ok:
        return "match", None
    if resp.sw == 0x6A88:
        return "empty", None
    if resp.sw1 == 0x63 and (resp.sw2 & 0xF0) == 0xC0:
        return "mismatch", resp.sw2 & 0x0F
    raise StatusWordError(resp.sw1, resp.sw2, context="VERIFY PIN (quickstart pre-flight)")


def _apply_pin_truth(steps: list[PlannedStep], verdict: str) -> list[PlannedStep]:
    """Adjust a plan after the pre-flight PIN check.

    ``empty`` means the structure was laid down (e.g. a manual pre-personalization)
    but personalization never happened: the set-pin skip was a false positive, and
    the PUK - created by the same structure - is assumed valueless too, so both
    flips run. Setting them loses nothing: there is no value to preserve. ``match``
    upgrades the skip reason to say the PIN was actually verified.
    """
    if verdict == "match":
        return [
            PlannedStep(s.step, s.run, "PIN already set (verified)")
            if s.step == "set-pin" and not s.run
            else s
            for s in steps
        ]
    if verdict != "empty":
        return steps
    out: list[PlannedStep] = []
    for s in steps:
        if s.step == "set-pin" and not s.run:
            out.append(PlannedStep("set-pin", True, "verifier exists but holds no value"))
        elif s.step == "set-puk" and not s.run:
            out.append(PlannedStep("set-puk", True, "verifier assumed valueless, like the PIN"))
        else:
            out.append(s)
    return out


def _collect_quickstart_facts(session, ref: int, mech: int) -> tuple[CardFacts, str]:
    """Read-only detection pass: lifecycle state, verifier status, object presence,
    and the non-destructive (slot, mechanism) key-object probe."""
    st = StateDetector(session, probe_fido=False, probe_desfire=False).detect()
    piv = _select(session)
    probe = session.transmit(keyimport.probe_apdu(ref, mech), context="probe quickstart")
    # "Certificate present" means a PARSEABLE certificate: a created-but-unused
    # container is zero-length per SP 800-73 4.1.1, and factory containers can
    # hold non-certificate placeholder data - neither should stop quickstart
    # from provisioning the slot.
    obj_name = SLOT_CERT_OBJECT.get(ref)
    cert_present = obj_name is not None and _read_cert_der(piv, obj_name) is not None
    objs = st.piv_objects or {}
    facts = CardFacts(
        pin_configured=bool(st.piv_pin and st.piv_pin.configured),
        puk_configured=bool(st.piv_puk and st.piv_puk.configured),
        key_object_present=probe.sw != 0x6A86,
        cert_present=cert_present,
        chuid_present=bool(objs.get("chuid")),
        ccc_present=bool(objs.get("ccc")),
    )
    return facts, st.piv.label


@command.command("quickstart")
@click.option(
    "--slot",
    default="9C",
    show_default=True,
    help="Key slot hex. Certificate modes need a SIGN-role slot (9C on this applet).",
)
@click.option(
    "--algorithm",
    default="ECCP256",
    show_default=True,
    help="ECCP256, ECCP384, RSA2048, RSA3072 or RSA4096; the slot must have a key object for it "
    "(RSA: only ms-logon's 9A among the built-in profiles — pass RSA2048 explicitly "
    "for Windows, which does not enumerate EC keys).",
)
@click.option("--subject", default="CN=Cryptnox Dev Card", show_default=True)
@click.option("--days", default=365, show_default=True, type=int)
@click.option(
    "--cert-mode",
    type=click.Choice(["self-signed", "csr", "none"]),
    default="self-signed",
    show_default=True,
    help="self-signed: sign on-card and import. csr: write a CSR for an external CA. "
    "none: keys/objects only.",
)
@click.option(
    "--csr-out",
    type=click.Path(dir_okay=False),
    help="Where to write the CSR (required with --cert-mode csr).",
)
@click.option(
    "--cert-out",
    type=click.Path(dir_okay=False),
    help="Also write the self-signed certificate PEM to FILE.",
)
@click.option(
    "--public-out", type=click.Path(dir_okay=False), help="Also write the public-key PEM to FILE."
)
@click.option(
    "--include-preperso",
    is_flag=True,
    help="If the PIV structure is missing, lay it down first (a MANUFACTURING-style "
    "step for dev/eval cards).",
)
@click.option(
    "--profile",
    "profile_name",
    default="cryptnox-default",
    show_default=True,
    help="Built-in pre-perso profile used by --include-preperso (e.g. ms-logon for a "
    "SIGN-capable 9A / Windows logon card).",
)
@click.option(
    "--default-keys",
    is_flag=True,
    help="Use the default GlobalPlatform TEST keys "
    "(publicly known - fine for dev/eval, never for deployment).",
)
@click.option(
    "--dry-run", "dry_run", is_flag=True, help="Detect, plan and show the steps; write nothing."
)
@click.pass_obj
def quickstart(
    app: AppContext,
    slot: str,
    algorithm: str,
    subject: str,
    days: int,
    cert_mode: str,
    csr_out: str | None,
    cert_out: str | None,
    public_out: str | None,
    include_preperso: bool,
    profile_name: str,
    default_keys: bool,
    dry_run: bool,
) -> None:
    """One-shot personalization: a blank or part-done card -> usable by standard
    PIV tooling (yubico-piv-tool, OpenSC).

    Chains [preperso] -> PIN -> PUK -> key -> certificate -> CHUID/CCC ->
    smoke-test over one card connection, skipping whatever is already done, and
    ends with the commands to verify the result. Contact reader required.
    """
    import datetime
    import hashlib
    import os
    import secrets as pysecrets
    import sys

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    ref = int(slot, 16)
    # ms-logon on 9A is the Windows shape, and the only built-in profile that gives a slot
    # an RSA key object. It matters because the Windows inbox minidriver does not enumerate
    # EC keys at all (confirmed 2026-08-14, reproduced on a YubiKey, so a Windows limit
    # rather than ours) -- an ECC 9A is unusable for the very purpose ms-logon is chosen for.
    windows_rsa_shape = profile_name == "ms-logon" and ref == pivc.KEYREF_PIV_AUTH

    algorithm_defaulted = (
        click.get_current_context().get_parameter_source("algorithm")
        == click.core.ParameterSource.DEFAULT
    )
    if windows_rsa_shape and algorithm_defaulted:
        # The default stays ECC everywhere, but don't let it land silently on the one
        # shape whose whole purpose is Windows: an ECC 9A card cannot log on there. An
        # operator who passed --algorithm made a choice; this fires only on the default.
        app.out.warn(
            "profile ms-logon on slot 9A defaulting to ECCP256 - but the Windows "
            "inbox minidriver does not enumerate EC keys, so this card will NOT work "
            "for Windows logon/RDP/TLS. For Windows, re-run with --algorithm RSA2048 "
            "(generated on-card; ms-logon's 9A has the RSA key object)."
        )

    alg = algorithm.upper()
    if alg.startswith("RSA") and not windows_rsa_shape:
        raise click.BadParameter(
            "on-card RSA needs a slot that has an RSA key object, and among the built-in "
            "profiles only ms-logon's 9A has one - so this combination would fail on the "
            "card. Use `--profile ms-logon --slot 9A`, or generate directly with `piv perso "
            "generate-key` if this card is known to have the object, or import an off-card "
            "key with `piv perso import-key`.",
            param_hint="--algorithm",
        )

    mech = perso_mod.ALGORITHMS.get(alg)
    if mech is None or mech not in pivc.SUPPORTED_ALGORITHMS:
        raise click.BadParameter(f"algorithm {algorithm!r} not supported by this applet")
    keyimport.validate_slot_mechanism(ref, mech)
    profile = prof_mod.builtin(profile_name)  # validates the name early (exit 8 on typo)
    if cert_mode != "none" and ref not in (
        pivc.KEYREF_PIV_AUTH,
        pivc.KEYREF_DIGITAL_SIGNATURE,
    ):
        raise click.BadParameter(
            "certificate modes sign on-card and need a SIGN-capable slot: 9C always; "
            "9A only on cards pre-personalized with a SIGN-capable 9A (the ms-logon "
            "profile) - a default-profile 9A fails the certificate step with 6985.",
            param_hint="--slot",
        )
    if cert_mode == "csr" and not csr_out:
        raise click.BadParameter("--cert-mode csr requires --csr-out", param_hint="--csr-out")
    if cert_out and cert_mode != "self-signed":
        raise click.BadParameter(
            "--cert-out applies to --cert-mode self-signed", param_hint="--cert-out"
        )

    with app.open_session() as session:
        facts, state_before = _collect_quickstart_facts(session, ref, mech)
        steps = _plan_quickstart(facts, QuickstartOptions(ref, mech, cert_mode, include_preperso))

        if dry_run or app.dry_run:
            planned = [
                {"step": s.step, "status": "would-run" if s.run else "skip", "reason": s.reason}
                for s in steps
            ]

            def human_dry(c: Console) -> None:
                c.print(f"[bold]DRY RUN[/bold] - card state: {state_before}")
                table = app.out.table("Step", "Plan", "Reason")
                for p in planned:
                    mark = (
                        "[cyan]would run[/cyan]"
                        if p["status"] == "would-run"
                        else "[dim]skip[/dim]"
                    )
                    table.add_row(str(p["step"]), mark, str(p["reason"] or ""))
                c.print(table)
                c.print("\n  [dim]Nothing was sent to the card.[/dim]")

            app.out.result(
                {
                    "quickstart": True,
                    "dry_run": True,
                    "state_before": state_before,
                    "steps": planned,
                },
                human_dry,
            )
            return

        # Resolve keys and the PIN before the plan is final: when the status probe
        # reports the PIN as set, a pre-flight VERIFY establishes the truth (the probe
        # cannot tell a set PIN from a created-but-valueless verifier), and the plan
        # may change as a result.
        keys = resolve_scp03_keys(app.redactor, default_keys=default_keys)
        run_set = {s.step for s in steps if s.run}
        pin_secret = resolve_secret(
            redactor=app.redactor,
            env_var="CRYPTNOX_PIV_NEW_PIN" if "set-pin" in run_set else "CRYPTNOX_PIV_PIN",
            prompt_label="New PIV PIN" if "set-pin" in run_set else "PIV PIN",
        )
        if "set-pin" not in run_set:
            verdict, tries = _pin_truth(_select(session), pin_secret)
            if verdict == "mismatch":
                raise CryptnoxError(
                    f"the PIN is set and the provided PIN does not match ({tries} tries "
                    "left). This pre-flight check consumed one retry - the certificate/"
                    "smoke-test step would have consumed it otherwise. Provide the card's "
                    "PIN (CRYPTNOX_PIV_PIN or the prompt) and re-run."
                )
            if verdict == "empty":
                app.out.warn(
                    "the PIN verifier exists but holds no value (structure loaded without "
                    "personalization) - the provided PIN will be SET; the PUK likewise."
                )
            steps = _apply_pin_truth(steps, verdict)
            run_set = {s.step for s in steps if s.run}

        to_run = [s.step for s in steps if s.run]
        app.out.warn(f"quickstart will run: {', '.join(to_run)}")
        if steps[0].run:
            app.out.warn(
                "--include-preperso lays down the applet structure (PUT DATA ADMIN) - "
                "a manufacturing-style step intended for dev/eval cards."
            )
        if not app.yes and not click.confirm("Proceed?", default=False):
            raise click.Abort()

        puk_secret = (
            resolve_secret(
                redactor=app.redactor, env_var="CRYPTNOX_PIV_NEW_PUK", prompt_label="New PIV PUK"
            )
            if "set-puk" in run_set
            else None
        )

        adm = PivAdmin(session)
        executed: list[dict[str, object]] = []
        outputs: dict[str, str | None] = {"public_key": None, "certificate": None, "csr": None}
        spki: bytes | None = None
        failed = False

        def record(step: str, status: str, **extra: object) -> None:
            executed.append({"step": step, "status": status, **extra})

        for planned_step in steps:
            if not planned_step.run:
                record(planned_step.step, "skipped", reason=planned_step.reason)
                continue
            try:
                if planned_step.step == "preperso-load-config":
                    for label, op in profile.build_ops():
                        adm.select()
                        adm.open(keys)
                        resp = adm.send(
                            preperso_mod.put_data_admin_apdu(preperso_mod.build_bulk([op])),
                            context=f"PUT DATA ADMIN [{label}]",
                        )
                        if not resp.ok:
                            raise StatusWordError(resp.sw1, resp.sw2, context=f"preperso [{label}]")
                    record(planned_step.step, "ok", detail={"profile": profile.name})
                elif planned_step.step == "set-pin":
                    padded = perso_mod.pad_pin(pin_secret)
                    app.redactor.register(padded)
                    resp = _set_verifier(adm, keys, pivc.REF_PIV_PIN, padded, label="PIN")
                    if not resp.ok:
                        raise StatusWordError(resp.sw1, resp.sw2, context="SET PIN")
                    record(planned_step.step, "ok", sw=resp.sw_hex())
                elif planned_step.step == "set-puk":
                    if puk_secret is None:  # unreachable: planner gates set-puk on a resolved PUK
                        raise RuntimeError("set-puk planned without a PUK value")
                    padded = perso_mod.pad_pin(puk_secret)
                    app.redactor.register(padded)
                    resp = _set_verifier(adm, keys, pivc.REF_PUK, padded, label="PUK")
                    if not resp.ok:
                        raise StatusWordError(resp.sw1, resp.sw2, context="SET PUK")
                    record(planned_step.step, "ok", sw=resp.sw_hex())
                elif planned_step.step == "generate-key":
                    public_key = _generate_key_on_card(adm, keys, ref, mech, label=slot)
                    spki = public_key.public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    fingerprint = hashlib.sha256(spki).hexdigest().upper()
                    if public_out:
                        Path(public_out).write_bytes(perso_mod.public_key_pem(public_key))
                        outputs["public_key"] = public_out
                    record(
                        planned_step.step,
                        "ok",
                        detail={"algorithm": alg, "public_key_sha256": fingerprint},
                    )
                elif planned_step.step == "certificate":
                    if spki is None:  # unreachable: generate-key runs whenever certificate runs
                        raise RuntimeError("certificate step planned without a generated key")
                    spki_bytes = spki
                    if cert_mode == "csr":
                        pem = _sign_with_session(
                            session,
                            ref,
                            mech,
                            pin_secret,
                            lambda s, _spki=spki_bytes: csr_mod.build_csr(subject, _spki, mech, s),
                        )
                        if csr_out is None:  # unreachable: csr mode validates --csr-out at parse
                            raise RuntimeError("csr mode without --csr-out")
                        Path(csr_out).write_bytes(pem)
                        outputs["csr"] = csr_out
                        record(
                            planned_step.step,
                            "ok",
                            detail={
                                "mode": "csr",
                                "note": "re-running quickstart regenerates the key and "
                                "invalidates this CSR",
                            },
                        )
                    else:
                        serial = int.from_bytes(pysecrets.token_bytes(8), "big") | 1
                        not_before = datetime.datetime.now(datetime.timezone.utc).replace(
                            microsecond=0
                        )
                        not_after = not_before + datetime.timedelta(days=days)

                        def _build_self_signed(
                            s,
                            _spki=spki_bytes,
                            _serial=serial,
                            _nb=not_before.isoformat(),
                            _na=not_after.isoformat(),
                        ):
                            return csr_mod.build_self_signed(
                                subject,
                                _spki,
                                mech,
                                s,
                                serial=_serial,
                                not_before=_nb,
                                not_after=_na,
                            )

                        pem = _sign_with_session(session, ref, mech, pin_secret, _build_self_signed)
                        cert_der = x509.load_pem_x509_certificate(pem).public_bytes(
                            serialization.Encoding.DER
                        )
                        resp = _import_cert_der(adm, keys, ref, cert_der, label=slot)
                        if not resp.ok:
                            raise StatusWordError(resp.sw1, resp.sw2, context="IMPORT cert")
                        if cert_out:
                            Path(cert_out).write_bytes(pem)
                            outputs["certificate"] = cert_out
                        record(
                            planned_step.step,
                            "ok",
                            detail={"mode": "self-signed", "subject": subject, "days": days},
                        )
                elif planned_step.step in ("write-chuid", "write-ccc"):
                    name = "chuid" if planned_step.step == "write-chuid" else "ccc"
                    results = _write_standard(adm, keys, (name,))
                    if not results[0]["ok"]:
                        raise StatusWordError(
                            int(str(results[0]["sw"])[:2], 16),
                            int(str(results[0]["sw"])[2:], 16),
                            context=f"PUT DATA {name}",
                        )
                    record(planned_step.step, "ok", sw=results[0]["sw"])
                elif planned_step.step == "smoke-test":
                    digest = os.urandom(keyimport.digest_for_mechanism(mech).digest_size)
                    try:
                        signature = _sign_with_session(
                            session, ref, mech, pin_secret, lambda s, _d=digest: s(_d)
                        )
                        record(planned_step.step, "ok", detail={"signature_len": len(signature)})
                    except StatusWordError as exc:
                        if exc.info.sw_hex() == "6985":
                            record(
                                planned_step.step,
                                "ok",
                                detail={"note": "slot role cannot sign on this applet"},
                            )
                        else:
                            raise
            except CryptnoxError as exc:
                record(planned_step.step, "failed", reason=str(exc))
                failed = True
                break

        try:
            _, state_after = _collect_quickstart_facts(session, ref, mech)
        except CryptnoxError:
            state_after = "unknown"

    reader = app.resolved_reader or "<your contact reader>"
    slot_lc = slot.lower()
    next_cmds = [
        f'yubico-piv-tool -r "{reader}" -a status',
        f'yubico-piv-tool -r "{reader}" -a read-certificate -s {slot_lc} -o {slot_lc}.crt.pem',
        f'yubico-piv-tool -r "{reader}" -a verify-pin',
    ]
    payload = {
        "quickstart": True,
        "dry_run": False,
        "slot": slot,
        "algorithm": alg,
        "cert_mode": cert_mode,
        "preperso_profile": profile.name,
        "state_before": state_before,
        "steps": executed,
        "state_after": state_after,
        "outputs": outputs,
        "next": next_cmds if not failed else [],
    }

    def human(c: Console) -> None:
        table = app.out.table("Step", "Result", "Note")
        for e in executed:
            mark = {
                "ok": "[green]ok[/green]",
                "skipped": "[dim]skipped[/dim]",
                "failed": "[red]failed[/red]",
            }[str(e["status"])]
            note = e.get("reason") or e.get("sw") or ""
            detail = e.get("detail")
            if isinstance(detail, dict) and detail.get("note"):
                note = detail["note"]
            table.add_row(str(e["step"]), mark, str(note))
        c.print(table)
        c.print(f"\n  Card state: {state_before} -> {state_after}")
        if failed:
            c.print(
                "[red]quickstart stopped at the first failure[/red]; completed steps are "
                "kept - fix the cause and re-run (it skips what is already done)."
            )
            return
        c.print("\n[bold]Verify with standard PIV tooling:[/bold]")
        for cmd_line in next_cmds:
            c.print(f"  {cmd_line}")
        c.print(
            "[dim]Yubico-proprietary actions (version, attest, set-mgm-key, and writes via "
            "yubico-piv-tool) do not apply: this card administers over SCP03 via "
            f"{CLI_NAME}.[/dim]"
        )

    app.out.result(payload, human)
    if failed:
        sys.exit(6)
