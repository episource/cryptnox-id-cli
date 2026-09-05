"""Fail-closed enforcement of the global ``--dry-run`` promise.

``--dry-run`` is documented as "write nothing to the card". Only a few commands can
actually *plan* their card operations; historically every other command silently ignored
the flag and executed for real - so ``--dry-run fido reset ...`` wiped the authenticator
it promised to spare. This module closes that hole centrally:

* commands in :data:`PLANS_OWN` implement ``app.dry_run`` themselves (they show a plan
  and send nothing) - left alone;
* commands in :data:`READ_ONLY` cannot change card state (and consume no secrets or
  retry counters) - left alone;
* everything else - :data:`NO_DRY_RUN`, and any future command nobody classified - is
  wrapped so that under ``--dry-run`` it REFUSES to run before opening a card session.

Refusing a read-only-but-unclassified command costs an error message; executing a
mutating one costs a card. Fail closed. A unit test asserts every leaf command is
classified in exactly one of the three sets, so adding a command forces the decision.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import click

from cryptnox_id_cli.cli.context import AppContext

#: Commands that implement ``app.dry_run`` themselves: they detect, plan, print the
#: intended steps, and send nothing. Verified by reading each implementation.
PLANS_OWN = frozenset(
    {
        "apdu select",
        "apdu send",
        "apdu transcript",
        "factory piv preperso finalize",
        "factory piv preperso load-config",
        "piv perso import-key",
        "piv perso import-p12",
        "piv quickstart",
    }
)

#: Commands that cannot mutate card state and consume no cardholder secrets or retry
#: counters, so running them under ``--dry-run`` is harmless. Local-file writers
#: (``report``, ``generate-chuid``, ``--out`` exports) belong here: the promise is
#: about the card. ``shell`` is a container - each forwarded line re-enters the root
#: group and gets its own guard.
READ_ONLY = frozenset(
    {
        "doctor",
        "info",
        "readers",
        "shell",
        "factory piv preperso export-config",
        "factory piv preperso init-config",
        "factory piv preperso inspect-defaults",
        "factory piv preperso status",
        "fido config show",
        "fido get-info",
        "fido info",
        "fido pin status",
        "fido ping",
        "genuine info",
        "genuine verify",
        "mifare apps list",
        "mifare files list",
        "mifare free-memory",
        "mifare info",
        "mifare read",
        "mifare record read",
        "mifare sdm read",
        "mifare value get",
        "mifare version",
        "piv admin status",
        "piv certs export",
        "piv certs inspect",
        "piv certs list",
        "piv discover",
        "piv export-attestation",
        "piv info",
        "piv objects list",
        "piv objects read",
        "piv perso generate-ccc",
        "piv perso generate-chuid",
        "piv perso generate-discovery",
        "piv pin status",
        "piv preperso",
        "piv slots",
        "piv status",
        "piv validate",
        "piv verify-attestation",
        "report card",
        "report fido",
        "report full",
        "report genuine",
        "report mifare",
        "report piv",
    }
)

#: Commands that mutate the card, or consume secrets / retry counters (a wrong PIN in a
#: "read" like ``fido credential list`` still burns an attempt), and have no planning
#: mode. Under ``--dry-run`` these refuse to run. The listing is deliberate: the
#: partition test forces every new command to be classified here or above.
NO_DRY_RUN = frozenset(
    {
        "fido config min-pin-length",
        "fido config toggle-always-uv",
        "fido credential assert",
        "fido credential create",
        "fido credential delete",
        "fido credential list",
        "fido credential self-test",
        "fido pin change",
        "fido pin set",
        "fido reset",
        "mifare app create",
        "mifare app delete",
        "mifare files create-standard",
        "mifare format",
        "mifare keys authenticate",
        "mifare keys change",
        "mifare record clear",
        "mifare record create",
        "mifare record write",
        "mifare sdm setup",
        "mifare value create",
        "mifare value credit",
        "mifare value debit",
        "mifare write",
        "piv admin authenticate",
        "piv perso generate-csr",
        "piv perso generate-key",
        "piv perso import-cert",
        "piv perso self-sign-cert",
        "piv perso set-mgmt-key",
        "piv perso set-pin",
        "piv perso set-puk",
        "piv perso smoke-test",
        "piv perso write-object",
        "piv perso write-standard-objects",
        "piv pin change",
        "piv pin unblock",
        "piv pin verify",
        "piv puk change",
    }
)


def _refusing(path: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def inner(*args: Any, **kwargs: Any) -> Any:
        ctx = click.get_current_context(silent=True)
        app = ctx.find_object(AppContext) if ctx is not None else None
        if app is not None and app.dry_run:
            raise click.ClickException(
                f"--dry-run: '{path}' cannot preview its card operations, so it refuses to "
                "run (fail-closed; nothing was sent to the card). Run it without --dry-run "
                "to execute."
            )
        return fn(*args, **kwargs)

    return inner


def install_guard(root: click.Group) -> None:
    """Wrap every leaf command not known to be dry-run-safe. Idempotent."""
    if getattr(root, "_dry_run_guard", False):  # pragma: no cover - import-time reentry
        return
    root._dry_run_guard = True  # type: ignore[attr-defined]
    _wrap(root, "")


def _wrap(group: click.Group, prefix: str) -> None:
    for name, cmd in group.commands.items():
        path = f"{prefix}{name}"
        if isinstance(cmd, click.Group):
            _wrap(cmd, path + " ")
        elif path not in READ_ONLY and path not in PLANS_OWN and cmd.callback is not None:
            cmd.callback = _refusing(path, cmd.callback)
