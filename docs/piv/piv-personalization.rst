PIV personalization
===================

The full PIV lifecycle: pre-personalization (structure), PIN/PUK values,
on-card key generation, external key import, CSRs and certificates, standard
data objects, validation, and the irreversible finalize step.

For the condensed version, see the :doc:`/piv/quick-start-a-working-piv-card`.

.. note::

   This card provisions the PIV **Application PIN** (key ref ``0x80``) only —
   there is no Global PIN option, and PIV's PIN is independent from FIDO2's
   (DESFire has no PIN at all; its access is symmetric-key based). Each
   application's PIN has its own retry counter and is managed separately.

Operator commands live under ``piv``; factory pre-personalization lives under
``factory piv preperso``. The SCP03 admin channel uses the card's GlobalPlatform
keys — development/evaluation cards use the GlobalPlatform test keys
(``--default-keys``); provisioned cards take theirs from the
``PIV_SCP03_ENC`` / ``PIV_SCP03_MAC`` / ``PIV_SCP03_DEK`` environment variables.

Quickstart (one shot)
----------------------

``piv quickstart`` chains the steps below over one card connection, skipping
whatever is already done (re-runs converge), and ends with the
``yubico-piv-tool`` commands that verify the result. It detects the card state
first; ``--dry-run`` shows the step plan without writing.

.. code-block:: console

   $ cryptnox-id piv quickstart --default-keys --dry-run
   $ cryptnox-id piv quickstart --default-keys                        # 9C, ECCP256, self-signed cert
   $ cryptnox-id piv quickstart --default-keys --cert-mode csr --csr-out 9c.csr.pem
   $ cryptnox-id piv quickstart --default-keys --include-preperso     # blank card: lay down the structure too

.. note::

   Secrets are resolved up front (``CRYPTNOX_PIV_NEW_PIN`` / ``CRYPTNOX_PIV_NEW_PUK``
   or masked prompts; ``CRYPTNOX_PIV_PIN`` when the PIN already exists). Quickstart
   defaults to ECC P-256. For a Windows card pass ``--algorithm RSA2048`` with
   ``--profile ms-logon`` on slot 9A (Windows does not enumerate EC keys; left on
   the ECC default, that combination warns). For RSA on any other card shape, use
   ``generate-key`` directly on a slot with an RSA key object, or :ref:`import a
   key <piv-personalization-import-key>`. A slot that already has a certificate is left
   untouched (never silently replaces a certified key); with ``--cert-mode csr`` a
   re-run regenerates the key and invalidates a previously exported CSR.
   ``finalize`` is never invoked by quickstart. The first failure stops the run
   with partial results and exit code 6; completed steps are kept.

The same sequence, below, as individual commands — useful to understand what
quickstart does, or to vary it.

Step 0 — factory: pre-personalize the applet structure
------------------------------------------------------

.. note::

   **Factory / provisioning step — not part of normal end-user setup.**
   Pre-personalization is done once at manufacturing; a card you receive is
   already structured, so start at Step 1. Full detail lives under
   :doc:`/factory/factory-commands`.

``load-config`` applies a profile (containers, PIN/PUK verifiers, key slots) to
a blank OpenFIPS201 applet over SCP03 — one short ``PUT DATA ADMIN`` per
command. See :doc:`/factory/pre-personalization-profiles` for the profile format itself.

.. code-block:: console

   $ cryptnox-id factory piv preperso status
   $ cryptnox-id factory piv preperso inspect-defaults
   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --dry-run
   $ cryptnox-id factory piv preperso load-config --profile cryptnox-default --default-keys

Step 1 — set the PIN and PUK
-----------------------------

.. code-block:: console

   $ cryptnox-id piv perso set-puk --default-keys     # prompts (masked) for the new PUK
   $ cryptnox-id piv perso set-pin --default-keys     # prompts (masked) for the new PIN
   $ cryptnox-id piv pin status                       # configured? retries?

Step 1b — set the management key (optional)
---------------------------------------------

Key reference 9B holds an AES key (``cryptnox-default``: AES-256). The applet
genuinely supports the PIV standard's management-key model (SP 800-73's
Administration Key, key reference 9B): a standard PIV write (``PUT DATA`` on
a container, ``GENERATE ASYMMETRIC KEY PAIR``) is authorized by *either* an
open SCP03 admin session *or* a completed 9B challenge-response (every
container/key in ``cryptnox-default`` is bound to 9B as its admin key). |cli|
only ever takes the SCP03 path and never authenticates with 9B itself — a
spec-compliant client that speaks GENERAL AUTHENTICATE with AES-256 (P1
``0x0C``) could use the other path once 9B is set.

.. code-block:: console

   $ cryptnox-id piv perso set-mgmt-key --default-keys   # prompts (masked) for the new key, as hex

The key value is raw AES key material (hex, sized to ``--algorithm``: 16/24/32 bytes).
``--algorithm`` must match whatever pre-perso gave the admin key object.

Step 2 — generate keys on the card
-----------------------------------

Keys are generated **on-card**; only the public key leaves. Use a SIGN-role
slot (9C) for anything you will sign with.

.. code-block:: console

   $ cryptnox-id piv perso generate-key --slot 9C --algorithm ECCP256 --out 9c.pub.pem --default-keys
   $ cryptnox-id piv perso generate-key --slot 9A --algorithm ECCP256 --out 9a.pub.pem --default-keys

A slot generates on-card for any mechanism it has a **key object** for, and the
pre-personalization profile decides which those are (see
:doc:`/factory/pre-personalization-profiles`). Every key object in ``cryptnox-default`` is ECC
(``ECCP256``, ``ECCP384``), so on such a card RSA has to be imported with
``import-key`` (next). A profile that provides an RSA object generates RSA
on-card just as well — ``ms-logon`` creates an ``RSA2048`` object on 9A, and::

   $ cryptnox-id piv perso generate-key --slot 9A --algorithm RSA2048 --out 9a.pub.pem --default-keys

succeeds there, with the private key never leaving the card. Requesting a
mechanism the slot has no object for returns ``6A80``.

``piv quickstart`` follows the same rule with training wheels: it defaults to
ECC P-256 everywhere, accepts explicit RSA only for ``--profile ms-logon`` on
9A (the one built-in shape with an RSA object, and the one Windows needs —
the ECC default warns there), and elsewhere refuses RSA early rather than
failing on the card. RSA-1024 is removed from the build; the CLI never offers
it.

.. _piv-personalization-import-key:

Step 2b — import an external private key
------------------------------------------

``import-key`` injects a host-generated key over SCP03 — for keys that must be
generated off-card (CA/HSM-issued, escrow or migration scenarios); for on-card
RSA see Step 2, which works on any slot with an RSA key object. The key
travels as CHANGE REFERENCE DATA ADMIN elements, **one element per SCP03
session** (JCOP 4.5), with large elements ISO-chained; the sequence starts
with a CLEAR, so re-running an import is safe. Accepts
PEM/DER, PKCS#8 or traditional, encrypted or not
(``CRYPTNOX_PIV_KEY_PASSWORD`` env var, or a masked prompt).

.. code-block:: console

   $ openssl genrsa -out rsa2048.key.pem 2048
   $ cryptnox-id piv perso import-key --slot 9C --key rsa2048.key.pem --default-keys --dry-run
   $ cryptnox-id piv perso import-key --slot 9C --key rsa2048.key.pem --default-keys \
       --create-key-object --public-out 9c-rsa.pub.pem

The target key **object** must exist with the same (slot, mechanism) pair and
the IMPORTABLE attribute. The ``cryptnox-default`` profile creates ECC-P256
objects only, so an RSA (or P-384) import needs either a profile that defines
it (the ``ms-logon`` profile pre-creates an importable RSA-2048 object on 9A —
see :doc:`/factory/pre-personalization-profiles`) or ``--create-key-object`` (a structural
``PUT DATA ADMIN``: development/evaluation cards only — a finalized applet
refuses it). RSA objects fix CRT vs. plain form at creation; ``--rsa-form``
must match, or the card rejects the import (``6A80``). A post-import smoke
test signs on-card and verifies against the imported key (skip with
``--no-smoke-test``; a non-SIGN slot reports "cannot sign" — that is the slot
role, not a failure).

For a PKI-issued credential delivered as PKCS#12, ``import-p12`` runs the key
import **and** the certificate import in one command (the Windows smart-card
logon / Remote Desktop enrollment path — see :doc:`/piv/windows-logon-and-remote-desktop`):

.. code-block:: console

   $ cryptnox-id piv perso import-p12 --slot 9A --p12 user.pfx --default-keys

Step 3 — CSR and certificates (on-card signing)
------------------------------------------------

.. code-block:: console

   $ cryptnox-id piv perso generate-csr   --slot 9C --subject "CN=Test User" \
       --public-key 9c.pub.pem --out 9c.csr.pem
   $ cryptnox-id piv perso self-sign-cert --slot 9C --subject "CN=Test User" \
       --public-key 9c.pub.pem --out 9c.crt.pem
   $ cryptnox-id piv perso import-cert    --slot 9C --cert 9c.crt.pem      # ISO command chaining

Signing requires a SIGN-role slot; an AUTHENTICATE-only slot (e.g. 9A) returns
``6985``. Large certificates are written with ISO command chaining
automatically.

Step 4 — data objects
-----------------------

.. code-block:: console

   $ cryptnox-id piv perso generate-chuid
   $ cryptnox-id piv perso generate-ccc
   $ cryptnox-id piv perso generate-discovery
   $ cryptnox-id piv perso write-standard-objects --default-keys
   $ cryptnox-id piv objects list

``generate-chuid``/``generate-ccc``/``generate-discovery`` build the object
bytes locally (no card, no keys needed) — pipe them into ``write-object``, or
use ``write-standard-objects`` to generate and write CHUID + CCC in one step.

Step 5 — validate and smoke-test
-----------------------------------

.. code-block:: console

   $ cryptnox-id piv perso smoke-test       # verify PIN, sign with 9C, read objects/certs
   $ cryptnox-id piv validate               # consistency check (NOT a FIPS/NIST validation)
   $ cryptnox-id report piv --out piv.json

Step 6 — finalize (irreversible, factory)
--------------------------------------------

.. note::

   **Factory / provisioning step — not part of normal end-user setup.**
   Finalizing is a manufacturing operation and is irreversible. See
   :doc:`/factory/factory-commands`.

``finalize`` transitions the applet to its ``SECURED`` operational state. It
is irreversible — recovery is a full applet reinstall. Interactively it asks
you to type the token ``FINALIZE-PIV``; non-interactively it requires the
``--i-understand-this-is-irreversible`` flag instead — either satisfies the
gate.

.. code-block:: console

   $ cryptnox-id factory piv preperso finalize --default-keys
   # at the prompt: Type FINALIZE-PIV to continue
   # (scripted/non-interactive: add --i-understand-this-is-irreversible)

Next steps
------------

* :doc:`/factory/pre-personalization-profiles` — customizing the pre-personalization profile
* :doc:`/piv/quick-start-a-working-piv-card` — the condensed, one-command path with a
  ``yubico-piv-tool`` interoperability matrix
* :doc:`/piv/piv-commands` — every ``piv`` command
