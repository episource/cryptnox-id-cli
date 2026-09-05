PIV commands
============

Operator and personalization commands for the PIV function (SP 800-73).
Administration runs over an SCP03 secure channel and is **contact-only**;
admin keys come from ``--default-keys`` (development cards) or the
``PIV_SCP03_ENC`` / ``PIV_SCP03_MAC`` / ``PIV_SCP03_DEK`` environment
variables. PIN values come from masked prompts or ``CRYPTNOX_PIV_PIN`` /
``CRYPTNOX_PIV_NEW_PIN`` / ``CRYPTNOX_PIV_NEW_PUK`` — never the command line.

Inspection
----------

.. code-block:: text

   piv info            applet AID/label, supported algorithms, key slots
   piv status          lifecycle state, PIN/PUK/management-key status, object presence
   piv discover        the Discovery object (PIN usage policy)
   piv slots           key slots and which hold a certificate
   piv validate        consistency check (NOT a NIST/FIPS validation)
   piv quickstart      one-shot personalization (see the PIV quick start)

PIN
---

.. code-block:: text

   piv pin status      PIN/PUK configured? retries left? (non-decrementing)
   piv pin verify      verify the PIN (a wrong PIN consumes one retry)
   piv pin change      change the PIN (cardholder; needs the current PIN)
   piv pin unblock     unblock a blocked PIN via the PUK (RESET RETRY COUNTER;
                       a wrong PUK consumes a PUK retry — see warning below)

PUK
---

.. code-block:: text

   piv puk change      change the PUK (cardholder; needs the current PUK)

``piv pin change`` and ``piv puk change`` are cardholder operations — they prove
knowledge of the current value in-band (no SCP03 admin channel), unlike the
``piv perso set-pin`` / ``set-puk`` issuance commands. ``piv pin unblock`` resets a
blocked PIN's retry counter using the PUK. Current/new values come from masked
prompts or the ``CRYPTNOX_PIV_PIN`` / ``CRYPTNOX_PIV_NEW_PIN`` / ``CRYPTNOX_PIV_PUK``
/ ``CRYPTNOX_PIV_NEW_PUK`` environment variables — never the command line.

.. warning::

   The PUK has its own retry counter, and every wrong PUK — entered through
   ``piv pin unblock``, ``piv puk change``, or any other tool — consumes one
   retry. Exhausting the PUK retries is **permanent**: a blocked PUK has no
   recovery path short of reinstalling the applet, which erases all keys and
   certificates. Check ``piv pin status`` (non-decrementing) before guessing.

Admin channel
-------------

.. code-block:: text

   piv admin status        probe the SCP03 channel (read-only)
   piv admin authenticate  open the channel (mutual auth) + harmless self-test

Certificates and objects
------------------------

.. code-block:: text

   piv certs list          certificate slots, subjects, expiry
   piv certs export        export a certificate (PEM/DER) - certificates are not secret
   piv certs inspect       certificate details for a slot
   piv objects list        PIV data objects and presence
   piv objects read        read a data object (hex or --out FILE)

Attestation
-----------

.. code-block:: text

   piv export-attestation  export the on-card key-attestation leaf (PEM chain / DER)
   piv verify-attestation  validate the attestation chain to the pinned Cryptnox root

The factory/issuance-time key-attestation leaf (slot 9C in this version) is stored
in the retired-slot-95 certificate container and chains to the pinned Cryptnox
attestation root. ``--csr`` additionally checks that the attested key is the one in
a CSR. The Cryptnox production root ships bundled, so ``verify-attestation`` anchors
the chain out of the box. Where no anchor covers a chain it reports that the chain
cannot be verified — it never passes silently.

To add anchors without rebuilding the package, point ``CRYPTNOX_TRUST_DIR`` at a
directory of PEM certificates:

.. code-block:: console

   $ export CRYPTNOX_TRUST_DIR=/etc/cryptnox/anchors
   $ cryptnox-id piv verify-attestation

Certificates are classified by inspection: self-issued CAs become pinned roots, other
CAs become intermediates, and non-CA material is ignored. The directory is *added* to
whatever ships bundled (duplicates are collapsed), so it extends the trust store rather
than replacing it. ``genuine verify --anchors DIR`` accepts a directory the same way for
that command alone.

Personalization (``piv perso``)
-------------------------------

.. code-block:: text

   piv perso set-pin                 set the initial PIN (over SCP03)
   piv perso set-puk                 set the initial PUK (over SCP03)
   piv perso set-mgmt-key            set the management key (9B, AES; over SCP03)
   piv perso generate-key            on-card key generation (per the slot's key objects)
   piv perso import-key              inject an externally generated private key
   piv perso import-p12              one-command PKCS#12 (.p12/.pfx) key + certificate import
   piv perso generate-csr            PKCS#10 CSR, signed on-card
   piv perso self-sign-cert          self-signed certificate (dev/test), signed on-card
   piv perso import-cert             write a certificate into the slot container
   piv perso generate-chuid          build a minimal CHUID object
   piv perso generate-ccc            build a minimal CCC object
   piv perso generate-discovery      build the Discovery object
   piv perso write-object            write any data object from a file
   piv perso write-standard-objects  generate + write CHUID and CCC
   piv perso smoke-test              verify PIN + one on-card signature

Notes
-----

* Signing needs a **SIGN-role** slot — 9C on this card; 9A (AUTHENTICATE role)
  returns ``6985`` for sign operations.
* On-card generation works for whichever **mechanisms the slot has a key object
  for**, which is decided by the pre-personalization profile, not by the applet.
  On ``cryptnox-default`` every key object is ECC (P-256/P-384), so RSA has to be
  imported there. ``ms-logon`` also creates an RSA-2048 object on 9A, and
  ``generate-key --slot 9A --algorithm RSA2048`` generates on-card on such a
  card. Asking for a mechanism the slot has no object for returns ``6A80``.
* ``piv quickstart`` defaults to ECC P-256. It accepts ``--algorithm RSA*``
  only for ``--profile ms-logon`` on slot 9A — the one built-in shape with an
  RSA key object — and rejects it elsewhere; pass ``--algorithm RSA2048``
  there for Windows, which does not enumerate EC keys (left on the ECC
  default, that combination warns). For other cards known to carry an RSA
  object, use ``piv perso generate-key`` directly.
* ``piv perso import-key`` is the way to place an **externally generated** RSA
  key. It sends the key as CHANGE REFERENCE DATA ADMIN elements over SCP03 and
  starts with a CLEAR, so re-runs are safe.
* Large objects (certificates) are written with ISO command chaining
  automatically.
* ``piv perso set-mgmt-key`` sets the AES value of key reference 9B, sent as
  CHANGE REFERENCE DATA ADMIN elements over SCP03 (CLEAR, then the raw key —
  same shape as ``import-key``; this admin command is SCP03-only, with no 9B
  alternative. The applet does genuinely support 9B as the PIV standard's
  management key (SP 800-73's Administration Key) for *standard* PIV writes
  (``PUT DATA``, ``GENERATE ASYMMETRIC KEY PAIR``): those accept either an
  open SCP03 admin session or a completed GENERAL AUTHENTICATE (INS 0x87)
  challenge-response with 9B — the genuinely standard part. |cli| only ever
  takes the SCP03 path itself. ``--algorithm`` must match the mechanism the
  pre-personalization profile gave the admin key object (``cryptnox-default``:
  AES256); a mismatch returns ``6A88``.
