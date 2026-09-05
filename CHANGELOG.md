# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RSA4096` alongside the existing algorithms: `perso generate-key`,
  `perso import-key`, CSR/self-signed-cert signing, and profile key
  mechanisms.
- `perso generate-key --create-key-object` - the same dev/eval fallback
  `import-key` already had.
- `perso set-mgmt-key` - set the PIV management key (9B, AES) via CHANGE
  REFERENCE DATA ADMIN over SCP03, the same shape as `set-pin`/`set-puk`.
- `piv status` now reports whether the management key (9B) is set, alongside
  PIN/PUK status.

## [1.0.3] - 2026-08-31

### Changed

- Package metadata: marked Production/Stable and declared the dual license
  (LGPL-3.0-or-later or commercial) as an SPDX expression.

## [1.0.2] - 2026-08-31

### Added

- CI workflow that publishes tagged releases to PyPI.

## [1.0.1] - 2026-08-28

### Fixed

- Install instructions lead with pipx: global `cryptnox-id` command, and works
  where PEP 668 blocks system-Python installs. venv stays for development.

## [1.0.0] - 2026-08-28

### Added

- **PIV (SP 800-73)** — read-only inspection (`info`, `status`, `slots`,
  `discover`, `validate`), PIN/PUK lifecycle (`pin verify`/`change`/`unblock`,
  `puk change`), certificate and data-object access, and the `piv perso`
  personalization set: on-card key generation, external key and PKCS#12 import,
  CSR and self-signed certificates signed on-card, CHUID/CCC objects, and a
  post-personalization smoke test.
- `piv quickstart` — one-shot personalization chaining pre-personalization
  through PIN/PUK, key, certificate, CHUID/CCC and a smoke test over a single
  card connection, skipping whatever is already done.
- **Factory pre-personalization** (`factory piv preperso`) — profile-driven
  applet structure over SCP03, with built-in profiles (`cryptnox-default`,
  `ms-logon`, `ssh`, `developer`, `npivp-lab`), YAML import/export, a dry-run
  mode, and the irreversible `finalize` behind a typed confirmation.
- **FIDO2 / CTAP 2.1** — `ping`, `info`, PIN status/set/change, credential
  create/assert/self-test/list/delete, `authenticatorConfig` policy (`alwaysUv`,
  minimum PIN length), and a gated `reset`. On Windows, a non-elevated `fido`
  command offers to relaunch itself through a UAC prompt and shows the elevated
  result in the original window.
- **MIFARE DESFire EV2/EV3** — application and file management, AES key
  operations, MACed reads and writes, value and record files, and EV3 Secure
  Dynamic Messaging (`sdm setup` / `sdm read`) per NXP AN12196.
- **Genuineness / attestation** — read-only device-key proof of possession and
  certificate-chain verification, plus PIV key-attestation export and
  validation. The Cryptnox production root ships pinned in the package, with the
  intermediates bundled so chains build offline; `$CRYPTNOX_TRUST_DIR` and
  `--anchors` add anchors without a rebuild. A chain no pinned root covers is
  reported as unverifiable, never as passing.
- `cryptnox-id shell` — an interactive prompt that runs subcommands without the
  `cryptnox-id` prefix, suitable for launching from a desktop shortcut.
- Cross-cutting: `readers`/`info`/`doctor` diagnostics, secret-safe JSON reports
  (`report …`), machine-readable `--json` output on every command, a redacted
  APDU log (`--apdu-log`), and raw APDU access for developers. With no
  `--reader`, the tool auto-selects the single Cryptnox/ACS reader holding a
  card and refuses to guess otherwise.
- Three interchangeable console commands: `cryptnox-id`, the short `cnx-id`,
  and `cryptnox-id-card`.

[Unreleased]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/cryptnox/cryptnox-id-cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/cryptnox/cryptnox-id-cli/releases/tag/v1.0.0
