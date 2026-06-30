# CLAUDE.md

Pure-Dart library: **holder** side of SD-JWT VC + OpenID4VCI/OpenID4VP for the
ROeID EUDI wallet (`roeid_flutter`). No Flutter dep.

**Read [`CONTEXT.md`](CONTEXT.md) before changing anything** — it has the
architecture, the decisions, the deviations from the design doc, and the
wire-format caveats. Design rationale: [`docs/SDJWT_OID4VC_LIB.md`](docs/SDJWT_OID4VC_LIB.md).

## Commands

```sh
dart test                              # full suite (must stay green, 100% line cov)
dart analyze                           # must stay clean (strict lints)
dart format . && dart fix --apply      # before committing
dart run example/sdjwt_oid4vc_example.dart
```

## Non-negotiables

- **Keep it key- and HTTP-agnostic.** The library takes an `Es256Signer` and an
  `Oid4vcHttp`; it must never import a key backend or a specific HTTP client.
  All crypto stays inside `src/core/ec.dart` (the only pointycastle user, not
  exported).
- **No ambient non-determinism in signing paths.** Time comes from `Clock`,
  salts from an injected generator — so tests are deterministic.
- **Holder role only.** No issuer/verifier server logic, no credential storage,
  no Relying-Party (verifier-cert) trust — those belong to the app/server.
- **Maintain 100% line coverage.** Prefer deleting unreachable defensive code
  over leaving it uncovered. Test doubles are in `test/support/`.
- Layered on purpose: `sdjwt` (format) is independent of `oid4vci`/`oid4vp`
  (transport) so a future `mdoc` codec reuses the transport. Don't cross-wire.
