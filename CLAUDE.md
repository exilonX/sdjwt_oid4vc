# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Pure-Dart library: **holder** side of SD-JWT VC + OpenID4VCI/OpenID4VP for the
ROeID EUDI wallet (`roeid_flutter`). No Flutter dep. Published on pub.dev.

**Read [`CONTEXT.md`](CONTEXT.md) before changing anything** — it has the
architecture, the decisions, the deviations from the design doc, and the
wire-format caveats. Design rationale: [`docs/SDJWT_OID4VC_LIB.md`](docs/SDJWT_OID4VC_LIB.md);
encrypted-response design: [`docs/DIRECT_POST_JWT.md`](docs/DIRECT_POST_JWT.md).

## Commands

```sh
dart test                                        # full suite (must stay green, 100% line cov)
dart test test/oid4vp/dcql_test.dart             # one file
dart test -N "x5cChain"                          # tests whose name matches
dart analyze --fatal-infos                       # CI gate (strict lints)
dart format . && dart fix --apply                # before committing
dart run example/sdjwt_oid4vc_example.dart       # CI smoke-tests this too
dart pub publish --dry-run                       # packaging gate (CI runs it on every PR)
```

Coverage (keep at 100%):

```sh
dart test --coverage=coverage && dart run coverage:format_coverage --lcov \
  --in=coverage --out=coverage/lcov.info --report-on=lib \
  --packages=.dart_tool/package_config.json
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs Ubuntu only: an SDK
matrix `[3.4.0, stable]` (the pubspec floor is really exercised), plus a
`pointycastle-floor` job that pins pointycastle 3.9.1. So don't use SDK
features newer than 3.4 or pointycastle APIs newer than 3.9.1. `lints` is pinned to
`^4` for the same reason. Releases go out by pushing a `v<version>` tag
(OIDC publish, see [PUBLISHING.md](PUBLISHING.md)); bump `pubspec.yaml` and
`CHANGELOG.md` together.

**SDK gotcha:** this machine may have more than one `dart` on `PATH` (a
standalone one and a Flutter-bundled one). A "language version too high" error
means `.dart_tool/package_config.json` was written by a newer SDK than the one
now running. Re-run `dart pub get` with the same `dart`.

## Architecture in one screen

- `lib/src/core/` holds the injected seams (`Es256Signer`, `Oid4vcHttp`, `Clock`)
  and the shared primitives. **`ec.dart` and `jwe.dart` are the only
  pointycastle/asn1lib users and are not exported.** No crypto type may leak
  into the public API.
- `lib/src/sdjwt/` is the format (parse, resolve, verify, present, KB-JWT, status list).
  `issuer_verifier.dart` is the single place that resolves an issuer key per
  `IssuerTrust` and asserts `alg`/`typ`. It is shared by `verifyIssuer` and
  `StatusListResolver`.
- `lib/src/oid4vci/` and `lib/src/oid4vp/` are the transport. `Oid4vciClient`
  treats the credential as an opaque string. `Oid4vpClient` is still typed to
  `SdJwtVc`, and a future mdoc codec needs a `Credential` interface there
  (CONTEXT §7.5).
- Every URL taken from untrusted input goes through `isSecureUrl`
  (`core/net.dart`): https, or loopback http only.
- Public surface: `lib/sdjwt_oid4vc.dart`. `lib/testing.dart` exports
  `SoftwareEs256Signer` for downstream tests.

## Non-negotiables

- **Keep it key- and HTTP-agnostic.** The library takes an `Es256Signer` and an
  `Oid4vcHttp`; it must never import a key backend or a specific HTTP client.
- **No ambient non-determinism in signing paths.** Time comes from `Clock`,
  salts from an injected generator, so tests are deterministic.
- **Holder role only.** No issuer/verifier server logic, no credential storage,
  no Relying-Party (verifier-cert) trust policy. Those belong to the app/server.
  The library exposes mechanisms, such as `RequestObjectSignature` and
  `IssuerTrust.x5cChain`; the app supplies anchors and makes the trust decision.
- **Maintain 100% line coverage.** Prefer deleting unreachable defensive code
  over leaving it uncovered. Test doubles are in `test/support/`
  (`FakeOid4vcHttp`, `der_cert.dart` for real x5c DER, deterministic
  salts/clock in `util.dart`). Tests may import `package:sdjwt_oid4vc/src/...`.
- Layered on purpose: `sdjwt` (format) is independent of `oid4vci`/`oid4vp`
  (transport) so a future `mdoc` codec reuses the transport. Don't cross-wire.

## Sibling repos (on-device / live validation lives there, not here)

- `../eudi-test-wallet`: Flutter reference wallet (`AttestedKeysSigner` adaptor,
  Mode A in-process mock, Mode B live `*.eudiw.dev`). `EUDI_LIVE_TESTING.md`
  has the live-test steps. It is validated on Android only.
- `../attested_secure_keys/attested_secure_keys`: the hardware-key plugin
  (Keystore / Secure Enclave + App Attest) behind `Es256Signer` in real apps.
