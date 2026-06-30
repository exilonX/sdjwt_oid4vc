# CONTEXT — `sdjwt_oid4vc`

Engineering notes for whoever (agent or human) works on this package next. The
*why* and the *current state*, not a re-statement of the code.

> Read first: [`docs/SDJWT_OID4VC_LIB.md`](docs/SDJWT_OID4VC_LIB.md) (the design
> proposal this implements) and [`docs/EUDI_ONBOARDING.md`](docs/EUDI_ONBOARDING.md)
> (the EUDI program this serves). README.md is the user-facing intro.

## 1. What this is and who uses it

A Dart library implementing the **holder/wallet** side of SD-JWT VC issuance
(OpenID4VCI) and presentation (OpenID4VP). Consumer: the ROeID EUDI wallet in
`roeid_flutter`. The library returns/accepts compact strings; the app does
storage (encrypted Hive) and supplies the holder key (hardware via
`attested_secure_keys`). No Flutter dependency — pure Dart, publishable.

## 2. Status (as of 2026-06-29)

Initial implementation **complete and green**: all four layers, an example, and
**137 tests at 100% line coverage** (`dart test`, `dart analyze` clean under a
strict lint set, `dart pub publish --dry-run` passes with 0 warnings). Version
`0.1.0-dev.1` (pre-release while the API settles). See §9 for repo/CI/release.

Proven elsewhere in the program: the full issue→present→verify loop works on
the reference EUDI wallet with the real IM seal. This library is the native
re-implementation of the holder half; it has **not yet been wired into
`roeid_flutter`** or run against the live `reges-eudi` issuer / verifier — that
is the next milestone (§7).

## 3. Architecture

Two strata, transport over format, so a future `mdoc` codec reuses the
transport untouched.

```
lib/
  sdjwt_oid4vc.dart      public barrel
  testing.dart           SoftwareEs256Signer (package:sdjwt_oid4vc/testing.dart)
  src/
    core/                injected contracts + shared primitives
      es256_signer.dart  Es256Signer, KeyAttestation  (THE injection point)
      http.dart          Oid4vcHttp, HttpResp, DefaultOid4vcHttp
      ec.dart            ES256 verify + JWK/x5c → P-256 key  (pointycastle; NOT exported)
      jwk.dart           RFC 7638 thumbprint
      jws.dart           signing input + compact-JWS decode
      b64u.dart          base64url (unpadded) — the only place the codec lives
      clock.dart         injectable time (no ambient DateTime.now in signing paths)
      errors.dart        sealed Oid4vcError hierarchy
    sdjwt/               the SD-JWT VC codec (format)
      sd_jwt.dart        SdJwt.parse/issue, SdJwtVc.resolveClaims/verifyIssuer/present
      disclosure.dart    Disclosure (parse/forClaim/digest)
      kb_jwt.dart        sd_hash + KB-JWT build
      issuer_trust.dart  IssuerTrust (x5cSignatureOnly | issuerMetadata)
    oid4vci/             issuance transport
      vci_client.dart    Oid4vciClient
      models.dart        CredentialOffer, IssuerMetadata, TokenResponse
    oid4vp/              presentation transport
      vp_client.dart     Oid4vpClient
      dcql.dart          DcqlQuery / DcqlCredentialQuery / DcqlClaim
      models.dart        PresentationRequest, CredentialMatch
```

`ec.dart` is the **only** file that touches pointycastle, and it is not
exported. The codec talks to it through `verifyEs256WithJwk` /
`verifyEs256WithX5c`, so no crypto type leaks into the public API. If you swap
crypto backends, this is the one file to change.

## 4. Key decisions

- **`Es256Signer` is the sole crypto seam.** The library verifies issuer
  signatures itself (it must, to show "trusted") but never *signs* — signing is
  delegated. `SoftwareEs256Signer` (test/example) signs with RFC 6979
  determinism, low-S normalised for third-party verifier interop.
- **Injected time/randomness.** `Clock` defaults to the system clock but is
  overridable; salts come from an injectable generator. This keeps token bytes
  deterministic in tests without an ambient `DateTime.now()`.
- **`x5c` parsed by hand with `asn1lib`.** `ecPublicKeyFromX5cLeaf` walks the
  TBSCertificate for the `ecPublicKey` SubjectPublicKeyInfo and decodes the
  uncompressed point. No `basic_utils`/extra dep. Tests build a real (minimal)
  DER cert via `test/support/der_cert.dart`.
- **Trust is signatures, not chains.** `IssuerTrust` verifies the issuer
  signature (key from `x5c` leaf or `jwt-vc-issuer` metadata). Trusted-List /
  LOTL validation is governance, out of scope. Relying-Party trust (the
  verifier's RPAC) is the *app's* job — see the three-key table in
  `EUDI_ONBOARDING.md §4`; this library only handles key (1) issuer and key (3)
  holder, never key (2) RP.
- **`verifyIssuer` returns `bool` but throws `SdJwtError` when the key cannot be
  resolved** (no `x5c`, unreachable metadata, malformed key). "Key found,
  signature mismatched" → `false`; "couldn't even get a key" → throw. Callers
  should treat both as untrusted but the distinction aids debugging.
- **Models co-located with their client** (`oid4vci/models.dart`,
  `oid4vp/models.dart`) instead of one `src/models/` dir as the design sketch
  drew it. Cohesion over the sketch; noted here so the sketch/lib mismatch isn't
  a surprise.

## 5. Deviations from `docs/SDJWT_OID4VC_LIB.md`

The doc is a *proposal*; these pragmatic changes were made while implementing:

- `requestToken` and `requestCredential` take the already-fetched
  `IssuerMetadata` (and `requestCredential` the `credentialConfigurationId`)
  rather than re-discovering — `redeemOffer` fetches metadata once and threads
  it. Avoids duplicate round-trips.
- Added `requestNonce` (the doc implies `POST /nonce` but didn't list a method)
  and the `nonceEndpoint` on `IssuerMetadata`. `redeemOffer` calls it only when
  the token response carries no `c_nonce`.
- `submit` returns `Future<String?>` (the optional `redirect_uri`) instead of
  `Future<void>` — matches the doc's prose ("returns the redirect/code").
- `SoftwareEs256Signer` is shipped under `package:sdjwt_oid4vc/testing.dart`
  (idiomatic, reusable by downstream tests) rather than living in `test/`.

## 6. Wire-format notes / things to confirm against the live issuer

These follow current OID4VCI/VP drafts but the reference deployments evolve —
verify against `reges-eudi` / `reges-eudi-verifier` when integrating:

- **Credential request body** uses `{credential_configuration_id, proof:
  {proof_type:jwt, jwt}}` and reads back both `credential` (string) and the
  newer `credentials: [...]` shapes. If the issuer expects the plural `proofs:
  {jwt:[...]}` form, adjust `Oid4vciClient.requestCredential`.
- **`key_attestation`** is attached to the credential request body (as
  `attestation.data`) when the signer supplies one. The exact placement
  (request body vs. inside the proof header) and shape are draft-dependent —
  `KeyAttestation` is a `{format, data}` String pair (matching what
  `attested_secure_keys` emits: `format` ∈ {`android-key`, `apple-appattest`,
  `apple-appassert`}, `data` = the chain/CBOR/JWT), so re-shaping the wire form
  is a one-line change. (`KeyAttestation` is a flat String pair, not an enum,
  precisely so it can carry every backend's output without modelling each.)
- **`.well-known` paths are path-aware** (RFC 8414 style): for
  `iss=https://h/p` the metadata is at `https://h/.well-known/<doc>/p`. Tests
  pin this; a live issuer that uses the naive `https://h/p/.well-known/<doc>`
  form would need a tweak in `_wellKnown` / `_wellKnownJwtVcIssuer`.
- **Request Object signature is NOT verified.** `parseRequest`/`fetchRequest`
  decode but do not check the JAR signature; the app must validate the RP
  certificate (`trustedReaderCertificates`) before trusting a request.

## 7. Next steps

1. Wire into `roeid_flutter`: implement `AttestedKeysSigner` (see
   `example/README.md`), one signer per credential (alias = credential id,
   `auth-required`).
2. Run the real loop: redeem a live `extras_salariat` offer from `reges-eudi`,
   present to `reges-eudi-verifier`. Capture real test vectors (a real offer, a
   real DCQL request, a real issuer `x5c`) and add them as fixtures.
3. PID (`urn:eudi:pid:1`) once `pscid-eudi` exists — same transport, possibly
   new claim shapes; resolve-claims already handles nested objects + arrays.
4. Later: `mdoc`/ISO 18013 codec under `src/mdoc/` on the same transport;
   status-list (revocation) checking — `statusRef` is exposed but not yet
   resolved.
   - Transport readiness for mdoc, precisely: `Oid4vciClient` is **already**
     format-agnostic (it moves the credential as an opaque string and never
     parses it). `Oid4vpClient` is **not yet** — `match`/`buildVpToken` are
     typed to `SdJwtVc` and call `.present()`. Generalizing means extracting a
     small `Credential` interface (`vct`/doctype, available claim names,
     `present(...)`) that both `SdJwtVc` and a future `Mdoc` implement; the
     fetch/parse-request/DCQL/submit half of OID4VP stays as-is. The injected
     `Es256Signer` carries over unchanged — mdoc's `DeviceAuth` is a COSE_Sign1
     over ES256, the same raw `R‖S` the signer already returns.

## 8. Working on this package

- `dart test` — full suite. `dart analyze` — must stay clean (strict lints in
  `analysis_options.yaml`: strict-casts/inference/raw-types + extra rules).
- `dart format .` then `dart fix --apply` keeps lints (esp.
  `require_trailing_commas`) satisfied.
- Coverage: `dart test --coverage=coverage` →
  `dart run coverage:format_coverage --lcov --in=coverage --out=coverage/lcov.info --report-on=lib --packages=.dart_tool/package_config.json`.
  Keep it at 100%; if a line is genuinely unreachable defensive code, remove it
  rather than leave it uncovered (that is why `verifyEs256` has no try/catch).
- Test doubles live in `test/support/`: `FakeOid4vcHttp` (handler + request
  log), `der_cert.dart` (builds a real x5c leaf), `util.dart` (deterministic
  salts/clock). Tests may import `package:sdjwt_oid4vc/src/...` directly to
  cover internals (e.g. `ec.dart`).
- Crypto is the risky surface. If you change `ec.dart`, the discriminating tests
  are in `test/core/ec_test.dart` and the end-to-end `test/integration/`.
- **Run the example** from the package root (it is a pure-Dart library, not a
  Flutter app — there is no `lib/main.dart`, so `flutter run` does not apply):
  `dart pub get` then `dart run example/sdjwt_oid4vc_example.dart`.
- **Two-SDK gotcha:** this dev machine has both a standalone Dart on `PATH`
  (older — was 3.4.1) and the Flutter-bundled Dart (3.11). They resolve
  differently. `dart pub get` must run with a Dart ≥ the pubspec floor; a
  "language version too high" error means a stale `.dart_tool/package_config.json`
  written by a newer SDK is being read by the older one. The floor is kept at
  **3.4.0** to match the standalone SDK, which is why `lints` is pinned to `^4`
  (5.x would force ≥3.5). Bump both together if the toolchain moves up.

## 9. Repo, CI & releasing

Repo: <https://github.com/exilonX/sdjwt_oid4vc> (same org/conventions as the
sibling `attested_secure_keys`). Pure-Dart single package — NOT a Flutter plugin
and NOT a melos workspace, so the CI is simpler than the sibling's.

- **CI** ([.github/workflows/ci.yml](.github/workflows/ci.yml)): on push/PR —
  analyze + test + example-smoke across an SDK **matrix `[3.4.0, stable]`** (so
  the declared floor is genuinely exercised), with `dart format` check, coverage
  → Codecov, and a `dart pub publish --dry-run` gate on stable.
- **Publishing** ([.github/workflows/publish.yml](.github/workflows/publish.yml)):
  tokenless via pub.dev + GitHub OIDC, triggered by a `v*` tag using the official
  `dart-lang/setup-dart` reusable workflow. One-time pub.dev setup
  (Admin → Automated publishing) is required before the first tagged release.
- **Versioning**: starts at `0.1.0-dev.1` (pre-release while the API settles),
  mirroring `attested_secure_keys`. `publish_to: none` was removed so the
  dry-run and OIDC publish work; nothing publishes except on a matching tag.
- **License**: Apache-2.0 (`LICENSE`), same as the sibling package.
- Lints are stricter here than the sibling (it uses bare `flutter_lints`); this
  package keeps `package:lints/recommended` + strict analyzer + extra rules.
