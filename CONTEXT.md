# CONTEXT — `sdjwt_oid4vc`

Engineering notes for whoever (agent or human) works on this package next. The
*why* and the *current state*, not a re-statement of the code.

> Read first: [`docs/SDJWT_OID4VC_LIB.md`](docs/SDJWT_OID4VC_LIB.md) (the design
> proposal this implements). README.md is the user-facing intro.

## 1. What this is and who uses it

A Dart library implementing the **holder/wallet** side of SD-JWT VC issuance
(OpenID4VCI) and presentation (OpenID4VP). Consumer: the ROeID EUDI wallet in
`roeid_flutter`. The library returns/accepts compact strings; the app does
storage (encrypted Hive) and supplies the holder key (hardware via
`attested_secure_keys`). No Flutter dependency — pure Dart, publishable.

## 2. Status (as of 2026-06-30)

Implementation **complete and green**: all four layers, an example, and
**200 tests at 100% line coverage** (`dart test`, `dart analyze` clean under a
strict lint set, `dart pub publish --dry-run` clean bar the dirty-tree
advisory). Version `0.1.0-dev.2` (pre-release while the API settles). See §9 for
repo/CI/release.

`0.1.0-dev.1` added the security hardening + the features a general-purpose
wallet needs (CHANGELOG has the list): `alg`/`typ` assertion on verify, HTTPS
enforcement, depth/duplicate-digest guards in `resolveClaims`, `nbf`/validity
enforcement, **issuer chain validation** (`IssuerTrust.x5cChain`), **RP request
authentication** (request-object signature exposed for the wallet to verify),
**revocation** (Token Status List resolver), **multi-credential DCQL**
(`credential_sets`), and **nested/array disclosure selection** in `present`.
What stays the app's: the **Trusted List data** itself (which anchors / the EU
LOTL), and certificate **revocation** (CRL/OCSP) — see §4, §7.

The full issue→present→verify loop has been proven end-to-end against a
reference EUDI wallet and a real qualified issuer seal. This library is the
native Dart re-implementation of the holder half; it has **not yet been wired
into a production wallet** or run against a live issuer / verifier — that is the
next milestone (§7).

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
      ec.dart            ES256 verify + JWK/x5c → P-256 key + X.509 chain validation  (pointycastle/asn1lib; NOT exported)
      jwe.dart           ECDH-ES + Concat-KDF + AES-GCM compact-JWE encrypt for direct_post.jwt  (pointycastle; NOT exported)
      net.dart           isSecureUrl — https-or-loopback gate for fetched URLs
      jwk.dart           RFC 7638 thumbprint
      jws.dart           signing input + compact-JWS decode
      b64u.dart          base64url (unpadded) — the only place the codec lives
      clock.dart         injectable time (no ambient DateTime.now in signing paths)
      errors.dart        sealed Oid4vcError hierarchy (incl. StatusError)
    sdjwt/               the SD-JWT VC codec (format)
      sd_jwt.dart        SdJwt.parse/issue, SdJwtVc.resolveClaims/verifyIssuer/present
      disclosure.dart    Disclosure (parse/forClaim/digest)
      kb_jwt.dart        sd_hash + KB-JWT build
      issuer_trust.dart  IssuerTrust (x5cSignatureOnly | x5cChain | issuerMetadata)
      issuer_verifier.dart  shared key-resolution + alg/typ guard (NOT exported)
      status_list.dart   StatusListResolver, StatusListRef, CredentialStatus
    oid4vci/             issuance transport
      vci_client.dart    Oid4vciClient
      models.dart        CredentialOffer, IssuerMetadata, TokenResponse
    oid4vp/              presentation transport
      vp_client.dart     Oid4vpClient (match/matchAll/buildVpToken/buildVpTokenObject)
      dcql.dart          DcqlQuery / DcqlCredentialQuery / DcqlClaim / DcqlCredentialSet
      models.dart        PresentationRequest (+ RequestObjectSignature, ResponseEncryption), CredentialMatch
```

`issuer_verifier.dart` is the single home for "resolve the issuer key per an
`IssuerTrust` and ES256-verify a JWS", shared by `SdJwtVc.verifyIssuer` (the
credential seal) and `StatusListResolver` (the status list token is itself an
issuer-signed JWT). It asserts `alg == ES256` and a caller-supplied `typ` set
before any key work. `status_list.dart` uses `package:archive` for the zlib
inflate of the status bitstring (pure Dart, no platform import).

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
- **Three issuer-trust modes.** `IssuerTrust` offers `signatureOnly` (key from
  the `x5c` leaf — integrity only), `x5cChain(trustAnchors)` (validate the chain
  to a caller-supplied anchor, then verify with the leaf), and `issuerMetadata`
  (key from `jwt-vc-issuer` metadata). `x5cChain` checks each link's
  ECDSA-SHA256 signature, every cert's validity window, and anchoring (top is —
  or is signed by — a currently-valid anchor); it does **not** do revocation
  (CRL/OCSP) or name/policy constraints, and the **anchors themselves** (the EU
  LOTL) are app-provided. The X.509 parsing/verify lives in `ec.dart`
  (`parseX509Certificate`, `certificateSignedBy`, `verifyEs256WithX5cChain`) so
  no crypto/ASN.1 type leaks out; `issuer_verifier` just orchestrates.
- **RP auth is mechanism-here, policy-there.** The library no longer discards
  the OID4VP request object's signature: `PresentationRequest.signature`
  (`RequestObjectSignature`) exposes the `x5c`/header/signing-input and offers
  `verifyWithX5cLeaf()` / `verifyWithJwk()` to confirm *integrity*. The wallet
  still owns the *trust* decision (chain to a reader trust anchor, SAN matches
  `clientIdValue`). The three keys split like this: key (1) issuer and key (3)
  holder fully here; key (2) RP — verify mechanism here, trust policy in the app.
- **`alg`/`typ` asserted before key work.** Defence-in-depth (the verify path is
  ES256-only regardless, so alg-confusion was never exploitable) plus
  cross-type-confusion protection (a status list token can't pass where a
  credential is expected). Lives in `issuer_verifier`.
- **HTTPS or loopback only.** Every URL dereferenced from untrusted input goes
  through `isSecureUrl` (`core/net.dart`): `https`, or `http` to
  localhost/127.0.0.1/::1 for dev. Keeps issuer keys / status lists off
  cleartext.
- **Revocation via `package:archive`.** The Token Status List bitstring is
  zlib-DEFLATE; `archive` gives a pure-Dart inflate with no platform import
  (keeps the library web-safe), at the cost of one extra dependency. `dart:io`'s
  `ZLibCodec` was the zero-dep alternative but would have bound the package to
  non-web platforms.
- **`present` selects by name *and* path.** Back-compat `disclose` (top-level
  names) plus `disclosePaths` (full DCQL paths). Path selection walks the
  credential to index each disclosure's path + ancestor chain, so revealing a
  nested claim also reveals the parent disclosures it needs to resolve.
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

These follow current OID4VCI/VP drafts but live deployments evolve — verify
against your target issuer / verifier when integrating:

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
- **Request Object signature is exposed, not auto-verified.**
  `parseRequest`/`fetchRequest` no longer discard the JAR signature — it is on
  `PresentationRequest.signature` with `verifyWithX5cLeaf()` / `verifyWithJwk()`.
  The app still validates the RP certificate (`trustedReaderCertificates`, SAN
  vs. `clientIdValue`) before trusting a request; the library only does the
  ES256 integrity check on demand. (These helpers are ES256-only — check
  `signature.alg` if a verifier might use another algorithm.)
- **Status list (revocation).** `StatusListResolver` follows the IETF Token
  Status List draft: `GET` the `statuslist+jwt`, optional issuer-signature
  verify, zlib-inflate `status_list.lst`, read `bits`-wide value at the index
  (LSB-first packing). Confirm against the live issuer's `bits`, the
  `Accept`/media type, and whether the token's `sub` must equal the list URI
  (not enforced yet).
- **Response modes.** `direct_post` and **`direct_post.jwt`** (encrypted) are
  both supported; `present()`/`submitResponse()` pick by `response_mode` and emit
  the OpenID4VP 1.0-final `vp_token` object-of-arrays (`{queryId: [presentation]}`
  via `buildVpTokenMap`). `direct_post.jwt` encrypts `{state, vp_token}` to the
  verifier's ephemeral `client_metadata` key with ECDH-ES (direct) + AES-GCM
  (`core/jwe.dart`); only that alg family is handled (no key-wrap / RSA / mdoc
  `apu`). The older `buildVpToken`/`buildVpTokenObject` (bare-string values) stay
  for legacy/plain callers.

## 7. Next steps

1. Wire into `roeid_flutter`: implement `AttestedKeysSigner` (see
   `example/README.md`), one signer per credential (alias = credential id,
   `auth-required`).
2. Run the real loop against a live issuer/verifier: redeem an offer, present
   the credential. Capture real test vectors (a real offer, a real DCQL request,
   a real issuer `x5c`) and add them as fixtures.
3. PID (`urn:eudi:pid:1`) once a PID issuer exists — same transport, possibly
   new claim shapes; resolve-claims already handles nested objects + arrays, and
   `present(disclosePaths:)` now selects nested/array claims by DCQL path.
4. **Trust anchors / LOTL wiring** — the chain *mechanism* is done
   (`IssuerTrust.x5cChain`); what's left is the *data*: the app fetches/parses
   the EU LOTL (or a configured anchor set) and feeds the DER anchors in. Same
   pattern for RP trust anchors on the (now exposed) request signature. Optional
   later: certificate revocation (CRL/OCSP), which `x5cChain` does not do.
5. Later: `mdoc`/ISO 18013 codec under `src/mdoc/` on the same transport.
   (Revocation of *credentials* is implemented — `StatusListResolver`.)
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
- **`pointycastle` is `>=3.9.1 <5.0.0`** so a wallet pinned to pointycastle
  3.9.x (the ROeID app, for PDF signing / NFC) resolves it with no override. We
  use only stable 3.9+ primitives. One sharp edge: `generateKeyPair()` returns
  the generic `Private/PublicKey` on 3.9.x and the narrowed types on 4.x, so
  `software_signer.dart` types the pair as `AsymmetricKeyPair<PublicKey,
  PrivateKey>` and downcasts — necessary (hence warning-free) on both. The
  `pointycastle-floor` CI job pins 3.9.1 and runs the suite to keep this true.
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
