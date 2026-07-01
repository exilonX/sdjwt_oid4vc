# sdjwt_oid4vc

[![CI](https://github.com/exilonX/sdjwt_oid4vc/actions/workflows/ci.yml/badge.svg)](https://github.com/exilonX/sdjwt_oid4vc/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/exilonX/sdjwt_oid4vc/branch/main/graph/badge.svg)](https://codecov.io/gh/exilonX/sdjwt_oid4vc)
[![pub package](https://img.shields.io/pub/v/sdjwt_oid4vc.svg)](https://pub.dev/packages/sdjwt_oid4vc)
[![pub points](https://img.shields.io/pub/points/sdjwt_oid4vc)](https://pub.dev/packages/sdjwt_oid4vc/score)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![style: lints](https://img.shields.io/badge/style-lints-40c4ff.svg)](https://pub.dev/packages/lints)

<!-- The pub.dev and Codecov badges activate after the first publish / coverage upload. -->

SD-JWT VC + OpenID4VCI/OpenID4VP protocol library for Dart wallets — the
**holder** role only. It is the piece a wallet app needs to import an
EUDI-style credential and present it to a verifier, with **selective
disclosure** and **key binding**.

There is no comprehensive Dart package for this on pub.dev (only classic OIDC
login clients and partial JOSE libraries), so this is a thin, reusable one,
deliberately scoped to what a wallet does.

## Design in one breath

- **Holder only.** No issuer/verifier server helpers.
- **Key-agnostic.** You inject an [`Es256Signer`]; the library never imports a
  key backend. Hardware (`attested_secure_keys`) is an adaptor; tests use an
  in-memory signer.
- **HTTP-agnostic.** You inject an `Oid4vcHttp` (default: `DefaultOid4vcHttp`
  over `package:http`). Testable with no network.
- **Layered.** Transport (`oid4vci`, `oid4vp`) is separate from format
  (`sdjwt`), so a future `mdoc` codec drops onto the same transport.
- **Pure.** No hidden I/O, no ambient clock — time and randomness are injected,
  so every signing path is deterministic under test.

## Install

```yaml
dependencies:
  sdjwt_oid4vc:
    git: https://github.com/exilonX/sdjwt_oid4vc
```

## The two seams you provide

Everything below takes the same two injected objects:

| Seam | Interface | Do you implement it? |
|---|---|---|
| Holder key | `Es256Signer` | **Yes** — there is no default; only you can reach your key. |
| HTTP transport | `Oid4vcHttp` | **No, usually** — pass `DefaultOid4vcHttp()`. |

`Es256Signer` is the one required adaptor. In production it wraps a
hardware-backed key (see [`example/README.md`](example/README.md) for the real
[`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys)
adaptor); in tests use the bundled `SoftwareEs256Signer`. It is three methods:
`publicJwk()`, `signEs256(signingInput)` (return raw `R‖S` base64url), and an
optional `attest(nonce)`.

`Oid4vcHttp` is just GET / form-POST / JSON-POST plumbing — **not** your API
logic. The OpenID4VCI/OpenID4VP endpoint choreography (which endpoints, what
bodies) already lives in `Oid4vciClient` / `Oid4vpClient`. Use the default
`DefaultOid4vcHttp` (over `package:http`) unless you want Dio, interceptors,
logging, certificate pinning, or a fake for tests — then implement the three
methods over your client of choice.

## Receive a credential (OpenID4VCI)

```dart
final signer = /* your Es256Signer, e.g. hardware-backed */;
final vci = Oid4vciClient(DefaultOid4vcHttp());

final compact = await vci.redeemOffer(
  offerUriOrJson: deepLink, // openid-credential-offer://...
  txCode: codeFromEmail,    // the one-time activation code
  signer: signer,
);

final credential = SdJwt.parse(compact);
if (!await credential.verifyIssuer(IssuerTrust.signatureOnly())) {
  throw StateError('issuer signature did not verify');
}
// Store `compact`; show credential.resolveClaims() to the user.
```

## Present a credential (OpenID4VP)

```dart
final vp = Oid4vpClient(DefaultOid4vcHttp());

final request = await vp.fetchRequest(authorizationRequest); // QR / deep link
final match = vp.match(request, heldCredentials);
if (match == null) return; // nothing satisfies the query

final vpToken = await vp.buildVpToken(
  credential: match.credential,
  revealClaims: match.requestedClaims, // disclose only what was asked
  req: request,
  signer: signer, // signs the KB-JWT → proof of possession
);
await vp.submit(req: request, vpToken: vpToken);
```

See [`example/`](example/) for a runnable end-to-end walk-through and the
hardware-key adaptor.

## Testing

`package:sdjwt_oid4vc/testing.dart` exposes `SoftwareEs256Signer`, a real P-256
key in memory. With it (and a fake `Oid4vcHttp`) the whole flow runs without
hardware or network. The suite has **100% line coverage**.

```sh
dart test
```

## Scope

In: SD-JWT VC (`dc+sd-jwt`) parse/resolve/verify/present (including nested and
array claims by DCQL path), OpenID4VCI pre-authorized-code issuance, OpenID4VP
presentation with DCQL (single and multi-credential `credential_sets`), KB-JWT,
issuer trust via `x5c` signature, **`x5c` chain validation** to caller-supplied
anchors, or `jwt-vc-issuer` metadata, **revocation** via the IETF Token Status
List, and the **request-object signature** exposed so the wallet can
authenticate the verifier.

Out (for now): mdoc/ISO 18013, W3C JSON-LD VC, OIDC login, issuer/verifier
server roles, and credential storage. The library does the *mechanism* but
leaves the *governance data* to the app: it validates an issuer `x5c` chain
against trust anchors **you provide** (fetching/parsing the EU Trusted List is
yours), it verifies a Relying-Party's request signature on demand but **you**
decide whether to trust the certificate, and certificate revocation (CRL/OCSP)
is out of scope.

## Context

Built for an EUDI wallet (holder role). Design rationale:
[`docs/SDJWT_OID4VC_LIB.md`](docs/SDJWT_OID4VC_LIB.md), engineering notes for
contributors: [`CONTEXT.md`](CONTEXT.md).
