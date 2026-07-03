# Changelog

## 0.1.2

- **Nested-claim DCQL matching** — `match`/`satisfiesRequest` now check requested
  claim *paths* (nested `["place_of_birth","locality"]`, array `["nationalities",
  0]`, and the `[…, null]` all-elements wildcard) against the reconstructed claim
  tree, not just top-level names. Presenting those paths already worked
  (`present(disclosePaths:)`); matching no longer falsely accepts a request for a
  nested claim the credential lacks.

## 0.1.1

OpenID4VP **`direct_post.jwt`** — encrypted authorization responses. Closes the
presentation leg against OpenID4VP 1.0-Final verifiers (e.g. the EUDI reference),
which require the `vp_token` to be POSTed as an encrypted JWE, not a plaintext
form field. All additive; the plain `direct_post` path is unchanged.

- **`Oid4vpClient.present(req, match, signer)`** — one call that builds the
  KB-JWT-bound presentation, assembles the 1.0-final `vp_token`, and submits it
  in whatever `response_mode` the request asked for (encrypting for
  `direct_post.jwt`).
- **`Oid4vpClient.submitResponse(req, vpToken)`** — response-mode-aware submit;
  **`buildVpTokenMap(...)`** builds the 1.0-final `{queryId: [presentation]}`
  shape. Failed submits now include the verifier's response body.
- **`PresentationRequest.responseEncryption`** (`ResponseEncryption`) — the
  verifier's ephemeral `use:enc` key + chosen `enc`, parsed from
  `client_metadata` (1.0-final; `ECDH-ES` direct, `A128GCM`/`A256GCM`).
- New internal `core/jwe.dart`: an ECDH-ES (direct) + Concat-KDF + AES-GCM
  compact-JWE encrypter (pointycastle; the only place the library generates a
  key). Verified against the RFC 7518 Appendix C Concat-KDF vector.

## 0.1.0-dev.2

No library changes since `dev.1`. This release validates the automated,
tag-triggered pub.dev publish pipeline (OIDC) end-to-end — `dev.1` was published
by hand.

## 0.1.0-dev.1

First pre-release. Security hardening and the features a general-purpose wallet
needs before production. All additive — existing call sites keep working.

- **Hardening (sdjwt/core)** — `verifyIssuer` now asserts the issuer JWT
  `alg`/`typ` before any key work (key resolution shared via a new internal
  `issuer_verifier`); `resolveClaims` bounds nesting depth and rejects duplicate
  disclosure digests and disclosed/clear claim collisions; all fetched URLs
  (metadata, JWKS, status lists, offers, request objects) must be `https`
  (loopback `http` allowed for dev).
- **Issuer chain validation** — new `IssuerTrust.x5cChain(trustAnchors)` mode
  validates the `x5c` chain (each link's ECDSA-SHA256 signature, every
  certificate's validity window, and anchoring to a caller-supplied trust
  anchor) before verifying with the leaf key. The Trusted List itself (the EU
  LOTL — which anchors) is app-provided; revocation (CRL/OCSP) and name/policy
  constraints remain out of scope.
- **Validity** — `notBefore` / `isNotYetValid` / `isValid(At)` getters, and an
  optional `enforceValidity` on `verifyIssuer` that folds the `nbf`..`exp`
  window into the result.
- **RP authentication (oid4vp)** — `PresentationRequest.signature` now exposes
  the request object's signing material (`x5c`, `alg`, `kid`, signing input)
  with `verifyWithX5cLeaf()` / `verifyWithJwk()` helpers, plus
  `clientIdScheme` / `clientIdValue`. The wallet still owns the trust decision.
- **Revocation** — `StatusListResolver` + `StatusListRef` / `CredentialStatus`
  resolve a credential's Token Status List entry (fetch, optional signature
  verification, zlib inflate, bit read). `SdJwtVc.statusListRef` exposes the
  reference. Adds an `archive` dependency for zlib inflate.
- **Multi-credential DCQL** — parses `credential_sets`; `matchAll`,
  `satisfiesRequest`, and `buildVpTokenObject` handle requests for several
  credentials at once.
- **Nested presentation** — `present` gains `disclosePaths` (full DCQL claim
  paths, including nested objects, array indices, and the `null` "all elements"
  wildcard), pulling in each path's ancestor disclosures.
- **Dependency** — `pointycastle` widened to `>=3.9.1 <5.0.0` (was `^4.0.0`).
  The library uses only stable 3.9+ primitives, so a wallet pinned to
  pointycastle 3.9.x (e.g. for PDF signing / NFC) resolves it with no dependency
  override. Verified on both 3.9.1 and 4.0.0; a CI job pins the floor.

## 0.1.0-dev.1 (unreleased)

Initial implementation of the holder/wallet protocol stack.

- **core** — injected `Es256Signer` and `Oid4vcHttp` contracts,
  `DefaultOid4vcHttp`, ES256 (P-256) verification with key resolution from JWK
  or `x5c`, RFC 7638 JWK thumbprint, base64url, compact-JWS helpers, injectable
  clock, sealed `Oid4vcError` hierarchy.
- **sdjwt** — SD-JWT VC codec: parse, `resolveClaims` (nested objects + array
  disclosures), `verifyIssuer` (`x5c` signature-only or `jwt-vc-issuer`
  metadata), `present` (selective disclosure + KB-JWT), and `issue` (for tests).
- **oid4vci** — `Oid4vciClient` for the pre-authorized-code flow:
  `parseOffer`, `fetchIssuerMetadata`, `requestToken`, `requestNonce`,
  `buildProof`, `requestCredential`, `redeemOffer`.
- **oid4vp** — `Oid4vpClient`: `fetchRequest`/`parseRequest`, DCQL `match`,
  `buildVpToken`, `submit`.
- **testing** — `SoftwareEs256Signer` (real in-memory P-256 key) under
  `package:sdjwt_oid4vc/testing.dart`.
- Test suite at 100% line coverage; `dart analyze` clean under strict lints.
