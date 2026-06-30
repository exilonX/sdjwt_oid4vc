# Changelog

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
