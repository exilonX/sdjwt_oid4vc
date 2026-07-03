# Design: OpenID4VP `direct_post.jwt` (encrypted authorization response)

- **Status:** Implemented (0.1.1) — `core/jwe.dart`, `Oid4vpClient.present`/`submitResponse`/`buildVpTokenMap`, `PresentationRequest.responseEncryption`. Decisions taken from §11: high-level `present()` **and** low-level `submitResponse()`; `enc` default `A128GCM`; multi-credential deferred (the map helper is ready); KAT pinned to the RFC 7518 Appendix C Concat-KDF vector.
- **Date:** 2026-07-02
- **Scope:** `sdjwt_oid4vc` (holder / `Oid4vpClient`)
- **Motivates:** closing the OpenID4VP presentation leg against the live EUDI reference verifier; freezing the VP-response wire format for `0.1.0`.

## TL;DR

The library can build and submit a plain `direct_post` presentation, but the EUDI reference
verifier (and OpenID4VP 1.0 Final's privacy default) uses **`response_mode: direct_post.jwt`** — the
wallet must POST an **encrypted JWE** carrying the `vp_token`, not a plaintext form field. Today
`Oid4vpClient.submit()` POSTs `vp_token=<compact>` and the verifier rejects it with **HTTP 400
`UnexpectedResponseMode`** *before* any decryption.

This adds, to `sdjwt_oid4vc`:

1. parsing of the request's `client_metadata` (the verifier's **ephemeral** encryption key + params),
2. a small **ECDH-ES → Concat-KDF → AES-GCM compact-JWE** encrypter (`core/jwe.dart`),
3. the OpenID4VP **1.0-final `vp_token` shape** (object keyed by DCQL query id, values are arrays) plus `state`,
4. a **response-mode-aware submit** that encrypts when `direct_post.jwt` is requested,
5. surfacing the response body on submit failure.

Everything else in the presentation flow already works end-to-end against live EUDI (verified on
device): `fetchRequest`, `verifyWithX5cLeaf` on the `x509_hash` JAR, DCQL `match`, and the
hardware-signed KB-JWT.

---

## 1. The finding (root cause)

Verified on a real device against `issuer.eudiw.dev` / `verifier.eudiw.dev`:

- Issuance (OpenID4VCI) is fully validated — a real EUDI PID SD-JWT VC is held, issuer-trusted via
  `x5cChain`, status valid.
- Presentation runs correctly through the **hardware KB-JWT**, then `submit()` returns **400**.

The 400 is **not** a crypto/parsing error. The EUDI verifier checks the response mode first: a
`direct_post.jwt` presentation that receives a plain `direct_post` body (a `vp_token` form field) is
rejected as `UnexpectedResponseMode` before decryption is attempted
(`eudi-srv-verifier-endpoint` `PostWalletResponse.kt:326-347`). So this is purely a **missing
response-encryption path**, not a bug in what we already send.

Target version: **OpenID for Verifiable Presentations 1.0, Final (2025-07-09)** — the version the EUDI
reference implements (holder lib `OpenId4VPSpec.kt`, and the `x509_hash` / `dc+sd-jwt` /
`encrypted_response_enc_values_supported` naming in the live request).

---

## 2. Goals / non-goals

**Goals**

- Send a spec-conformant `direct_post.jwt` response that the EUDI verifier accepts (HTTP 200).
- Keep it holder-only, pure-Dart, and use the primitives already present (`pointycastle`, `asn1lib`).
- No change to the existing plain-`direct_post` path or to issuance.

**Non-goals (explicitly out of scope for this change)**

- `mso_mdoc` responses / the `apu` = mdoc-nonce / ISO 18013-7 SessionTranscript path.
- `ECDH-ES+A128KW`/`+A256KW` (key-wrap) or `RSA-OAEP` alg families — EUDI uses **`ECDH-ES` direct**.
- Encrypting the *request* (we only decrypt-free-read requests) or signed **and** encrypted responses.
- Presentation Exchange (`presentation_submission`) — DCQL only.
- The nested-claim DCQL gap (see §10) — tracked separately.

---

## 3. Target wire contract (what a conformant wallet sends)

### 3.1 The POST

- `POST` the request's `response_uri`.
- `Content-Type: application/x-www-form-urlencoded`.
- **Exactly one field:** `response=<compact JWE>`. `state` is **not** a form field here — it lives inside
  the JWE plaintext.
- Success: **HTTP 200**. Body is `{"redirect_uri": "…?response_code=…"}` when the transaction was
  initialized with a redirect template, otherwise an empty 200 (poll mode). The wallet should follow
  `redirect_uri` if present.

### 3.2 The JWE (an unsigned, encrypted JWT — RFC 7516)

Protected header:

| field | value | notes |
|---|---|---|
| `alg` | `ECDH-ES` | direct key agreement — **no** key-wrap; must equal the recipient JWK's `alg` |
| `enc` | `A128GCM` (default) or `A256GCM` | first of `encrypted_response_enc_values_supported` we support |
| `kid` | the verifier enc key's `kid` | **mandatory**; selects the verifier's per-transaction key |
| `epk` | our ephemeral P-256 public JWK `{kty,crv,x,y}` | fresh per response |
| `apv` | `base64url(nonce)` | `nonce` = the request's `nonce` |
| `apu` | **omitted** | (only `mso_mdoc` sets `apu`) |

The encrypted-key segment of the compact JWE is **empty** (direct ECDH-ES: the KDF output *is* the CEK).

### 3.3 The JWE plaintext (JWT claims)

For a single `dc+sd-jwt` DCQL credential whose query `id` is `pid`:

```json
{
  "state": "<request.state>",
  "vp_token": { "pid": ["<issuer-sd-jwt>~<disclosure>~…~<kb-jwt>"] }
}
```

- `vp_token` is a **JSON object keyed by the DCQL query id**; each value is an **array** of
  presentation strings (one presentation ⇒ a one-element array). Not a bare string, not a top-level
  array. This is the 1.0-final DCQL shape.
- The array element for `dc+sd-jwt` is the compact SD-JWT **with the KB-JWT appended**
  (`…~<kb-jwt>`) — exactly what `credential.present(...)` / `buildVpToken(...)` already returns.
- `state` is **required** and must equal the request's `state` (the verifier hard-checks it).
- No `presentation_submission` (that is Presentation Exchange; DCQL replaces it).

### 3.4 The encryption key is ephemeral

`client_metadata.jwks.keys[]` carries a **fresh per-transaction** EC `use:enc` key. Read it from every
request; never cache it. The old JARM fields `authorization_encrypted_response_alg`/`_enc` are **absent**
in 1.0-final: `alg` comes from the JWK's own `alg`, `enc` from `encrypted_response_enc_values_supported`.

_Live example (captured):_ enc JWK `{kty:EC, crv:P-256, use:enc, alg:ECDH-ES, kid:e07bbf08-…, x:…, y:…}`,
`encrypted_response_enc_values_supported: ["A128GCM","A256GCM"]`, `response_mode:"direct_post.jwt"`,
`nonce:"abcdefgh1234567890"`, DCQL query id `pid`.

---

## 4. Current implementation & gaps

| Concern | Where | Gap |
|---|---|---|
| Submit | `lib/src/oid4vp/vp_client.dart:174-198` — `submit()` `postForm({vp_token, state})` | plain `direct_post` only; no `direct_post.jwt` |
| Request parse | `vp_client.dart:213-239` — `_requestFromJson` | ignores `client_metadata`; enc key/params never captured |
| Request model | `lib/src/oid4vp/models.dart:31-80` — `PresentationRequest` | no `response_mode` encryption fields |
| vp_token build | `vp_client.dart:135-170` — `buildVpToken` (bare string), `buildVpTokenObject` (`{id: string}`) | neither emits the 1.0-final `{id: [string]}` array shape |
| Crypto | `lib/src/core/ec.dart` | ECDSA **verify** + JWK/x5c → `ECPublicKey` + `p256` domain params exist; **no** ECDH, ephemeral keygen, Concat-KDF, or AES-GCM |
| JWK | `lib/src/core/jwk.dart` — `Jwk.thumbprint` | fine for the `epk` `kid`; enc key is read as a plain `Map` |
| Errors | `vp_client.dart:186-190` | `submit` throws `Presentation submit failed (<status>)` without the body |

`pointycastle` (already a dependency) provides everything the JWE needs:
`ECKeyGenerator`, `ECDHBasicAgreement`, `SHA256Digest`, `GCMBlockCipher`/`AESEngine`.

---

## 5. Design / change set

### 5.1 Parse `client_metadata` → a `ResponseEncryption` value

Extend `_requestFromJson` to read `client_metadata` and, when present, build a small immutable value
carried on `PresentationRequest`:

```dart
class ResponseEncryption {
  final Map<String, dynamic> recipientJwk; // the use:enc EC JWK (kty/crv/x/y/kid/alg)
  final String alg;                        // 'ECDH-ES' (from the JWK's alg)
  final String enc;                        // chosen from encrypted_response_enc_values_supported
  final String? kid;                       // recipientJwk['kid'] — echoed into the JWE header
}
```

Selection rules (1.0-final):
- `recipientJwk` = first `client_metadata.jwks.keys[]` with `use == 'enc'`, `kty == 'EC'`, `crv == 'P-256'`.
- `alg` = `recipientJwk['alg']` (must be `ECDH-ES`; reject others for now).
- `enc` = first of `client_metadata.encrypted_response_enc_values_supported` we support, preferring
  `A128GCM`, else `A256GCM`. Default `A128GCM` when the list is absent.

Add `PresentationRequest.responseEncryption` (nullable). Purely additive — the plain path leaves it null.

### 5.2 vp_token in the 1.0-final DCQL shape

Add a helper that assembles the response `vp_token` object from one or more matches:

```dart
// { "<queryId>": ["<compact sd-jwt ~ kb-jwt>"] }
Map<String, List<String>> vpTokenByQueryId; // one entry per presented credential
```

For the common single-credential case this is `{ match.queryId : [ await buildVpToken(...) ] }`.
(`buildVpTokenObject` already keys by query id but emits string values — align it to arrays, or route
`direct_post.jwt` through this new helper and leave `buildVpTokenObject` for legacy callers.)

### 5.3 New `lib/src/core/jwe.dart` — ECDH-ES compact-JWE encrypter

A single not-exported function; the only new crypto in the library.

```dart
/// Encrypts [plaintext] to a compact JWE for [recipientJwk] using
/// ECDH-ES (direct) key agreement + AES-GCM ([enc] = 'A128GCM' | 'A256GCM').
/// Adds `epk`, `kid`, and `apv` to the protected header. `apu` is omitted.
String encryptCompactJweEcdhEs({
  required Map<String, dynamic> recipientJwk,
  required String enc,
  required String? kid,
  required List<int> plaintext,
  required String apv, // already base64url(nonce)
});
```

Steps (see the crypto appendix §7 for exact byte layouts):

1. Ephemeral P-256 keypair (`ECKeyGenerator`); its public point → the `epk` JWK.
2. ECDH agreement (`ECDHBasicAgreement`) with the recipient key → `Z` (32-byte X coordinate).
3. Concat-KDF (single SHA-256 pass, RFC 7518 §4.6.2) → CEK (16 bytes for A128GCM, 32 for A256GCM).
4. AES-GCM (`GCMBlockCipher`) with a random 96-bit IV, 128-bit tag,
   `AAD = ASCII(base64url(protected-header-JSON))`.
5. Assemble `base64url(header) . "" . base64url(iv) . base64url(ciphertext) . base64url(tag)`
   (empty encrypted-key segment).

Reuse `ecPublicKeyFromJwk` and the `p256` domain params from `core/ec.dart`; reuse `b64uEncode`. This is
the first place the library generates a key — acceptable and isolated (production already ships
`pointycastle`).

### 5.4 Response-mode-aware submit

Route the final POST by `response_mode`. Recommended shape — a high-level one-call helper plus a
mode-aware low-level submit:

```dart
// High-level (single credential): build KB-JWT, assemble vp_token, submit per mode.
Future<String?> present({
  required PresentationRequest req,
  required CredentialMatch match,
  required Es256Signer signer,
});

// Low-level: mode-aware.
Future<String?> submitResponse({
  required PresentationRequest req,
  required Map<String, List<String>> vpToken, // 1.0-final shape
});
```

`submitResponse`:
- `direct_post` → `postForm({ 'vp_token': jsonEncode(vpToken), if (state) 'state': state })`.
- `direct_post.jwt` → require `req.responseEncryption`; build plaintext
  `{ 'state': req.state, 'vp_token': vpToken }`, `encryptCompactJweEcdhEs(...)`,
  then `postForm({ 'response': jwe })`.
- Both: read `redirect_uri` from a 200 JSON body if present, else return null.

Keep the existing `submit({req, vpToken:String})` as a thin legacy wrapper (plain mode, single string)
to avoid breaking callers — or deprecate it in favour of `submitResponse`.

### 5.5 Surface the failure body

On a non-2xx submit, include `resp.body` (trimmed/capped) in `PresentationError` so a 400 reports the
verifier's `error`/`error_description` (e.g. `UnexpectedResponseMode`, `InvalidJarm`) instead of a bare
status. Cheap, and it turns the next failure into a one-line diagnosis.

---

## 6. Public API impact

- **Additive:** `PresentationRequest.responseEncryption` (nullable); new `present(...)` /
  `submitResponse(...)`; `ResponseEncryption` type.
- **Backward compatible:** existing `submit`, `buildVpToken`, `buildVpTokenObject`, `match` unchanged
  (optionally deprecate `submit` in favour of `submitResponse`).
- No new package dependencies.

---

## 7. Crypto appendix — exact byte layout (ECDH-ES direct + AES-GCM)

Because `alg` is **`ECDH-ES` (direct)**, the Concat-KDF output **is** the CEK; there is no key-wrap and
the JWE encrypted-key segment is empty.

**Z (shared secret):** `ECDHBasicAgreement` returns the shared X coordinate as a `BigInt`; encode it as
**32 bytes, big-endian, left-padded**.

**Concat-KDF (NIST SP 800-56A, RFC 7518 §4.6.2), single SHA-256 pass** (`keydatalen` = 128 or 256 bits ⇒
one iteration):

```
DerivedKey = SHA256( AlgorithmConcat ) [ leftmost keydatalen bits ]
AlgorithmConcat =
    counter(4B BE = 00 00 00 01)
  || Z (32B)
  || AlgorithmID  = len(4B BE) || ASCII(enc)          // e.g. 00 00 00 07 || "A128GCM"
  || PartyUInfo   = len(4B BE) || apu-bytes           // apu omitted ⇒ 00 00 00 00
  || PartyVInfo   = len(4B BE) || apv-bytes           // apv-bytes = raw nonce bytes (= b64url-decode(apv))
  || SuppPubInfo  = keydatalen as 4B BE               // e.g. 00 00 00 80 for 128
  // SuppPrivInfo empty
```

- For **ECDH-ES direct**, `AlgorithmID` uses the **`enc`** value (not `alg`).
- `apv-bytes` are the raw nonce bytes — the same bytes you base64url-encoded into the header `apv`.

**AES-GCM:** key = CEK; **96-bit random IV**; **128-bit tag**;
`AAD = ASCII(base64url(protected-header-JSON))`; plaintext = the `{state, vp_token}` JSON bytes.

**Compact assembly:** `b64u(header) . "" . b64u(iv) . b64u(ciphertext) . b64u(tag)`.

pointycastle mapping: `ECKeyGenerator` + `ECKeyGeneratorParameters(p256)` (seed a `SecureRandom` from
`Random.secure()`); `ECDHBasicAgreement`; `SHA256Digest`; `GCMBlockCipher(AESEngine())` with
`AEADParameters(KeyParameter(cek), 128, iv, aad)`.

---

## 8. Test plan

**Unit (pure Dart, no network)**
1. **Round-trip:** encrypt to a known recipient EC private key, then decrypt (a test-only ECDH-ES/GCM
   decrypt, or a fixture) → recover `{state, vp_token}`. Assert header (`alg/enc/kid/epk/apv`, empty
   encrypted-key segment) and the `{id:[...]}` `vp_token` shape.
2. **Known-answer:** derive a CEK from a fixed ephemeral key + fixed recipient key + fixed
   `enc`/`apv`, and pin it against a vector computed offline (guards the Concat-KDF byte layout).
3. **Selection:** `client_metadata` parsing picks the `use:enc` P-256 key, `alg=ECDH-ES`, and prefers
   `A128GCM`; rejects unsupported alg/enc.
4. **vp_token shape:** single match → `{ queryId: [compact] }`; `state` echoed.

**Integration (live EUDI, manual, on device via the test wallet)**
- Mode B present against `verifier.eudiw.dev` with a `dc+sd-jwt` PID request (`family_name`,
  `given_name`) → expect **HTTP 200** and a `redirect_uri` with `response_code`.
- Regression: plain-`direct_post` path (the in-process mock) still passes.

---

## 9. Rollout

- **Dependency:** this is library work, so the test wallet switches its `sdjwt_oid4vc` dep from
  pub.dev (`^0.1.0-dev.2`) to the local source (`g:/code/roeid/sdjwt_oid4vc`, github.com/exilonX/…)
  while iterating; changes flow back and we bump the dev version.
- **Retest:** the test wallet's Mode A/B toggle exercises both transports; Mode B closes the present
  leg once this lands.
- **Effort:** ~1 new file (`core/jwe.dart`, ~150-220 LOC) + `models`/`vp_client` edits (~80 LOC) +
  tests. Contained; no API breakage.

---

## 10. Secondary gap (nested-claim DCQL) — **resolved in 0.1.2**

Previously `match`/`_satisfies` compared only **top-level** claim names, so a request for a nested/array
path (`["place_of_birth","locality"]`, `["age_equal_or_over","18"]`, `["nationalities",0]`) either matched
vacuously or was ignored. `_satisfies` now resolves each DCQL claim **path** against the reconstructed
claim tree (string → object member, int → array index, `null` → all elements), so matching honours nested
requests. Disclosure already worked via `present(disclosePaths:)` / `CredentialMatch.requestedPaths`; the
one-call `present(req, match, signer)` now selects nested claims end-to-end.

---

## 11. Open questions

- **`present()` vs extend `submit()`** — one high-level helper (recommended) vs. only the low-level
  mode-aware `submitResponse`. Decide the public surface.
- **`enc` default** — A128GCM (spec default) vs A256GCM (also offered). Propose A128GCM.
- **Multi-credential** (`buildVpTokenObject` array alignment) — do it now or defer with the DCQL work.
- **KAT source** — compute the Concat-KDF/GCM vector with a reference (e.g. `jose`/nimbus) offline and
  pin it.

---

## 12. References

- OpenID4VP 1.0 Final (2025-07-09): response mode `direct_post.jwt`; JWE `alg`/`enc`/`kid` rules; payload
  `vp_token` object-of-arrays example.
- RFC 7516 (JWE), RFC 7518 §4.6 (ECDH-ES, Concat-KDF `AlgorithmID`/`PartyInfo`/`SuppPubInfo`), RFC 7638
  (JWK thumbprint).
- EUDI holder lib `eudi-lib-jvm-siop-openid4vp-kt` (`ResponseEncryption.kt`, `DefaultResponseDispatcher.kt`,
  `ClientMetaDataValidator.kt`) — reference for `apv=base64url(nonce)`, `apu` omitted, `response` form
  field, and the `vp_token` array shape.
- EUDI `eudi-srv-verifier-endpoint` (`PostWalletResponse.kt`, `VerifyEncryptedResponseWithNimbus.kt`) —
  the `UnexpectedResponseMode` 400, `state` check, and decrypt (alg=ECDH-ES, enc∈{A128GCM,A256GCM}).
- Live capture: `verifier-backend.eudiw.dev` request payload (ephemeral enc JWK, `encrypted_response_enc_values_supported`).
- This repo: `lib/src/oid4vp/vp_client.dart`, `lib/src/oid4vp/models.dart`, `lib/src/core/ec.dart`,
  `lib/src/core/jwk.dart`.
