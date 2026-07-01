# `sdjwt_oid4vc` — librărie Dart de protocol SD-JWT VC + OpenID4VCI/OpenID4VP (rol holder)

> Propunere de design + interfață publică. **Pachet Dart standalone, publicabil pe pub.dev**, repo propriu
> (ca `attested_secure_keys`). Consumator tipic: un portofel EUDI Dart (rol holder).

---

## 1. De ce există (research)

Pe pub.dev **nu există** o librărie Dart cuprinzătoare pentru SD-JWT VC + OpenID4VCI/OpenID4VP (holder). Există:
- `openid_client` / `oidc` — **OIDC clasic** (login), NU verifiable credentials;
- `jose`-uri Dart parțiale, dar fără SD-JWT VC / OID4VCI / OID4VP;
- SDK-uri OID4VC mature **doar în alte limbaje** (walt.id — Kotlin/JS; libs EUDI — Swift/Kotlin/Rust).

Deci scriem un pachet **thin**, **specific nevoii noastre** dar **reutilizabil de orice wallet** Dart.

## 2. Principii de design

1. **Doar rol holder/wallet** — fără helperi de issuer/verifier (ăia sunt server-side).
2. **Decuplat de chei** — librăria NU importă `attested_secure_keys`; primește un **`Es256Signer`** (interfață).
   `attested_secure_keys` devine un **adaptor** injectat (recomandat, first-class — cu exemplu). Pentru teste:
   un signer software.
3. **Decuplat de HTTP** — primește un **`Oid4vcHttp`** (interfață); implementare default peste `package:http`.
   Testabil fără rețea.
4. **Stratificat: transport vs format.** `oid4vci`/`oid4vp` (transport, agnostic de format) sunt separate de
   `sdjwt` (codec). Mâine se adaugă un codec `mdoc` pe **același** transport, fără rescriere.
5. **Logică pură** — fără I/O ascuns, fără `Date.now()` magic; tot ce e ne-determinist (timp, random salt)
   se injectează sau e izolat, ca să fie testabil.

## 3. Layout pachet

```
sdjwt_oid4vc/
├── lib/
│   ├── src/
│   │   ├── core/       (Es256Signer, Oid4vcHttp, jwk.dart, jws.dart, b64u.dart, errors.dart)
│   │   ├── sdjwt/      (sd_jwt.dart, disclosure.dart, kb_jwt.dart)
│   │   ├── oid4vci/    (vci_client.dart, models)
│   │   ├── oid4vp/     (vp_client.dart, dcql.dart, models)
│   │   └── models/     (CredentialOffer, IssuerMetadata, TokenResponse, PresentationRequest, …)
│   └── sdjwt_oid4vc.dart   (export public)
└── example/            (adaptor attested_secure_keys + flow complet)
```

---

## 4. Interfața publică — fiecare funcție, exact ce face

### 4.1 `core` — contractele injectate

```dart
/// Cheia holder. SINGURA dependență de cripto — implementată de attested_secure_keys (hardware)
/// sau de un signer software (teste). Librăria nu știe NIMIC despre hardware.
abstract class Es256Signer {
  /// JWK public al cheii holder (kty:EC, crv:P-256, x, y). Intră în `cnf` și în header-ul proof-ului.
  Future<Map<String, dynamic>> publicJwk();

  /// Semnează signing-input-ul JOSE (`base64url(header).base64url(payload)`).
  /// Întoarce semnătura ca **raw R‖S (64B) base64url** (formatul JOSE ES256). Declanșează poarta
  /// biometric/PIN dacă cheia e auth-required (hardware).
  Future<String> signEs256(String signingInput);

  /// OPȚIONAL: key attestation legat de `nonce` (Android Keystore chain / iOS App Attest).
  /// `null` dacă implementarea nu o suportă (atunci librăria pur și simplu n-o atașează).
  Future<KeyAttestation?> attest(String nonce) async => null;
}

/// HTTP injectabil (testabil, agnostic de Dio/http). Implementare default: DefaultOid4vcHttp (package:http).
abstract class Oid4vcHttp {
  Future<HttpResp> get(Uri url, {Map<String, String>? headers});
  Future<HttpResp> postForm(Uri url, Map<String, String> form, {Map<String, String>? headers});
  Future<HttpResp> postJson(Uri url, Object body, {Map<String, String>? headers});
}
```

Helperi `core` expuși: `Jwk.thumbprint(jwk)` (RFC 7638, pt. `kid`), `b64uEncode/Decode`, `Jws.signingInput(header, payload)`. Erori: `Oid4vcError` + subtipuri (`OfferParseError`, `TokenError`, `CredentialError`, `PresentationError`, `SdJwtError`).

### 4.2 `sdjwt` — codec-ul SD-JWT VC

```dart
class SdJwt {
  /// Parsează forma compactă `<issuer-JWT>~<disclosure>~…~[<KB-JWT>]`. Decodează header + payload-ul
  /// issuer-JWT-ului și fiecare disclosure ([salt, name, value]). NU verifică semnătura (vezi verifyIssuer).
  static SdJwtVc parse(String compact);

  /// Construiește un SD-JWT VC (rol normal e al ISSUER-ului — expus pt. teste/holder care re-împachetează).
  static Future<String> issue({required Map<String,dynamic> claims, required Map<String,dynamic> header,
                               required Set<String> selectivelyDisclosable, required Es256Signer signer});
}

class SdJwtVc {
  Map<String, dynamic> get header;        // alg, typ (dc+sd-jwt), x5c?, kid?
  Map<String, dynamic> get issuerClaims;  // iss, vct, cnf, iat, exp, status?, _sd, _sd_alg
  List<Disclosure> get disclosures;       // câmpurile selectiv-dezvăluibile disponibile

  /// Reconstituie setul COMPLET de claims (combină _sd cu disclosures-urile prezente). Pentru afișare în wallet.
  Map<String, dynamic> resolveClaims();

  /// Verifică semnătura emitentului. Rezolvă cheia prin `trust`:
  ///  - din header.x5c (cert chain) — modul nostru;
  ///  - sau prin issuer-metadata (`<iss>/.well-known/jwt-vc-issuer`) dacă x5c lipsește.
  /// În pilot, `trust` poate fi `IssuerTrust.signatureOnly()` (verifică doar semnătura, fără Trusted List).
  Future<bool> verifyIssuer(IssuerTrust trust, {Oid4vcHttp? http});

  bool get isExpired;                     // pe baza `exp`
  String? get statusRef;                  // referința de status list (pt. revocare v2)
}

class Disclosure { String get salt; String get name; dynamic get value; }
```

### 4.3 `oid4vci` — clientul de EMITERE

```dart
class Oid4vciClient {
  Oid4vciClient(this._http);

  /// Parsează deep link-ul `openid-credential-offer://?...` SAU JSON-ul ofertei (de la /oferta/:id).
  /// Întoarce: credential_issuer, lista de credential_configuration_ids, grants (pre-authorized_code,
  /// dacă tx_code e cerut + lungimea lui).
  Future<CredentialOffer> parseOffer(String offerUriOrJson);

  /// GET `<issuer>/.well-known/openid-credential-issuer` (+ oauth-authorization-server). Endpoint-uri + vct-uri.
  Future<IssuerMetadata> fetchIssuerMetadata(CredentialOffer offer);

  /// POST /token cu grant `pre-authorized_code` + `tx_code`. Întoarce access_token + c_nonce.
  Future<TokenResponse> requestToken({required CredentialOffer offer, required String txCode});

  /// Construiește **proof JWT** (typ `openid4vci-proof+jwt`): header.jwk = signer.publicJwk();
  /// payload {aud: issuer, nonce: c_nonce, iat}; semnat cu signer. Asta leagă cheia holder (`cnf`).
  Future<String> buildProof({required String issuer, required String cNonce, required Es256Signer signer});

  /// POST /credential cu access_token + proof. Dacă `attestation` != null, atașează key_attestation.
  /// Întoarce SD-JWT VC-ul compact (string).
  Future<String> requestCredential({required IssuerMetadata meta, required TokenResponse token,
                                    required String proofJwt, KeyAttestation? attestation});

  /// CONVENIENȚĂ: rulează tot dansul (parseOffer→metadata→token→proof→credential) și întoarce SD-JWT VC-ul.
  /// Cere atestare via signer.attest(c_nonce) dacă signer-ul o suportă.
  Future<String> redeemOffer({required String offerUriOrJson, required String txCode, required Es256Signer signer});
}
```

### 4.4 `oid4vp` — clientul de PREZENTARE

```dart
class Oid4vpClient {
  Oid4vpClient(this._http);

  /// Preia Request Object-ul (gestionează `request_uri` cu `request_uri_method=post` + wallet_nonce) și-l
  /// parsează: DCQL (ce vct + ce claim-uri), nonce, client_id (=aud), response_uri, response_mode.
  Future<PresentationRequest> fetchRequest(String authzRequestUriOrJar);

  /// Parsează un Request Object deja obținut (JWT JAR) fără fetch.
  PresentationRequest parseRequest(String requestObjectJwt);

  /// Alege din credențialele deținute una care satisface DCQL-ul cererii (după vct + claim paths). null dacă niciuna.
  CredentialMatch? match(PresentationRequest req, List<SdJwtVc> held);

  /// Construiește `vp_token`: alege disclosures pt. `revealClaims`, calculează sd_hash, semnează **KB-JWT**
  /// (typ `kb+jwt`, payload {nonce: req.nonce, aud: req.clientId, sd_hash, iat}) cu signer-ul. Întoarce
  /// prezentarea `<issuer-JWT>~<disclosures alese>~<KB-JWT>`.
  Future<String> buildVpToken({required SdJwtVc credential, required Iterable<String> revealClaims,
                               required PresentationRequest req, required Es256Signer signer});

  /// Trimite răspunsul (`direct_post`) la `response_uri`. Întoarce eventualul redirect/cod de la verifier.
  Future<void> submit({required PresentationRequest req, required String vpToken});
}
```

### 4.5 Modele expuse (pe scurt)
`CredentialOffer {issuer, configIds, preAuthCode, txCodeRequired, txCodeLength}` · `IssuerMetadata
{credentialEndpoint, tokenEndpoint, nonceEndpoint, vcts}` · `TokenResponse {accessToken, cNonce}` ·
`PresentationRequest {clientId, nonce, responseUri, responseMode, dcql}` · `CredentialMatch {credential,
requestedClaims}` · `KeyAttestation {format(android-key|apple), bytesOrJwt}`.

---

## 5. Adaptor `attested_secure_keys` (exemplu de integrare — în `example/`)

```dart
class AttestedKeysSigner implements Es256Signer {
  AttestedKeysSigner(this._keys, this.alias);          // attested_secure_keys + alias per credențial
  @override Future<Map<String,dynamic>> publicJwk() => _keys.publicJwk(alias);
  @override Future<String> signEs256(String input) => _keys.signEs256(alias, input); // întoarce raw R‖S
  @override Future<KeyAttestation?> attest(String nonce) async =>
      KeyAttestation.from(await _keys.attest(alias, nonce));
}
```
roeid_flutter creează un `AttestedKeysSigner` per credențial (alias=credentialId, `auth-required`) și-l dă
librăriei. Atât. Restul (proof, KB-JWT, disclosures) e logică pură în librărie.

## 6. Ce NU face (out of scope)
- **mdoc / ISO 18013** (CBOR/COSE, proximity) — codec separat, viitor (transport-ul e pregătit, §2.4).
- **W3C JSON-LD VC / BBS+**.
- **OIDC login** (ăla e `openid_client`/`oidc`).
- **Rolurile issuer/verifier** (server-side: emitent, verifier).
- **Stocarea** credențialelor (e a app-ului — Hive criptat; librăria întoarce/primește string-uri).

## 7. Testare
Cu un **`SoftwareEs256Signer`** (cheie EC P-256 în memorie) + un **`FakeOid4vcHttp`** (răspunsuri canate),
toată logica (offer→token→proof→credential, request→disclose→KB-JWT→submit) se testează **fără hardware și
fără rețea**. Vectori de test: emitere reală de la un emitent live + cereri DCQL de la un verifier live.
