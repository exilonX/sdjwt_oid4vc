# Example

`sdjwt_oid4vc_example.dart` is a runnable, self-contained walk-through of the
**holder** lifecycle — it plays issuer, holder, and verifier in one process, so
it needs no network and no hardware:

```sh
dart run example/sdjwt_oid4vc_example.dart
```

It steps through: receive a credential → trust the issuer (and check validity) →
check revocation → authenticate the verifier → present only the asked-for claim
→ inspect what was disclosed. Each line is annotated with the call a real wallet
makes (`[WALLET USES]`).

## What the library is for, and which calls to make

| You want to… | Call |
|---|---|
| Receive a credential from an issuer | `Oid4vciClient.redeemOffer(...)` |
| Parse a stored credential string | `SdJwt.parse(compact)` |
| Read its claims for display | `SdJwtVc.resolveClaims()` |
| Prove the issuer signed it | `SdJwtVc.verifyIssuer(IssuerTrust...)` |
| …with full certificate-chain trust | `IssuerTrust.x5cChain(trustAnchors: ...)` |
| Enforce it is currently valid | `verifyIssuer(..., enforceValidity: true)` |
| Check it is not revoked | `StatusListResolver(http).resolve(vc.statusListRef!)` |
| Read an incoming presentation request | `Oid4vpClient.fetchRequest` / `parseRequest` |
| Authenticate the verifier (RP) | `request.signature!.verifyWithX5cLeaf()` / `verifyWithJwk(...)` |
| Pick a credential + claims for the request | `Oid4vpClient.match` (or `matchAll` for many) |
| Build the presentation | `Oid4vpClient.buildVpToken` (or `buildVpTokenObject` for many) |
| Reveal a nested/array claim by path | `SdJwtVc.present(disclosePaths: ...)` |
| Send the response | `Oid4vpClient.submit(...)` |

The two seams you provide are an `Es256Signer` (the holder key — **required**)
and an `Oid4vcHttp` (transport — defaults to `DefaultOid4vcHttp`).

## Wiring a hardware key (`attested_secure_keys`)

The library never imports a key backend; you inject an `Es256Signer`. In a real
wallet that signer is hardware-backed — implement three methods over your key
library (method names below follow `attested_secure_keys`; adapt as needed):

```dart
import 'package:attested_secure_keys/attested_secure_keys.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';

/// Adapts one hardware key (selected by [alias]) to `Es256Signer`.
class AttestedKeysSigner implements Es256Signer {
  AttestedKeysSigner(this._keys, this.alias);

  final AttestedSecureKeys _keys;
  final String alias; // e.g. the credential id; the key is `auth-required`

  @override
  Future<Map<String, dynamic>> publicJwk() => _keys.publicJwk(alias);

  @override
  Future<String> signEs256(String signingInput) =>
      _keys.signEs256(alias, signingInput); // returns raw R‖S, base64url

  @override
  Future<KeyAttestation?> attest(String nonce) async {
    final attestation = await _keys.attest(alias, nonce);
    // `format` is the opaque type token the issuer keys on (e.g. 'android-key',
    // 'apple-appattest'); `data` is the serialized chain / CBOR / JWT.
    return KeyAttestation(format: attestation.format, data: attestation.data);
  }
}
```

Then the wallet creates one signer per credential and hands it to the clients:

```dart
final signer = AttestedKeysSigner(keys, credentialId);
final compact = await Oid4vciClient(DefaultOid4vcHttp())
    .redeemOffer(offerUriOrJson: offerLink, txCode: code, signer: signer);
// ...later, at a verifier...
final vpToken = await Oid4vpClient(DefaultOid4vcHttp())
    .buildVpToken(credential: vc, revealClaims: claims, req: req, signer: signer);
```

Everything else — proof JWT, KB-JWT, disclosures, `sd_hash`, chain validation —
is pure logic in the library. The biometric/PIN gate fires inside `signEs256`
when the hardware key is `auth-required`.
