# Example

`sdjwt_oid4vc_example.dart` is a runnable, self-contained walk-through:

```sh
dart run example/sdjwt_oid4vc_example.dart
```

It mints a credential, verifies the issuer signature, then presents only one
claim — playing issuer, holder, and verifier in one process so it needs no
network and no hardware.

## Wiring a hardware key (`attested_secure_keys`)

The library never imports a key backend; you inject an `Es256Signer`. In a real
wallet that signer is hardware-backed. The adaptor is small — wrap one key
(selected by `alias`, one per credential) and map the three methods. This is the
real `attested_secure_keys` API, not a sketch:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:attested_secure_keys/attested_secure_keys.dart' as ask;
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';

/// Adapts one hardware key (alias = credentialId, `auth-required`) to the
/// library's [Es256Signer] seam.
class AttestedKeysSigner implements Es256Signer {
  AttestedKeysSigner(this._keys, this.alias);

  final ask.AttestedSecureKeys _keys;
  final String alias;

  @override
  Future<Map<String, dynamic>> publicJwk() async {
    final info = await _keys.getKeyInfo(alias: alias);
    if (info == null) throw StateError('No holder key for "$alias".');
    return Map<String, dynamic>.from(info.publicJwk.toJson());
  }

  @override
  Future<String> signEs256(String signingInput) async {
    // Returns raw R‖S, base64url — exactly the ES256 wire form this library
    // wants. The biometric/PIN gate fires here for an auth-required key.
    final sig = await _keys.sign(
      alias: alias,
      payload: Uint8List.fromList(utf8.encode(signingInput)),
      promptTitle: 'ROeID',
    );
    return sig.jose;
  }

  @override
  Future<KeyAttestation?> attest(String nonce) async {
    final a = await _keys.attest(
      alias: alias,
      serverNonce: Uint8List.fromList(utf8.encode(nonce)),
    );
    final json = a.toJson();
    return KeyAttestation(
      format: json['type']! as String,        // 'android-key' | 'apple-appattest' | …
      data: jsonEncode(json),                  // x5c chain / CBOR / JWT, per format
    );
  }
}
```

The wallet generates one auth-gated key per credential at import time, then
hands a signer over it to the clients:

```dart
final keys = ask.AttestedSecureKeys();
await keys.generateKey(
  alias: credentialId,
  userAuth: const ask.UserAuthPolicy.perUseBiometric(),
);
final signer = AttestedKeysSigner(keys, credentialId);

final credential = await Oid4vciClient(DefaultOid4vcHttp())
    .redeemOffer(offerUriOrJson: offerLink, txCode: code, signer: signer);
// ...later, at a verifier...
final vpToken = await Oid4vpClient(DefaultOid4vcHttp())
    .buildVpToken(credential: vc, revealClaims: claims, req: req, signer: signer);
```

Everything else — proof JWT, KB-JWT, disclosures, `sd_hash` — is pure logic in
the library. (`attested_secure_keys` is a Flutter plugin, so it is intentionally
**not** a dependency of this pure-Dart package; the adaptor lives in your app.)
