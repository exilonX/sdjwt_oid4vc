/// Optional proof that the holder key lives in hardware, bound to a
/// server-supplied `nonce`.
///
/// Kept as an opaque [format] + [data] pair so it can carry any of the shapes a
/// key backend produces (an Android Keystore X.509 chain, an iOS App Attest
/// CBOR object, or an OpenID4VCI `keyattestation+jwt`) without this library
/// modelling each one. The issuer re-verifies it against the manufacturer
/// roots; the wallet never makes a trust decision from it.
class KeyAttestation {
  const KeyAttestation({required this.format, required this.data});

  /// The attestation type token the issuer keys on — e.g. `android-key`,
  /// `apple-appattest`, `apple-appassert`. Tells the issuer how to parse [data].
  final String format;

  /// The attestation payload, serialized per [format].
  final String data;
}

/// The holder's signing key — the **only** cryptographic dependency this
/// library has, and it is injected, never imported.
///
/// Production wallets back this with hardware (e.g. `attested_secure_keys`);
/// tests back it with an in-memory key. The library knows nothing about which.
abstract class Es256Signer {
  /// Public JWK of the holder key (`kty:EC`, `crv:P-256`, `x`, `y`). Goes into
  /// the credential's `cnf` claim and into proof / KB-JWT headers.
  Future<Map<String, dynamic>> publicJwk();

  /// Signs a JOSE signing input (`base64url(header).base64url(payload)`) and
  /// returns the signature as **raw R‖S (64 bytes), base64url** — the ES256
  /// wire format. A hardware implementation triggers the biometric/PIN gate
  /// here when the key is auth-required.
  Future<String> signEs256(String signingInput);

  /// Optional key attestation bound to [nonce]. Returns `null` when the
  /// implementation cannot attest, in which case the library simply omits it.
  Future<KeyAttestation?> attest(String nonce) async => null;
}
