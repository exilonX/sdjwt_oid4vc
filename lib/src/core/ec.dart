import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import 'b64u.dart';

/// ECDSA P-256 primitives the library needs internally. The holder *signing*
/// key is injected via `Es256Signer`; what lives here is only what the library
/// must do itself: **verify** an issuer signature and turn a public key
/// (JWK or x5c leaf certificate) into a point on P-256.
///
/// Not exported. `SoftwareEs256Signer` (test support) has its own signing code
/// so production builds never pull in key generation.

/// OID `ecPublicKey` — the SubjectPublicKeyInfo algorithm we accept.
const String _ecPublicKeyOid = '1.2.840.10045.2.1';

/// The P-256 (a.k.a. prime256v1 / secp256r1) domain parameters.
final ECDomainParameters p256 = ECCurve_secp256r1();

/// Verifies an ES256 JWS signature.
///
/// [signature] is the raw `R‖S` (64 bytes) JOSE form. Returns `false` for any
/// malformed input (wrong signature length, point not on curve) rather than
/// throwing — a verification routine answers yes/no, it does not crash.
bool verifyEs256({
  required String signingInput,
  required Uint8List signature,
  required ECPublicKey publicKey,
}) {
  if (signature.length != 64) return false;
  final r = _bytesToBigInt(signature.sublist(0, 32));
  final s = _bytesToBigInt(signature.sublist(32, 64));

  // pointycastle returns false (never throws) when r/s are out of [1, n-1],
  // so a malformed-but-64-byte signature simply fails to verify.
  final verifier = ECDSASigner(SHA256Digest())
    ..init(false, PublicKeyParameter<ECPublicKey>(publicKey));
  return verifier.verifySignature(
    Uint8List.fromList(utf8.encode(signingInput)),
    ECSignature(r, s),
  );
}

/// Verifies an ES256 signature against a public key given as an EC JWK.
/// Throws [FormatException] if the JWK is not a usable P-256 key.
bool verifyEs256WithJwk({
  required String signingInput,
  required Uint8List signature,
  required Map<String, dynamic> jwk,
}) =>
    verifyEs256(
      signingInput: signingInput,
      signature: signature,
      publicKey: ecPublicKeyFromJwk(jwk),
    );

/// Verifies an ES256 signature against the public key in an `x5c` leaf.
/// Throws [FormatException] if the leaf carries no usable P-256 key.
bool verifyEs256WithX5c({
  required String signingInput,
  required Uint8List signature,
  required List<String> x5c,
}) =>
    verifyEs256(
      signingInput: signingInput,
      signature: signature,
      publicKey: ecPublicKeyFromX5cLeaf(x5c),
    );

/// Builds a P-256 public key from an EC JWK (`kty:EC`, `crv:P-256`, `x`, `y`).
///
/// Throws [FormatException] if the JWK is not a usable P-256 key.
ECPublicKey ecPublicKeyFromJwk(Map<String, dynamic> jwk) {
  if (jwk['kty'] != 'EC' || jwk['crv'] != 'P-256') {
    throw FormatException('Expected an EC P-256 JWK', jwk);
  }
  final x = jwk['x'];
  final y = jwk['y'];
  if (x is! String || y is! String) {
    throw FormatException('JWK x/y must be base64url strings', jwk);
  }
  final point = p256.curve.createPoint(
    _bytesToBigInt(b64uDecode(x)),
    _bytesToBigInt(b64uDecode(y)),
  );
  return ECPublicKey(point, p256);
}

/// Extracts the P-256 public key from the **leaf** certificate of an `x5c`
/// chain (RFC 7515 — base64, *not* base64url, DER X.509).
///
/// Walks the TBSCertificate for the SubjectPublicKeyInfo whose algorithm is
/// `ecPublicKey`, then decodes the uncompressed point. Throws [FormatException]
/// when the leaf is missing or carries no EC key.
ECPublicKey ecPublicKeyFromX5cLeaf(List<String> x5c) {
  if (x5c.isEmpty) {
    throw const FormatException('x5c chain is empty');
  }
  final der = base64.decode(x5c.first.replaceAll(RegExp(r'\s'), ''));
  final certificate = ASN1Parser(der).nextObject();
  if (certificate is! ASN1Sequence || certificate.elements.isEmpty) {
    throw const FormatException('x5c leaf is not an X.509 certificate');
  }
  final tbs = certificate.elements.first;
  if (tbs is! ASN1Sequence) {
    throw const FormatException('x5c leaf has no TBSCertificate');
  }
  final spki = _findSubjectPublicKeyInfo(tbs.elements);
  if (spki == null) {
    throw const FormatException('x5c leaf has no EC SubjectPublicKeyInfo');
  }
  final point = p256.curve.decodePoint(spki.contentBytes());
  if (point == null) {
    throw const FormatException('x5c leaf public key is not on P-256');
  }
  return ECPublicKey(point, p256);
}

/// Finds the `subjectPublicKey` BIT STRING of an EC SubjectPublicKeyInfo among
/// the TBSCertificate's [elements]. The SPKI is the only `SEQUENCE { algId,
/// BIT STRING }` whose algId names `ecPublicKey`, which uniquely identifies it.
ASN1BitString? _findSubjectPublicKeyInfo(List<ASN1Object> elements) {
  for (final element in elements) {
    if (element is! ASN1Sequence || element.elements.length != 2) continue;
    final algId = element.elements[0];
    final key = element.elements[1];
    if (key is! ASN1BitString || algId is! ASN1Sequence) continue;
    final namesEcPublicKey = algId.elements.any(
      (o) => o is ASN1ObjectIdentifier && o.identifier == _ecPublicKeyOid,
    );
    if (namesEcPublicKey) return key;
  }
  return null;
}

/// Big-endian unsigned bytes to [BigInt].
BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}
