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
/// `ecPublicKey`, then decodes the uncompressed point. This reads only the key,
/// not the chain — see [parseX509Certificate] for full chain validation. Throws
/// [FormatException] when the leaf is missing or carries no EC key.
ECPublicKey ecPublicKeyFromX5cLeaf(List<String> x5c) {
  if (x5c.isEmpty) {
    throw const FormatException('x5c chain is empty');
  }
  return _ecPublicKeyFromTbs(
    _tbsOf(base64.decode(x5c.first.replaceAll(RegExp(r'\s'), ''))),
  );
}

/// Parses the Certificate SEQUENCE in [der] and returns its TBSCertificate.
ASN1Sequence _tbsOf(Uint8List der) {
  final certificate = ASN1Parser(der).nextObject();
  if (certificate is! ASN1Sequence || certificate.elements.isEmpty) {
    throw const FormatException('Not an X.509 certificate');
  }
  final tbs = certificate.elements.first;
  if (tbs is! ASN1Sequence) {
    throw const FormatException('Certificate has no TBSCertificate');
  }
  return tbs;
}

/// Decodes the EC P-256 public key from a TBSCertificate's SubjectPublicKeyInfo.
ECPublicKey _ecPublicKeyFromTbs(ASN1Sequence tbs) {
  final spki = _findSubjectPublicKeyInfo(tbs.elements);
  if (spki == null) {
    throw const FormatException('Certificate has no EC SubjectPublicKeyInfo');
  }
  final point = p256.curve.decodePoint(spki.contentBytes());
  if (point == null) {
    throw const FormatException('Certificate public key is not on P-256');
  }
  return ECPublicKey(point, p256);
}

/// A parsed X.509 certificate — only what a chain check needs: the subject's
/// public key, its validity window, and the material to verify the certificate
/// was signed by its issuer. P-256 / ECDSA-with-SHA256 only.
class X509Certificate {
  X509Certificate._(
    this.der,
    this.tbsBytes,
    this.publicKey,
    this.notBeforeEpoch,
    this.notAfterEpoch,
    this._sigR,
    this._sigS,
  );

  /// Full DER of the certificate — used for trust-anchor identity.
  final Uint8List der;

  /// Exact TBSCertificate DER — the bytes the issuer signed.
  final Uint8List tbsBytes;

  /// The subject's P-256 public key.
  final ECPublicKey publicKey;

  /// Validity bounds, in epoch seconds.
  final int notBeforeEpoch;
  final int notAfterEpoch;

  final BigInt _sigR;
  final BigInt _sigS;

  /// Whether [nowEpochSeconds] is within `notBefore`..`notAfter`.
  bool isValidAt(int nowEpochSeconds) =>
      nowEpochSeconds >= notBeforeEpoch && nowEpochSeconds <= notAfterEpoch;
}

/// Parses one base64 DER X.509 certificate (an `x5c` entry). Throws
/// [FormatException] unless it is a P-256 / ECDSA-with-SHA256 certificate with a
/// validity period — the only shape this library validates.
X509Certificate parseX509Certificate(String base64Der) {
  final der = base64.decode(base64Der.replaceAll(RegExp(r'\s'), ''));
  final certificate = ASN1Parser(der).nextObject();
  if (certificate is! ASN1Sequence || certificate.elements.length < 3) {
    throw const FormatException('Not an X.509 certificate');
  }
  final tbs = certificate.elements[0];
  final signatureValue = certificate.elements[2];
  if (tbs is! ASN1Sequence || signatureValue is! ASN1BitString) {
    throw const FormatException('Malformed certificate structure');
  }
  final validity = _validityOf(tbs.elements);
  if (validity == null) {
    throw const FormatException('Certificate has no validity period');
  }
  final (r, s) = _decodeEcdsaSignature(signatureValue.contentBytes());
  return X509Certificate._(
    Uint8List.fromList(der),
    tbs.encodedBytes.sublist(0, tbs.totalEncodedByteLength),
    _ecPublicKeyFromTbs(tbs),
    validity.$1,
    validity.$2,
    r,
    s,
  );
}

/// Verifies that [certificate]'s own signature was produced by [issuerKey] —
/// i.e. that [issuerKey] issued it. ECDSA-with-SHA256 over the TBSCertificate.
bool certificateSignedBy(X509Certificate certificate, ECPublicKey issuerKey) {
  final verifier = ECDSASigner(SHA256Digest())
    ..init(false, PublicKeyParameter<ECPublicKey>(issuerKey));
  return verifier.verifySignature(
    certificate.tbsBytes,
    ECSignature(certificate._sigR, certificate._sigS),
  );
}

/// Validates the [x5c] chain to one of [trustAnchors] at [nowEpoch] and, on
/// success, verifies [signingInput]/[signature] with the validated leaf key.
///
/// Returns `false` when the chain does not validate — a broken link, a
/// certificate outside its validity window, or no trusted anchor — or when the
/// credential signature does not match. Throws [FormatException] when any
/// certificate (chain or anchor) cannot be parsed.
///
/// Checks every link's signature and validity window, and that the top of the
/// chain is, or was issued by, a currently-valid anchor. Revocation (CRL/OCSP)
/// and name/policy constraints are out of scope.
bool verifyEs256WithX5cChain({
  required String signingInput,
  required Uint8List signature,
  required List<String> x5c,
  required List<String> trustAnchors,
  required int nowEpoch,
}) {
  final chain = x5c.map(parseX509Certificate).toList();
  final anchors = trustAnchors.map(parseX509Certificate).toList();

  for (final certificate in chain) {
    if (!certificate.isValidAt(nowEpoch)) return false;
  }
  for (var i = 0; i < chain.length - 1; i++) {
    if (!certificateSignedBy(chain[i], chain[i + 1].publicKey)) return false;
  }

  final top = chain.last;
  final anchored = anchors.any(
    (anchor) =>
        anchor.isValidAt(nowEpoch) &&
        (_sameDer(top.der, anchor.der) ||
            certificateSignedBy(top, anchor.publicKey)),
  );
  if (!anchored) return false;

  return verifyEs256(
    signingInput: signingInput,
    signature: signature,
    publicKey: chain.first.publicKey,
  );
}

bool _sameDer(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Finds the `Validity` SEQUENCE (two time values) in a TBSCertificate and
/// returns `(notBefore, notAfter)` epoch seconds, or `null` if absent.
(int, int)? _validityOf(List<ASN1Object> elements) {
  for (final element in elements) {
    if (element is! ASN1Sequence || element.elements.length != 2) continue;
    final from = element.elements[0];
    final to = element.elements[1];
    if (_isTime(from) && _isTime(to)) return (_epoch(from), _epoch(to));
  }
  return null;
}

bool _isTime(ASN1Object o) => o is ASN1UtcTime || o is ASN1GeneralizedTime;

int _epoch(ASN1Object o) {
  final value = o is ASN1UtcTime
      ? o.dateTimeValue
      : (o as ASN1GeneralizedTime).dateTimeValue;
  return value.toUtc().millisecondsSinceEpoch ~/ 1000;
}

/// Decodes an X.509 ECDSA signature value (`SEQUENCE { r INTEGER, s INTEGER }`)
/// into its `(r, s)`. Throws [FormatException] if it is not that shape.
(BigInt, BigInt) _decodeEcdsaSignature(Uint8List content) {
  final sig = ASN1Parser(content).nextObject();
  if (sig is! ASN1Sequence || sig.elements.length != 2) {
    throw const FormatException('Certificate signature is not ECDSA');
  }
  final r = sig.elements[0];
  final s = sig.elements[1];
  if (r is! ASN1Integer || s is! ASN1Integer) {
    throw const FormatException('Certificate signature is not ECDSA');
  }
  return (r.valueAsBigInteger, s.valueAsBigInteger);
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
