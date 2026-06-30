import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';

/// Builds a minimal, parseable X.509 DER certificate (base64, for an `x5c`
/// entry) whose SubjectPublicKeyInfo carries the EC P-256 key from [jwk].
///
/// It is *not* a signed/valid chain — only the structure the wallet reads (an
/// `ecPublicKey` SPKI with the uncompressed point) is real. That is exactly
/// what `IssuerTrust.signatureOnly()` consumes: the key, not the chain.
String buildX5cLeafFromJwk(Map<String, dynamic> jwk) {
  final x = b64uDecode(jwk['x'] as String);
  final y = b64uDecode(jwk['y'] as String);

  final algorithm = ASN1Sequence()
    ..add(
      ASN1ObjectIdentifier.fromComponentString(
        '1.2.840.10045.2.1',
      ),
    ) // ecPublicKey
    ..add(
      ASN1ObjectIdentifier.fromComponentString(
        '1.2.840.10045.3.1.7',
      ),
    ); // prime256v1
  final subjectPublicKey =
      ASN1BitString(Uint8List.fromList([0x04, ...x, ...y]));
  final spki = ASN1Sequence()
    ..add(algorithm)
    ..add(subjectPublicKey);

  ASN1Sequence ecdsaWithSha256() => ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.10045.4.3.2'));

  final tbsCertificate = ASN1Sequence()
    ..add(ASN1Integer.fromInt(1)) // serialNumber
    ..add(ecdsaWithSha256()) // signature algorithm
    ..add(ASN1Sequence()) // issuer (empty)
    ..add(spki);

  final certificate = ASN1Sequence()
    ..add(tbsCertificate)
    ..add(ecdsaWithSha256())
    ..add(ASN1BitString(Uint8List.fromList([0x00]))); // dummy signature

  return base64.encode(certificate.encodedBytes);
}

/// Builds a base64 DER X.509 certificate for [subjectJwk]'s key, **genuinely
/// signed** by [issuer] (ECDSA-with-SHA256 over the TBSCertificate) and carrying
/// a validity window. Unlike [buildX5cLeafFromJwk] this is real enough for chain
/// validation: parse it with `parseX509Certificate` and verify the link with
/// `certificateSignedBy`. A self-signed root is just `issuer == subject's key`.
String buildSignedCert({
  required Map<String, dynamic> subjectJwk,
  required SoftwareEs256Signer issuer,
  DateTime? notBefore,
  DateTime? notAfter,
}) {
  final x = b64uDecode(subjectJwk['x'] as String);
  final y = b64uDecode(subjectJwk['y'] as String);

  ASN1Sequence ecPublicKeyAlg() => ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.10045.2.1'))
    ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.10045.3.1.7'));
  ASN1Sequence ecdsaWithSha256() => ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.10045.4.3.2'));

  final spki = ASN1Sequence()
    ..add(ecPublicKeyAlg())
    ..add(ASN1BitString(Uint8List.fromList([0x04, ...x, ...y])));

  final validity = ASN1Sequence()
    ..add(_time(notBefore ?? DateTime.utc(2020)))
    ..add(_time(notAfter ?? DateTime.utc(2040)));

  final tbs = ASN1Sequence()
    ..add(ASN1Integer.fromInt(1)) // serialNumber
    ..add(ecdsaWithSha256()) // signature algorithm
    ..add(ASN1Sequence()) // issuer (empty Name)
    ..add(validity)
    ..add(ASN1Sequence()) // subject (empty Name)
    ..add(spki);

  final tbsBytes = tbs.encodedBytes.sublist(0, tbs.totalEncodedByteLength);
  final raw = issuer.signBytes(tbsBytes); // 64-byte R‖S
  final signatureValue = ASN1Sequence()
    ..add(ASN1Integer(_bigInt(raw.sublist(0, 32))))
    ..add(ASN1Integer(_bigInt(raw.sublist(32, 64))));

  final certificate = ASN1Sequence()
    ..add(tbs)
    ..add(ecdsaWithSha256())
    ..add(
      ASN1BitString(
        signatureValue.encodedBytes
            .sublist(0, signatureValue.totalEncodedByteLength),
      ),
    );
  return base64.encode(
    certificate.encodedBytes.sublist(0, certificate.totalEncodedByteLength),
  );
}

/// X.509 (RFC 5280) uses UTCTime for years before 2050 and GeneralizedTime from
/// 2050 on — mirror that so chain fixtures exercise both encodings.
ASN1Object _time(DateTime dt) {
  final utc = dt.toUtc();
  return utc.year >= 2050 ? ASN1GeneralizedTime(utc) : ASN1UtcTime(utc);
}

BigInt _bigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}
