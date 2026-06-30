import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';

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
