import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';

void main() async {
  final signer = SoftwareEs256Signer.generate(random: Random(7));
  final jwk = signer.publicJwkSync();
  const signingInput = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZGEifQ';
  final signature = b64uDecode(await signer.signEs256(signingInput));

  group('verifyEs256', () {
    test('accepts a genuine signature via JWK', () {
      expect(
        verifyEs256WithJwk(
          signingInput: signingInput,
          signature: signature,
          jwk: jwk,
        ),
        isTrue,
      );
    });

    test('rejects a tampered signing input', () {
      expect(
        verifyEs256WithJwk(
          signingInput: '$signingInput.tampered',
          signature: signature,
          jwk: jwk,
        ),
        isFalse,
      );
    });

    test('rejects a signature of the wrong length', () {
      expect(
        verifyEs256WithJwk(
          signingInput: signingInput,
          signature: Uint8List.fromList([1, 2, 3]),
          jwk: jwk,
        ),
        isFalse,
      );
    });
  });

  group('ecPublicKeyFromJwk', () {
    test('rejects a non-EC or non-P-256 key', () {
      expect(
        () => ecPublicKeyFromJwk(const {'kty': 'RSA'}),
        throwsFormatException,
      );
      expect(
        () => ecPublicKeyFromJwk(const {'kty': 'EC', 'crv': 'P-384'}),
        throwsFormatException,
      );
    });

    test('rejects missing coordinates', () {
      expect(
        () => ecPublicKeyFromJwk(const {'kty': 'EC', 'crv': 'P-256', 'x': 'a'}),
        throwsFormatException,
      );
    });
  });

  group('ecPublicKeyFromX5cLeaf', () {
    test('extracts the key and verifies a real signature', () {
      final x5c = [buildX5cLeafFromJwk(jwk)];
      expect(
        verifyEs256WithX5c(
          signingInput: signingInput,
          signature: signature,
          x5c: x5c,
        ),
        isTrue,
      );
    });

    test('throws on an empty chain', () {
      expect(() => ecPublicKeyFromX5cLeaf(const []), throwsFormatException);
    });

    test('throws on non-base64 content', () {
      expect(
        () => ecPublicKeyFromX5cLeaf(const ['%%% not base64 %%%']),
        throwsFormatException,
      );
    });

    test('throws when the DER is not a certificate SEQUENCE', () {
      final der = base64.encode(ASN1Integer.fromInt(5).encodedBytes);
      expect(() => ecPublicKeyFromX5cLeaf([der]), throwsFormatException);
    });

    test('throws when the TBSCertificate is not a SEQUENCE', () {
      final cert = ASN1Sequence()..add(ASN1Integer.fromInt(1));
      final der = base64.encode(cert.encodedBytes);
      expect(() => ecPublicKeyFromX5cLeaf([der]), throwsFormatException);
    });

    test('throws when there is no EC SubjectPublicKeyInfo', () {
      final cert = ASN1Sequence()..add(ASN1Sequence());
      final der = base64.encode(cert.encodedBytes);
      expect(() => ecPublicKeyFromX5cLeaf([der]), throwsFormatException);
    });
  });
}
