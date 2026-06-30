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

  group('parseX509Certificate', () {
    test('parses a signed certificate and verifies its self-signature', () {
      final cert = parseX509Certificate(
        buildSignedCert(subjectJwk: jwk, issuer: signer),
      );
      final at2030 = DateTime.utc(2030).millisecondsSinceEpoch ~/ 1000;
      final at2010 = DateTime.utc(2010).millisecondsSinceEpoch ~/ 1000;
      expect(cert.isValidAt(at2030), isTrue);
      expect(cert.isValidAt(at2010), isFalse);
      // Self-signed: the parsed key verifies the certificate's own signature.
      expect(certificateSignedBy(cert, cert.publicKey), isTrue);
    });

    test('rejects DER that is not a 3-field certificate', () {
      final notACert = base64.encode(ASN1Integer.fromInt(5).encodedBytes);
      expect(() => parseX509Certificate(notACert), throwsFormatException);

      final twoFields = ASN1Sequence()
        ..add(ASN1Sequence())
        ..add(ASN1Sequence());
      expect(
        () => parseX509Certificate(base64.encode(twoFields.encodedBytes)),
        throwsFormatException,
      );
    });

    test('rejects a non-sequence tbs or non-bitstring signature', () {
      final badTbs = ASN1Sequence()
        ..add(ASN1Integer.fromInt(1)) // tbs must be a SEQUENCE
        ..add(ASN1Sequence())
        ..add(ASN1BitString(Uint8List.fromList([0])));
      expect(
        () => parseX509Certificate(base64.encode(badTbs.encodedBytes)),
        throwsFormatException,
      );

      final badSig = ASN1Sequence()
        ..add(ASN1Sequence())
        ..add(ASN1Sequence())
        ..add(ASN1Integer.fromInt(1)); // signatureValue must be a BIT STRING
      expect(
        () => parseX509Certificate(base64.encode(badSig.encodedBytes)),
        throwsFormatException,
      );
    });

    test('rejects a certificate with no validity period', () {
      expect(
        () => parseX509Certificate(buildX5cLeafFromJwk(jwk)),
        throwsFormatException,
      );
    });

    test('rejects a non-ECDSA signature value', () {
      ASN1Sequence validity() => ASN1Sequence()
        ..add(ASN1UtcTime(DateTime.utc(2020)))
        ..add(ASN1UtcTime(DateTime.utc(2040)));
      String certWith(ASN1Object signatureValue) {
        final cert = ASN1Sequence()
          ..add(ASN1Sequence()..add(validity()))
          ..add(ASN1Sequence())
          ..add(ASN1BitString(Uint8List.fromList(signatureValue.encodedBytes)));
        return base64.encode(cert.encodedBytes);
      }

      // Not a SEQUENCE at all.
      expect(
        () => parseX509Certificate(certWith(ASN1Integer.fromInt(7))),
        throwsFormatException,
      );
      // A SEQUENCE, but not of two INTEGERs.
      final notIntegers = ASN1Sequence()
        ..add(ASN1Sequence())
        ..add(ASN1Sequence());
      expect(
        () => parseX509Certificate(certWith(notIntegers)),
        throwsFormatException,
      );
    });
  });
}
