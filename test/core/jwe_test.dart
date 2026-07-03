import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:sdjwt_oid4vc/src/core/b64u.dart';
import 'package:sdjwt_oid4vc/src/core/jwe.dart';
import 'package:test/test.dart';

import '../support/jwe_recipient.dart';

void main() {
  group('Concat-KDF (RFC 7518 Appendix C known-answer)', () {
    test('derives the documented A128GCM key', () {
      // The worked example: Z, AlgorithmID=A128GCM, apu="Alice", apv="Bob".
      final z = Uint8List.fromList([
        158, 86, 217, 29, 129, 113, 53, 211, //
        114, 131, 66, 131, 191, 132, 38, 156,
        251, 49, 110, 163, 218, 128, 106, 72,
        246, 218, 167, 121, 140, 254, 144, 196,
      ]);
      final cek = concatKdf(
        sharedSecret: z,
        keyBits: 128,
        algorithmId: 'A128GCM',
        apu: ascii.encode('Alice'),
        apv: ascii.encode('Bob'),
      );
      // RFC 7518 §C: derived key == base64url "VqqN6vgjbSBcIijNcacQGg".
      expect(b64uEncode(cek), 'VqqN6vgjbSBcIijNcacQGg');
    });
  });

  group('encryptCompactJweEcdhEs', () {
    final apv = b64uEncode(utf8.encode('abcdefgh1234567890'));

    test('A128GCM round-trips and sets the expected header', () {
      final r = recipient(1, kid: 'verifier-key-1');
      final plaintext = utf8.encode('{"state":"s","vp_token":{"pid":["x~y"]}}');

      final jwe = encryptCompactJweEcdhEs(
        recipientJwk: r.jwk,
        enc: 'A128GCM',
        kid: 'verifier-key-1',
        plaintext: plaintext,
        apv: apv,
        random: Random(42),
      );

      final parts = jwe.split('.');
      expect(parts.length, 5, reason: 'compact JWE has five segments');
      expect(parts[1], isEmpty, reason: 'ECDH-ES direct: empty encrypted-key');

      final header = jsonDecode(utf8.decode(b64uDecode(parts.first)))
          as Map<String, dynamic>;
      expect(header['alg'], 'ECDH-ES');
      expect(header['enc'], 'A128GCM');
      expect(header['kid'], 'verifier-key-1');
      expect(header['apv'], apv);
      expect(header.containsKey('apu'), isFalse);
      final epk = header['epk'] as Map;
      expect(epk['kty'], 'EC');
      expect(epk['crv'], 'P-256');
      expect(epk['x'], isA<String>());
      expect(epk['y'], isA<String>());

      expect(decryptJwe(jwe, r.private), plaintext);
    });

    test('A256GCM round-trips', () {
      final r = recipient(2);
      final plaintext = utf8.encode('a longer plaintext payload for A256GCM');
      final jwe = encryptCompactJweEcdhEs(
        recipientJwk: r.jwk,
        enc: 'A256GCM',
        kid: null,
        plaintext: plaintext,
        apv: apv,
        random: Random(7),
      );
      final header = jsonDecode(utf8.decode(b64uDecode(jwe.split('.').first)))
          as Map<String, dynamic>;
      expect(header['enc'], 'A256GCM');
      expect(header.containsKey('kid'), isFalse); // kid omitted when null
      expect(decryptJwe(jwe, r.private), plaintext);
    });

    test('two encryptions use fresh ephemeral keys (distinct epk)', () {
      final r = recipient(3);
      String epkX(String jwe) {
        final h = jsonDecode(utf8.decode(b64uDecode(jwe.split('.').first)))
            as Map<String, dynamic>;
        return (h['epk'] as Map)['x'] as String;
      }

      final a = encryptCompactJweEcdhEs(
        recipientJwk: r.jwk,
        enc: 'A128GCM',
        kid: null,
        plaintext: const [1, 2, 3],
        apv: apv,
        random: Random(1),
      );
      final b = encryptCompactJweEcdhEs(
        recipientJwk: r.jwk,
        enc: 'A128GCM',
        kid: null,
        plaintext: const [1, 2, 3],
        apv: apv,
        random: Random(2),
      );
      expect(epkX(a), isNot(epkX(b)));
    });

    test('rejects an unsupported enc', () {
      expect(
        () => encryptCompactJweEcdhEs(
          recipientJwk: recipient(4).jwk,
          enc: 'A192GCM',
          kid: null,
          plaintext: const [0],
          apv: apv,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a non-P-256 recipient key', () {
      expect(
        () => encryptCompactJweEcdhEs(
          recipientJwk: const {'kty': 'RSA', 'n': 'x', 'e': 'AQAB'},
          enc: 'A128GCM',
          kid: null,
          plaintext: const [0],
          apv: apv,
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
