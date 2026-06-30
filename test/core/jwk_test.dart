import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('Jwk.thumbprint', () {
    test('matches the RFC 7638 §3.1 RSA worked example', () {
      // The canonical example from the RFC; its thumbprint is fixed.
      const jwk = {
        'kty': 'RSA',
        'n': '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4'
            'cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n'
            '3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4Qy'
            'Q5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ'
            'Hzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6We'
            'Zu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEg'
            'U8awapJzKnqDKgw',
        'e': 'AQAB',
        'alg': 'RS256',
        'kid': '2011-04-29',
      };
      expect(
        Jwk.thumbprint(jwk),
        'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
      );
    });

    test('is stable for EC keys and ignores non-canonical members', () {
      const ec = {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'use': 'sig',
      };
      final withExtra = {...ec, 'kid': 'ignored'};
      expect(Jwk.thumbprint(ec), Jwk.thumbprint(withExtra));
      expect(Jwk.thumbprint(ec), isNotEmpty);
    });

    test('supports OKP keys', () {
      const okp = {
        'kty': 'OKP',
        'crv': 'Ed25519',
        'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
      };
      expect(Jwk.thumbprint(okp), isNotEmpty);
    });

    test('throws for an unsupported key type', () {
      expect(
        () => Jwk.thumbprint(const {'kty': 'oct', 'k': 'AAAA'}),
        throwsArgumentError,
      );
    });

    test('throws when a required member is missing or not a string', () {
      expect(
        () => Jwk.thumbprint(const {'kty': 'EC', 'crv': 'P-256', 'x': 'a'}),
        throwsArgumentError,
      );
      expect(
        () => Jwk.thumbprint(
          const {'kty': 'EC', 'crv': 'P-256', 'x': 'a', 'y': 1},
        ),
        throwsArgumentError,
      );
    });
  });
}
