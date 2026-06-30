import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  test('toString includes the runtime type and message', () {
    expect(
      const OfferParseError('bad offer').toString(),
      'OfferParseError: bad offer',
    );
  });

  test('toString appends the cause when present', () {
    expect(
      const TokenError('failed', cause: 'socket reset').toString(),
      'TokenError: failed (cause: socket reset)',
    );
  });

  test('every subtype is an Oid4vcError and an Exception', () {
    const errors = <Oid4vcError>[
      OfferParseError('a'),
      TokenError('b'),
      CredentialError('c'),
      PresentationError('d'),
      SdJwtError('e'),
      HttpError('f', statusCode: 500),
    ];
    for (final error in errors) {
      expect(error, isA<Exception>());
      expect(error.message, isNotEmpty);
    }
  });

  test('HttpError keeps the status code', () {
    expect(const HttpError('boom', statusCode: 404).statusCode, 404);
    expect(const HttpError('no response').statusCode, isNull);
  });
}
