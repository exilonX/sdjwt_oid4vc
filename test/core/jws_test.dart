import 'dart:convert';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('Jws.signingInput', () {
    test('is base64url(header).base64url(payload)', () {
      const header = {'alg': 'ES256', 'typ': 'JWT'};
      const payload = {'sub': 'ada', 'n': 1};
      final input = Jws.signingInput(header, payload);
      final parts = input.split('.');
      expect(parts, hasLength(2));
      expect(jsonDecode(b64uDecodeToString(parts[0])), header);
      expect(jsonDecode(b64uDecodeToString(parts[1])), payload);
    });
  });

  group('Jws.decompose', () {
    test('decodes header, payload, signature and keeps signing input', () {
      const header = {'alg': 'ES256'};
      const payload = {'iss': 'x'};
      final signingInput = Jws.signingInput(header, payload);
      final signature = [1, 2, 3, 4];
      final jws = Jws.decompose('$signingInput.${b64uEncode(signature)}');

      expect(jws.header, header);
      expect(jws.payload, payload);
      expect(jws.signature, signature);
      expect(jws.signingInput, signingInput);
    });

    test('rejects a token that is not three segments', () {
      expect(() => Jws.decompose('only.two'), throwsFormatException);
      expect(() => Jws.decompose('a.b.c.d'), throwsFormatException);
    });

    test('rejects a header/payload that is not a JSON object', () {
      final notObject = b64uEncodeString(jsonEncode([1, 2, 3]));
      final goodPayload = b64uEncodeString(jsonEncode({'a': 1}));
      expect(
        () => Jws.decompose('$notObject.$goodPayload.${b64uEncode([0])}'),
        throwsFormatException,
      );
    });
  });

  test('decodeJsonObject rejects non-objects', () {
    expect(
      () => Jws.decodeJsonObject(b64uEncodeString('"a string"')),
      throwsFormatException,
    );
  });
}
