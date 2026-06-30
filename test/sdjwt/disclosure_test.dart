import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('object-property disclosure', () {
    final disclosure =
        Disclosure.forClaim(salt: 'salt123', name: 'given_name', value: 'Ada');

    test('round-trips through parse', () {
      final parsed = Disclosure.parse(disclosure.encoded);
      expect(parsed.salt, 'salt123');
      expect(parsed.name, 'given_name');
      expect(parsed.value, 'Ada');
      expect(parsed.isArrayElement, isFalse);
    });

    test('digest is base64url(sha256(ASCII(encoded)))', () {
      final expected =
          b64uEncode(sha256.convert(utf8.encode(disclosure.encoded)).bytes);
      expect(disclosure.digest(sha256), expected);
    });

    test('toString shows name and value', () {
      expect(disclosure.toString(), contains('given_name: Ada'));
    });
  });

  group('array-element disclosure', () {
    final encoded = b64uEncodeString(jsonEncode(['saltX', 'RO']));

    test('parses with a null name', () {
      final parsed = Disclosure.parse(encoded);
      expect(parsed.salt, 'saltX');
      expect(parsed.name, isNull);
      expect(parsed.value, 'RO');
      expect(parsed.isArrayElement, isTrue);
      expect(parsed.toString(), contains('RO'));
    });
  });

  group('parse rejects malformed disclosures', () {
    void expectRejected(Object json) {
      expect(
        () => Disclosure.parse(b64uEncodeString(jsonEncode(json))),
        throwsFormatException,
      );
    }

    test('not an array', () => expectRejected({'a': 1}));
    test('too few elements', () => expectRejected(['only-salt']));
    test('too many elements', () => expectRejected(['s', 'n', 'v', 'extra']));
    test('non-string salt', () => expectRejected([1, 'name', 'value']));
    test('non-string name', () => expectRejected(['s', 2, 'value']));
  });
}
