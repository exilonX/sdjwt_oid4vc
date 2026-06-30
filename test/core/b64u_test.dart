import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('b64uEncode', () {
    test('is unpadded and url-safe', () {
      expect(b64uEncode([0xff, 0xff, 0xff]), '____');
      expect(b64uEncode([0xfb]), '-w');
      expect(b64uEncode(const []), '');
      expect(b64uEncode([0]), isNot(contains('=')));
    });
  });

  group('b64uDecode', () {
    test('round-trips every length class', () {
      for (final length in [0, 1, 2, 3, 4, 5, 16, 31, 32, 33]) {
        final bytes = List<int>.generate(length, (i) => (i * 37 + 11) & 0xff);
        expect(b64uDecode(b64uEncode(bytes)), bytes, reason: 'len=$length');
      }
    });

    test('accepts url-safe alphabet and padded input', () {
      expect(b64uDecode('____'), [0xff, 0xff, 0xff]);
      expect(b64uDecode('-w'), [0xfb]);
      expect(b64uDecode('AA=='), [0]);
    });

    test('rejects an impossible length (len % 4 == 1)', () {
      expect(() => b64uDecode('A'), throwsFormatException);
    });
  });

  group('string helpers', () {
    test('round-trip UTF-8 including non-ASCII and JSON glyphs', () {
      const text = 'héllo wörld {}~.-_';
      expect(b64uDecodeToString(b64uEncodeString(text)), text);
    });
  });
}
