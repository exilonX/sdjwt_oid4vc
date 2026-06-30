import 'package:sdjwt_oid4vc/src/core/net.dart';
import 'package:test/test.dart';

void main() {
  group('isSecureUrl', () {
    test('accepts https on any host', () {
      expect(isSecureUrl(Uri.parse('https://issuer.example/x')), isTrue);
    });

    test('accepts http only on loopback hosts (local dev)', () {
      expect(isSecureUrl(Uri.parse('http://localhost:8080/x')), isTrue);
      expect(isSecureUrl(Uri.parse('http://127.0.0.1/x')), isTrue);
      expect(isSecureUrl(Uri.parse('http://[::1]:9000/x')), isTrue);
    });

    test('rejects http to a non-loopback host', () {
      expect(isSecureUrl(Uri.parse('http://issuer.example/x')), isFalse);
    });

    test('rejects non-http(s) schemes', () {
      expect(isSecureUrl(Uri.parse('ftp://issuer.example/x')), isFalse);
    });
  });
}
