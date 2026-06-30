import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

/// Extends [Es256Signer] without overriding `attest`, so calling it exercises
/// the default implementation.
class _StubSigner extends Es256Signer {
  @override
  Future<Map<String, dynamic>> publicJwk() async => const {'kty': 'EC'};

  @override
  Future<String> signEs256(String signingInput) async => 'sig';
}

void main() {
  test('the default attest implementation returns null', () async {
    expect(await _StubSigner().attest('nonce'), isNull);
  });
}
