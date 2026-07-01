import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

import 'support/fake_http.dart';

/// Conformance tests against the *published* test vectors of the specs this
/// library implements. Unlike the rest of the suite (which round-trips through
/// our own encoders), these pin our decoders to bytes that come straight out of
/// the RFC/draft text — so a divergence from the wire format fails here.
///
/// Sources:
///  - SD-JWT (RFC 9901 / draft-ietf-oauth-selective-disclosure-jwt), the
///    worked disclosure examples (§ "Disclosures for … Claims").
///  - Token Status List (draft-ietf-oauth-status-list), the "Test Vectors"
///    appendix (1-bit and 2-bit encoded lists).
void main() {
  group('SD-JWT disclosure vectors (RFC 9901)', () {
    // Each row: the base64url Disclosure exactly as printed in the spec, the
    // array it must decode to, and the SHA-256 digest the spec derives from it.
    const vectors = <({
      String disclosure,
      String salt,
      String? name,
      Object? value,
      String digest,
    })>[
      (
        disclosure:
            'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd',
        salt: '2GLC42sKQveCfGfryNRN9w',
        name: 'given_name',
        value: 'John',
        digest: 'jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4',
      ),
      (
        disclosure:
            'WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd',
        salt: 'eluV5Og3gSNII8EYnsxA_A',
        name: 'family_name',
        value: 'Doe',
        digest: 'TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo',
      ),
      (
        disclosure:
            'WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRy'
            'ZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9u'
            'IjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0',
        salt: 'AJx-095VPrpTtN4QMOqROA',
        name: 'address',
        value: {
          'street_address': '123 Main St',
          'locality': 'Anytown',
          'region': 'Anystate',
          'country': 'US',
        },
        digest: 'XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE',
      ),
      // Array-element disclosure (2-element form): ["salt", value].
      (
        disclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0',
        salt: 'lklxF5jMYlGTPUovMNIvCA',
        name: null,
        value: 'US',
        digest: 'pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo',
      ),
    ];

    for (final v in vectors) {
      test('decodes and digests ${v.name ?? 'array element'}', () {
        final d = Disclosure.parse(v.disclosure);
        expect(d.salt, v.salt);
        expect(d.name, v.name);
        expect(d.value, v.value);
        expect(d.isArrayElement, v.name == null);
        // The digest is taken over the ASCII of the disclosure exactly as given.
        expect(d.digest(sha256), v.digest, reason: 'sha-256 digest mismatch');
      });
    }
  });

  group('Token Status List vectors (draft-ietf-oauth-status-list)', () {
    // Feed the resolver the *spec's own* base64url lst (its DEFLATE bytes), so
    // this exercises our zlib-inflate + LSB-first bit reader, not our encoder.
    Future<CredentialStatus> statusAt(
      int bits,
      String lst,
      int index,
    ) {
      final header = {'alg': 'ES256', 'typ': 'statuslist+jwt'};
      final payload = {
        'iss': 'https://issuer.example',
        'sub': 'https://status.example/1',
        'status_list': {'bits': bits, 'lst': lst},
      };
      // trust: null below, so the (placeholder) signature is never checked.
      final token = '${Jws.signingInput(header, payload)}.AA';
      final resolver = StatusListResolver(
        FakeOid4vcHttp((_) => HttpResp(200, token)),
      );
      return resolver.resolve(
        StatusListRef(uri: Uri.parse('https://status.example/1'), index: index),
      );
    }

    test('1-bit list "eNrbuRgAAhcBXQ" decodes every index', () async {
      const lst = 'eNrbuRgAAhcBXQ';
      const expected = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
      for (var i = 0; i < expected.length; i++) {
        final value = (await statusAt(1, lst, i)).value;
        expect(value, expected[i], reason: 'idx $i');
      }
    });

    test('2-bit list "eNo76fITAAPfAgc" decodes every index', () async {
      const lst = 'eNo76fITAAPfAgc';
      const expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
      for (var i = 0; i < expected.length; i++) {
        final value = (await statusAt(2, lst, i)).value;
        expect(value, expected[i], reason: 'idx $i');
      }
    });

    test('2-bit vector maps to the well-known status kinds', () async {
      Future<CredentialStatusKind> kindAt(int i) async =>
          (await statusAt(2, 'eNo76fITAAPfAgc', i)).kind;
      expect(await kindAt(0), CredentialStatusKind.invalid); // status 1
      expect(await kindAt(2), CredentialStatusKind.valid); // status 0
      expect(await kindAt(1), CredentialStatusKind.suspended); // status 2
      expect(await kindAt(3), CredentialStatusKind.applicationSpecific); // 3
    });
  });
}
