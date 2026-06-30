import 'dart:math';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

/// The P-256 group order, to assert low-S normalisation.
final _n = BigInt.parse(
  'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
  radix: 16,
);

BigInt _be(List<int> bytes) =>
    bytes.fold(BigInt.zero, (acc, b) => (acc << 8) | BigInt.from(b));

void main() {
  test('a seeded generator is reproducible', () {
    final a = SoftwareEs256Signer.generate(random: Random(1)).publicJwkSync();
    final b = SoftwareEs256Signer.generate(random: Random(1)).publicJwkSync();
    expect(a, b);
  });

  test('the default (secure) generator produces a usable P-256 key', () {
    final jwk = SoftwareEs256Signer.generate().publicJwkSync();
    expect(jwk['crv'], 'P-256');
    expect(b64uDecode(jwk['x'] as String), hasLength(32));
  });

  test('publicJwk is a P-256 EC key and matches the sync accessor', () async {
    final signer = SoftwareEs256Signer.generate(random: Random(2));
    final jwk = await signer.publicJwk();
    expect(jwk['kty'], 'EC');
    expect(jwk['crv'], 'P-256');
    expect(b64uDecode(jwk['x'] as String), hasLength(32));
    expect(jwk['x'], signer.publicJwkSync()['x']);
  });

  test('signatures are 64 bytes, deterministic, low-S and verifiable',
      () async {
    final signer = SoftwareEs256Signer.generate(random: Random(3));
    const input = 'header.payload';

    final first = await signer.signEs256(input);
    final second = await signer.signEs256(input);
    expect(first, second, reason: 'RFC 6979 determinism');

    final raw = b64uDecode(first);
    expect(raw, hasLength(64));
    expect(_be(raw.sublist(32, 64)) <= _n >> 1, isTrue, reason: 'low-S');

    expect(
      verifyEs256WithJwk(
        signingInput: input,
        signature: raw,
        jwk: signer.publicJwkSync(),
      ),
      isTrue,
    );
  });

  test('attest returns null unless an attestor is supplied', () async {
    final plain = SoftwareEs256Signer.generate(random: Random(4));
    expect(await plain.attest('nonce'), isNull);

    final attesting = SoftwareEs256Signer.generate(
      random: Random(4),
      attestor: (nonce) => KeyAttestation(
        format: 'android-key',
        data: 'attested:$nonce',
      ),
    );
    final attestation = await attesting.attest('n1');
    expect(attestation?.data, 'attested:n1');
    expect(attestation?.format, 'android-key');
  });
}
