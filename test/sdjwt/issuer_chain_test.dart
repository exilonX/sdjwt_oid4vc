import 'dart:math';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';
import '../support/util.dart';

void main() {
  // A three-tier PKI: root (the trust anchor) → intermediate → leaf, where the
  // leaf key is the credential issuer's key.
  final root = SoftwareEs256Signer.generate(random: Random(400));
  final intermediate = SoftwareEs256Signer.generate(random: Random(401));
  final leaf = SoftwareEs256Signer.generate(random: Random(402));

  // "now" is 2030, inside the certs' default 2020..2040 validity window.
  final at2030 = fixedClock(DateTime.utc(2030).millisecondsSinceEpoch ~/ 1000);

  final rootCert =
      buildSignedCert(subjectJwk: root.publicJwkSync(), issuer: root);
  final intermediateCert =
      buildSignedCert(subjectJwk: intermediate.publicJwkSync(), issuer: root);
  final leafCert =
      buildSignedCert(subjectJwk: leaf.publicJwkSync(), issuer: intermediate);

  Future<SdJwtVc> credential({
    required List<String> x5c,
    SoftwareEs256Signer? signer,
  }) async =>
      SdJwt.parse(
        await SdJwt.issue(
          claims: const {
            'iss': 'https://issuer.example',
            'vct': 'v',
            'n': 'Ada',
          },
          header: {'x5c': x5c},
          selectivelyDisclosable: const {'n'},
          signer: signer ?? leaf,
        ),
      );

  Future<bool> trusts(
    SdJwtVc vc,
    List<String> anchors,
  ) =>
      vc.verifyIssuer(
        IssuerTrust.x5cChain(trustAnchors: anchors),
        now: at2030,
      );

  group('IssuerTrust.x5cChain', () {
    test('accepts a chain that links up to a trust anchor', () async {
      final vc = await credential(x5c: [leafCert, intermediateCert]);
      expect(await trusts(vc, [rootCert]), isTrue);
    });

    test('accepts when the anchor itself is the top of the chain', () async {
      final vc = await credential(x5c: [leafCert, intermediateCert, rootCert]);
      expect(await trusts(vc, [rootCert]), isTrue);
    });

    test('accepts a long-lived anchor (GeneralizedTime validity)', () async {
      // notAfter in 2060 → encoded as GeneralizedTime, like a real CA root.
      final longLivedRoot = buildSignedCert(
        subjectJwk: root.publicJwkSync(),
        issuer: root,
        notAfter: DateTime.utc(2060),
      );
      final vc = await credential(x5c: [leafCert, intermediateCert]);
      expect(await trusts(vc, [longLivedRoot]), isTrue);
    });

    test('rejects an untrusted anchor set', () async {
      final stranger = SoftwareEs256Signer.generate(random: Random(403));
      final strangerCert = buildSignedCert(
        subjectJwk: stranger.publicJwkSync(),
        issuer: stranger,
      );
      final vc = await credential(x5c: [leafCert, intermediateCert]);
      expect(await trusts(vc, [strangerCert]), isFalse);
    });

    test('rejects a broken link in the chain', () async {
      // The leaf was signed by `intermediate`; present a different one.
      final other = SoftwareEs256Signer.generate(random: Random(404));
      final otherIntermediateCert =
          buildSignedCert(subjectJwk: other.publicJwkSync(), issuer: root);
      final vc = await credential(x5c: [leafCert, otherIntermediateCert]);
      expect(await trusts(vc, [rootCert]), isFalse);
    });

    test('rejects an expired certificate in the chain', () async {
      final expiredLeaf = buildSignedCert(
        subjectJwk: leaf.publicJwkSync(),
        issuer: intermediate,
        notAfter: DateTime.utc(2025),
      );
      final vc = await credential(x5c: [expiredLeaf, intermediateCert]);
      expect(await trusts(vc, [rootCert]), isFalse);
    });

    test('rejects an expired trust anchor', () async {
      final expiredRoot = buildSignedCert(
        subjectJwk: root.publicJwkSync(),
        issuer: root,
        notAfter: DateTime.utc(2025),
      );
      final vc = await credential(x5c: [leafCert, intermediateCert]);
      expect(await trusts(vc, [expiredRoot]), isFalse);
    });

    test('rejects a credential not signed by the leaf key', () async {
      final imposter = SoftwareEs256Signer.generate(random: Random(405));
      final vc = await credential(
        x5c: [leafCert, intermediateCert],
        signer: imposter,
      );
      expect(await trusts(vc, [rootCert]), isFalse);
    });

    test('throws without any trust anchors', () async {
      final vc = await credential(x5c: [leafCert, intermediateCert]);
      expect(
        () => trusts(vc, const []),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('throws on an unparseable certificate in the chain', () async {
      // The minimal leaf cert has no validity period → not chain-validatable.
      final vc =
          await credential(x5c: [buildX5cLeafFromJwk(leaf.publicJwkSync())]);
      expect(
        () => trusts(vc, [rootCert]),
        throwsA(isA<SdJwtError>()),
      );
    });
  });
}
