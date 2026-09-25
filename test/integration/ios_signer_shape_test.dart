import 'dart:math';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/fake_http.dart';
import '../support/util.dart';

/// On iOS the holder key signs through CryptoKit (`SecureEnclave.P256`), whose
/// ECDSA signatures are randomised and **not** low-S normalised. The rest of the
/// suite signs with [SoftwareEs256Signer], which always emits low-S. These tests
/// check that the library passes a high-S signature through unchanged and that
/// its own ES256 verification accepts one. JOSE ES256 does not require low-S,
/// and a high-S signature is equally valid.
void main() {
  final holder = _HighSSigner(SoftwareEs256Signer.generate(random: Random(9)));

  test('the Apple-shaped signer really emits high-S signatures', () async {
    final sig = b64uDecode(await holder.signEs256('probe'));
    final s = BigInt.parse(
      sig.sublist(32).map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16,
    );
    expect(s > p256.n >> 1, isTrue);
  });

  test('an OpenID4VCI proof carries the high-S signature verbatim and verifies',
      () async {
    final signer = _RecordingSigner(holder);
    final proof = await Oid4vciClient(
      FakeOid4vcHttp((_) => HttpResp(404, '')),
      now: fixedClock(1700),
    ).buildProof(
      issuer: 'https://issuer.example',
      cNonce: 'CN',
      signer: signer,
    );

    final jws = Jws.decompose(proof);
    expect(proof.split('.').last, signer.last);
    expect(
      verifyEs256WithJwk(
        signingInput: jws.signingInput,
        signature: jws.signature,
        jwk: await holder.publicJwk(),
      ),
      isTrue,
    );
  });

  test('a KB-JWT carries the high-S signature verbatim and verifies', () async {
    final issuer = SoftwareEs256Signer.generate(random: Random(10));
    final credential = SdJwt.parse(
      await SdJwt.issue(
        claims: {
          'iss': 'https://issuer.example',
          'vct': 'urn:eudi:pid:1',
          'cnf': {'jwk': await holder.publicJwk()},
          'given_name': 'Ana',
        },
        header: const {},
        selectivelyDisclosable: const {'given_name'},
        signer: issuer,
      ),
    );
    const req = PresentationRequest(
      clientId: 'x509_hash:abc',
      nonce: 'N',
      responseMode: 'direct_post.jwt',
      dcql: DcqlQuery([]),
    );

    final signer = _RecordingSigner(holder);
    final vpToken = await Oid4vpClient(
      FakeOid4vcHttp((_) => HttpResp(404, '')),
      now: fixedClock(1700),
    ).buildVpToken(
      credential: credential,
      revealClaims: const {'given_name'},
      req: req,
      signer: signer,
    );

    final kbJwt = vpToken.split('~').last;
    expect(kbJwt.split('.').last, signer.last);
    final jws = Jws.decompose(kbJwt);
    expect(
      verifyEs256WithJwk(
        signingInput: jws.signingInput,
        signature: jws.signature,
        jwk: await holder.publicJwk(),
      ),
      isTrue,
    );
  });
}

/// Wraps a signer and flips every signature to its high-S twin `(r, n - s)`,
/// mimicking CryptoKit on iOS.
class _HighSSigner implements Es256Signer {
  _HighSSigner(this._inner);

  final Es256Signer _inner;

  @override
  Future<Map<String, dynamic>> publicJwk() => _inner.publicJwk();

  @override
  Future<String> signEs256(String signingInput) async {
    final raw = b64uDecode(await _inner.signEs256(signingInput));
    final s = BigInt.parse(
      raw.sublist(32).map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16,
    );
    final highS = (p256.n - s).toRadixString(16).padLeft(64, '0');
    return b64uEncode([
      ...raw.sublist(0, 32),
      for (var i = 0; i < 64; i += 2)
        int.parse(highS.substring(i, i + 2), radix: 16),
    ]);
  }

  @override
  Future<KeyAttestation?> attest(String nonce) => _inner.attest(nonce);
}

/// Records the last signature handed out, to prove the library emits it as-is.
class _RecordingSigner implements Es256Signer {
  _RecordingSigner(this._inner);

  final Es256Signer _inner;
  String? last;

  @override
  Future<Map<String, dynamic>> publicJwk() => _inner.publicJwk();

  @override
  Future<String> signEs256(String signingInput) async =>
      last = await _inner.signEs256(signingInput);

  @override
  Future<KeyAttestation?> attest(String nonce) => _inner.attest(nonce);
}
