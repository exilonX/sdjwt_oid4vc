import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';
import '../support/fake_http.dart';
import '../support/util.dart';

void main() {
  final signer = SoftwareEs256Signer.generate(random: Random(11));
  final jwk = signer.publicJwkSync();

  group('parse', () {
    test('splits issuer JWT, disclosures and KB-JWT', () {
      final disclosure =
          Disclosure.forClaim(salt: 's', name: 'n', value: 'v').encoded;
      final base = customSdJwt(
        const {'iss': 'x', '_sd_alg': 'sha-256'},
        disclosures: [disclosure],
      );
      // base already ends with '~' (no KB-JWT).
      expect(SdJwt.parse(base).disclosures, hasLength(1));
      expect(SdJwt.parse(base).kbJwt, isNull);

      final withKb = SdJwt.parse('${base}KB.JWT.SIG');
      expect(withKb.disclosures, hasLength(1));
      expect(withKb.kbJwt, 'KB.JWT.SIG');
    });

    test('handles a bare issuer JWT with no tilde', () {
      final jwt = customSdJwt(const {'iss': 'x'}).split('~').first;
      final vc = SdJwt.parse(jwt);
      expect(vc.disclosures, isEmpty);
      expect(vc.kbJwt, isNull);
    });

    test('throws SdJwtError on a malformed issuer JWT', () {
      expect(() => SdJwt.parse('not.a.jwt~'), throwsA(isA<SdJwtError>()));
    });

    test('throws SdJwtError on a malformed disclosure', () {
      final jwt = customSdJwt(const {'iss': 'x'}).split('~').first;
      expect(
        () => SdJwt.parse('$jwt~@@notbase64@@~'),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('resolveClaims', () {
    test('merges flat disclosures and strips SD machinery', () {
      final given =
          Disclosure.forClaim(salt: 's1', name: 'given_name', value: 'Ada');
      final compact = customSdJwt(
        {
          'iss': 'x',
          'vct': 'v',
          '_sd': [given.digest(sha256)],
          '_sd_alg': 'sha-256',
        },
        disclosures: [given.encoded],
      );
      final claims = SdJwt.parse(compact).resolveClaims();
      expect(claims['given_name'], 'Ada');
      expect(claims['vct'], 'v');
      expect(claims.containsKey('_sd'), isFalse);
      expect(claims.containsKey('_sd_alg'), isFalse);
    });

    test('resolves nested objects and array elements, omits undisclosed', () {
      final street =
          Disclosure.forClaim(salt: 's2', name: 'street', value: 'Main');
      final arrayElement = b64uEncodeString(jsonEncode(['s3', 'RO']));
      final arrayDigest = Disclosure.parse(arrayElement).digest(sha256);

      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          'address': {
            '_sd': [street.digest(sha256)],
          },
          'nationalities': [
            {'...': arrayDigest},
            {'...': 'digest-with-no-disclosure'},
            'XX',
          ],
        },
        disclosures: [street.encoded, arrayElement],
      );

      final claims = SdJwt.parse(compact).resolveClaims();
      expect((claims['address'] as Map)['street'], 'Main');
      expect(claims['nationalities'], ['RO', 'XX']);
    });

    test('throws on an unsupported _sd_alg', () {
      // A disclosure forces hash evaluation, which is where the alg is checked.
      final d = Disclosure.forClaim(salt: 's', name: 'n', value: 'v');
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-1',
          '_sd': [d.digest(sha256)],
        },
        disclosures: [d.encoded],
      );
      expect(
        () => SdJwt.parse(compact).resolveClaims(),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('issue', () {
    test('round-trips through parse and resolve', () async {
      final compact = await SdJwt.issue(
        claims: const {
          'iss': 'https://issuer.example',
          'vct': 'https://issuer.example/cred/v1',
          'given_name': 'Ada',
          'family_name': 'Byron',
          'exp': 4102444800,
        },
        header: const {'kid': 'k1'},
        selectivelyDisclosable: const {'given_name', 'family_name'},
        signer: signer,
        saltGenerator: seqSalts(['s1', 's2']),
      );

      final vc = SdJwt.parse(compact);
      expect(vc.disclosures, hasLength(2));
      expect(vc.header['kid'], 'k1');
      expect(vc.header['typ'], 'dc+sd-jwt');
      expect(vc.issuerClaims['_sd_alg'], 'sha-256');

      // `_sd` digests are sorted, and the cleartext claims are gone.
      final sd = (vc.issuerClaims['_sd'] as List).cast<String>();
      expect(sd, equals([...sd]..sort()));
      expect(vc.issuerClaims.containsKey('given_name'), isFalse);

      final claims = vc.resolveClaims();
      expect(claims['given_name'], 'Ada');
      expect(claims['family_name'], 'Byron');
    });

    test('supports sha-384 and rejects an unsupported hash', () async {
      final compact = await SdJwt.issue(
        claims: const {'iss': 'x', 'secret': 's'},
        header: const {},
        selectivelyDisclosable: const {'secret'},
        signer: signer,
        saltGenerator: seqSalts(['s1']),
        hash: sha384,
      );
      final vc = SdJwt.parse(compact);
      expect(vc.issuerClaims['_sd_alg'], 'sha-384');
      expect(vc.resolveClaims()['secret'], 's');

      expect(
        () => SdJwt.issue(
          claims: const {'iss': 'x'},
          header: const {},
          selectivelyDisclosable: const {},
          signer: signer,
          hash: sha1,
        ),
        throwsArgumentError,
      );
    });
  });

  group('getters', () {
    test('vct, confirmationJwk and statusRef', () {
      final compact = customSdJwt({
        'iss': 'x',
        'vct': 'https://t/v1',
        'cnf': {'jwk': jwk},
        'status': {
          'status_list': {'idx': 3, 'uri': 'https://issuer/status/1'},
        },
      });
      final vc = SdJwt.parse(compact);
      expect(vc.vct, 'https://t/v1');
      expect(vc.confirmationJwk, jwk);
      expect(vc.statusRef, 'https://issuer/status/1');
    });

    test('absent/typed-wrong optional claims yield null', () {
      final vc = SdJwt.parse(customSdJwt(const {'iss': 'x', 'vct': 1}));
      expect(vc.vct, isNull);
      expect(vc.confirmationJwk, isNull);
      expect(vc.statusRef, isNull);
    });

    test('isExpiredAt honours exp; isExpired uses the system clock', () {
      final vc = SdJwt.parse(customSdJwt(const {'iss': 'x', 'exp': 2000}));
      expect(vc.isExpiredAt(1999), isFalse);
      expect(vc.isExpiredAt(2000), isTrue);
      expect(vc.isExpiredAt(2001), isTrue);
      expect(vc.isExpired, isTrue); // exp is in 1970

      final noExp = SdJwt.parse(customSdJwt(const {'iss': 'x'}));
      expect(noExp.isExpiredAt(9999999999), isFalse);
    });
  });

  group('verifyIssuer (x5c, signatureOnly)', () {
    test('returns true for a matching key', () async {
      final compact = await _issued(
        signer,
        header: {
          'x5c': [buildX5cLeafFromJwk(jwk)],
        },
      );
      expect(
        await SdJwt.parse(compact).verifyIssuer(IssuerTrust.signatureOnly()),
        isTrue,
      );
    });

    test('returns false when the x5c key is a different key', () async {
      final other = SoftwareEs256Signer.generate(random: Random(99));
      final compact = await _issued(
        signer,
        header: {
          'x5c': [buildX5cLeafFromJwk(other.publicJwkSync())],
        },
      );
      expect(
        await SdJwt.parse(compact).verifyIssuer(IssuerTrust.signatureOnly()),
        isFalse,
      );
    });

    test('throws when there is no x5c', () async {
      final compact = await _issued(signer, header: const {});
      expect(
        () => SdJwt.parse(compact).verifyIssuer(IssuerTrust.signatureOnly()),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('verifyIssuer (issuer metadata)', () {
    Future<String> issuedBy(
      String iss, {
      Map<String, dynamic> header = const {},
    }) =>
        SdJwt.issue(
          claims: {'iss': iss, 'vct': 'v'},
          header: header,
          selectivelyDisclosable: const {},
          signer: signer,
        );

    test('resolves an inline JWK set', () async {
      final compact = await issuedBy('https://issuer.example/tenant');
      final http = FakeOid4vcHttp.byPath({
        '/.well-known/jwt-vc-issuer/tenant': jsonResponse({
          'issuer': 'https://issuer.example/tenant',
          'jwks': {
            'keys': [jwk],
          },
        }),
      });
      expect(
        await SdJwt.parse(compact)
            .verifyIssuer(IssuerTrust.issuerMetadata(), http: http),
        isTrue,
      );
    });

    test('follows jwks_uri and selects the key by kid', () async {
      final other = SoftwareEs256Signer.generate(random: Random(5));
      final compact = await issuedBy(
        'https://issuer.example',
        header: {'kid': 'k1'},
      );
      final http = FakeOid4vcHttp.byPath({
        '/.well-known/jwt-vc-issuer': jsonResponse({
          'jwks_uri': 'https://issuer.example/keys.json',
        }),
        '/keys.json': jsonResponse({
          'keys': [
            {...other.publicJwkSync(), 'kid': 'k0'},
            {...jwk, 'kid': 'k1'},
          ],
        }),
      });
      expect(
        await SdJwt.parse(compact)
            .verifyIssuer(IssuerTrust.issuerMetadata(), http: http),
        isTrue,
      );
    });

    test('requires an http client', () async {
      final compact = await issuedBy('https://issuer.example');
      expect(
        () => SdJwt.parse(compact).verifyIssuer(IssuerTrust.issuerMetadata()),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('fails clearly on bad iss / metadata / empty key set', () async {
      final noIss = SdJwt.parse(customSdJwt(const {'vct': 'v'}));
      expect(
        () => noIss.verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath(const {}),
        ),
        throwsA(isA<SdJwtError>()),
      );

      final compact = await issuedBy('https://issuer.example');
      final vc = SdJwt.parse(compact);

      // 404 from the metadata endpoint.
      expect(
        () => vc.verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath(const {}),
        ),
        throwsA(isA<SdJwtError>()),
      );

      // Neither jwks nor jwks_uri.
      expect(
        () => vc.verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath({
            '/.well-known/jwt-vc-issuer': jsonResponse(const {}),
          }),
        ),
        throwsA(isA<SdJwtError>()),
      );

      // Empty key set.
      expect(
        () => vc.verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath({
            '/.well-known/jwt-vc-issuer': jsonResponse({
              'jwks': {'keys': <Object>[]},
            }),
          }),
        ),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('present', () {
    test('reveals the chosen claim and binds a verifiable KB-JWT', () async {
      final compact = await SdJwt.issue(
        claims: const {
          'iss': 'x',
          'vct': 'v',
          'given_name': 'Ada',
          'family_name': 'Byron',
        },
        header: const {},
        selectivelyDisclosable: const {'given_name', 'family_name'},
        signer: signer,
        saltGenerator: seqSalts(['s1', 's2']),
      );

      final presentation = await SdJwt.parse(compact).present(
        disclose: {'given_name'},
        audience: 'https://verifier.example',
        nonce: 'nonce-1',
        signer: signer,
        now: fixedClock(1700),
      );

      final presented = SdJwt.parse(presentation);
      expect(presented.disclosures, hasLength(1));
      expect(presented.disclosures.single.name, 'given_name');
      expect(presented.kbJwt, isNotNull);

      final kb = Jws.decompose(presented.kbJwt!);
      expect(kb.header['typ'], 'kb+jwt');
      expect(kb.payload['aud'], 'https://verifier.example');
      expect(kb.payload['nonce'], 'nonce-1');
      expect(kb.payload['iat'], 1700);

      final prefix = presentation.substring(
        0,
        presentation.length - presented.kbJwt!.length,
      );
      expect(kb.payload['sd_hash'], KbJwt.sdHash(prefix, sha256));
      expect(
        verifyEs256WithJwk(
          signingInput: kb.signingInput,
          signature: kb.signature,
          jwk: jwk,
        ),
        isTrue,
      );
    });
  });

  group('present by path (nested / arrays)', () {
    Future<String> presentPaths(String compact, Set<List<Object?>> paths) =>
        SdJwt.parse(compact).present(
          disclosePaths: paths,
          audience: 'aud',
          nonce: 'n',
          signer: signer,
          now: fixedClock(1),
        );

    test('reveals a nested claim by path, leaving siblings hidden', () async {
      final street =
          Disclosure.forClaim(salt: 's1', name: 'street', value: 'Main');
      final city = Disclosure.forClaim(salt: 's2', name: 'city', value: 'Cluj');
      final compact = customSdJwt(
        {
          'iss': 'x',
          'vct': 'v',
          '_sd_alg': 'sha-256',
          'address': {
            '_sd': [street.digest(sha256), city.digest(sha256)],
          },
        },
        disclosures: [street.encoded, city.encoded],
      );

      final presented = SdJwt.parse(
        await presentPaths(compact, {
          ['address', 'street'],
        }),
      );
      expect(presented.disclosures.map((d) => d.name), ['street']);
      final address = presented.resolveClaims()['address'] as Map;
      expect(address['street'], 'Main');
      expect(address.containsKey('city'), isFalse);
    });

    test('pulls in the parent disclosure for a doubly-nested claim', () async {
      final street =
          Disclosure.forClaim(salt: 's1', name: 'street', value: 'Main');
      final address = Disclosure.forClaim(
        salt: 's2',
        name: 'address',
        value: {
          '_sd': [street.digest(sha256)],
        },
      );
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          '_sd': [address.digest(sha256)],
        },
        disclosures: [address.encoded, street.encoded],
      );

      final presented = SdJwt.parse(
        await presentPaths(compact, {
          ['address', 'street'],
        }),
      );
      expect(
        presented.disclosures.map((d) => d.name).toSet(),
        {'address', 'street'},
      );
      expect((presented.resolveClaims()['address'] as Map)['street'], 'Main');
    });

    test('discloses a single array element, or all via a null wildcard',
        () async {
      final ro = b64uEncodeString(jsonEncode(['s1', 'RO']));
      final de = b64uEncodeString(jsonEncode(['s2', 'DE']));
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          'nationalities': [
            {'...': Disclosure.parse(ro).digest(sha256)},
            {'...': Disclosure.parse(de).digest(sha256)},
            'XX', // a clear (non-disclosure) array element
          ],
        },
        disclosures: [ro, de],
      );

      final one = SdJwt.parse(
        await presentPaths(compact, {
          ['nationalities', 0],
        }),
      );
      expect(one.resolveClaims()['nationalities'], ['RO', 'XX']);

      final all = SdJwt.parse(
        await presentPaths(compact, {
          ['nationalities', null],
        }),
      );
      expect(all.resolveClaims()['nationalities'], ['RO', 'DE', 'XX']);
    });

    test('a null wildcard does not select a non-array position', () async {
      final compact = await SdJwt.issue(
        claims: const {'iss': 'x', 'vct': 'v', 'given_name': 'Ada'},
        header: const {},
        selectivelyDisclosable: const {'given_name'},
        signer: signer,
        saltGenerator: seqSalts(['s1']),
      );
      final presented = SdJwt.parse(
        await presentPaths(compact, {
          [null],
        }),
      );
      expect(presented.disclosures, isEmpty);
    });

    test('rejects presenting a pathologically deep credential', () async {
      Object deep(int n) {
        Object node = 'leaf';
        for (var i = 0; i < n; i++) {
          node = {'a': node};
        }
        return node;
      }

      final d = Disclosure.forClaim(salt: 's', name: 'deep', value: deep(40));
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          '_sd': [d.digest(sha256)],
        },
        disclosures: [d.encoded],
      );
      expect(
        () => presentPaths(compact, {
          ['deep'],
        }),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('verifyIssuer error edges', () {
    test('wraps an invalid x5c leaf as SdJwtError', () async {
      final compact = await _issued(
        signer,
        header: const {
          'x5c': ['@@@ not a certificate @@@'],
        },
      );
      expect(
        () => SdJwt.parse(compact).verifyIssuer(IssuerTrust.signatureOnly()),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('wraps a non-EC issuer JWK as SdJwtError', () async {
      final compact = await SdJwt.issue(
        claims: const {'iss': 'https://issuer.example', 'vct': 'v'},
        header: const {},
        selectivelyDisclosable: const {},
        signer: signer,
      );
      final http = FakeOid4vcHttp.byPath({
        '/.well-known/jwt-vc-issuer': jsonResponse({
          'jwks': {
            'keys': [
              {'kty': 'RSA', 'n': 'AQAB', 'e': 'AQAB'},
            ],
          },
        }),
      });
      expect(
        () => SdJwt.parse(compact)
            .verifyIssuer(IssuerTrust.issuerMetadata(), http: http),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects a non-absolute iss', () {
      final vc = SdJwt.parse(customSdJwt(const {'iss': 'not-absolute'}));
      expect(
        () => vc.verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath(const {}),
        ),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects a non-absolute jwks_uri', () async {
      final compact = await SdJwt.issue(
        claims: const {'iss': 'https://issuer.example', 'vct': 'v'},
        header: const {},
        selectivelyDisclosable: const {},
        signer: signer,
      );
      final http = FakeOid4vcHttp.byPath({
        '/.well-known/jwt-vc-issuer': jsonResponse({'jwks_uri': 'relative'}),
      });
      expect(
        () => SdJwt.parse(compact)
            .verifyIssuer(IssuerTrust.issuerMetadata(), http: http),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('resolveClaims hardening', () {
    test('rejects two disclosures sharing one digest', () {
      final d = Disclosure.forClaim(salt: 's', name: 'n', value: 'v');
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          '_sd': [d.digest(sha256)],
        },
        disclosures: [d.encoded, d.encoded], // same disclosure twice
      );
      expect(
        () => SdJwt.parse(compact).resolveClaims(),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects a digest referenced more than once', () {
      final d = Disclosure.forClaim(salt: 's', name: 'n', value: 'v');
      final compact = customSdJwt(
        {
          'iss': 'x',
          '_sd_alg': 'sha-256',
          '_sd': [d.digest(sha256), d.digest(sha256)], // same digest twice
        },
        disclosures: [d.encoded],
      );
      expect(
        () => SdJwt.parse(compact).resolveClaims(),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects a disclosed claim that collides with a clear one', () {
      final d = Disclosure.forClaim(salt: 's', name: 'n', value: 'v');
      final compact = customSdJwt(
        {
          'iss': 'x',
          'n': 'clear', // a clear claim of the same name
          '_sd_alg': 'sha-256',
          '_sd': [d.digest(sha256)],
        },
        disclosures: [d.encoded],
      );
      expect(
        () => SdJwt.parse(compact).resolveClaims(),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects nesting beyond the depth limit', () {
      Object deep(int n) {
        Object node = 'leaf';
        for (var i = 0; i < n; i++) {
          node = {'a': node};
        }
        return node;
      }

      final compact = customSdJwt({'iss': 'x', 'deep': deep(40)});
      expect(
        () => SdJwt.parse(compact).resolveClaims(),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('validity window', () {
    test('exposes nbf / isValid and honours the window', () {
      final vc = SdJwt.parse(
        customSdJwt(const {'iss': 'x', 'nbf': 1000, 'exp': 2000}),
      );
      expect(vc.notBefore, 1000);
      expect(vc.isNotYetValidAt(999), isTrue);
      expect(vc.isNotYetValidAt(1000), isFalse);
      expect(vc.isValidAt(999), isFalse); // before nbf
      expect(vc.isValidAt(1500), isTrue);
      expect(vc.isValidAt(2000), isFalse); // at exp
      expect(vc.isNotYetValid, isFalse); // nbf is in 1970

      final none = SdJwt.parse(customSdJwt(const {'iss': 'x'}));
      expect(none.notBefore, isNull);
      expect(none.isNotYetValidAt(0), isFalse);
      expect(none.isValid, isTrue);
    });

    test('verifyIssuer enforceValidity rejects an out-of-window credential',
        () async {
      final compact = await SdJwt.issue(
        claims: {'iss': 'https://issuer.example', 'vct': 'v', 'exp': 2000},
        header: {
          'x5c': [buildX5cLeafFromJwk(jwk)],
        },
        selectivelyDisclosable: const {},
        signer: signer,
      );
      final vc = SdJwt.parse(compact);

      // Signature is valid regardless of the clock.
      expect(await vc.verifyIssuer(IssuerTrust.signatureOnly()), isTrue);
      // Expired under enforcement → not currently trustworthy.
      expect(
        await vc.verifyIssuer(
          IssuerTrust.signatureOnly(),
          enforceValidity: true,
          now: fixedClock(3000),
        ),
        isFalse,
      );
      // Inside the window under enforcement → trustworthy.
      expect(
        await vc.verifyIssuer(
          IssuerTrust.signatureOnly(),
          enforceValidity: true,
          now: fixedClock(1500),
        ),
        isTrue,
      );
    });
  });

  group('header guard', () {
    test('rejects a non-ES256 alg before any key work', () {
      final compact = customSdJwt(
        const {'iss': 'x'},
        header: const {'alg': 'HS256', 'typ': 'dc+sd-jwt'},
      );
      expect(
        () => SdJwt.parse(compact).verifyIssuer(IssuerTrust.signatureOnly()),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('rejects an unexpected or missing typ', () {
      final wrongTyp = customSdJwt(
        const {'iss': 'x'},
        header: const {'alg': 'ES256', 'typ': 'jwt'},
      );
      expect(
        () => SdJwt.parse(wrongTyp).verifyIssuer(IssuerTrust.signatureOnly()),
        throwsA(isA<SdJwtError>()),
      );

      final noTyp = customSdJwt(
        const {'iss': 'x'},
        header: const {'alg': 'ES256'},
      );
      expect(
        () => SdJwt.parse(noTyp).verifyIssuer(IssuerTrust.signatureOnly()),
        throwsA(isA<SdJwtError>()),
      );
    });
  });

  group('metadata transport security', () {
    test('refuses an http iss', () {
      final compact = customSdJwt(const {'iss': 'http://issuer.example'});
      expect(
        () => SdJwt.parse(compact).verifyIssuer(
          IssuerTrust.issuerMetadata(),
          http: FakeOid4vcHttp.byPath(const {}),
        ),
        throwsA(isA<SdJwtError>()),
      );
    });

    test('refuses an http jwks_uri', () {
      final compact = customSdJwt(const {'iss': 'https://issuer.example'});
      final http = FakeOid4vcHttp.byPath({
        '/.well-known/jwt-vc-issuer': jsonResponse(
          {'jwks_uri': 'http://issuer.example/keys.json'},
        ),
      });
      expect(
        () => SdJwt.parse(compact)
            .verifyIssuer(IssuerTrust.issuerMetadata(), http: http),
        throwsA(isA<SdJwtError>()),
      );
    });
  });
}

Future<String> _issued(
  SoftwareEs256Signer signer, {
  required Map<String, dynamic> header,
}) =>
    SdJwt.issue(
      claims: const {'iss': 'https://issuer.example', 'vct': 'v', 'n': 'Ada'},
      header: header,
      selectivelyDisclosable: const {'n'},
      signer: signer,
    );
