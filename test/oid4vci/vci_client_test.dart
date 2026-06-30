import 'dart:convert';
import 'dart:math';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/fake_http.dart';
import '../support/util.dart';

const _issuer = 'https://issuer.example';

final _issuerMeta = {
  'credential_issuer': _issuer,
  'credential_endpoint': '$_issuer/credential',
  'nonce_endpoint': '$_issuer/nonce',
  'credential_configurations_supported': {
    'extras_salariat': {
      'vct': '$_issuer/extras/v1',
      'format': 'dc+sd-jwt',
    },
  },
};

String _offerJson({bool txCode = true}) => jsonEncode({
      'credential_issuer': _issuer,
      'credential_configuration_ids': ['extras_salariat'],
      'grants': {
        preAuthorizedCodeGrant: {
          'pre-authorized_code': 'PAC',
          if (txCode) 'tx_code': {'length': 4},
        },
      },
    });

/// A fully-wired happy-path issuer. [credential] is what `/credential` returns.
FakeOid4vcHttp happyIssuer({String credential = 'ISSUED.SD~JWT~'}) =>
    FakeOid4vcHttp((req) {
      switch (req.url.path) {
        case '/.well-known/openid-credential-issuer':
          return jsonResponse(_issuerMeta);
        case '/.well-known/oauth-authorization-server':
          return jsonResponse({'token_endpoint': '$_issuer/token'});
        case '/token':
          return jsonResponse({'access_token': 'AT', 'c_nonce': 'CN'});
        case '/nonce':
          return jsonResponse({'c_nonce': 'CN2'});
        case '/credential':
          return jsonResponse({'credential': credential});
        default:
          return HttpResp(404, 'no route: ${req.url.path}');
      }
    });

void main() {
  final signer = SoftwareEs256Signer.generate(random: Random(21));

  group('parseOffer', () {
    final client = Oid4vciClient(happyIssuer());

    test('parses raw JSON', () async {
      final offer = await client.parseOffer(_offerJson());
      expect(offer.issuer, _issuer);
      expect(offer.preAuthCode, 'PAC');
    });

    test('parses a deep link with an inline credential_offer', () async {
      final link =
          'openid-credential-offer://?credential_offer=${Uri.encodeQueryComponent(_offerJson())}';
      expect((await client.parseOffer(link)).configIds, ['extras_salariat']);
    });

    test('follows credential_offer_uri', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/offer/1'
            ? jsonResponse(jsonDecode(_offerJson()) as Object)
            : HttpResp(404, ''),
      );
      final offer = await Oid4vciClient(http).parseOffer(
        'openid-credential-offer://?credential_offer_uri=$_issuer/offer/1',
      );
      expect(offer.preAuthCode, 'PAC');
    });

    test('throws when the URI carries no offer', () async {
      expect(
        () => client.parseOffer('https://issuer.example/nothing'),
        throwsA(isA<OfferParseError>()),
      );
    });

    test('throws when an offer_uri fetch fails', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(500, 'boom'));
      expect(
        () => Oid4vciClient(http)
            .parseOffer('x://?credential_offer_uri=$_issuer/o'),
        throwsA(isA<OfferParseError>()),
      );
    });

    test('refuses to fetch an offer_uri over insecure http', () async {
      expect(
        () => Oid4vciClient(happyIssuer())
            .parseOffer('x://?credential_offer_uri=http://issuer.example/o'),
        throwsA(isA<CredentialError>()),
      );
    });
  });

  group('fetchIssuerMetadata', () {
    test('discovers endpoints and vct map via AS metadata', () async {
      final meta = await Oid4vciClient(happyIssuer()).fetchIssuerMetadata(
        await Oid4vciClient(happyIssuer()).parseOffer(_offerJson()),
      );
      expect(meta.credentialEndpoint, Uri.parse('$_issuer/credential'));
      expect(meta.tokenEndpoint, Uri.parse('$_issuer/token'));
      expect(meta.nonceEndpoint, Uri.parse('$_issuer/nonce'));
      expect(meta.vcts, {'extras_salariat': '$_issuer/extras/v1'});
    });

    test('uses an inline token_endpoint when present', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/.well-known/openid-credential-issuer'
            ? jsonResponse({..._issuerMeta, 'token_endpoint': '$_issuer/t2'})
            : HttpResp(404, ''),
      );
      final client = Oid4vciClient(http);
      final meta = await client.fetchIssuerMetadata(
        await client.parseOffer(_offerJson()),
      );
      expect(meta.tokenEndpoint, Uri.parse('$_issuer/t2'));
    });

    test('throws when credential_endpoint is missing', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/.well-known/openid-credential-issuer'
            ? jsonResponse({'credential_issuer': _issuer})
            : HttpResp(404, ''),
      );
      final client = Oid4vciClient(http);
      expect(
        () async => client.fetchIssuerMetadata(
          await client.parseOffer(_offerJson()),
        ),
        throwsA(isA<CredentialError>()),
      );
    });
  });

  group('requestToken', () {
    test('posts the grant, code and tx_code', () async {
      final http = happyIssuer();
      final client = Oid4vciClient(http);
      final offer = await client.parseOffer(_offerJson());
      final meta = await client.fetchIssuerMetadata(offer);

      final token = await client.requestToken(
        offer: offer,
        meta: meta,
        txCode: '1234',
      );
      expect(token.accessToken, 'AT');
      expect(token.cNonce, 'CN');
      expect(http.last.url, Uri.parse('$_issuer/token'));
      expect(http.last.form, {
        'grant_type': preAuthorizedCodeGrant,
        'pre-authorized_code': 'PAC',
        'tx_code': '1234',
      });
    });

    test('omits tx_code when the offer does not require it', () async {
      final http = happyIssuer();
      final client = Oid4vciClient(http);
      final offer = await client.parseOffer(_offerJson(txCode: false));
      final meta = await client.fetchIssuerMetadata(offer);
      await client.requestToken(offer: offer, meta: meta, txCode: '');
      expect(http.last.form.containsKey('tx_code'), isFalse);
    });

    test('throws when the offer has no pre-authorized code', () async {
      final client = Oid4vciClient(happyIssuer());
      final meta = await client
          .fetchIssuerMetadata(await client.parseOffer(_offerJson()));
      const offer = CredentialOffer(
        issuer: _issuer,
        configIds: ['x'],
        preAuthCode: null,
        txCodeRequired: false,
      );
      expect(
        () => client.requestToken(offer: offer, meta: meta, txCode: '1'),
        throwsA(isA<TokenError>()),
      );
    });

    test('surfaces the issuer error_description', () async {
      final http = FakeOid4vcHttp((req) {
        if (req.url.path == '/token') {
          return HttpResp(
            400,
            jsonEncode(
              {'error': 'invalid_grant', 'error_description': 'bad code'},
            ),
          );
        }
        return req.url.path.endsWith('credential-issuer')
            ? jsonResponse(_issuerMeta)
            : jsonResponse({'token_endpoint': '$_issuer/token'});
      });
      final client = Oid4vciClient(http);
      final offer = await client.parseOffer(_offerJson());
      final meta = await client.fetchIssuerMetadata(offer);
      expect(
        () => client.requestToken(offer: offer, meta: meta, txCode: 'x'),
        throwsA(
          isA<TokenError>()
              .having((e) => e.message, 'message', contains('bad code')),
        ),
      );
    });
  });

  group('requestNonce', () {
    Future<IssuerMetadata> meta(FakeOid4vcHttp http) async {
      final client = Oid4vciClient(http);
      return client.fetchIssuerMetadata(await client.parseOffer(_offerJson()));
    }

    test('returns the c_nonce', () async {
      final http = happyIssuer();
      expect(
        await Oid4vciClient(http).requestNonce(meta: await meta(http)),
        'CN2',
      );
    });

    test('throws without a nonce endpoint', () async {
      final noNonce = IssuerMetadata(
        issuer: _issuer,
        credentialEndpoint: _Uris.credential,
        tokenEndpoint: _Uris.token,
        nonceEndpoint: null,
        vcts: const {},
      );
      expect(
        () => Oid4vciClient(happyIssuer()).requestNonce(meta: noNonce),
        throwsA(isA<CredentialError>()),
      );
    });

    test('throws on a bad nonce response', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/nonce'
            ? jsonResponse(const {}) // no c_nonce
            : jsonResponse(_issuerMeta),
      );
      final m = await meta(happyIssuer());
      expect(
        () => Oid4vciClient(http).requestNonce(meta: m),
        throwsA(isA<CredentialError>()),
      );
    });

    test('throws when the nonce endpoint returns an error', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/nonce'
            ? HttpResp(500, 'down')
            : jsonResponse(_issuerMeta),
      );
      final m = await meta(happyIssuer());
      expect(
        () => Oid4vciClient(http).requestNonce(meta: m),
        throwsA(isA<CredentialError>()),
      );
    });
  });

  group('buildProof', () {
    test('produces a verifiable openid4vci-proof+jwt', () async {
      final client = Oid4vciClient(happyIssuer(), now: fixedClock(1700));
      final proof = await client.buildProof(
        issuer: _issuer,
        cNonce: 'CN',
        signer: signer,
      );
      final jws = Jws.decompose(proof);
      expect(jws.header['typ'], 'openid4vci-proof+jwt');
      expect(jws.header['jwk'], signer.publicJwkSync());
      expect(jws.payload['aud'], _issuer);
      expect(jws.payload['nonce'], 'CN');
      expect(jws.payload['iat'], 1700);
      expect(
        verifyEs256WithJwk(
          signingInput: jws.signingInput,
          signature: jws.signature,
          jwk: signer.publicJwkSync(),
        ),
        isTrue,
      );
    });
  });

  group('requestCredential', () {
    final meta = IssuerMetadata(
      issuer: _issuer,
      credentialEndpoint: _Uris.credential,
      tokenEndpoint: _Uris.token,
      nonceEndpoint: null,
      vcts: {},
    );
    const token = TokenResponse(accessToken: 'AT', cNonce: null);

    test('sends auth + proof and returns the credential string', () async {
      final http = FakeOid4vcHttp((_) => jsonResponse({'credential': 'C1'}));
      final result = await Oid4vciClient(http).requestCredential(
        meta: meta,
        token: token,
        proofJwt: 'PROOF',
        credentialConfigurationId: 'extras_salariat',
      );
      expect(result, 'C1');
      expect(http.last.headers!['authorization'], 'Bearer AT');
      final body = http.last.body! as Map<String, dynamic>;
      expect(body['credential_configuration_id'], 'extras_salariat');
      expect(body['proof'], {'proof_type': 'jwt', 'jwt': 'PROOF'});
      expect(body.containsKey('key_attestation'), isFalse);
    });

    test('attaches key_attestation when present', () async {
      final http = FakeOid4vcHttp((_) => jsonResponse({'credential': 'C1'}));
      await Oid4vciClient(http).requestCredential(
        meta: meta,
        token: token,
        proofJwt: 'PROOF',
        credentialConfigurationId: 'x',
        attestation: const KeyAttestation(
          format: 'android-key',
          data: 'ATTEST',
        ),
      );
      expect((http.last.body! as Map)['key_attestation'], 'ATTEST');
    });

    test('reads the newer credentials[] response shapes', () async {
      final asObject = FakeOid4vcHttp(
        (_) => jsonResponse({
          'credentials': [
            {'credential': 'C2'},
          ],
        }),
      );
      expect(
        await Oid4vciClient(asObject).requestCredential(
          meta: meta,
          token: token,
          proofJwt: 'P',
          credentialConfigurationId: 'x',
        ),
        'C2',
      );

      final asString = FakeOid4vcHttp(
        (_) => jsonResponse({
          'credentials': ['C3'],
        }),
      );
      expect(
        await Oid4vciClient(asString).requestCredential(
          meta: meta,
          token: token,
          proofJwt: 'P',
          credentialConfigurationId: 'x',
        ),
        'C3',
      );
    });

    test('throws on an error response and on a missing credential', () async {
      final error = FakeOid4vcHttp((_) => HttpResp(400, 'bad'));
      expect(
        () => Oid4vciClient(error).requestCredential(
          meta: meta,
          token: token,
          proofJwt: 'P',
          credentialConfigurationId: 'x',
        ),
        throwsA(isA<CredentialError>()),
      );

      final empty = FakeOid4vcHttp((_) => jsonResponse(const {}));
      expect(
        () => Oid4vciClient(empty).requestCredential(
          meta: meta,
          token: token,
          proofJwt: 'P',
          credentialConfigurationId: 'x',
        ),
        throwsA(isA<CredentialError>()),
      );
    });
  });

  group('redeemOffer', () {
    test('runs the whole flow and returns the credential', () async {
      final credential = await SdJwt.issue(
        claims: const {'iss': _issuer, 'vct': '$_issuer/extras/v1'},
        header: const {},
        selectivelyDisclosable: const {},
        signer: signer,
      );
      final http = happyIssuer(credential: credential);
      final result = await Oid4vciClient(http).redeemOffer(
        offerUriOrJson: _offerJson(),
        txCode: '1234',
        signer: signer,
      );
      expect(result, credential);
    });

    test('uses the nonce endpoint when the token has no c_nonce, and attests',
        () async {
      final attestingSigner = SoftwareEs256Signer.generate(
        random: Random(21),
        attestor: (n) => KeyAttestation(
          format: 'android-key',
          data: 'att:$n',
        ),
      );
      final http = FakeOid4vcHttp((req) {
        switch (req.url.path) {
          case '/.well-known/openid-credential-issuer':
            return jsonResponse(_issuerMeta);
          case '/.well-known/oauth-authorization-server':
            return jsonResponse({'token_endpoint': '$_issuer/token'});
          case '/token':
            return jsonResponse({'access_token': 'AT'}); // no c_nonce
          case '/nonce':
            return jsonResponse({'c_nonce': 'FRESH'});
          case '/credential':
            return jsonResponse({'credential': 'OK'});
          default:
            return HttpResp(404, '');
        }
      });
      final result = await Oid4vciClient(http).redeemOffer(
        offerUriOrJson: _offerJson(),
        txCode: '1234',
        signer: attestingSigner,
      );
      expect(result, 'OK');
      // The credential request carried the attestation bound to the fresh nonce.
      final credentialReq =
          http.requests.firstWhere((r) => r.url.path == '/credential');
      expect((credentialReq.body! as Map)['key_attestation'], 'att:FRESH');
    });

    test('throws when the offer has no configuration ids', () async {
      final offer = jsonEncode({
        'credential_issuer': _issuer,
        'grants': {
          preAuthorizedCodeGrant: {'pre-authorized_code': 'PAC'},
        },
      });
      expect(
        () => Oid4vciClient(happyIssuer())
            .redeemOffer(offerUriOrJson: offer, txCode: '1', signer: signer),
        throwsA(isA<OfferParseError>()),
      );
    });
  });

  group('discovery edge cases', () {
    test('parseOffer throws on invalid JSON', () async {
      expect(
        () => Oid4vciClient(happyIssuer()).parseOffer('{ not json'),
        throwsA(isA<OfferParseError>()),
      );
    });

    test('fetchIssuerMetadata discovers the token endpoint via an AS',
        () async {
      const as = 'https://as.example';
      final http = FakeOid4vcHttp((req) {
        switch (req.url.path) {
          case '/.well-known/openid-credential-issuer':
            return jsonResponse({
              ..._issuerMeta,
              'authorization_servers': [as],
            });
          case '/.well-known/oauth-authorization-server':
            expect(req.url.host, 'as.example');
            return jsonResponse({'token_endpoint': '$as/token'});
          default:
            return HttpResp(404, '');
        }
      });
      final client = Oid4vciClient(http);
      final meta = await client.fetchIssuerMetadata(
        await client.parseOffer(_offerJson()),
      );
      expect(meta.tokenEndpoint, Uri.parse('$as/token'));
    });

    test('fetchIssuerMetadata throws when the metadata GET fails', () async {
      final client = Oid4vciClient(FakeOid4vcHttp((_) => HttpResp(404, '')));
      expect(
        () async => client.fetchIssuerMetadata(
          await Oid4vciClient(happyIssuer()).parseOffer(_offerJson()),
        ),
        throwsA(isA<CredentialError>()),
      );
    });

    test('fetchIssuerMetadata rejects a non-absolute endpoint URL', () async {
      final http = FakeOid4vcHttp(
        (req) => req.url.path == '/.well-known/openid-credential-issuer'
            ? jsonResponse({
                'credential_issuer': _issuer,
                'credential_endpoint': 'relative/credential',
                'token_endpoint': '$_issuer/token',
              })
            : HttpResp(404, ''),
      );
      final client = Oid4vciClient(http);
      expect(
        () async => client.fetchIssuerMetadata(
          await client.parseOffer(_offerJson()),
        ),
        throwsA(isA<CredentialError>()),
      );
    });
  });
}

/// Compile-time `Uri` constants for the metadata fixtures above.
abstract final class _Uris {
  static final credential = Uri.parse('$_issuer/credential');
  static final token = Uri.parse('$_issuer/token');
}
