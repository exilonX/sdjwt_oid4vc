import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/fake_http.dart';
import '../support/util.dart';

/// Regression tests pinned to bytes captured from the **live EUDI reference
/// services** (`backend.issuer.eudiw.dev`, `verifier-backend.eudiw.dev`) — see
/// `test/fixtures/eudi/README.md` for provenance. Unlike the rest of the suite,
/// nothing here is produced by our own encoders, so a drift between the library
/// and the deployed wire format fails here first.
void main() {
  String fixture(String name) =>
      File('test/fixtures/eudi/$name').readAsStringSync().trim();

  group('EUDI issuer metadata (backend.issuer.eudiw.dev)', () {
    const issuer = 'https://backend.issuer.eudiw.dev';
    const pidConfig = 'eu.europa.ec.eudi.pid_vc_sd_jwt';

    // Serves the two documents exactly where the live host serves them; every
    // other URL — including the RFC 8414 path-aware AS location — is a 404,
    // as it is live.
    FakeOid4vcHttp liveIssuer() => FakeOid4vcHttp((req) {
          if (req.url.host != 'backend.issuer.eudiw.dev') {
            return HttpResp(404, '');
          }
          return switch (req.url.path) {
            '/.well-known/openid-credential-issuer' =>
              HttpResp(200, fixture('issuer_metadata.json')),
            '/.well-known/oauth-authorization-server' =>
              HttpResp(200, fixture('authorization_server_metadata.json')),
            _ => HttpResp(404, ''),
          };
        });

    // The offer itself is synthetic (the live one is minted behind an
    // interactive form); only its issuer + configuration id matter here.
    final offerJson = jsonEncode({
      'credential_issuer': issuer,
      'credential_configuration_ids': [pidConfig],
      'grants': {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'PAC',
        },
      },
    });

    test('resolves the endpoints and the PID vct', () async {
      final client = Oid4vciClient(liveIssuer());
      final meta =
          await client.fetchIssuerMetadata(await client.parseOffer(offerJson));

      expect(meta.credentialEndpoint, Uri.parse('$issuer/credential'));
      expect(meta.nonceEndpoint, Uri.parse('$issuer/nonce'));
      expect(meta.vcts[pidConfig], 'urn:eudi:pid:1');
    });

    test(
        'finds the token endpoint of an AS (…/oidc) that serves its metadata '
        'only at the host root', () async {
      final http = liveIssuer();
      final client = Oid4vciClient(http);
      final meta =
          await client.fetchIssuerMetadata(await client.parseOffer(offerJson));

      expect(meta.tokenEndpoint, Uri.parse('$issuer/oidc/token'));
      // RFC 8414 location first, then the host-root fallback.
      expect(
        http.requests.map((r) => r.url.path).skip(1),
        [
          '/.well-known/oauth-authorization-server/oidc',
          '/.well-known/oauth-authorization-server',
        ],
      );
    });
  });

  group('EUDI verifier request (verifier-backend.eudiw.dev)', () {
    final authzRequest = fixture('authorization_request_uri.txt');
    final requestUri = Uri.parse(authzRequest).queryParameters['request_uri']!;
    final jar = fixture('request_object.jwt');

    // Serves the signed request object at its request_uri, and records (then
    // accepts) the wallet's POST to the response_uri.
    FakeOid4vcHttp liveVerifier() => FakeOid4vcHttp(
          (req) => req.url.toString() == requestUri
              ? HttpResp(200, jar)
              : HttpResp(200, ''),
        );

    Future<PresentationRequest> fetch(Oid4vcHttp http) =>
        Oid4vpClient(http, now: fixedClock(1790363467))
            .fetchRequest(authzRequest);

    test('parses the x509_hash, direct_post.jwt request and its DCQL',
        () async {
      final req = await fetch(liveVerifier());

      expect(req.clientIdScheme, 'x509_hash');
      expect(req.responseMode, 'direct_post.jwt');
      expect(req.responseUri?.host, 'verifier-backend.eudiw.dev');
      expect(req.nonce, 'sdjwt-oid4vc-fixture-nonce');
      expect(req.state, isNotNull);

      final query = req.dcql.credentials.single;
      expect(query.id, 'pid');
      expect(query.format, 'dc+sd-jwt');
      expect(query.vctValues, ['urn:eudi:pid:1']);
      expect(query.claims.map((c) => c.path), [
        ['family_name'],
        ['given_name'],
        ['place_of_birth', 'locality'],
      ]);
    });

    test('request signature verifies against its x5c leaf', () async {
      final signature = (await fetch(liveVerifier())).signature!;

      expect(signature.alg, 'ES256');
      expect(signature.x5c, hasLength(1));
      expect(signature.verifyWithX5cLeaf(), isTrue);

      final tampered = RequestObjectSignature(
        header: signature.header,
        signingInput: '${signature.signingInput}x',
        signature: signature.signature,
      );
      expect(tampered.verifyWithX5cLeaf(), isFalse);
    });

    test('x509_hash client_id is the SHA-256 of the x5c leaf', () async {
      // The binding a wallet checks before trusting the leaf (OpenID4VP §5.9.3).
      final req = await fetch(liveVerifier());
      final leafDer = base64.decode(req.signature!.x5c.first);

      expect(b64uEncode(sha256.convert(leafDer).bytes), req.clientIdValue);
    });

    test('reads the ephemeral response-encryption key', () async {
      final encryption = (await fetch(liveVerifier())).responseEncryption!;

      expect(encryption.alg, 'ECDH-ES');
      expect(encryption.enc, 'A128GCM');
      expect(encryption.kid, 'cc56950b-cb4c-4c11-8516-e06f5115ac44');
      expect(encryption.recipientJwk['crv'], 'P-256');
    });

    test('presents a PID-shaped credential as a JWE to the verifier key',
        () async {
      final http = liveVerifier();
      final client = Oid4vpClient(http, now: fixedClock(1790363467));
      final req = await client.fetchRequest(authzRequest);

      final family =
          Disclosure.forClaim(salt: 'a', name: 'family_name', value: 'Popescu');
      final given =
          Disclosure.forClaim(salt: 'b', name: 'given_name', value: 'Ana');
      final locality =
          Disclosure.forClaim(salt: 'c', name: 'locality', value: 'Bucuresti');
      final country =
          Disclosure.forClaim(salt: 'd', name: 'country', value: 'RO');
      final pid = SdJwt.parse(
        customSdJwt(
          {
            'iss': 'https://backend.issuer.eudiw.dev',
            'vct': 'urn:eudi:pid:1',
            '_sd_alg': 'sha-256',
            '_sd': [family.digest(sha256), given.digest(sha256)],
            'place_of_birth': {
              '_sd': [locality.digest(sha256), country.digest(sha256)],
            },
          },
          disclosures: [
            family.encoded,
            given.encoded,
            locality.encoded,
            country.encoded,
          ],
        ),
      );

      final match = client.match(req, [pid])!;
      await client.present(
        req: req,
        match: match,
        signer: SoftwareEs256Signer.generate(random: Random(7)),
      );

      final post = http.last;
      expect(post.url, req.responseUri);
      expect(post.form.keys, ['response']);
      final jwe = post.form['response']!.split('.');
      expect(jwe, hasLength(5));
      final header =
          jsonDecode(b64uDecodeToString(jwe.first)) as Map<String, dynamic>;
      expect(header['alg'], 'ECDH-ES');
      expect(header['enc'], 'A128GCM');
      expect(header['kid'], req.responseEncryption!.kid);
      expect((header['epk'] as Map)['crv'], 'P-256');
      expect(header['apv'], b64uEncodeString(req.nonce));
    });
  });
}
