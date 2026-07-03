import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';
import '../support/fake_http.dart';
import '../support/jwe_recipient.dart';
import '../support/util.dart';

const _vct = 'https://issuer.example/extras/v1';
const _mdlVct = 'https://issuer.example/mdl/v1';
const _clientId = 'https://verifier.example';

/// A two-credential DCQL query (a PID-like and an mDL-like credential),
/// optionally wrapped in a `credential_sets` that requires both.
Map<String, dynamic> multiDcql({bool sets = true}) => {
      'credentials': [
        {
          'id': 'pid',
          'format': 'dc+sd-jwt',
          'meta': {
            'vct_values': [_vct],
          },
          'claims': [
            {
              'path': ['given_name'],
            },
          ],
        },
        {
          'id': 'mdl',
          'format': 'dc+sd-jwt',
          'meta': {
            'vct_values': [_mdlVct],
          },
          'claims': [
            {
              'path': ['family_name'],
            },
          ],
        },
      ],
      if (sets)
        'credential_sets': [
          {
            'options': [
              ['pid', 'mdl'],
            ],
          },
        ],
    };

/// A request object JWT (JAR) with a throwaway signature — fine wherever the
/// test does not exercise signature verification.
String requestJwt(Map<String, dynamic> payload) {
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'},
    payload,
  );
  return '$signingInput.${b64uEncode([1, 2, 3])}';
}

/// A request object JWT genuinely signed by [verifier], optionally carrying an
/// `x5c` chain — for the RP-authentication tests.
Future<String> signedRequestJwt(
  Map<String, dynamic> payload,
  SoftwareEs256Signer verifier, {
  List<String>? x5c,
  String? kid,
}) async {
  final header = {
    'alg': 'ES256',
    'typ': 'oauth-authz-req+jwt',
    if (kid != null) 'kid': kid,
    if (x5c != null) 'x5c': x5c,
  };
  final signingInput = Jws.signingInput(header, payload);
  return '$signingInput.${await verifier.signEs256(signingInput)}';
}

Map<String, dynamic> dcql({
  List<String>? vctValues = const [_vct],
  List<String> claims = const ['given_name'],
}) =>
    {
      'credentials': [
        {
          'id': 'c1',
          'format': 'dc+sd-jwt',
          if (vctValues != null) 'meta': {'vct_values': vctValues},
          'claims': [
            for (final name in claims)
              {
                'path': [name],
              },
          ],
        },
      ],
    };

Map<String, dynamic> requestPayload({
  Map<String, dynamic>? query,
  String responseUri = '$_clientId/response',
}) =>
    {
      'client_id': _clientId,
      'nonce': 'nonce-1',
      'response_mode': 'direct_post',
      'response_uri': responseUri,
      'state': 'st-1',
      'dcql_query': query ?? dcql(),
    };

void main() {
  final signer = SoftwareEs256Signer.generate(random: Random(31));

  Future<SdJwtVc> heldCredential({String vct = _vct}) async {
    final compact = await SdJwt.issue(
      claims: {
        'iss': 'https://issuer.example',
        'vct': vct,
        'given_name': 'Ada',
        'family_name': 'Byron',
      },
      header: const {},
      selectivelyDisclosable: const {'given_name', 'family_name'},
      signer: signer,
      saltGenerator: seqSalts(['s1', 's2']),
    );
    return SdJwt.parse(compact);
  }

  group('fetchRequest', () {
    final unusedHttp = FakeOid4vcHttp((_) => HttpResp(404, ''));

    test('parses a JAR passed directly', () async {
      final req = await Oid4vpClient(unusedHttp)
          .fetchRequest(requestJwt(requestPayload()));
      expect(req.clientId, _clientId);
      expect(req.nonce, 'nonce-1');
      expect(req.responseUri, Uri.parse('$_clientId/response'));
      expect(req.responseMode, 'direct_post');
      expect(req.state, 'st-1');
      expect(req.dcql.credentials.single.vctValues, [_vct]);
    });

    test('follows a request_uri via GET', () async {
      final http = FakeOid4vcHttp(
        (r) => r.url.path == '/req'
            ? HttpResp(200, requestJwt(requestPayload()))
            : HttpResp(404, ''),
      );
      final req = await Oid4vpClient(http)
          .fetchRequest('openid4vp://?request_uri=$_clientId/req');
      expect(req.clientId, _clientId);
      expect(http.last.method, 'GET');
    });

    test('follows a request_uri via POST and can read a JSON body', () async {
      final http = FakeOid4vcHttp(
        (r) => HttpResp(200, jsonEncode(requestPayload())),
      );
      final req = await Oid4vpClient(http).fetchRequest(
        'openid4vp://?request_uri=$_clientId/req&request_uri_method=post',
      );
      expect(req.clientId, _clientId);
      expect(http.last.method, 'POST_FORM');
    });

    test('parses inline parameters with a JSON-string dcql_query', () async {
      final link = Uri(
        scheme: 'openid4vp',
        host: '',
        queryParameters: {
          'client_id': _clientId,
          'nonce': 'n',
          'response_uri': '$_clientId/r',
          'dcql_query': jsonEncode(dcql()),
        },
      ).toString();
      final req = await Oid4vpClient(unusedHttp).fetchRequest(link);
      expect(req.clientId, _clientId);
      expect(req.dcql.credentials.single.claimNames, ['given_name']);
    });

    test('throws when the input is neither a URI nor a JWT', () async {
      expect(
        () => Oid4vpClient(unusedHttp).fetchRequest('ht tp:// bad'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('throws when a URI has no request or parameters', () async {
      expect(
        () =>
            Oid4vpClient(unusedHttp).fetchRequest('https://verifier.example/x'),
        throwsA(isA<PresentationError>()),
      );
    });
  });

  group('parseRequest', () {
    test('throws on a malformed request object', () {
      expect(
        () => Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')))
            .parseRequest('not.a.jwt'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('throws when client_id / nonce / dcql_query are missing', () {
      final client = Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')));
      expect(
        () => client.parseRequest(requestJwt(const {'nonce': 'n'})),
        throwsA(isA<PresentationError>()),
      );
      expect(
        () => client.parseRequest(requestJwt(const {'client_id': 'c'})),
        throwsA(isA<PresentationError>()),
      );
      expect(
        () => client.parseRequest(
          requestJwt(const {'client_id': 'c', 'nonce': 'n'}),
        ),
        throwsA(isA<PresentationError>()),
      );
    });
  });

  group('match', () {
    final client = Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')));

    test('matches on vct and returns the requested claims', () async {
      final req = client.parseRequest(requestJwt(requestPayload()));
      final result = client.match(req, [await heldCredential()]);
      expect(result, isNotNull);
      expect(result!.requestedClaims, {'given_name'});
    });

    test('an empty claim set reveals all disclosures', () async {
      final req = client.parseRequest(
        requestJwt(requestPayload(query: dcql(claims: const []))),
      );
      final result = client.match(req, [await heldCredential()]);
      expect(result!.requestedClaims, {'given_name', 'family_name'});
    });

    test('matches with no vct constraint', () async {
      final req = client.parseRequest(
        requestJwt(requestPayload(query: dcql(vctValues: null))),
      );
      expect(client.match(req, [await heldCredential()]), isNotNull);
    });

    test('returns null on a vct mismatch', () async {
      final req = client.parseRequest(requestJwt(requestPayload()));
      final other = await heldCredential(vct: 'https://other/v1');
      expect(client.match(req, [other]), isNull);
    });

    test('returns null when a requested claim is unavailable', () async {
      final req = client.parseRequest(
        requestJwt(requestPayload(query: dcql(claims: const ['ssn']))),
      );
      expect(client.match(req, [await heldCredential()]), isNull);
    });

    test('picks the satisfying credential among several held', () async {
      final req = client.parseRequest(requestJwt(requestPayload()));
      final wrong = await heldCredential(vct: 'https://other/v1');
      final right = await heldCredential();
      final result = client.match(req, [wrong, right]);
      expect(result!.credential.vct, _vct);
    });
  });

  group('buildVpToken', () {
    test('delegates to the codec and binds client_id/nonce', () async {
      final client = Oid4vpClient(
        FakeOid4vcHttp((_) => HttpResp(404, '')),
        now: fixedClock(1700),
      );
      final req = client.parseRequest(requestJwt(requestPayload()));
      final credential = await heldCredential();

      final vpToken = await client.buildVpToken(
        credential: credential,
        revealClaims: const {'given_name'},
        req: req,
        signer: signer,
      );

      final presented = SdJwt.parse(vpToken);
      expect(presented.disclosures.single.name, 'given_name');
      final kb = Jws.decompose(presented.kbJwt!);
      expect(kb.payload['aud'], _clientId);
      expect(kb.payload['nonce'], 'nonce-1');
      expect(kb.payload['iat'], 1700);
    });
  });

  group('submit', () {
    PresentationRequest req(String responseUri) =>
        Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')))
            .parseRequest(requestJwt(requestPayload(responseUri: responseUri)));

    test('posts vp_token + state and returns a redirect_uri', () async {
      final http = FakeOid4vcHttp(
        (_) => jsonResponse({'redirect_uri': '$_clientId/done'}),
      );
      final redirect = await Oid4vpClient(http).submit(
        req: req('$_clientId/response'),
        vpToken: 'VP',
      );
      expect(redirect, '$_clientId/done');
      expect(http.last.form, {'vp_token': 'VP', 'state': 'st-1'});
    });

    test('returns null for an empty or non-JSON body', () async {
      final empty = FakeOid4vcHttp((_) => HttpResp(200, '   '));
      expect(
        await Oid4vpClient(empty)
            .submit(req: req('$_clientId/r'), vpToken: 'V'),
        isNull,
      );
      final text = FakeOid4vcHttp((_) => HttpResp(200, 'OK'));
      expect(
        await Oid4vpClient(text).submit(req: req('$_clientId/r'), vpToken: 'V'),
        isNull,
      );
    });

    test('throws when there is no response_uri', () async {
      final client = Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')));
      final request = client.parseRequest(
        requestJwt({
          'client_id': _clientId,
          'nonce': 'n',
          'dcql_query': dcql(),
        }),
      );
      expect(
        () => client.submit(req: request, vpToken: 'V'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('throws when the verifier rejects the submission', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(400, 'bad'));
      expect(
        () => Oid4vpClient(http).submit(req: req('$_clientId/r'), vpToken: 'V'),
        throwsA(isA<PresentationError>()),
      );
    });
  });

  group('fetchRequest error edges', () {
    test('throws when the request_uri fetch fails', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(500, 'down'));
      expect(
        () => Oid4vpClient(http)
            .fetchRequest('openid4vp://?request_uri=$_clientId/req'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('throws when the request_uri body is neither a JWT nor JSON',
        () async {
      final http = FakeOid4vcHttp((_) => HttpResp(200, 'garbage{'));
      expect(
        () => Oid4vpClient(http)
            .fetchRequest('openid4vp://?request_uri=$_clientId/req'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('rejects a non-absolute request_uri', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(404, ''));
      expect(
        () => Oid4vpClient(http).fetchRequest('openid4vp://?request_uri=rel'),
        throwsA(isA<PresentationError>()),
      );
    });

    test('refuses to fetch a request_uri over insecure http', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(404, ''));
      expect(
        () => Oid4vpClient(http)
            .fetchRequest('openid4vp://?request_uri=http://verifier.example/r'),
        throwsA(isA<PresentationError>()),
      );
    });
  });

  group('multi-credential DCQL', () {
    final client = Oid4vpClient(
      FakeOid4vcHttp((_) => HttpResp(404, '')),
      now: fixedClock(1700),
    );

    PresentationRequest reqWith(Map<String, dynamic> query) =>
        client.parseRequest(requestJwt(requestPayload(query: query)));

    test('matchAll returns one match per satisfiable query', () async {
      final req = reqWith(multiDcql());
      final matches = client.matchAll(
        req,
        [await heldCredential(), await heldCredential(vct: _mdlVct)],
      );
      expect(matches.map((m) => m.queryId), ['pid', 'mdl']);
      expect(client.satisfiesRequest(req, matches), isTrue);
    });

    test('a required set is unsatisfied when one credential is missing',
        () async {
      final req = reqWith(multiDcql());
      final onlyPid = client.matchAll(req, [await heldCredential()]);
      expect(onlyPid.map((m) => m.queryId), ['pid']);
      expect(client.satisfiesRequest(req, onlyPid), isFalse);
    });

    test('with no credential_sets, every listed credential is required',
        () async {
      final req = reqWith(multiDcql(sets: false));
      final both = client.matchAll(
        req,
        [await heldCredential(), await heldCredential(vct: _mdlVct)],
      );
      expect(client.satisfiesRequest(req, both), isTrue);
      expect(
        client.satisfiesRequest(
          req,
          client.matchAll(req, [await heldCredential()]),
        ),
        isFalse,
      );
    });

    test('optional sets do not block satisfaction', () async {
      final req = reqWith({
        'credentials': [
          {
            'id': 'pid',
            'meta': {
              'vct_values': [_vct],
            },
            'claims': [
              {
                'path': ['given_name'],
              },
            ],
          },
          {
            'id': 'extra',
            'meta': {
              'vct_values': ['https://none/v1'],
            },
            'claims': const <Map<String, dynamic>>[],
          },
        ],
        'credential_sets': [
          {
            'options': [
              ['pid'],
            ],
          },
          {
            'options': [
              ['extra'],
            ],
            'required': false,
          },
        ],
      });
      final matches = client.matchAll(req, [await heldCredential()]);
      expect(matches.map((m) => m.queryId), ['pid']);
      expect(client.satisfiesRequest(req, matches), isTrue);
    });

    test('buildVpTokenObject keys each presentation by its query id', () async {
      final req = reqWith(multiDcql());
      final matches = client.matchAll(
        req,
        [await heldCredential(), await heldCredential(vct: _mdlVct)],
      );
      final vpToken = await client.buildVpTokenObject(
        matches: matches,
        req: req,
        signer: signer,
      );

      final object = jsonDecode(vpToken) as Map<String, dynamic>;
      expect(object.keys, containsAll(<String>['pid', 'mdl']));

      final pid = SdJwt.parse(object['pid'] as String);
      expect(pid.disclosures.single.name, 'given_name');
      expect(Jws.decompose(pid.kbJwt!).payload['nonce'], 'nonce-1');

      final mdl = SdJwt.parse(object['mdl'] as String);
      expect(mdl.disclosures.single.name, 'family_name');
    });
  });

  group('direct_post.jwt (encrypted response)', () {
    final now = fixedClock(1700);
    final rcpt = recipient(9, kid: 'enc-key-1');

    Map<String, dynamic> clientMetadata({
      Map<String, dynamic>? encJwk,
      List<Object?> keys = const [],
      List<String>? encSupported = const ['A128GCM', 'A256GCM'],
      bool omitJwks = false,
    }) =>
        {
          if (!omitJwks)
            'jwks': {
              'keys': keys.isNotEmpty ? keys : [encJwk ?? rcpt.jwk],
            },
          if (encSupported != null)
            'encrypted_response_enc_values_supported': encSupported,
        };

    Map<String, dynamic> encPayload({
      Map<String, dynamic>? metadata,
      String responseMode = 'direct_post.jwt',
      String responseUri = '$_clientId/response',
    }) =>
        {
          'client_id': _clientId,
          'nonce': 'nonce-1',
          'response_mode': responseMode,
          'response_uri': responseUri,
          'state': 'st-1',
          'dcql_query': dcql(),
          'client_metadata': metadata ?? clientMetadata(),
        };

    Oid4vpClient clientWith(FakeOid4vcHttp http) =>
        Oid4vpClient(http, now: now);
    final offlineClient = clientWith(FakeOid4vcHttp((_) => HttpResp(404, '')));

    test('parseRequest reads the enc key and prefers A128GCM', () {
      final re = offlineClient
          .parseRequest(requestJwt(encPayload()))
          .responseEncryption!;
      expect(re.alg, 'ECDH-ES');
      expect(re.enc, 'A128GCM'); // preferred over the also-offered A256GCM
      expect(re.kid, 'enc-key-1');
      expect(re.recipientJwk['x'], rcpt.jwk['x']);
    });

    test('selects A256GCM only when A128GCM is not offered', () {
      final re = offlineClient
          .parseRequest(
            requestJwt(
              encPayload(
                metadata: clientMetadata(encSupported: const ['A256GCM']),
              ),
            ),
          )
          .responseEncryption!;
      expect(re.enc, 'A256GCM');
    });

    test('defaults enc to A128GCM when the list is absent', () {
      final re = offlineClient
          .parseRequest(
            requestJwt(
              encPayload(metadata: clientMetadata(encSupported: null)),
            ),
          )
          .responseEncryption!;
      expect(re.enc, 'A128GCM');
    });

    test('responseEncryption is null without a usable enc key', () {
      PresentationRequest parse(Map<String, dynamic> payload) =>
          offlineClient.parseRequest(requestJwt(payload));

      // No client_metadata at all.
      expect(parse(requestPayload()).responseEncryption, isNull);
      // client_metadata present but no jwks.
      expect(
        parse(encPayload(metadata: clientMetadata(omitJwks: true)))
            .responseEncryption,
        isNull,
      );
      // A non-map entry, then exhausted.
      expect(
        parse(encPayload(metadata: clientMetadata(keys: const ['nope'])))
            .responseEncryption,
        isNull,
      );
      // Right kind of key, wrong alg (e.g. key-wrap) — we only do ECDH-ES.
      final wrongAlg = {...rcpt.jwk, 'alg': 'ECDH-ES+A128KW'};
      expect(
        parse(encPayload(metadata: clientMetadata(encJwk: wrongAlg)))
            .responseEncryption,
        isNull,
      );
    });

    test('present() encrypts to the verifier and round-trips', () async {
      final http = FakeOid4vcHttp(
        (_) => jsonResponse({'redirect_uri': '$_clientId/done'}),
      );
      final client = clientWith(http);
      final req = client.parseRequest(requestJwt(encPayload()));
      final match = client.match(req, [await heldCredential()])!;

      final redirect =
          await client.present(req: req, match: match, signer: signer);
      expect(redirect, '$_clientId/done');

      // Exactly one form field: response=<compact JWE>.
      expect(http.last.form.keys, ['response']);
      final plaintext = utf8.decode(
        decryptJwe(http.last.form['response']!, rcpt.private),
      );
      final decoded = jsonDecode(plaintext) as Map<String, dynamic>;
      expect(decoded['state'], 'st-1');
      final vpToken = decoded['vp_token'] as Map<String, dynamic>;
      final presentations =
          vpToken['c1'] as List; // 1.0-final: object of arrays
      expect(presentations, hasLength(1));
      final presented = SdJwt.parse(presentations.single as String);
      expect(presented.disclosures.single.name, 'given_name');
      expect(Jws.decompose(presented.kbJwt!).payload['nonce'], 'nonce-1');
    });

    test('throws when direct_post.jwt has no encryption key', () async {
      final req = offlineClient.parseRequest(
        requestJwt(encPayload(metadata: clientMetadata(omitJwks: true))),
      );
      expect(req.responseEncryption, isNull);
      expect(
        () => offlineClient.submitResponse(
          req: req,
          vpToken: const {
            'c1': ['x'],
          },
        ),
        throwsA(isA<PresentationError>()),
      );
    });

    test('plain direct_post submitResponse posts the object vp_token',
        () async {
      final http = FakeOid4vcHttp((_) => HttpResp(200, ''));
      final client = clientWith(http);
      final req = client.parseRequest(
        requestJwt(encPayload(responseMode: 'direct_post')),
      );
      final result = await client.submitResponse(
        req: req,
        vpToken: const {
          'c1': ['P'],
        },
      );
      expect(result, isNull);
      expect(jsonDecode(http.last.form['vp_token']!), {
        'c1': ['P'],
      });
      expect(http.last.form['state'], 'st-1');
    });

    test('submitResponse returns null on a non-JSON 200 body', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(200, 'OK'));
      final client = clientWith(http);
      final req = client.parseRequest(
        requestJwt(encPayload(responseMode: 'direct_post')),
      );
      expect(
        await client.submitResponse(
          req: req,
          vpToken: const {
            'c1': ['P'],
          },
        ),
        isNull,
      );
    });

    test('surfaces a short verifier error body', () async {
      final http = FakeOid4vcHttp(
        (_) => HttpResp(400, '{"error":"UnexpectedResponseMode"}'),
      );
      final client = clientWith(http);
      final req = client.parseRequest(requestJwt(encPayload()));
      final match = client.match(req, [await heldCredential()])!;
      await expectLater(
        () => client.present(req: req, match: match, signer: signer),
        throwsA(
          predicate<Object>(
            (e) =>
                e is PresentationError &&
                e.toString().contains('UnexpectedResponseMode'),
          ),
        ),
      );
    });

    test('caps an oversized error body', () async {
      final http = FakeOid4vcHttp((_) => HttpResp(400, 'x' * 500));
      final client = clientWith(http);
      final req = client.parseRequest(requestJwt(encPayload()));
      final match = client.match(req, [await heldCredential()])!;
      await expectLater(
        () => client.present(req: req, match: match, signer: signer),
        throwsA(
          predicate<Object>(
            (e) => e is PresentationError && e.toString().contains('…'),
          ),
        ),
      );
    });

    test('submitResponse throws without a response_uri', () {
      final req = offlineClient.parseRequest(
        requestJwt(const {
          'client_id': _clientId,
          'nonce': 'n',
          'response_mode': 'direct_post.jwt',
          'dcql_query': {
            'credentials': [
              {
                'id': 'c1',
                'claims': [
                  {
                    'path': ['given_name'],
                  },
                ],
              },
            ],
          },
        }),
      );
      expect(
        () => offlineClient.submitResponse(
          req: req,
          vpToken: const {
            'c1': ['x'],
          },
        ),
        throwsA(isA<PresentationError>()),
      );
    });
  });

  group('nested-claim DCQL (paths beyond top level)', () {
    final client = Oid4vpClient(
      FakeOid4vcHttp((_) => HttpResp(404, '')),
      now: fixedClock(1700),
    );

    // A PID-shaped credential: top-level given_name, a nested place_of_birth
    // object, a nested age_equal_or_over object, and a nationalities array —
    // each member selectively disclosable.
    final givenName =
        Disclosure.forClaim(salt: 'a', name: 'given_name', value: 'Erika');
    final locality =
        Disclosure.forClaim(salt: 'b', name: 'locality', value: 'Cologne');
    final country =
        Disclosure.forClaim(salt: 'c', name: 'country', value: 'DE');
    final over18 = Disclosure.forClaim(salt: 'd', name: '18', value: true);
    final nationality =
        Disclosure.parse(b64uEncodeString(jsonEncode(['e', 'DE'])));

    final pid = SdJwt.parse(
      customSdJwt(
        {
          'iss': 'https://pid-issuer.example',
          'vct': 'urn:eudi:pid:1',
          '_sd_alg': 'sha-256',
          '_sd': [givenName.digest(sha256)],
          'place_of_birth': {
            '_sd': [locality.digest(sha256), country.digest(sha256)],
          },
          'age_equal_or_over': {
            '_sd': [over18.digest(sha256)],
          },
          'nationalities': [
            {'...': nationality.digest(sha256)},
          ],
        },
        disclosures: [
          givenName.encoded,
          locality.encoded,
          country.encoded,
          over18.encoded,
          nationality.encoded,
        ],
      ),
    );

    Map<String, dynamic> pidQuery(List<List<Object?>> paths) => {
          'credentials': [
            {
              'id': 'pid',
              'format': 'dc+sd-jwt',
              'meta': {
                'vct_values': ['urn:eudi:pid:1'],
              },
              'claims': [
                for (final path in paths) {'path': path},
              ],
            },
          ],
        };

    PresentationRequest reqFor(List<List<Object?>> paths) =>
        client.parseRequest(
          requestJwt(requestPayload(query: pidQuery(paths))),
        );

    test('matches a request for nested-object + array claims', () {
      final req = reqFor([
        ['age_equal_or_over', '18'],
        ['place_of_birth', 'locality'],
        ['nationalities', 0],
      ]);
      final match = client.match(req, [pid]);
      expect(match, isNotNull);
      expect(match!.queryId, 'pid');
      expect(match.requestedPaths, [
        ['age_equal_or_over', '18'],
        ['place_of_birth', 'locality'],
        ['nationalities', 0],
      ]);
    });

    test('matches an all-elements array wildcard', () {
      expect(
        client.match(
          reqFor([
            ['nationalities', null],
          ]),
          [pid],
        ),
        isNotNull,
      );
    });

    test('does not match when a nested claim is absent', () {
      // place_of_birth has no postal_code member.
      expect(
        client.match(
          reqFor([
            ['place_of_birth', 'postal_code'],
          ]),
          [pid],
        ),
        isNull,
      );
    });

    test('does not match a bad index or a path into a scalar', () {
      List<List<Object?>> p(List<Object?> path) => [path];
      // out-of-range array index
      expect(client.match(reqFor(p(['nationalities', 5])), [pid]), isNull);
      // string segment into a scalar value
      expect(client.match(reqFor(p(['given_name', 'x'])), [pid]), isNull);
      // int segment into a non-list
      expect(client.match(reqFor(p(['given_name', 0])), [pid]), isNull);
      // wildcard whose elements lack the remaining path
      final wildcardMiss =
          client.match(reqFor(p(['nationalities', null, 'x'])), [pid]);
      expect(wildcardMiss, isNull);
    });

    test('present reveals exactly the requested nested claims, hides the rest',
        () async {
      final http = FakeOid4vcHttp((_) => HttpResp(200, ''));
      final presenter = Oid4vpClient(http, now: fixedClock(1700));
      final req = presenter.parseRequest(
        requestJwt(
          requestPayload(
            query: pidQuery([
              ['age_equal_or_over', '18'],
              ['place_of_birth', 'locality'],
            ]),
          ),
        ),
      );
      final match = presenter.match(req, [pid])!;
      await presenter.present(req: req, match: match, signer: signer);

      final vpToken =
          jsonDecode(http.last.form['vp_token']!) as Map<String, dynamic>;
      final presented = SdJwt.parse((vpToken['pid'] as List).single as String);

      // Only the two requested nested disclosures ride along.
      final names = presented.disclosures.map((d) => d.name).toSet();
      expect(names, {'18', 'locality'});
      final resolved = presented.resolveClaims();
      final placeOfBirth = resolved['place_of_birth'] as Map;
      expect((resolved['age_equal_or_over'] as Map)['18'], true);
      expect(placeOfBirth['locality'], 'Cologne');
      // Siblings + unrelated top-level claims stay hidden.
      expect(placeOfBirth.containsKey('country'), isFalse);
      expect(resolved.containsKey('given_name'), isFalse);
    });
  });

  group('request object signature (RP authentication)', () {
    final client = Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')));
    final verifier = SoftwareEs256Signer.generate(random: Random(77));
    final verifierJwk = verifier.publicJwkSync();
    final leaf = buildX5cLeafFromJwk(verifierJwk);

    test('captures and verifies the JAR signing material', () async {
      final jar =
          await signedRequestJwt(requestPayload(), verifier, x5c: [leaf]);
      final sig = client.parseRequest(jar).signature!;
      expect(sig.alg, 'ES256');
      expect(sig.kid, isNull);
      expect(sig.x5c, [leaf]);
      expect(sig.verifyWithX5cLeaf(), isTrue);
      expect(sig.verifyWithJwk(verifierJwk), isTrue);
    });

    test('rejects a signature made by a different key', () async {
      final other = SoftwareEs256Signer.generate(random: Random(78));
      final jar = await signedRequestJwt(
        requestPayload(),
        verifier,
        x5c: [buildX5cLeafFromJwk(other.publicJwkSync())],
      );
      final sig = client.parseRequest(jar).signature!;
      expect(sig.verifyWithX5cLeaf(), isFalse);
      expect(sig.verifyWithJwk(other.publicJwkSync()), isFalse);
    });

    test('exposes kid and tolerates a missing x5c', () async {
      final jar =
          await signedRequestJwt(requestPayload(), verifier, kid: 'rp-1');
      final sig = client.parseRequest(jar).signature!;
      expect(sig.kid, 'rp-1');
      expect(sig.x5c, isEmpty);
      expect(sig.verifyWithJwk(verifierJwk), isTrue);
    });

    test('throws PresentationError on an unusable x5c leaf or bad JWK', () {
      final si = Jws.signingInput(
        const {
          'alg': 'ES256',
          'typ': 'oauth-authz-req+jwt',
          'x5c': ['@@@ not a certificate @@@'],
        },
        requestPayload(),
      );
      final sig =
          client.parseRequest('$si.${b64uEncode([1, 2, 3])}').signature!;
      expect(sig.verifyWithX5cLeaf, throwsA(isA<PresentationError>()));
      expect(
        () => sig.verifyWithJwk(const {'kty': 'RSA', 'n': 'AQAB', 'e': 'AQAB'}),
        throwsA(isA<PresentationError>()),
      );
    });

    test('is null for an unsigned inline request', () async {
      final link = Uri(
        scheme: 'openid4vp',
        host: '',
        queryParameters: {
          'client_id': _clientId,
          'nonce': 'n',
          'response_uri': '$_clientId/r',
          'dcql_query': jsonEncode(dcql()),
        },
      ).toString();
      final req = await client.fetchRequest(link);
      expect(req.signature, isNull);
    });

    test('splits the client_id scheme from its value', () {
      PresentationRequest parse(String clientId) => client.parseRequest(
            requestJwt({...requestPayload(), 'client_id': clientId}),
          );

      final dns = parse('x509_san_dns:verifier.example');
      expect(dns.clientIdScheme, 'x509_san_dns');
      expect(dns.clientIdValue, 'verifier.example');

      final bare = parse('https://verifier.example'); // unknown 'https' prefix
      expect(bare.clientIdScheme, isNull);
      expect(bare.clientIdValue, 'https://verifier.example');

      final plain = parse('preregistered-id'); // no colon at all
      expect(plain.clientIdScheme, isNull);
      expect(plain.clientIdValue, 'preregistered-id');
    });
  });
}
