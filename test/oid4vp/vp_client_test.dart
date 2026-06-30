import 'dart:convert';
import 'dart:math';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/fake_http.dart';
import '../support/util.dart';

const _vct = 'https://issuer.example/extras/v1';
const _clientId = 'https://verifier.example';

/// A request object JWT (JAR). `parseRequest` never verifies it, so a fake
/// signature is fine.
String requestJwt(Map<String, dynamic> payload) {
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'},
    payload,
  );
  return '$signingInput.${b64uEncode([1, 2, 3])}';
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
  });
}
