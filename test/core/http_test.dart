import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('DefaultOid4vcHttp', () {
    test('GET returns status, body and lower-cased headers', () async {
      final transport = DefaultOid4vcHttp(
        client: MockClient((req) async {
          expect(req.method, 'GET');
          expect(req.url, Uri.parse('https://x/y'));
          return http.Response('hello', 200, headers: {'X-Test': 'v'});
        }),
      );
      final resp = await transport.get(Uri.parse('https://x/y'));
      expect(resp.statusCode, 200);
      expect(resp.body, 'hello');
      expect(resp.ok, isTrue);
      expect(resp.headers['x-test'], 'v');
    });

    test('postForm sends a urlencoded body and merges headers', () async {
      late http.Request seen;
      final transport = DefaultOid4vcHttp(
        client: MockClient((req) async {
          seen = req;
          return http.Response('{}', 200);
        }),
      );
      await transport.postForm(
        Uri.parse('https://x/token'),
        {'grant_type': 'g', 'code': 'c'},
        headers: {'authorization': 'Bearer t'},
      );
      expect(seen.headers['content-type'], contains('x-www-form-urlencoded'));
      expect(seen.headers['authorization'], 'Bearer t');
      expect(seen.bodyFields, {'grant_type': 'g', 'code': 'c'});
    });

    test('postJson sends a JSON body', () async {
      late http.Request seen;
      final transport = DefaultOid4vcHttp(
        client: MockClient((req) async {
          seen = req;
          return http.Response('{}', 200);
        }),
      );
      await transport.postJson(
        Uri.parse('https://x/c'),
        {'a': 1},
        headers: {'authorization': 'Bearer t'},
      );
      expect(seen.headers['content-type'], contains('application/json'));
      expect(seen.headers['authorization'], 'Bearer t');
      expect(jsonDecode(seen.body), {'a': 1});
    });

    test('wraps a transport failure in HttpError', () async {
      final transport = DefaultOid4vcHttp(
        client: MockClient((_) async => throw http.ClientException('down')),
      );
      expect(
        () => transport.get(Uri.parse('https://x')),
        throwsA(isA<HttpError>()),
      );
    });

    test('close() is safe whether or not the client was injected', () {
      DefaultOid4vcHttp().close();
      DefaultOid4vcHttp(client: MockClient((_) async => http.Response('', 200)))
          .close();
    });
  });

  group('HttpResp', () {
    test('ok reflects the 2xx range', () {
      expect(const HttpResp(204, '').ok, isTrue);
      expect(const HttpResp(299, '').ok, isTrue);
      expect(const HttpResp(300, '').ok, isFalse);
      expect(const HttpResp(500, '').ok, isFalse);
    });

    test('json parses an object', () {
      expect(const HttpResp(200, '{"a":1}').json(), {'a': 1});
    });

    test('json throws HttpError for invalid or non-object bodies', () {
      expect(
        () => const HttpResp(200, 'not json').json(),
        throwsA(isA<HttpError>()),
      );
      expect(
        () => const HttpResp(200, '[1,2]').json(),
        throwsA(isA<HttpError>()),
      );
    });
  });
}
