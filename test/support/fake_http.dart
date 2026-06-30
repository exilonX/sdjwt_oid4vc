import 'dart:convert';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';

/// A request captured by [FakeOid4vcHttp], for assertions in tests.
class FakeRequest {
  FakeRequest(this.method, this.url, this.headers, this.body);

  final String method; // GET | POST_FORM | POST_JSON
  final Uri url;
  final Map<String, String>? headers;
  final Object? body; // Map<String,String> for form, Object for json

  /// The form body, when this was a form POST.
  Map<String, String> get form => body! as Map<String, String>;
}

/// An [Oid4vcHttp] that answers from a handler and records every request, so
/// the whole protocol can be exercised with no network.
class FakeOid4vcHttp implements Oid4vcHttp {
  FakeOid4vcHttp(this._handler);

  /// Routes by URL path, with a fallback for anything unmatched.
  factory FakeOid4vcHttp.byPath(Map<String, HttpResp> routes) =>
      FakeOid4vcHttp((req) {
        final resp = routes[req.url.path];
        if (resp == null) {
          return HttpResp(404, 'no route for ${req.url.path}');
        }
        return resp;
      });

  final HttpResp Function(FakeRequest request) _handler;
  final List<FakeRequest> requests = [];

  /// The most recently received request.
  FakeRequest get last => requests.last;

  @override
  Future<HttpResp> get(Uri url, {Map<String, String>? headers}) =>
      _record(FakeRequest('GET', url, headers, null));

  @override
  Future<HttpResp> postForm(
    Uri url,
    Map<String, String> form, {
    Map<String, String>? headers,
  }) =>
      _record(FakeRequest('POST_FORM', url, headers, form));

  @override
  Future<HttpResp> postJson(
    Uri url,
    Object body, {
    Map<String, String>? headers,
  }) =>
      _record(FakeRequest('POST_JSON', url, headers, body));

  Future<HttpResp> _record(FakeRequest request) {
    requests.add(request);
    return Future.value(_handler(request));
  }
}

/// Builds a 200 response carrying [body] as JSON.
HttpResp jsonResponse(Object body) => HttpResp(200, jsonEncode(body));
