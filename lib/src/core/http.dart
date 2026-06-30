import 'dart:convert';

import 'package:http/http.dart' as http;

import 'errors.dart';

/// A minimal HTTP response, decoupled from any client library.
class HttpResp {
  const HttpResp(
    this.statusCode,
    this.body, {
    this.headers = const {},
  });

  final int statusCode;
  final String body;

  /// Lower-cased response header names mapped to their values.
  final Map<String, String> headers;

  /// Whether the status is 2xx.
  bool get ok => statusCode >= 200 && statusCode < 300;

  /// Parses the body as a JSON object.
  ///
  /// Throws [HttpError] if the body is not valid JSON or not an object — the
  /// callers here always expect an object (token response, metadata, …).
  Map<String, dynamic> json() {
    final Object? decoded;
    try {
      decoded = jsonDecode(body);
    } on FormatException catch (e) {
      throw HttpError('Response body was not valid JSON', cause: e);
    }
    if (decoded is! Map<String, dynamic>) {
      throw const HttpError('Response body was not a JSON object');
    }
    return decoded;
  }
}

/// Injectable HTTP transport. Implementations must not retry or follow
/// auth challenges silently — the protocol clients drive the flow.
abstract class Oid4vcHttp {
  Future<HttpResp> get(Uri url, {Map<String, String>? headers});

  /// POST an `application/x-www-form-urlencoded` body.
  Future<HttpResp> postForm(
    Uri url,
    Map<String, String> form, {
    Map<String, String>? headers,
  });

  /// POST an `application/json` body ([body] is JSON-encoded by the impl).
  Future<HttpResp> postJson(
    Uri url,
    Object body, {
    Map<String, String>? headers,
  });
}

/// Default [Oid4vcHttp] over `package:http`.
///
/// Pass a custom [http.Client] to inject mocks in tests or to share a tuned
/// client (timeouts, proxies) in production. Owns the client it created and
/// closes it in [close]; never closes one you passed in.
class DefaultOid4vcHttp implements Oid4vcHttp {
  DefaultOid4vcHttp({http.Client? client})
      : _client = client ?? http.Client(),
        _ownsClient = client == null;

  final http.Client _client;
  final bool _ownsClient;

  @override
  Future<HttpResp> get(Uri url, {Map<String, String>? headers}) =>
      _send(_client.get(url, headers: headers));

  @override
  Future<HttpResp> postForm(
    Uri url,
    Map<String, String> form, {
    Map<String, String>? headers,
  }) =>
      _send(
        _client.post(
          url,
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            ...?headers,
          },
          body: form,
        ),
      );

  @override
  Future<HttpResp> postJson(
    Uri url,
    Object body, {
    Map<String, String>? headers,
  }) =>
      _send(
        _client.post(
          url,
          headers: {
            'content-type': 'application/json',
            ...?headers,
          },
          body: jsonEncode(body),
        ),
      );

  Future<HttpResp> _send(Future<http.Response> pending) async {
    final http.Response response;
    try {
      response = await pending;
    } on http.ClientException catch (e) {
      throw HttpError('HTTP request failed', cause: e);
    }
    return HttpResp(
      response.statusCode,
      response.body,
      headers: response.headers
          .map((name, value) => MapEntry(name.toLowerCase(), value)),
    );
  }

  /// Closes the underlying client if this instance created it.
  void close() {
    if (_ownsClient) _client.close();
  }
}
