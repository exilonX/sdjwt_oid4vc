import 'dart:convert';

import '../core/clock.dart';
import '../core/errors.dart';
import '../core/es256_signer.dart';
import '../core/http.dart';
import '../core/jws.dart';
import '../sdjwt/sd_jwt.dart';
import 'dcql.dart';
import 'models.dart';

/// OpenID4VP **holder** client: fetch a request, match it against held
/// credentials, build the `vp_token`, and submit it.
class Oid4vpClient {
  Oid4vpClient(this._http, {Clock now = systemClock}) : _now = now;

  final Oid4vcHttp _http;
  final Clock _now;

  /// Resolves an authorization request from a deep link, an inline request, or
  /// a `request_uri` reference (handling `request_uri_method=post`), and parses
  /// it into a [PresentationRequest].
  Future<PresentationRequest> fetchRequest(String authzRequestUriOrJar) async {
    final trimmed = authzRequestUriOrJar.trim();
    if (_looksLikeJwt(trimmed)) return parseRequest(trimmed);

    final uri = Uri.tryParse(trimmed);
    if (uri == null) {
      throw const PresentationError('Request is neither a URI nor a JWT');
    }
    final params = uri.queryParameters;

    final requestUri = params['request_uri'];
    if (requestUri != null) {
      final body = await _fetchRequestObject(
        _uri(requestUri),
        post: params['request_uri_method'] == 'post',
      );
      return _looksLikeJwt(body)
          ? parseRequest(body)
          : _requestFromJson(_decodeObject(body));
    }

    if (params.containsKey('client_id')) {
      return _requestFromJson(params);
    }
    throw const PresentationError(
      'Request URI has neither request_uri nor inline parameters',
    );
  }

  /// Parses an already-obtained Request Object JWT (JAR) without fetching.
  /// The signature is **not** verified here (see [PresentationRequest]).
  PresentationRequest parseRequest(String requestObjectJwt) {
    final JwsParts jws;
    try {
      jws = Jws.decompose(requestObjectJwt);
    } on FormatException catch (e) {
      throw PresentationError('Malformed request object', cause: e);
    }
    return _requestFromJson(jws.payload);
  }

  /// Picks the first held credential that satisfies a query in [req], or `null`
  /// if none do. Matches on `vct` and on whether the requested claims are
  /// available; an empty claim set means "reveal the whole credential".
  CredentialMatch? match(PresentationRequest req, List<SdJwtVc> held) {
    for (final query in req.dcql.credentials) {
      for (final credential in held) {
        if (!_satisfies(query, credential)) continue;
        final requested = query.claimNames.isEmpty
            ? credential.disclosures
                .map((d) => d.name)
                .whereType<String>()
                .toSet()
            : query.claimNames.toSet();
        return CredentialMatch(
          credential: credential,
          requestedClaims: requested,
        );
      }
    }
    return null;
  }

  /// Builds the `vp_token`: discloses [revealClaims], computes `sd_hash`, and
  /// signs the KB-JWT bound to the request's `client_id`/`nonce`.
  Future<String> buildVpToken({
    required SdJwtVc credential,
    required Iterable<String> revealClaims,
    required PresentationRequest req,
    required Es256Signer signer,
  }) =>
      credential.present(
        disclose: revealClaims.toSet(),
        audience: req.clientId,
        nonce: req.nonce,
        signer: signer,
        now: _now,
      );

  /// Submits the `vp_token` to the verifier's `response_uri` (`direct_post`).
  /// Returns the `redirect_uri` the verifier sends back, if any.
  Future<String?> submit({
    required PresentationRequest req,
    required String vpToken,
  }) async {
    final uri = req.responseUri;
    if (uri == null) {
      throw const PresentationError('Request has no response_uri');
    }
    final resp = await _http.postForm(uri, {
      'vp_token': vpToken,
      if (req.state != null) 'state': req.state!,
    });
    if (!resp.ok) {
      throw PresentationError(
        'Presentation submit failed (${resp.statusCode})',
      );
    }
    if (resp.body.trim().isEmpty) return null;
    try {
      final redirect = resp.json()['redirect_uri'];
      return redirect is String ? redirect : null;
    } on Oid4vcError {
      return null; // non-JSON body: nothing to redirect to
    }
  }

  // --- internals -----------------------------------------------------------

  Future<String> _fetchRequestObject(Uri uri, {required bool post}) async {
    final resp =
        post ? await _http.postForm(uri, const {}) : await _http.get(uri);
    if (!resp.ok) {
      throw PresentationError(
        'Request object fetch failed (${resp.statusCode})',
      );
    }
    return resp.body;
  }

  PresentationRequest _requestFromJson(Map<String, dynamic> json) {
    final clientId = json['client_id'];
    if (clientId is! String) {
      throw const PresentationError('Request is missing client_id');
    }
    final nonce = json['nonce'];
    if (nonce is! String) {
      throw const PresentationError('Request is missing nonce');
    }
    final dcql = DcqlQuery.fromJson(_coerceDcql(json['dcql_query']));

    final responseMode = json['response_mode'];
    final responseUri = json['response_uri'];
    final state = json['state'];
    return PresentationRequest(
      clientId: clientId,
      nonce: nonce,
      dcql: dcql,
      responseMode: responseMode is String ? responseMode : 'direct_post',
      responseUri: responseUri is String ? Uri.tryParse(responseUri) : null,
      state: state is String ? state : null,
    );
  }

  Map<String, dynamic> _coerceDcql(Object? value) {
    if (value is Map<String, dynamic>) return value;
    if (value is String) return _decodeObject(value); // inline query param
    throw const PresentationError('Request is missing dcql_query');
  }

  bool _satisfies(DcqlCredentialQuery query, SdJwtVc credential) {
    if (query.vctValues.isNotEmpty) {
      final vct = credential.vct;
      if (vct == null || !query.vctValues.contains(vct)) return false;
    }
    final available = credential.resolveClaims().keys.toSet();
    return query.claimNames.every(available.contains);
  }

  bool _looksLikeJwt(String value) =>
      value.split('.').length == 3 && !value.contains(RegExp(r'\s'));

  Map<String, dynamic> _decodeObject(String json) {
    final Object? decoded;
    try {
      decoded = jsonDecode(json);
    } on FormatException catch (e) {
      throw PresentationError('Expected a JSON object', cause: e);
    }
    if (decoded is! Map<String, dynamic>) {
      throw const PresentationError('Expected a JSON object');
    }
    return decoded;
  }

  Uri _uri(String value) {
    final uri = Uri.tryParse(value);
    if (uri == null || !uri.isAbsolute) {
      throw PresentationError('Not an absolute URL: $value');
    }
    return uri;
  }
}
