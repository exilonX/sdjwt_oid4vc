import 'dart:convert';

import '../core/clock.dart';
import '../core/errors.dart';
import '../core/es256_signer.dart';
import '../core/http.dart';
import '../core/jws.dart';
import '../core/net.dart';
import 'models.dart';

/// OpenID4VCI **holder** client: turns a credential offer into an issued
/// SD-JWT VC over the pre-authorized-code flow.
///
/// Every step is a separate method so a wallet can drive the UI between them
/// (e.g. prompt for the `tx_code`); [redeemOffer] runs the whole dance.
class Oid4vciClient {
  Oid4vciClient(this._http, {Clock now = systemClock}) : _now = now;

  final Oid4vcHttp _http;
  final Clock _now;

  /// Parses an `openid-credential-offer://…` deep link, a
  /// `credential_offer` / `credential_offer_uri` query, or raw offer JSON.
  Future<CredentialOffer> parseOffer(String offerUriOrJson) async {
    final trimmed = offerUriOrJson.trim();
    if (trimmed.startsWith('{')) return _decodeOffer(trimmed);

    final uri = Uri.tryParse(trimmed);
    if (uri == null) {
      throw const OfferParseError('Offer is neither a URI nor JSON');
    }
    final inline = uri.queryParameters['credential_offer'];
    if (inline != null) return _decodeOffer(inline);

    final byReference = uri.queryParameters['credential_offer_uri'];
    if (byReference != null) {
      final resp = await _http.get(_uri(byReference));
      if (!resp.ok) {
        throw OfferParseError('Offer fetch failed (${resp.statusCode})');
      }
      return CredentialOffer.fromJson(resp.json());
    }
    throw const OfferParseError(
      'URI has no credential_offer or credential_offer_uri',
    );
  }

  /// Fetches `/.well-known/openid-credential-issuer` and the authorization
  /// server metadata, producing the endpoints + `vct` map the flow needs.
  Future<IssuerMetadata> fetchIssuerMetadata(CredentialOffer offer) async {
    final issuerUri = _uri(offer.issuer);
    final issuerMeta =
        await _getJson(_wellKnown(issuerUri, 'openid-credential-issuer'));

    return IssuerMetadata(
      issuer: offer.issuer,
      credentialEndpoint: _requiredUri(issuerMeta, 'credential_endpoint'),
      tokenEndpoint: await _discoverTokenEndpoint(issuerMeta, issuerUri),
      nonceEndpoint: _optionalUri(issuerMeta, 'nonce_endpoint'),
      vcts: _extractVcts(issuerMeta),
    );
  }

  /// `POST /token` with the pre-authorized code and the user's `tx_code`.
  Future<TokenResponse> requestToken({
    required CredentialOffer offer,
    required IssuerMetadata meta,
    required String txCode,
  }) async {
    final code = offer.preAuthCode;
    if (code == null) {
      throw const TokenError('Offer has no pre-authorized_code');
    }
    final resp = await _http.postForm(meta.tokenEndpoint, {
      'grant_type': preAuthorizedCodeGrant,
      'pre-authorized_code': code,
      if (offer.txCodeRequired) 'tx_code': txCode,
    });
    if (!resp.ok) {
      throw TokenError('Token request failed: ${_errorOf(resp)}');
    }
    return TokenResponse.fromJson(resp.json());
  }

  /// `POST /nonce` — fetches a fresh `c_nonce` when the token response did not
  /// carry one.
  Future<String> requestNonce({required IssuerMetadata meta}) async {
    final endpoint = meta.nonceEndpoint;
    if (endpoint == null) {
      throw const CredentialError('Issuer metadata has no nonce_endpoint');
    }
    final resp = await _http.postForm(endpoint, const {});
    if (!resp.ok) {
      throw CredentialError('Nonce request failed (${resp.statusCode})');
    }
    final nonce = resp.json()['c_nonce'];
    if (nonce is! String) {
      throw const CredentialError('Nonce response is missing c_nonce');
    }
    return nonce;
  }

  /// Builds the proof JWT (`typ: openid4vci-proof+jwt`) that binds the holder
  /// key to the credential. `header.jwk` is the holder public key; the payload
  /// commits to the issuer audience and the `c_nonce`.
  Future<String> buildProof({
    required String issuer,
    required String cNonce,
    required Es256Signer signer,
  }) async {
    final header = {
      'typ': 'openid4vci-proof+jwt',
      'alg': 'ES256',
      'jwk': await signer.publicJwk(),
    };
    final payload = {'aud': issuer, 'nonce': cNonce, 'iat': _now()};
    final signingInput = Jws.signingInput(header, payload);
    final signature = await signer.signEs256(signingInput);
    return '$signingInput.$signature';
  }

  /// `POST /credential` with the access token and proof; returns the compact
  /// SD-JWT VC. Attaches `key_attestation` when [attestation] is present.
  Future<String> requestCredential({
    required IssuerMetadata meta,
    required TokenResponse token,
    required String proofJwt,
    required String credentialConfigurationId,
    KeyAttestation? attestation,
  }) async {
    final body = <String, dynamic>{
      'credential_configuration_id': credentialConfigurationId,
      'proof': {'proof_type': 'jwt', 'jwt': proofJwt},
      if (attestation != null) 'key_attestation': attestation.data,
    };
    final resp = await _http.postJson(
      meta.credentialEndpoint,
      body,
      headers: {'authorization': 'Bearer ${token.accessToken}'},
    );
    if (!resp.ok) {
      throw CredentialError('Credential request failed: ${_errorOf(resp)}');
    }
    return _extractCredential(resp.json());
  }

  /// Runs the whole flow: offer → metadata → token → nonce → proof → credential.
  /// Requests a key attestation from [signer] when it supports one.
  Future<String> redeemOffer({
    required String offerUriOrJson,
    required String txCode,
    required Es256Signer signer,
  }) async {
    final offer = await parseOffer(offerUriOrJson);
    if (offer.configIds.isEmpty) {
      throw const OfferParseError('Offer has no credential_configuration_ids');
    }
    final meta = await fetchIssuerMetadata(offer);
    final token = await requestToken(offer: offer, meta: meta, txCode: txCode);
    final cNonce = token.cNonce ?? await requestNonce(meta: meta);
    final proof =
        await buildProof(issuer: offer.issuer, cNonce: cNonce, signer: signer);
    final attestation = await signer.attest(cNonce);
    return requestCredential(
      meta: meta,
      token: token,
      proofJwt: proof,
      credentialConfigurationId: offer.configIds.first,
      attestation: attestation,
    );
  }

  // --- internals -----------------------------------------------------------

  Future<CredentialOffer> _decodeOffer(String json) {
    final Object? decoded;
    try {
      decoded = jsonDecode(json);
    } on FormatException catch (e) {
      throw OfferParseError('Offer is not valid JSON', cause: e);
    }
    if (decoded is! Map<String, dynamic>) {
      throw const OfferParseError('Offer is not a JSON object');
    }
    return Future.value(CredentialOffer.fromJson(decoded));
  }

  Future<Uri> _discoverTokenEndpoint(
    Map<String, dynamic> issuerMeta,
    Uri issuerUri,
  ) async {
    final inline = issuerMeta['token_endpoint'];
    if (inline is String) return _uri(inline);

    final servers = issuerMeta['authorization_servers'];
    final base =
        servers is List && servers.isNotEmpty && servers.first is String
            ? _uri(servers.first as String)
            : issuerUri;
    final asMeta =
        await _getJson(_wellKnown(base, 'oauth-authorization-server'));
    return _requiredUri(asMeta, 'token_endpoint');
  }

  Map<String, String> _extractVcts(Map<String, dynamic> issuerMeta) {
    final out = <String, String>{};
    final configs = issuerMeta['credential_configurations_supported'];
    if (configs is Map) {
      configs.forEach((id, config) {
        if (id is String && config is Map) {
          final vct = config['vct'];
          if (vct is String) out[id] = vct;
        }
      });
    }
    return out;
  }

  String _extractCredential(Map<String, dynamic> json) {
    final credential = json['credential'];
    if (credential is String) return credential;

    final credentials = json['credentials'];
    if (credentials is List && credentials.isNotEmpty) {
      final first = credentials.first;
      if (first is String) return first;
      if (first is Map) {
        final inner = first['credential'];
        if (inner is String) return inner;
      }
    }
    throw const CredentialError('Credential response has no credential');
  }

  Future<Map<String, dynamic>> _getJson(Uri url) async {
    final resp = await _http.get(url);
    if (!resp.ok) {
      throw CredentialError(
        'Metadata fetch failed (${resp.statusCode}) for $url',
      );
    }
    return resp.json();
  }

  Uri _wellKnown(Uri base, String document) {
    final basePath = base.path == '/' ? '' : base.path;
    return base.replace(path: '/.well-known/$document$basePath');
  }

  Uri _requiredUri(Map<String, dynamic> json, String field) {
    final value = json[field];
    if (value is! String) {
      throw CredentialError('Metadata is missing $field');
    }
    return _uri(value);
  }

  Uri? _optionalUri(Map<String, dynamic> json, String field) {
    final value = json[field];
    return value is String ? _uri(value) : null;
  }

  Uri _uri(String value) {
    final uri = Uri.tryParse(value);
    if (uri == null || !uri.isAbsolute) {
      throw CredentialError('Not an absolute URL: $value');
    }
    if (!isSecureUrl(uri)) {
      throw CredentialError('Refusing to fetch over an insecure URL: $value');
    }
    return uri;
  }

  String _errorOf(HttpResp resp) {
    try {
      final json = resp.json();
      final description = json['error_description'] ?? json['error'];
      if (description is String) return '${resp.statusCode} $description';
    } on Oid4vcError {
      // Body was not JSON; fall through to the bare status.
    }
    return '${resp.statusCode}';
  }
}
