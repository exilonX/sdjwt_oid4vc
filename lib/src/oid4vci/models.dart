import '../core/errors.dart';

/// The OpenID4VCI grant type for the pre-authorized code flow — the only grant
/// this wallet uses.
const String preAuthorizedCodeGrant =
    'urn:ietf:params:oauth:grant-type:pre-authorized_code';

/// A parsed credential offer (from a `openid-credential-offer://` deep link or
/// the offer JSON).
class CredentialOffer {
  const CredentialOffer({
    required this.issuer,
    required this.configIds,
    required this.preAuthCode,
    required this.txCodeRequired,
    this.txCodeLength,
    this.txCodeInputMode,
    this.txCodeDescription,
  });

  /// Parses the offer's JSON object. Throws [OfferParseError] if mandatory
  /// fields are missing.
  factory CredentialOffer.fromJson(Map<String, dynamic> json) {
    final issuer = json['credential_issuer'];
    if (issuer is! String) {
      throw const OfferParseError('Offer is missing credential_issuer');
    }
    final ids = json['credential_configuration_ids'];
    final configIds = ids is List
        ? ids.whereType<String>().toList(growable: false)
        : const <String>[];

    String? preAuthCode;
    var txCodeRequired = false;
    int? txCodeLength;
    String? txCodeInputMode;
    String? txCodeDescription;

    final grants = json['grants'];
    if (grants is Map) {
      final grant = grants[preAuthorizedCodeGrant];
      if (grant is Map) {
        final code = grant['pre-authorized_code'];
        if (code is String) preAuthCode = code;
        final txCode = grant['tx_code'];
        if (txCode is Map) {
          txCodeRequired = true;
          final length = txCode['length'];
          if (length is int) txCodeLength = length;
          final inputMode = txCode['input_mode'];
          if (inputMode is String) txCodeInputMode = inputMode;
          final description = txCode['description'];
          if (description is String) txCodeDescription = description;
        }
      }
    }

    return CredentialOffer(
      issuer: issuer,
      configIds: configIds,
      preAuthCode: preAuthCode,
      txCodeRequired: txCodeRequired,
      txCodeLength: txCodeLength,
      txCodeInputMode: txCodeInputMode,
      txCodeDescription: txCodeDescription,
    );
  }

  /// The `credential_issuer` URL.
  final String issuer;

  /// `credential_configuration_ids` — the credentials on offer.
  final List<String> configIds;

  /// The `pre-authorized_code`, or `null` if the offer carries no such grant.
  final String? preAuthCode;

  /// Whether the issuer requires a `tx_code` (e.g. a code emailed to the user).
  final bool txCodeRequired;

  /// Expected `tx_code` length, when advertised.
  final int? txCodeLength;

  /// `tx_code` input mode (`numeric` / `text`), when advertised.
  final String? txCodeInputMode;

  /// Human-readable hint for the `tx_code`, when advertised.
  final String? txCodeDescription;
}

/// The issuer endpoints and credential types this wallet needs, gathered from
/// `/.well-known/openid-credential-issuer` (+ the authorization server's
/// `/.well-known/oauth-authorization-server`).
class IssuerMetadata {
  const IssuerMetadata({
    required this.issuer,
    required this.credentialEndpoint,
    required this.tokenEndpoint,
    required this.nonceEndpoint,
    required this.vcts,
  });

  /// The `credential_issuer` identifier.
  final String issuer;

  /// Where `POST /credential` goes.
  final Uri credentialEndpoint;

  /// Where `POST /token` goes (from the authorization server metadata).
  final Uri tokenEndpoint;

  /// Where `POST /nonce` goes, when the issuer exposes a nonce endpoint.
  final Uri? nonceEndpoint;

  /// `credential_configuration_id` → `vct`, for the configurations on offer.
  final Map<String, String> vcts;
}

/// The result of `POST /token`.
class TokenResponse {
  const TokenResponse({required this.accessToken, required this.cNonce});

  /// Parses the token endpoint's JSON response. Throws [TokenError] when there
  /// is no `access_token`.
  factory TokenResponse.fromJson(Map<String, dynamic> json) {
    final accessToken = json['access_token'];
    if (accessToken is! String) {
      throw const TokenError('Token response is missing access_token');
    }
    final cNonce = json['c_nonce'];
    return TokenResponse(
      accessToken: accessToken,
      cNonce: cNonce is String ? cNonce : null,
    );
  }

  /// The bearer token authorizing `POST /credential`.
  final String accessToken;

  /// The issuer challenge to embed in the proof, if returned here. When `null`
  /// the wallet fetches one from the nonce endpoint.
  final String? cNonce;
}
