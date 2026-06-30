import 'dart:typed_data';

import '../core/ec.dart';
import '../core/errors.dart';
import '../sdjwt/sd_jwt.dart';
import 'dcql.dart';

/// `client_id` scheme prefixes OpenID4VP defines for the modern
/// `<scheme>:<value>` form. A bare URL `client_id` (legacy / `redirect_uri`
/// default) has no recognised prefix and reports a `null` scheme.
const Set<String> _knownClientIdSchemes = {
  'x509_san_dns',
  'x509_san_uri',
  'x509_hash',
  'verifier_attestation',
  'redirect_uri',
  'did',
  'decentralized_identifier',
  'web-origin',
  'openid_federation',
};

/// A parsed OpenID4VP authorization request (Request Object).
///
/// The library does **not** decide whether to *trust* the Relying Party — that
/// policy (is this certificate on my trust list? does its SAN match
/// `client_id`?) lives in the wallet. But it does expose what the wallet needs
/// to make that decision: [signature] carries the request object's signing
/// material (cert chain + a verify helper) when the request arrived as a signed
/// JAR, and [clientIdScheme] / [clientIdValue] split the `client_id`.
class PresentationRequest {
  const PresentationRequest({
    required this.clientId,
    required this.nonce,
    required this.responseMode,
    required this.dcql,
    this.responseUri,
    this.state,
    this.signature,
  });

  /// `client_id` — also the audience the KB-JWT must commit to.
  final String clientId;

  /// `nonce` — the verifier's freshness challenge, echoed in the KB-JWT.
  final String nonce;

  /// `response_mode` (e.g. `direct_post`).
  final String responseMode;

  /// The query stating which credential/claims to present.
  final DcqlQuery dcql;

  /// Where the response is posted (`response_uri`), if any.
  final Uri? responseUri;

  /// Opaque `state` to echo back to the verifier, if present.
  final String? state;

  /// The request object's signing material when it arrived as a signed JAR,
  /// else `null` (unsigned inline parameters). The wallet uses this to
  /// authenticate the verifier before presenting.
  final RequestObjectSignature? signature;

  /// The `client_id` scheme prefix (e.g. `x509_san_dns`, `did`, `redirect_uri`)
  /// when `client_id` is of the `<scheme>:<value>` form, else `null`.
  String? get clientIdScheme {
    final colon = clientId.indexOf(':');
    if (colon < 0) return null;
    final scheme = clientId.substring(0, colon);
    return _knownClientIdSchemes.contains(scheme) ? scheme : null;
  }

  /// The `client_id` with any recognised scheme prefix stripped (e.g. the DNS
  /// name for `x509_san_dns`). Equals `client_id` when there is no scheme.
  String get clientIdValue {
    final scheme = clientIdScheme;
    return scheme == null ? clientId : clientId.substring(scheme.length + 1);
  }
}

/// The signing material of a signed OpenID4VP request object (a JAR — a
/// JWT-Secured Authorization Request).
///
/// Exposed so the wallet can authenticate the Relying Party. The library
/// confirms *integrity* (the signature matches the key in the chain) on demand;
/// the wallet owns the *trust* decision — validating the certificate to a trust
/// anchor and checking its SAN against [PresentationRequest.clientIdValue].
class RequestObjectSignature {
  const RequestObjectSignature({
    required this.header,
    required this.signingInput,
    required this.signature,
  });

  /// Protected header of the request object (`alg`, `kid`, `x5c`, …).
  final Map<String, dynamic> header;

  /// The exact `base64url(header).base64url(payload)` bytes that were signed.
  final String signingInput;

  /// Raw signature bytes (`R‖S` for ES256).
  final Uint8List signature;

  /// `alg` from the header, if a string. These helpers verify ES256 only;
  /// inspect this first if the verifier might use another algorithm.
  String? get alg => header['alg'] is String ? header['alg'] as String : null;

  /// `kid` from the header, if a string.
  String? get kid => header['kid'] is String ? header['kid'] as String : null;

  /// The `x5c` chain (base64 DER, leaf first) the verifier signed with, if
  /// present — what the wallet validates against its trust list.
  List<String> get x5c {
    final value = header['x5c'];
    return value is List ? value.whereType<String>().toList() : const [];
  }

  /// Verifies the signature against the public key in the `x5c` leaf.
  ///
  /// Confirms the request really was signed by the key in that certificate; the
  /// wallet must still decide whether to trust the certificate. Throws
  /// [PresentationError] if the leaf carries no usable P-256 key.
  bool verifyWithX5cLeaf() {
    try {
      return verifyEs256WithX5c(
        signingInput: signingInput,
        signature: signature,
        x5c: x5c,
      );
    } on FormatException catch (e) {
      throw PresentationError('Request x5c leaf is unusable', cause: e);
    }
  }

  /// Verifies the signature against a caller-supplied EC P-256 JWK — e.g. a key
  /// the wallet resolved from `client_id` or a verifier trust list. Throws
  /// [PresentationError] if [jwk] is not a usable P-256 key.
  bool verifyWithJwk(Map<String, dynamic> jwk) {
    try {
      return verifyEs256WithJwk(
        signingInput: signingInput,
        signature: signature,
        jwk: jwk,
      );
    } on FormatException catch (e) {
      throw PresentationError(
        'Verifier JWK is not a usable P-256 key',
        cause: e,
      );
    }
  }
}

/// A held credential that satisfies a request, plus the claims to reveal.
class CredentialMatch {
  const CredentialMatch({
    required this.credential,
    required this.requestedClaims,
    this.queryId = '',
    this.requestedPaths = const [],
  });

  /// The credential to present.
  final SdJwtVc credential;

  /// The top-level claim names the verifier asked for (the disclosures to
  /// reveal). Empty in the query means "reveal the whole credential".
  final Set<String> requestedClaims;

  /// The DCQL credential-query id this match answers — the key the verifier
  /// expects in a multi-credential `vp_token`.
  final String queryId;

  /// The full DCQL claim paths requested, including nested (`["address",
  /// "street"]`) and array paths — what [SdJwtVc.present] uses to reveal nested
  /// claims precisely.
  final List<List<Object?>> requestedPaths;
}
