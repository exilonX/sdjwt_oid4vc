import '../sdjwt/sd_jwt.dart';
import 'dcql.dart';

/// A parsed OpenID4VP authorization request (Request Object).
///
/// The library does **not** verify the request object's signature — Relying
/// Party trust (RPAC / `trustedReaderCertificates`) is the wallet app's
/// responsibility, deliberately out of scope here.
class PresentationRequest {
  const PresentationRequest({
    required this.clientId,
    required this.nonce,
    required this.responseMode,
    required this.dcql,
    this.responseUri,
    this.state,
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
}

/// A held credential that satisfies a request, plus the claims to reveal.
class CredentialMatch {
  const CredentialMatch({
    required this.credential,
    required this.requestedClaims,
  });

  /// The credential to present.
  final SdJwtVc credential;

  /// The claim names the verifier asked for (the disclosures to reveal).
  final Set<String> requestedClaims;
}
