/// Every error this library throws on its own behalf is an [Oid4vcError].
///
/// It is `sealed`, so a `switch` over a caught error is exhaustive and the
/// analyzer flags any new subtype a caller forgot to handle. Lower-level
/// failures (bad base64, malformed JSON, socket errors) surface as the usual
/// Dart exceptions until a layer that has domain context wraps them — keeping
/// the [cause] so nothing is lost.
sealed class Oid4vcError implements Exception {
  const Oid4vcError(this.message, {this.cause});

  /// Human-readable, developer-facing summary. Never contains secrets
  /// (`tx_code`, access tokens, private key material are never logged here).
  final String message;

  /// The lower-level error this one wraps, if any.
  final Object? cause;

  @override
  String toString() {
    final base = '$runtimeType: $message';
    return cause == null ? base : '$base (cause: $cause)';
  }
}

/// A credential offer (deep link or JSON) could not be parsed.
class OfferParseError extends Oid4vcError {
  const OfferParseError(super.message, {super.cause});
}

/// The `POST /token` exchange failed (bad `tx_code`, error response, …).
class TokenError extends Oid4vcError {
  const TokenError(super.message, {super.cause});
}

/// The `POST /credential` exchange failed.
class CredentialError extends Oid4vcError {
  const CredentialError(super.message, {super.cause});
}

/// An OpenID4VP request could not be fetched/parsed, or a response could not
/// be built/submitted.
class PresentationError extends Oid4vcError {
  const PresentationError(super.message, {super.cause});
}

/// An SD-JWT VC could not be parsed, resolved, or verified.
class SdJwtError extends Oid4vcError {
  const SdJwtError(super.message, {super.cause});
}

/// A transport-level failure carrying the HTTP status when there was one.
class HttpError extends Oid4vcError {
  const HttpError(super.message, {this.statusCode, super.cause});

  /// The HTTP status code, or `null` if the request never got a response.
  final int? statusCode;
}

/// A credential's revocation status could not be resolved — the status list was
/// unreachable or malformed, its signature did not verify, or the index was out
/// of range.
class StatusError extends Oid4vcError {
  const StatusError(super.message, {super.cause});
}
