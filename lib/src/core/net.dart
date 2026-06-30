/// Network-safety helpers shared by every layer that dereferences a URL taken
/// from untrusted input: issuer/AS metadata, JWKS, status lists, request
/// objects, offer/credential endpoints.
///
/// A credential or a request can carry any URL, and the wallet will fetch it.
/// Allowing plain `http` to an arbitrary host lets a network attacker serve
/// issuer keys, a revocation status list, or a request object over cleartext —
/// so we require `https`, with a carve-out for loopback hosts so local
/// development against an `http://localhost` issuer still works.
library;

/// Whether [uri] is safe to fetch over: `https`, or `http` to a loopback host
/// (`localhost`, `127.0.0.1`, or `::1`) for local development.
bool isSecureUrl(Uri uri) {
  if (uri.scheme == 'https') return true;
  if (uri.scheme == 'http') return _isLoopback(uri.host);
  return false;
}

bool _isLoopback(String host) {
  final h = host.toLowerCase();
  return h == 'localhost' || h == '127.0.0.1' || h == '::1' || h == '[::1]';
}
