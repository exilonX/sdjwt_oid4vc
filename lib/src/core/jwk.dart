import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'b64u.dart';

/// JWK helpers. The only one we need is the RFC 7638 thumbprint, used to derive
/// a stable `kid` for the holder key.
abstract final class Jwk {
  /// RFC 7638 thumbprint of [jwk]: SHA-256 over the canonical JSON of the
  /// key's *required* members, lexicographically ordered, returned as
  /// unpadded base64url.
  ///
  /// Supports the key types a wallet meets in practice: `EC` (our holder key),
  /// `RSA`, and `OKP`. Throws [ArgumentError] for anything else or a member
  /// that is missing/not a string.
  static String thumbprint(Map<String, dynamic> jwk) {
    final kty = jwk['kty'];
    // Built in lexicographic key order on purpose — that *is* the canonical
    // form RFC 7638 requires, so no sort step is needed.
    final members = switch (kty) {
      'EC' => {
          'crv': _string(jwk, 'crv'),
          'kty': 'EC',
          'x': _string(jwk, 'x'),
          'y': _string(jwk, 'y'),
        },
      'RSA' => {
          'e': _string(jwk, 'e'),
          'kty': 'RSA',
          'n': _string(jwk, 'n'),
        },
      'OKP' => {
          'crv': _string(jwk, 'crv'),
          'kty': 'OKP',
          'x': _string(jwk, 'x'),
        },
      _ => throw ArgumentError.value(kty, 'jwk[kty]', 'unsupported key type'),
    };
    final canonical = jsonEncode(members);
    return b64uEncode(sha256.convert(utf8.encode(canonical)).bytes);
  }

  static String _string(Map<String, dynamic> jwk, String member) {
    final value = jwk[member];
    if (value is! String) {
      throw ArgumentError.value(value, 'jwk[$member]', 'expected a string');
    }
    return value;
  }
}
