import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../core/b64u.dart';
import '../core/es256_signer.dart';
import '../core/jws.dart';

/// Key Binding JWT helpers (SD-JWT VC, `typ: kb+jwt`).
///
/// The KB-JWT is the holder's fresh proof-of-possession at presentation time:
/// it signs the verifier's `nonce`, the audience, and a hash of exactly the
/// disclosures being presented, so a captured presentation cannot be replayed
/// or have disclosures swapped.
abstract final class KbJwt {
  /// `sd_hash` over the presented prefix — the issuer JWT plus the chosen
  /// disclosures, each followed by `~` (the bytes preceding the KB-JWT).
  static String sdHash(String presentedPrefix, Hash hash) =>
      b64uEncode(hash.convert(utf8.encode(presentedPrefix)).bytes);

  /// Builds and signs a KB-JWT binding [sdHashValue] to [audience]/[nonce] at
  /// [issuedAt] (epoch seconds). Returns the compact JWT.
  static Future<String> build({
    required String sdHashValue,
    required String audience,
    required String nonce,
    required int issuedAt,
    required Es256Signer signer,
  }) async {
    const header = {'typ': 'kb+jwt', 'alg': 'ES256'};
    final payload = {
      'iat': issuedAt,
      'aud': audience,
      'nonce': nonce,
      'sd_hash': sdHashValue,
    };
    final signingInput = Jws.signingInput(header, payload);
    final signature = await signer.signEs256(signingInput);
    return '$signingInput.$signature';
  }
}
