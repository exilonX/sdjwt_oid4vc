import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../core/b64u.dart';

/// One selectively-disclosable value of an SD-JWT VC.
///
/// A disclosure is `base64url(JSON([salt, name, value]))` for an object
/// property, or `base64url(JSON([salt, value]))` for an array element. The
/// [encoded] form is kept verbatim because the digest that links it into the
/// issuer JWT is taken over *those* ASCII bytes, not over a re-serialised copy.
class Disclosure {
  const Disclosure._(this.encoded, this.salt, this.name, this.value);

  /// Parses one base64url disclosure string.
  ///
  /// Throws [FormatException] if it is not a 2- or 3-element JSON array with a
  /// string salt (and, for object properties, a string name).
  factory Disclosure.parse(String encoded) {
    final decoded = jsonDecode(b64uDecodeToString(encoded));
    if (decoded is! List || decoded.length < 2 || decoded.length > 3) {
      throw FormatException(
        'Disclosure must be a 2- or 3-element array',
        encoded,
      );
    }
    final salt = decoded.first;
    if (salt is! String) {
      throw FormatException('Disclosure salt must be a string', encoded);
    }
    if (decoded.length == 3) {
      final name = decoded[1];
      if (name is! String) {
        throw FormatException('Disclosure name must be a string', encoded);
      }
      return Disclosure._(encoded, salt, name, decoded[2]);
    }
    return Disclosure._(encoded, salt, null, decoded[1]);
  }

  /// Builds (and encodes) a fresh object-property disclosure.
  factory Disclosure.forClaim({
    required String salt,
    required String name,
    required Object? value,
  }) {
    final encoded = b64uEncodeString(jsonEncode([salt, name, value]));
    return Disclosure._(encoded, salt, name, value);
  }

  /// The disclosure exactly as it appears in the compact serialization.
  final String encoded;

  /// Random salt that blinds the digest.
  final String salt;

  /// Claim name, or `null` for an array-element disclosure.
  final String? name;

  /// The disclosed value (any JSON type).
  final Object? value;

  /// Whether this discloses an array element (rather than an object property).
  bool get isArrayElement => name == null;

  /// The digest that references this disclosure from `_sd` (object property) or
  /// from an `{"...": digest}` array entry: `base64url(hash(ASCII(encoded)))`.
  String digest(Hash hash) =>
      b64uEncode(hash.convert(utf8.encode(encoded)).bytes);

  @override
  String toString() =>
      'Disclosure(${isArrayElement ? value : '$name: $value'})';
}
