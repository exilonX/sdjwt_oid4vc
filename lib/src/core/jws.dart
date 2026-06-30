import 'dart:convert';
import 'dart:typed_data';

import 'b64u.dart';

/// The three decoded parts of a compact JWS (`header.payload.signature`).
class JwsParts {
  const JwsParts({
    required this.header,
    required this.payload,
    required this.signature,
    required this.signingInput,
  });

  /// Protected header (`alg`, `typ`, `kid`, `x5c`, `jwk`, …).
  final Map<String, dynamic> header;

  /// Decoded claims set.
  final Map<String, dynamic> payload;

  /// Raw signature bytes. For ES256 this is `R‖S` (64 bytes).
  final Uint8List signature;

  /// The exact bytes that were signed: `base64url(header).base64url(payload)`.
  /// Kept verbatim from the input so verification re-hashes the original bytes,
  /// not a re-serialised (and possibly reordered) copy.
  final String signingInput;
}

/// Compact-JWS helpers shared by the SD-JWT codec and the OID4VP request parser.
abstract final class Jws {
  /// The JOSE signing input for [header] and [payload]:
  /// `base64url(JSON(header)).base64url(JSON(payload))`.
  ///
  /// This is the string an [Es256Signer] signs. It does not sign — it only
  /// assembles the bytes, so it stays pure and synchronous.
  static String signingInput(
    Map<String, dynamic> header,
    Map<String, dynamic> payload,
  ) =>
      '${b64uEncodeString(jsonEncode(header))}'
      '.${b64uEncodeString(jsonEncode(payload))}';

  /// Splits and decodes a compact JWS into its parts.
  ///
  /// Throws [FormatException] when the shape is wrong (not three segments, not
  /// base64url, or header/payload not a JSON object). Callers that have domain
  /// context wrap this into the appropriate [Oid4vcError].
  static JwsParts decompose(String compact) {
    final segments = compact.split('.');
    if (segments.length != 3) {
      throw FormatException(
        'Expected 3 JWS segments, got ${segments.length}',
        compact,
      );
    }
    return JwsParts(
      header: decodeJsonObject(segments[0]),
      payload: decodeJsonObject(segments[1]),
      signature: b64uDecode(segments[2]),
      signingInput: '${segments[0]}.${segments[1]}',
    );
  }

  /// Decodes one base64url segment into a JSON object, or throws
  /// [FormatException] if it is not an object.
  static Map<String, dynamic> decodeJsonObject(String segment) {
    final decoded = jsonDecode(b64uDecodeToString(segment));
    if (decoded is! Map<String, dynamic>) {
      throw FormatException('Expected a JSON object', segment);
    }
    return decoded;
  }
}
