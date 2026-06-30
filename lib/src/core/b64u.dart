import 'dart:convert';
import 'dart:typed_data';

/// base64url **without padding** — the encoding JOSE/SD-JWT uses everywhere
/// (RFC 7515 §2). These four helpers are the only place the codec lives, so the
/// `-`/`_` alphabet and the missing `=` padding are handled in exactly one spot.

/// Encodes [bytes] as unpadded base64url.
String b64uEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Encodes [text] (UTF-8) as unpadded base64url.
String b64uEncodeString(String text) => b64uEncode(utf8.encode(text));

/// Decodes unpadded (or padded) base64url into bytes.
///
/// Re-adds the padding `dart:convert` insists on. Throws [FormatException] for
/// an impossible length or characters outside the base64url alphabet.
Uint8List b64uDecode(String input) {
  final padded = switch (input.length % 4) {
    0 => input,
    2 => '$input==',
    3 => '$input=',
    _ => throw FormatException('Invalid base64url length', input),
  };
  return base64Url.decode(padded);
}

/// Decodes unpadded base64url into a UTF-8 string.
String b64uDecodeToString(String input) => utf8.decode(b64uDecode(input));
