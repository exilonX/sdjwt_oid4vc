import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';

/// A salt generator that hands out [salts] in order — deterministic disclosures
/// for tests.
String Function() seqSalts(List<String> salts) {
  var index = 0;
  return () => salts[index++];
}

/// A fixed clock (epoch seconds) for deterministic `iat` values.
int Function() fixedClock(int epochSeconds) => () => epochSeconds;

/// Builds a compact SD-JWT with a fake signature — fine for `parse`/`resolve`/
/// `match`/`present` tests, which never verify the issuer signature. Pass
/// hand-built [disclosures] (e.g. via `Disclosure.forClaim`) referenced by
/// digest in [payload]'s `_sd` arrays to construct nested credentials.
String customSdJwt(
  Map<String, dynamic> payload, {
  List<String> disclosures = const [],
  Map<String, dynamic> header = const {'alg': 'ES256', 'typ': 'dc+sd-jwt'},
}) {
  final signingInput = Jws.signingInput(header, payload);
  final buffer = StringBuffer('$signingInput.${b64uEncode([9, 9, 9])}~');
  for (final disclosure in disclosures) {
    buffer.write('$disclosure~');
  }
  return buffer.toString();
}
