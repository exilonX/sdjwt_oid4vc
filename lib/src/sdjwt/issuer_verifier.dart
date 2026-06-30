import 'dart:typed_data';

import '../core/clock.dart';
import '../core/ec.dart';
import '../core/errors.dart';
import '../core/http.dart';
import '../core/net.dart';
import 'issuer_trust.dart';

/// Resolves an issuer's public key per an [IssuerTrust] policy and verifies an
/// ES256 JWS signature with it.
///
/// Shared by the SD-JWT VC codec (a credential's issuer seal) and the status
/// list resolver (a status list token is itself an issuer-signed JWT): both
/// need the same `x5c`-leaf / `.well-known` metadata key resolution and the
/// same `alg`/`typ` guard, so it lives in exactly one place.
///
/// Returns whether the signature is valid. Throws [SdJwtError] when the header
/// carries the wrong `alg`/`typ`, or when the key cannot be resolved (no `x5c`,
/// unreachable metadata, malformed key) — a different condition from "key
/// found, signature does not match", which returns `false`.
Future<bool> verifyIssuerSignature({
  required Map<String, dynamic> header,
  required String signingInput,
  required Uint8List signature,
  required Object? iss,
  required IssuerTrust trust,
  required Set<String> allowedTypes,
  Oid4vcHttp? http,
  Clock now = systemClock,
}) async {
  _assertAlgAndType(header, allowedTypes);
  switch (trust.mode) {
    case IssuerTrustMode.x5cSignatureOnly:
      try {
        return verifyEs256WithX5c(
          signingInput: signingInput,
          signature: signature,
          x5c: _x5cCertificates(header),
        );
      } on FormatException catch (e) {
        throw SdJwtError('Invalid x5c leaf certificate', cause: e);
      }
    case IssuerTrustMode.x5cChain:
      if (trust.trustAnchors.isEmpty) {
        throw const SdJwtError(
          'x5cChain trust requires at least one trust anchor',
        );
      }
      try {
        return verifyEs256WithX5cChain(
          signingInput: signingInput,
          signature: signature,
          x5c: _x5cCertificates(header),
          trustAnchors: trust.trustAnchors,
          nowEpoch: now(),
        );
      } on FormatException catch (e) {
        throw SdJwtError('Unparseable certificate in x5c chain', cause: e);
      }
    case IssuerTrustMode.issuerMetadata:
      final jwk = await _issuerJwkFromMetadata(header, iss, http);
      try {
        return verifyEs256WithJwk(
          signingInput: signingInput,
          signature: signature,
          jwk: jwk,
        );
      } on FormatException catch (e) {
        throw SdJwtError('Issuer JWK is not a usable P-256 key', cause: e);
      }
  }
}

/// Rejects an unexpected `alg` or `typ` before any key work. The `alg` guard is
/// defence-in-depth (the verify path only ever runs ECDSA P-256, so an attacker
/// cannot downgrade to `none`/`HS256` anyway); the `typ` guard stops one signed
/// JWT type being accepted where another is expected (a status list token fed
/// in place of a credential, say).
void _assertAlgAndType(Map<String, dynamic> header, Set<String> allowedTypes) {
  if (header['alg'] != 'ES256') {
    throw SdJwtError('Unsupported JWS alg ${header['alg']}; expected ES256');
  }
  final typ = header['typ'];
  if (typ is! String || !allowedTypes.contains(typ)) {
    throw SdJwtError('Unexpected JWS typ $typ; expected one of $allowedTypes');
  }
}

List<String> _x5cCertificates(Map<String, dynamic> header) {
  final x5c = header['x5c'];
  if (x5c is! List) {
    throw const SdJwtError('Header has no x5c; cannot use signatureOnly trust');
  }
  final certs = x5c.whereType<String>().toList();
  if (certs.isEmpty) {
    throw const SdJwtError('Header x5c contains no certificates');
  }
  return certs;
}

Future<Map<String, dynamic>> _issuerJwkFromMetadata(
  Map<String, dynamic> header,
  Object? iss,
  Oid4vcHttp? http,
) async {
  if (http == null) {
    throw const SdJwtError('issuerMetadata trust requires an Oid4vcHttp');
  }
  if (iss is! String) {
    throw const SdJwtError('Credential has no string iss claim');
  }
  final issuerUri = Uri.tryParse(iss);
  if (issuerUri == null || !issuerUri.isAbsolute) {
    throw SdJwtError('iss is not an absolute URI: $iss');
  }
  if (!isSecureUrl(issuerUri)) {
    throw SdJwtError('Refusing to fetch issuer metadata over http: $iss');
  }

  final metadata = await _getJson(http, _wellKnownJwtVcIssuer(issuerUri));
  final keys = await _resolveJwks(metadata, http);
  return _selectJwk(keys, header['kid']);
}

Future<Map<String, dynamic>> _getJson(Oid4vcHttp http, Uri url) async {
  final resp = await http.get(url);
  if (!resp.ok) {
    throw SdJwtError(
      'Issuer metadata fetch failed (${resp.statusCode}) for $url',
    );
  }
  return resp.json();
}

Future<List<Map<String, dynamic>>> _resolveJwks(
  Map<String, dynamic> metadata,
  Oid4vcHttp http,
) async {
  final inline = metadata['jwks'];
  if (inline is Map<String, dynamic>) return _keysOf(inline);

  final jwksUri = metadata['jwks_uri'];
  if (jwksUri is String) {
    final uri = Uri.tryParse(jwksUri);
    if (uri == null || !uri.isAbsolute) {
      throw SdJwtError('jwks_uri is not an absolute URI: $jwksUri');
    }
    if (!isSecureUrl(uri)) {
      throw SdJwtError('Refusing to fetch jwks_uri over http: $jwksUri');
    }
    return _keysOf(await _getJson(http, uri));
  }
  throw const SdJwtError('Issuer metadata has neither jwks nor jwks_uri');
}

List<Map<String, dynamic>> _keysOf(Map<String, dynamic> jwks) {
  final keys = jwks['keys'];
  if (keys is! List) {
    throw const SdJwtError('JWK set has no keys array');
  }
  return keys.whereType<Map<String, dynamic>>().toList();
}

Map<String, dynamic> _selectJwk(List<Map<String, dynamic>> keys, Object? kid) {
  if (keys.isEmpty) {
    throw const SdJwtError('Issuer JWK set is empty');
  }
  if (kid is String) {
    for (final key in keys) {
      if (key['kid'] == kid) return key;
    }
  }
  return keys.first;
}

Uri _wellKnownJwtVcIssuer(Uri iss) {
  final issuerPath = iss.path == '/' ? '' : iss.path;
  return iss.replace(path: '/.well-known/jwt-vc-issuer$issuerPath');
}
