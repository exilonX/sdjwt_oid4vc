import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/b64u.dart';
import '../core/clock.dart';
import '../core/ec.dart';
import '../core/errors.dart';
import '../core/es256_signer.dart';
import '../core/http.dart';
import '../core/jws.dart';
import 'disclosure.dart';
import 'issuer_trust.dart';
import 'kb_jwt.dart';

/// Codec for the SD-JWT VC compact serialization
/// `<issuer-JWT>~<disclosure>~…~[<KB-JWT>]`.
abstract final class SdJwt {
  /// Parses the compact form into an [SdJwtVc]. Decodes the issuer JWT and each
  /// disclosure; does **not** verify the signature (see [SdJwtVc.verifyIssuer]).
  ///
  /// Throws [SdJwtError] if the issuer JWT or any disclosure is malformed.
  static SdJwtVc parse(String compact) {
    final parts = compact.split('~');
    final issuerJwt = parts.first;
    final JwsParts jws;
    try {
      jws = Jws.decompose(issuerJwt);
    } on FormatException catch (e) {
      throw SdJwtError('Malformed issuer JWT', cause: e);
    }

    // `a~d1~…~dn~`  -> disclosures are the middle parts, KB-JWT (if any) is last.
    // `a`           -> bare JWT, no disclosures, no KB-JWT.
    final String? kbJwt;
    final List<String> disclosureStrings;
    if (parts.length == 1) {
      kbJwt = null;
      disclosureStrings = const [];
    } else {
      kbJwt = parts.last.isEmpty ? null : parts.last;
      disclosureStrings = parts.sublist(1, parts.length - 1);
    }

    final disclosures = <Disclosure>[];
    for (final raw in disclosureStrings) {
      try {
        disclosures.add(Disclosure.parse(raw));
      } on FormatException catch (e) {
        throw SdJwtError('Malformed disclosure', cause: e);
      }
    }

    return SdJwtVc._(
      issuerJwt: issuerJwt,
      header: jws.header,
      issuerClaims: jws.payload,
      signature: jws.signature,
      signingInput: jws.signingInput,
      disclosures: disclosures,
      kbJwt: kbJwt,
    );
  }

  /// Issues an SD-JWT VC. The issuer role normally lives server-side; this is
  /// exposed for tests and for a holder that re-packages a credential.
  ///
  /// Every claim named in [selectivelyDisclosable] becomes a disclosure (its
  /// digest goes into `_sd`); the rest stay in the clear. [saltGenerator]
  /// defaults to a cryptographically-secure 128-bit salt; inject a deterministic
  /// one in tests.
  static Future<String> issue({
    required Map<String, dynamic> claims,
    required Map<String, dynamic> header,
    required Set<String> selectivelyDisclosable,
    required Es256Signer signer,
    String Function()? saltGenerator,
    Hash hash = sha256,
  }) async {
    final salt = saltGenerator ?? _secureSalt;
    final payload = <String, dynamic>{};
    final digests = <String>[];
    final disclosures = <Disclosure>[];

    claims.forEach((name, value) {
      if (selectivelyDisclosable.contains(name)) {
        final disclosure =
            Disclosure.forClaim(salt: salt(), name: name, value: value);
        disclosures.add(disclosure);
        digests.add(disclosure.digest(hash));
      } else {
        payload[name] = value;
      }
    });

    if (digests.isNotEmpty) {
      digests.sort(); // hide the original claim order
      payload['_sd'] = digests;
    }
    payload['_sd_alg'] = _algName(hash);

    final fullHeader = {'alg': 'ES256', 'typ': 'dc+sd-jwt', ...header};
    final signingInput = Jws.signingInput(fullHeader, payload);
    final signature = await signer.signEs256(signingInput);

    final buffer = StringBuffer('$signingInput.$signature~');
    for (final disclosure in disclosures) {
      buffer.write('${disclosure.encoded}~');
    }
    return buffer.toString();
  }

  static String _secureSalt() {
    final random = Random.secure();
    final bytes =
        Uint8List.fromList(List.generate(16, (_) => random.nextInt(256)));
    return b64uEncode(bytes);
  }

  static String _algName(Hash hash) {
    if (hash == sha256) return 'sha-256';
    if (hash == sha384) return 'sha-384';
    if (hash == sha512) return 'sha-512';
    throw ArgumentError.value(hash, 'hash', 'unsupported _sd_alg hash');
  }
}

/// A parsed SD-JWT VC.
class SdJwtVc {
  SdJwtVc._({
    required this.issuerJwt,
    required this.header,
    required this.issuerClaims,
    required Uint8List signature,
    required String signingInput,
    required this.disclosures,
    required this.kbJwt,
  })  : _signature = signature,
        _signingInput = signingInput;

  /// The raw issuer JWT (first compact segment), kept for re-hashing on verify
  /// and for assembling presentations.
  final String issuerJwt;

  /// Issuer JWT protected header (`alg`, `typ`, `x5c?`, `kid?`).
  final Map<String, dynamic> header;

  /// Issuer JWT claims (`iss`, `vct`, `cnf`, `iat`, `exp`, `status?`, `_sd`,
  /// `_sd_alg`).
  final Map<String, dynamic> issuerClaims;

  /// The disclosures carried in the compact form.
  final List<Disclosure> disclosures;

  /// The KB-JWT if this is a presentation, else `null`.
  final String? kbJwt;

  final Uint8List _signature;
  final String _signingInput;

  /// `vct` — the credential type, if present.
  String? get vct =>
      issuerClaims['vct'] is String ? issuerClaims['vct'] as String : null;

  /// The holder confirmation JWK (`cnf.jwk`), if present.
  Map<String, dynamic>? get confirmationJwk {
    final cnf = issuerClaims['cnf'];
    if (cnf is Map<String, dynamic>) {
      final jwk = cnf['jwk'];
      if (jwk is Map<String, dynamic>) return jwk;
    }
    return null;
  }

  /// The status-list reference URI for revocation checks, if present.
  String? get statusRef {
    final status = issuerClaims['status'];
    if (status is Map) {
      final statusList = status['status_list'];
      if (statusList is Map) {
        final uri = statusList['uri'];
        if (uri is String) return uri;
      }
    }
    return null;
  }

  /// Whether `exp` is in the past relative to the system clock.
  bool get isExpired => isExpiredAt(systemClock());

  /// Whether `exp` is at or before [nowEpochSeconds]. Returns `false` when there
  /// is no `exp`.
  bool isExpiredAt(int nowEpochSeconds) {
    final exp = issuerClaims['exp'];
    return exp is int && nowEpochSeconds >= exp;
  }

  /// Reconstitutes the full claim set: registered claims plus every value that
  /// the carried disclosures reveal, with the `_sd` / `_sd_alg` / `{"...": …}`
  /// machinery removed. This is what a wallet shows the user.
  Map<String, dynamic> resolveClaims() {
    final byDigest = <String, Disclosure>{
      for (final d in disclosures) d.digest(_hash): d,
    };
    return _resolveObject(issuerClaims, byDigest);
  }

  /// Verifies the issuer signature, resolving the key per [trust].
  ///
  /// Returns whether the signature is valid. Throws [SdJwtError] when the key
  /// itself cannot be resolved (no `x5c`, unreachable metadata, malformed key) —
  /// a different condition from "key found, signature does not match".
  Future<bool> verifyIssuer(IssuerTrust trust, {Oid4vcHttp? http}) async {
    switch (trust.mode) {
      case IssuerTrustMode.x5cSignatureOnly:
        final certs = _x5cCertificates();
        try {
          return verifyEs256WithX5c(
            signingInput: _signingInput,
            signature: _signature,
            x5c: certs,
          );
        } on FormatException catch (e) {
          throw SdJwtError('Invalid x5c leaf certificate', cause: e);
        }
      case IssuerTrustMode.issuerMetadata:
        final jwk = await _issuerJwkFromMetadata(http);
        try {
          return verifyEs256WithJwk(
            signingInput: _signingInput,
            signature: _signature,
            jwk: jwk,
          );
        } on FormatException catch (e) {
          throw SdJwtError('Issuer JWK is not a usable P-256 key', cause: e);
        }
    }
  }

  /// Builds a presentation of this credential: discloses the claims named in
  /// [disclose], computes `sd_hash`, signs a KB-JWT bound to [audience]/[nonce],
  /// and returns `<issuer-JWT>~<chosen disclosures>~<KB-JWT>`.
  ///
  /// Only top-level object-property disclosures are selectable by name — which
  /// is what our flat credentials use. [now] supplies the KB-JWT `iat`.
  Future<String> present({
    required Set<String> disclose,
    required String audience,
    required String nonce,
    required Es256Signer signer,
    Clock now = systemClock,
  }) async {
    final chosen = disclosures
        .where((d) => d.name != null && disclose.contains(d.name))
        .toList();

    final prefix = StringBuffer('$issuerJwt~');
    for (final disclosure in chosen) {
      prefix.write('${disclosure.encoded}~');
    }
    final presented = prefix.toString();

    final kb = await KbJwt.build(
      sdHashValue: KbJwt.sdHash(presented, _hash),
      audience: audience,
      nonce: nonce,
      issuedAt: now(),
      signer: signer,
    );
    return '$presented$kb';
  }

  // --- internals -----------------------------------------------------------

  Hash get _hash => _hashForAlg(issuerClaims['_sd_alg']);

  static Hash _hashForAlg(Object? alg) => switch (alg) {
        null || 'sha-256' => sha256,
        'sha-384' => sha384,
        'sha-512' => sha512,
        _ => throw SdJwtError('Unsupported _sd_alg: $alg'),
      };

  List<String> _x5cCertificates() {
    final x5c = header['x5c'];
    if (x5c is! List) {
      throw const SdJwtError(
        'Header has no x5c; cannot use signatureOnly trust',
      );
    }
    final certs = x5c.whereType<String>().toList();
    if (certs.isEmpty) {
      throw const SdJwtError('Header x5c contains no certificates');
    }
    return certs;
  }

  Future<Map<String, dynamic>> _issuerJwkFromMetadata(Oid4vcHttp? http) async {
    if (http == null) {
      throw const SdJwtError('issuerMetadata trust requires an Oid4vcHttp');
    }
    final iss = issuerClaims['iss'];
    if (iss is! String) {
      throw const SdJwtError('Credential has no string iss claim');
    }
    final issuerUri = Uri.tryParse(iss);
    if (issuerUri == null || !issuerUri.isAbsolute) {
      throw SdJwtError('iss is not an absolute URI: $iss');
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

  Map<String, dynamic> _selectJwk(
    List<Map<String, dynamic>> keys,
    Object? kid,
  ) {
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

  static Uri _wellKnownJwtVcIssuer(Uri iss) {
    final issuerPath = iss.path == '/' ? '' : iss.path;
    return iss.replace(path: '/.well-known/jwt-vc-issuer$issuerPath');
  }

  Map<String, dynamic> _resolveObject(
    Map<String, dynamic> object,
    Map<String, Disclosure> byDigest,
  ) {
    final out = <String, dynamic>{};
    object.forEach((key, value) {
      if (key == '_sd' || key == '_sd_alg') return;
      out[key] = _resolveValue(value, byDigest);
    });

    final sd = object['_sd'];
    if (sd is List) {
      for (final digest in sd) {
        if (digest is! String) continue;
        final disclosure = byDigest[digest];
        if (disclosure != null && disclosure.name != null) {
          out[disclosure.name!] = _resolveValue(disclosure.value, byDigest);
        }
      }
    }
    return out;
  }

  List<dynamic> _resolveArray(
    List<dynamic> array,
    Map<String, Disclosure> byDigest,
  ) {
    final out = <dynamic>[];
    for (final element in array) {
      if (element is Map<String, dynamic> &&
          element.length == 1 &&
          element['...'] is String) {
        final disclosure = byDigest[element['...']];
        if (disclosure != null && disclosure.name == null) {
          out.add(_resolveValue(disclosure.value, byDigest));
        }
        // An undisclosed array element is simply omitted.
      } else {
        out.add(_resolveValue(element, byDigest));
      }
    }
    return out;
  }

  dynamic _resolveValue(dynamic value, Map<String, Disclosure> byDigest) {
    if (value is Map<String, dynamic>) return _resolveObject(value, byDigest);
    if (value is List) return _resolveArray(value, byDigest);
    return value;
  }
}
