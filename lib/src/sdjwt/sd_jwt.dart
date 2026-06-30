import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/b64u.dart';
import '../core/clock.dart';
import '../core/errors.dart';
import '../core/es256_signer.dart';
import '../core/http.dart';
import '../core/jws.dart';
import 'disclosure.dart';
import 'issuer_trust.dart';
import 'issuer_verifier.dart';
import 'kb_jwt.dart';
import 'status_list.dart';

/// The `typ` header values this codec accepts for an SD-JWT VC issuer JWT.
/// `dc+sd-jwt` is the current SD-JWT VC media type; `vc+sd-jwt` is the older
/// spelling still emitted by some deployments.
const Set<String> _sdJwtVcTypes = {'dc+sd-jwt', 'vc+sd-jwt'};

/// Hard cap on selective-disclosure nesting depth, so a maliciously deep
/// credential cannot exhaust the stack while [SdJwtVc.resolveClaims] walks it.
/// Real credentials nest only a few levels; 32 is comfortably above that.
const int _maxResolveDepth = 32;

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

  /// The structured status-list reference (`uri` + `idx`) for revocation, if
  /// present — feed it to a `StatusListResolver` to learn whether this
  /// credential is still valid.
  StatusListRef? get statusListRef => StatusListRef.fromClaims(issuerClaims);

  /// Whether `exp` is in the past relative to the system clock.
  bool get isExpired => isExpiredAt(systemClock());

  /// Whether `exp` is at or before [nowEpochSeconds]. Returns `false` when there
  /// is no `exp`.
  bool isExpiredAt(int nowEpochSeconds) {
    final exp = issuerClaims['exp'];
    return exp is int && nowEpochSeconds >= exp;
  }

  /// `nbf` ("not before") — the epoch second the credential starts being valid,
  /// if present.
  int? get notBefore {
    final nbf = issuerClaims['nbf'];
    return nbf is int ? nbf : null;
  }

  /// Whether `nbf` is still in the future relative to the system clock.
  bool get isNotYetValid => isNotYetValidAt(systemClock());

  /// Whether [nowEpochSeconds] is before `nbf`. Returns `false` when there is no
  /// `nbf`.
  bool isNotYetValidAt(int nowEpochSeconds) {
    final nbf = issuerClaims['nbf'];
    return nbf is int && nowEpochSeconds < nbf;
  }

  /// Whether the credential is inside its validity window now (`nbf` reached and
  /// `exp` not passed). Credentials with neither bound are always valid.
  bool get isValid => isValidAt(systemClock());

  /// Whether [nowEpochSeconds] is inside the credential's `nbf`..`exp` window.
  bool isValidAt(int nowEpochSeconds) =>
      !isExpiredAt(nowEpochSeconds) && !isNotYetValidAt(nowEpochSeconds);

  /// Reconstitutes the full claim set: registered claims plus every value that
  /// the carried disclosures reveal, with the `_sd` / `_sd_alg` / `{"...": …}`
  /// machinery removed. This is what a wallet shows the user.
  Map<String, dynamic> resolveClaims() =>
      _resolveObject(issuerClaims, _byDigest(), <String>{}, 0);

  /// Indexes the carried disclosures by their digest, rejecting two disclosures
  /// that hash to the same digest. `_hash` is read only when there is something
  /// to digest, so a credential with no disclosures never trips on an exotic
  /// `_sd_alg`.
  Map<String, Disclosure> _byDigest() {
    final byDigest = <String, Disclosure>{};
    if (disclosures.isNotEmpty) {
      final hash = _hash;
      for (final disclosure in disclosures) {
        final digest = disclosure.digest(hash);
        if (byDigest.containsKey(digest)) {
          throw const SdJwtError('Two disclosures share the same digest');
        }
        byDigest[digest] = disclosure;
      }
    }
    return byDigest;
  }

  /// Verifies the issuer signature, resolving the key per [trust].
  ///
  /// Returns whether the signature is valid. Throws [SdJwtError] when the header
  /// carries the wrong `alg`/`typ`, or when the key itself cannot be resolved
  /// (no `x5c`, unreachable metadata, malformed key) — a different condition
  /// from "key found, signature does not match".
  ///
  /// With [enforceValidity] set, a signature-valid credential that is outside
  /// its `nbf`..`exp` window at [now] also returns `false` — so a single call
  /// answers "is this a currently-trustworthy issuer signature?". The
  /// [isExpired] / [isNotYetValid] getters let a caller tell the two apart.
  Future<bool> verifyIssuer(
    IssuerTrust trust, {
    Oid4vcHttp? http,
    bool enforceValidity = false,
    Clock now = systemClock,
  }) async {
    final signatureValid = await verifyIssuerSignature(
      header: header,
      signingInput: _signingInput,
      signature: _signature,
      iss: issuerClaims['iss'],
      trust: trust,
      allowedTypes: _sdJwtVcTypes,
      http: http,
      now: now,
    );
    if (!signatureValid) return false;
    if (enforceValidity && !isValidAt(now())) return false;
    return true;
  }

  /// Builds a presentation of this credential: discloses the chosen claims,
  /// computes `sd_hash`, signs a KB-JWT bound to [audience]/[nonce], and returns
  /// `<issuer-JWT>~<chosen disclosures>~<KB-JWT>`.
  ///
  /// Two ways to choose what to reveal, unioned:
  /// - [disclose] — top-level object-property names (the flat-credential case).
  /// - [disclosePaths] — full DCQL claim paths (`["address","street"]`,
  ///   `[1]`, or `[null]` for every array element), which also pulls in the
  ///   parent disclosures a nested claim needs to resolve.
  ///
  /// [now] supplies the KB-JWT `iat`.
  Future<String> present({
    Set<String> disclose = const {},
    Set<List<Object?>> disclosePaths = const {},
    required String audience,
    required String nonce,
    required Es256Signer signer,
    Clock now = systemClock,
  }) async {
    final prefix = StringBuffer('$issuerJwt~');
    for (final disclosure in _selectDisclosures(disclose, disclosePaths)) {
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

  /// The disclosures to include for [disclose] (top-level names) ∪
  /// [disclosePaths] (full paths, with each match's ancestor chain), emitted in
  /// the credential's original disclosure order.
  List<Disclosure> _selectDisclosures(
    Set<String> disclose,
    Set<List<Object?>> disclosePaths,
  ) {
    final include = <Disclosure>{};
    // Name-based: any object-property disclosure with a requested name, at any
    // depth — this is the flat / "reveal whole" behaviour.
    for (final disclosure in disclosures) {
      if (disclosure.name != null && disclose.contains(disclosure.name)) {
        include.add(disclosure);
      }
    }
    // Path-based: each site whose path a request matches, plus the ancestor
    // disclosures that path depends on to resolve.
    if (disclosePaths.isNotEmpty) {
      for (final site in _disclosureSites()) {
        if (disclosePaths.any((path) => _pathMatches(path, site.path))) {
          include.addAll(site.chain);
        }
      }
    }
    return disclosures.where(include.contains).toList();
  }

  /// Walks the issuer claims and records, for every disclosure, the path it
  /// sits at and the chain of disclosures that must be revealed to reach it.
  List<_DisclosureSite> _disclosureSites() {
    final byDigest = _byDigest();
    final sites = <_DisclosureSite>[];

    void walk(
      dynamic node,
      List<Object?> path,
      List<Disclosure> chain,
      int depth,
    ) {
      if (depth > _maxResolveDepth) {
        throw const SdJwtError('Credential nesting exceeds the depth limit');
      }
      if (node is Map<String, dynamic>) {
        node.forEach((key, value) {
          if (key == '_sd') {
            if (value is! List) return;
            for (final digest in value) {
              if (digest is! String) continue;
              final disclosure = byDigest[digest];
              if (disclosure == null || disclosure.name == null) continue;
              final childPath = [...path, disclosure.name];
              final childChain = [...chain, disclosure];
              sites.add(_DisclosureSite(childPath, childChain));
              walk(disclosure.value, childPath, childChain, depth + 1);
            }
          } else if (key != '_sd_alg') {
            walk(value, [...path, key], chain, depth + 1);
          }
        });
      } else if (node is List) {
        for (var i = 0; i < node.length; i++) {
          final element = node[i];
          if (element is Map<String, dynamic> &&
              element.length == 1 &&
              element['...'] is String) {
            final disclosure = byDigest[element['...']];
            if (disclosure == null || disclosure.name != null) continue;
            final childPath = [...path, i];
            final childChain = [...chain, disclosure];
            sites.add(_DisclosureSite(childPath, childChain));
            walk(disclosure.value, childPath, childChain, depth + 1);
          } else {
            walk(element, [...path, i], chain, depth + 1);
          }
        }
      }
    }

    walk(issuerClaims, const [], const [], 0);
    return sites;
  }

  /// Whether the DCQL [requested] path selects the disclosure at [sitePath]. A
  /// `null` element is the DCQL "all array elements" wildcard, matching any int
  /// index; everything else must match exactly.
  static bool _pathMatches(List<Object?> requested, List<Object?> sitePath) {
    if (requested.length != sitePath.length) return false;
    for (var i = 0; i < requested.length; i++) {
      final want = requested[i];
      if (want == null) {
        if (sitePath[i] is! int) return false;
      } else if (want != sitePath[i]) {
        return false;
      }
    }
    return true;
  }

  // --- internals -----------------------------------------------------------

  Hash get _hash => _hashForAlg(issuerClaims['_sd_alg']);

  static Hash _hashForAlg(Object? alg) => switch (alg) {
        null || 'sha-256' => sha256,
        'sha-384' => sha384,
        'sha-512' => sha512,
        _ => throw SdJwtError('Unsupported _sd_alg: $alg'),
      };

  /// Resolves an object level, splicing in the disclosures whose digests appear
  /// in its `_sd`. [consumed] tracks every digest already spliced anywhere in
  /// the credential, so a digest reused twice (a disclosure-substitution trick)
  /// is rejected; a disclosed name that collides with a claim already at this
  /// level is rejected too. Both are SD-JWT processing rules.
  Map<String, dynamic> _resolveObject(
    Map<String, dynamic> object,
    Map<String, Disclosure> byDigest,
    Set<String> consumed,
    int depth,
  ) {
    final out = <String, dynamic>{};
    object.forEach((key, value) {
      if (key == '_sd' || key == '_sd_alg') return;
      out[key] = _resolveValue(value, byDigest, consumed, depth + 1);
    });

    final sd = object['_sd'];
    if (sd is List) {
      for (final digest in sd) {
        if (digest is! String) continue;
        final disclosure = byDigest[digest];
        if (disclosure == null || disclosure.name == null) continue;
        _consume(digest, consumed);
        final name = disclosure.name!;
        if (out.containsKey(name)) {
          throw SdJwtError('Disclosed claim "$name" collides with a clear one');
        }
        out[name] =
            _resolveValue(disclosure.value, byDigest, consumed, depth + 1);
      }
    }
    return out;
  }

  List<dynamic> _resolveArray(
    List<dynamic> array,
    Map<String, Disclosure> byDigest,
    Set<String> consumed,
    int depth,
  ) {
    final out = <dynamic>[];
    for (final element in array) {
      if (element is Map<String, dynamic> &&
          element.length == 1 &&
          element['...'] is String) {
        final digest = element['...'] as String;
        final disclosure = byDigest[digest];
        if (disclosure != null && disclosure.name == null) {
          _consume(digest, consumed);
          out.add(
            _resolveValue(disclosure.value, byDigest, consumed, depth + 1),
          );
        }
        // An undisclosed array element is simply omitted.
      } else {
        out.add(_resolveValue(element, byDigest, consumed, depth + 1));
      }
    }
    return out;
  }

  dynamic _resolveValue(
    dynamic value,
    Map<String, Disclosure> byDigest,
    Set<String> consumed,
    int depth,
  ) {
    if (depth > _maxResolveDepth) {
      throw const SdJwtError('Credential nesting exceeds the depth limit');
    }
    if (value is Map<String, dynamic>) {
      return _resolveObject(value, byDigest, consumed, depth);
    }
    if (value is List) return _resolveArray(value, byDigest, consumed, depth);
    return value;
  }

  void _consume(String digest, Set<String> consumed) {
    if (!consumed.add(digest)) {
      throw const SdJwtError(
        'A disclosure digest is referenced more than once',
      );
    }
  }
}

/// Where one disclosure sits in the credential: its [path] (object keys and
/// array indices from the root) and the [chain] of disclosures — itself plus
/// every ancestor disclosure — that must be revealed together to expose it.
class _DisclosureSite {
  _DisclosureSite(this.path, this.chain);

  final List<Object?> path;
  final List<Disclosure> chain;
}
