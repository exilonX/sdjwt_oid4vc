import '../core/errors.dart';

/// A Digital Credentials Query Language (DCQL) query — the modern OpenID4VP way
/// a verifier states *which* credentials and *which* claims it wants.
class DcqlQuery {
  const DcqlQuery(this.credentials);

  /// Parses the `dcql_query` object. Throws [PresentationError] if there is no
  /// `credentials` array.
  factory DcqlQuery.fromJson(Map<String, dynamic> json) {
    final credentials = json['credentials'];
    if (credentials is! List) {
      throw const PresentationError('dcql_query has no credentials array');
    }
    return DcqlQuery(
      credentials
          .whereType<Map<String, dynamic>>()
          .map(DcqlCredentialQuery.fromJson)
          .toList(growable: false),
    );
  }

  /// One entry per credential the verifier is asking for.
  final List<DcqlCredentialQuery> credentials;
}

/// One requested credential within a [DcqlQuery].
class DcqlCredentialQuery {
  const DcqlCredentialQuery({
    required this.id,
    required this.format,
    required this.vctValues,
    required this.claims,
  });

  factory DcqlCredentialQuery.fromJson(Map<String, dynamic> json) {
    final id = json['id'];
    final format = json['format'];

    var vctValues = const <String>[];
    final meta = json['meta'];
    if (meta is Map) {
      final values = meta['vct_values'];
      if (values is List) {
        vctValues = values.whereType<String>().toList(growable: false);
      }
    }

    final claims = json['claims'];
    return DcqlCredentialQuery(
      id: id is String ? id : '',
      format: format is String ? format : null,
      vctValues: vctValues,
      claims: claims is List
          ? claims
              .whereType<Map<String, dynamic>>()
              .map(DcqlClaim.fromJson)
              .toList(growable: false)
          : const <DcqlClaim>[],
    );
  }

  /// The query identifier (echoed in the response mapping).
  final String id;

  /// Requested credential format (e.g. `dc+sd-jwt`), or `null` if unconstrained.
  final String? format;

  /// Acceptable `vct` values (`meta.vct_values`); empty means unconstrained.
  final List<String> vctValues;

  /// Requested claims. Empty means "the whole credential".
  final List<DcqlClaim> claims;

  /// The top-level claim names this query asks for (single-segment string
  /// paths). Multi-segment / array paths are out of scope for the flat
  /// credentials this wallet handles and are skipped.
  List<String> get claimNames =>
      claims.map((c) => c.name).whereType<String>().toList(growable: false);
}

/// A single claim path within a [DcqlCredentialQuery].
class DcqlClaim {
  const DcqlClaim(this.path);

  factory DcqlClaim.fromJson(Map<String, dynamic> json) {
    final path = json['path'];
    return DcqlClaim(
      path is List ? List<Object?>.from(path) : const <Object?>[],
    );
  }

  /// The claim path: strings select object members, ints select array indices,
  /// `null` selects all array elements.
  final List<Object?> path;

  /// The claim name when this is a single-segment object path, else `null`.
  String? get name =>
      path.length == 1 && path.first is String ? path.first as String : null;
}
