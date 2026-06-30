import '../core/errors.dart';

/// A Digital Credentials Query Language (DCQL) query — the modern OpenID4VP way
/// a verifier states *which* credentials and *which* claims it wants.
class DcqlQuery {
  const DcqlQuery(this.credentials, {this.credentialSets = const []});

  /// Parses the `dcql_query` object. Throws [PresentationError] if there is no
  /// `credentials` array.
  factory DcqlQuery.fromJson(Map<String, dynamic> json) {
    final credentials = json['credentials'];
    if (credentials is! List) {
      throw const PresentationError('dcql_query has no credentials array');
    }
    final sets = json['credential_sets'];
    return DcqlQuery(
      credentials
          .whereType<Map<String, dynamic>>()
          .map(DcqlCredentialQuery.fromJson)
          .toList(growable: false),
      credentialSets: sets is List
          ? sets
              .whereType<Map<String, dynamic>>()
              .map(DcqlCredentialSet.fromJson)
              .toList(growable: false)
          : const [],
    );
  }

  /// One entry per credential the verifier is asking for.
  final List<DcqlCredentialQuery> credentials;

  /// Optional `credential_sets` — combinations and alternatives over
  /// [credentials]. Empty means "every credential listed is required".
  final List<DcqlCredentialSet> credentialSets;
}

/// One `credential_sets` entry: a set of acceptable [options], each option a
/// combination of [DcqlCredentialQuery.id]s that together satisfy the set
/// (e.g. "a PID, OR (a driving licence AND an age credential)").
class DcqlCredentialSet {
  const DcqlCredentialSet({required this.options, this.required = true});

  factory DcqlCredentialSet.fromJson(Map<String, dynamic> json) {
    final options = json['options'];
    final required = json['required'];
    return DcqlCredentialSet(
      options: options is List
          ? options
              .whereType<List<dynamic>>()
              .map((o) => o.whereType<String>().toList(growable: false))
              .toList(growable: false)
          : const [],
      required: required is bool ? required : true,
    );
  }

  /// Each option is a list of credential-query ids; satisfying *all* of them in
  /// any one option satisfies the set.
  final List<List<String>> options;

  /// Whether this set must be satisfied. Defaults to `true` per the spec.
  final bool required;
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
