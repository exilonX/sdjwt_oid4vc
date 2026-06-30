import 'package:archive/archive.dart';

import '../core/b64u.dart';
import '../core/errors.dart';
import '../core/http.dart';
import '../core/jws.dart';
import '../core/net.dart';
import 'issuer_trust.dart';
import 'issuer_verifier.dart';

/// A reference to a credential's entry in a Token Status List (IETF
/// `draft-ietf-oauth-status-list`): the [uri] of the status list token and the
/// [index] of this credential within it.
class StatusListRef {
  const StatusListRef({required this.uri, required this.index});

  /// Reads `status.status_list.{uri, idx}` from a credential's claims, or
  /// returns `null` when there is no usable status list reference.
  static StatusListRef? fromClaims(Map<String, dynamic> claims) {
    final status = claims['status'];
    if (status is! Map) return null;
    final statusList = status['status_list'];
    if (statusList is! Map) return null;
    final uri = statusList['uri'];
    final index = statusList['idx'];
    if (uri is! String || index is! int) return null;
    final parsed = Uri.tryParse(uri);
    if (parsed == null || !parsed.isAbsolute) return null;
    return StatusListRef(uri: parsed, index: index);
  }

  /// Where the status list token is published.
  final Uri uri;

  /// This credential's position in the status list.
  final int index;
}

/// The four status values the Token Status List spec defines; anything else is
/// issuer-defined ("application specific").
enum CredentialStatusKind { valid, invalid, suspended, applicationSpecific }

/// The resolved status of one credential.
class CredentialStatus {
  const CredentialStatus(this.value);

  /// The raw status value read from the list (0 = valid, 1 = invalid/revoked,
  /// 2 = suspended, 3+ = application specific).
  final int value;

  /// The well-known meaning of [value].
  CredentialStatusKind get kind => switch (value) {
        0 => CredentialStatusKind.valid,
        1 => CredentialStatusKind.invalid,
        2 => CredentialStatusKind.suspended,
        _ => CredentialStatusKind.applicationSpecific,
      };

  /// Whether the credential is still valid (status 0).
  bool get isValid => value == 0;

  @override
  String toString() => 'CredentialStatus($value, $kind)';
}

/// Resolves a credential's revocation status from its Token Status List.
///
/// Fetches the status list token referenced by a [StatusListRef], optionally
/// verifies its issuer signature (the token is itself an issuer-signed JWT),
/// inflates the compressed bitstring, and reads the credential's status bit(s).
class StatusListResolver {
  StatusListResolver(this._http);

  final Oid4vcHttp _http;

  /// Resolves the status at [ref]. When [trust] is supplied, the status list
  /// token's issuer signature is verified first (and the call fails if it does
  /// not verify); without it, the token is decoded but not authenticated.
  ///
  /// Throws [StatusError] when the token is unreachable, malformed, or the index
  /// is out of range; key-resolution problems surface as [SdJwtError].
  Future<CredentialStatus> resolve(
    StatusListRef ref, {
    IssuerTrust? trust,
  }) async {
    if (!isSecureUrl(ref.uri)) {
      throw StatusError(
        'Refusing to fetch a status list over http: ${ref.uri}',
      );
    }
    final resp = await _http.get(
      ref.uri,
      headers: const {'accept': 'application/statuslist+jwt'},
    );
    if (!resp.ok) {
      throw StatusError('Status list fetch failed (${resp.statusCode})');
    }

    final JwsParts jws;
    try {
      jws = Jws.decompose(resp.body.trim());
    } on FormatException catch (e) {
      throw StatusError('Status list token is not a JWS', cause: e);
    }

    if (trust != null) {
      final ok = await verifyIssuerSignature(
        header: jws.header,
        signingInput: jws.signingInput,
        signature: jws.signature,
        iss: jws.payload['iss'],
        trust: trust,
        allowedTypes: const {'statuslist+jwt'},
        http: _http,
      );
      if (!ok) {
        throw const StatusError('Status list signature did not verify');
      }
    }

    return CredentialStatus(_statusAt(_statusList(jws.payload), ref.index));
  }

  /// Inflates the `status_list.lst` bitstring and returns `(bytes, bits)`.
  ({List<int> bytes, int bits}) _statusList(Map<String, dynamic> payload) {
    final statusList = payload['status_list'];
    if (statusList is! Map) {
      throw const StatusError('Status list token has no status_list');
    }
    final bits = statusList['bits'];
    final lst = statusList['lst'];
    if (bits is! int || lst is! String) {
      throw const StatusError('status_list is missing bits/lst');
    }
    if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
      throw StatusError('Unsupported status_list bits: $bits');
    }
    final List<int> compressed;
    try {
      compressed = b64uDecode(lst);
    } on FormatException catch (e) {
      throw StatusError('status_list lst is not base64url', cause: e);
    }
    try {
      return (bytes: const ZLibDecoder().decodeBytes(compressed), bits: bits);
    } on FormatException catch (e) {
      throw StatusError('status_list lst could not be inflated', cause: e);
    }
  }

  int _statusAt(({List<int> bytes, int bits}) list, int index) {
    final statusesPerByte = 8 ~/ list.bits;
    final byteIndex = index ~/ statusesPerByte;
    if (index < 0 || byteIndex >= list.bytes.length) {
      throw StatusError('Status index $index is out of range');
    }
    // Statuses are packed least-significant-bit first within each byte.
    final shift = (index % statusesPerByte) * list.bits;
    final mask = (1 << list.bits) - 1;
    return (list.bytes[byteIndex] >> shift) & mask;
  }
}
