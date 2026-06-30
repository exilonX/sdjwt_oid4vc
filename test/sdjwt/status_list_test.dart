import 'dart:math';

import 'package:archive/archive.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';
import '../support/fake_http.dart';

const _statusUri = 'https://status.example/1';

/// Packs [statuses] into a byte array, [bits] per entry, least-significant-bit
/// first — the layout the Token Status List spec defines.
List<int> _pack(List<int> statuses, int bits) {
  final perByte = 8 ~/ bits;
  final bytes = List<int>.filled((statuses.length + perByte - 1) ~/ perByte, 0);
  for (var i = 0; i < statuses.length; i++) {
    final shift = (i % perByte) * bits;
    bytes[i ~/ perByte] |= (statuses[i] & ((1 << bits) - 1)) << shift;
  }
  return bytes;
}

/// Signs an arbitrary JWT payload as [issuer].
Future<String> _signJwt(
  SoftwareEs256Signer issuer,
  Map<String, dynamic> payload, {
  String typ = 'statuslist+jwt',
  List<String>? x5c,
}) async {
  final header = {'alg': 'ES256', 'typ': typ, if (x5c != null) 'x5c': x5c};
  final signingInput = Jws.signingInput(header, payload);
  return '$signingInput.${await issuer.signEs256(signingInput)}';
}

/// A signed status list token whose bitstring encodes [statuses].
Future<String> _statusToken(
  SoftwareEs256Signer issuer, {
  required int bits,
  required List<int> statuses,
  List<String>? x5c,
}) =>
    _signJwt(
      issuer,
      {
        'iss': 'https://status.example',
        'sub': _statusUri,
        'iat': 1,
        'status_list': {
          'bits': bits,
          'lst': b64uEncode(const ZLibEncoder().encode(_pack(statuses, bits))),
        },
      },
      x5c: x5c,
    );

StatusListRef _ref(int index) =>
    StatusListRef(uri: Uri.parse(_statusUri), index: index);

StatusListResolver _resolverFor(String body, {int status = 200}) =>
    StatusListResolver(FakeOid4vcHttp((_) => HttpResp(status, body)));

void main() {
  final issuer = SoftwareEs256Signer.generate(random: Random(300));
  final leaf = buildX5cLeafFromJwk(issuer.publicJwkSync());

  group('resolve', () {
    test('reads a 1-bit list and verifies the issuer signature', () async {
      final token = await _statusToken(
        issuer,
        bits: 1,
        statuses: [0, 1, 0, 1],
        x5c: [leaf],
      );
      final resolver = _resolverFor(token);

      final valid =
          await resolver.resolve(_ref(0), trust: IssuerTrust.signatureOnly());
      expect(valid.isValid, isTrue);
      expect(valid.kind, CredentialStatusKind.valid);

      final revoked =
          await resolver.resolve(_ref(1), trust: IssuerTrust.signatureOnly());
      expect(revoked.isValid, isFalse);
      expect(revoked.kind, CredentialStatusKind.invalid);
    });

    test('decodes without trust when no verification is asked for', () async {
      final token = await _statusToken(issuer, bits: 1, statuses: [0, 1]);
      final status = await _resolverFor(token).resolve(_ref(1));
      expect(status.value, 1);
      expect(status.toString(), contains('invalid'));
    });

    test('reads a 2-bit list across all four status kinds', () async {
      final token = await _statusToken(issuer, bits: 2, statuses: [0, 1, 2, 3]);
      final resolver = _resolverFor(token);
      expect(
        (await resolver.resolve(_ref(0))).kind,
        CredentialStatusKind.valid,
      );
      expect(
        (await resolver.resolve(_ref(1))).kind,
        CredentialStatusKind.invalid,
      );
      expect(
        (await resolver.resolve(_ref(2))).kind,
        CredentialStatusKind.suspended,
      );
      expect(
        (await resolver.resolve(_ref(3))).kind,
        CredentialStatusKind.applicationSpecific,
      );
    });

    test('fails when the signature does not verify under trust', () async {
      final other = SoftwareEs256Signer.generate(random: Random(301));
      final token = await _statusToken(
        issuer,
        bits: 1,
        statuses: [0, 1],
        x5c: [buildX5cLeafFromJwk(other.publicJwkSync())],
      );
      expect(
        () => _resolverFor(token)
            .resolve(_ref(0), trust: IssuerTrust.signatureOnly()),
        throwsA(isA<StatusError>()),
      );
    });
  });

  group('resolve error edges', () {
    test('refuses an http status list URL', () {
      expect(
        () => StatusListResolver(FakeOid4vcHttp((_) => HttpResp(404, '')))
            .resolve(StatusListRef(uri: Uri.parse('http://s/1'), index: 0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when the fetch fails', () {
      expect(
        () => _resolverFor('down', status: 503).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when the body is not a JWS', () {
      expect(
        () => _resolverFor('garbage').resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when status_list is missing or malformed', () async {
      final noList = await _signJwt(issuer, {'iss': 'x'});
      expect(
        () => _resolverFor(noList).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );

      final badFields = await _signJwt(issuer, {
        'status_list': {'bits': 'one', 'lst': 'AA'},
      });
      expect(
        () => _resolverFor(badFields).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws on unsupported bits', () async {
      final token = await _statusToken(issuer, bits: 3, statuses: [0, 1]);
      expect(
        () => _resolverFor(token).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when lst is not base64url', () async {
      final token = await _signJwt(issuer, {
        'status_list': {
          'bits': 1,
          'lst': 'A',
        }, // length 1: impossible base64url
      });
      expect(
        () => _resolverFor(token).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when lst is not valid zlib', () async {
      final token = await _signJwt(issuer, {
        'status_list': {
          'bits': 1,
          'lst': b64uEncode([0, 1, 2, 3]),
        },
      });
      expect(
        () => _resolverFor(token).resolve(_ref(0)),
        throwsA(isA<StatusError>()),
      );
    });

    test('throws when the index is out of range', () async {
      final token = await _statusToken(issuer, bits: 1, statuses: [0]);
      final resolver = _resolverFor(token);
      expect(() => resolver.resolve(_ref(100)), throwsA(isA<StatusError>()));
      expect(() => resolver.resolve(_ref(-1)), throwsA(isA<StatusError>()));
    });
  });

  group('SdJwtVc.statusListRef', () {
    Future<SdJwtVc> issued(Map<String, dynamic> status) async => SdJwt.parse(
          await SdJwt.issue(
            claims: {'iss': 'https://i', 'vct': 'v', 'status': status},
            header: const {},
            selectivelyDisclosable: const {},
            signer: issuer,
          ),
        );

    test('parses uri + idx', () async {
      final vc = await issued({
        'status_list': {'uri': _statusUri, 'idx': 5},
      });
      expect(vc.statusListRef!.uri, Uri.parse(_statusUri));
      expect(vc.statusListRef!.index, 5);
    });

    test('is null when absent or malformed', () async {
      final none = SdJwt.parse(
        await SdJwt.issue(
          claims: const {'iss': 'https://i', 'vct': 'v'},
          header: const {},
          selectivelyDisclosable: const {},
          signer: issuer,
        ),
      );
      expect(none.statusListRef, isNull);

      expect((await issued({'status_list': 'nope'})).statusListRef, isNull);
      expect(
        (await issued({
          'status_list': {'uri': _statusUri}, // no idx
        }))
            .statusListRef,
        isNull,
      );
      expect(
        (await issued({
          'status_list': {'uri': 'relative', 'idx': 1}, // not absolute
        }))
            .statusListRef,
        isNull,
      );
    });
  });
}
