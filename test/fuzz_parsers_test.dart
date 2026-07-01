import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import 'support/fake_http.dart';

/// Property/fuzz tests for the parsers that sit on attacker-controlled input
/// (credentials, disclosures, offers, request objects, status tokens).
///
/// The security-relevant invariant is **"no unexpected crash"**: on *any* input,
/// a parser may reject it by throwing a declared [Exception] ([Oid4vcError] or
/// [FormatException]), but it must never throw a Dart [Error] — a `RangeError`,
/// `StateError`, `TypeError`, `NoSuchMethodError`, etc. is an unhandled crash on
/// hostile input, i.e. a bug. The generators are seeded, so any failure prints a
/// reproducing input and the suite stays deterministic.
void main() {
  /// Runs [body] and fails only if it throws a Dart [Error] (a crash). Declared
  /// [Exception]s are the parser correctly rejecting the input.
  Future<void> onlyRejects(String input, FutureOr<void> Function() body) async {
    try {
      await body();
    } on Object catch (e) {
      if (e is Error) {
        fail('crash (${e.runtimeType}) on input <<<$input>>>\n$e');
      }
      // An Exception here is the parser rejecting bad input — that's fine.
    }
  }

  // ---- generators -----------------------------------------------------------

  /// A random byte-ish string: printable ASCII, JSON/JWT punctuation, and the
  /// odd control/high char, so we hit delimiter and decoder edge cases.
  String randomJunk(Random r) {
    const alphabet = 'abcXYZ0139 .~-_={}[]":,/\\+\n\t\u00e9\u00ff\u0100'
        'eyJ0'; // JWT-ish opener; ASCII-only source

    final len = r.nextInt(60);
    return String.fromCharCodes(
      List.generate(len, (_) {
        // Sometimes a fully random code unit, usually an alphabet pick.
        return r.nextBool()
            ? alphabet.codeUnitAt(r.nextInt(alphabet.length))
            : r.nextInt(0x2FF);
      }),
    );
  }

  /// A random JSON value up to a small depth (strings, numbers, bools, null,
  /// nested lists/maps).
  Object? randomJson(Random r, int depth) {
    switch (r.nextInt(depth <= 0 ? 4 : 6)) {
      case 0:
        return randomJunk(r);
      case 1:
        return r.nextInt(1 << 30) - (1 << 29);
      case 2:
        return r.nextBool();
      case 3:
        return null;
      case 4:
        return List.generate(r.nextInt(4), (_) => randomJson(r, depth - 1));
      default:
        return {
          for (var i = 0; i < r.nextInt(4); i++)
            'k${r.nextInt(1000)}': randomJson(r, depth - 1),
        };
    }
  }

  String b64uJson(Object? value) => b64uEncodeString(jsonEncode(value));

  /// A syntactically valid disclosure for a random (name, value).
  String randomDisclosure(Random r) {
    final salt = 'salt${r.nextInt(1 << 30)}';
    final value = randomJson(r, 2);
    return r.nextBool()
        ? b64uJson([salt, 'k${r.nextInt(1000)}', value]) // object property
        : b64uJson([salt, value]); // array element
  }

  /// A compact SD-JWT with an arbitrary (unsigned) issuer JWT, a random set of
  /// `_sd` digests, random disclosures, and maybe a trailing KB-JWT slot. The
  /// signature is never checked by `parse`, so this reaches the resolve logic
  /// (depth limit, duplicate digests, name collisions) with hostile shapes.
  String randomCompact(Random r) {
    final header = <String, Object?>{
      'alg': r.nextBool() ? 'ES256' : randomJunk(r),
      'typ': r.nextBool() ? 'dc+sd-jwt' : randomJunk(r),
    };
    final sdDigests = List.generate(r.nextInt(6), (_) {
      // Half real disclosure digests, half noise the resolver can't match.
      return r.nextBool()
          ? b64uEncode(sha256.convert(utf8.encode(randomDisclosure(r))).bytes)
          : randomJunk(r);
    });
    final payload = <String, Object?>{
      'iss': 'https://issuer.example',
      'vct': 'https://vct.example/type',
      if (r.nextBool()) '_sd_alg': r.nextBool() ? 'sha-256' : randomJunk(r),
      if (sdDigests.isNotEmpty) '_sd': sdDigests,
      'claim': randomJson(r, 3),
    };
    final jwt = '${Jws.signingInput(header, payload)}.${b64uJson('sig')}';
    final parts = <String>[
      jwt,
      for (var i = 0; i < r.nextInt(6); i++) randomDisclosure(r),
    ];
    final compact = parts.join('~');
    return r.nextBool() ? '$compact~' : compact; // optional trailing tilde/KB
  }

  const iterations = 400;

  group('malformed input never crashes (throws Error)', () {
    test('Disclosure.parse', () async {
      final r = Random(1);
      for (var i = 0; i < iterations; i++) {
        final input = r.nextBool() ? randomJunk(r) : b64uJson(randomJson(r, 2));
        await onlyRejects(input, () => Disclosure.parse(input));
      }
    });

    test('b64uDecode', () async {
      final r = Random(2);
      for (var i = 0; i < iterations; i++) {
        final input = randomJunk(r);
        await onlyRejects(input, () => b64uDecode(input));
      }
    });

    test('Jws.decompose', () async {
      final r = Random(3);
      for (var i = 0; i < iterations; i++) {
        final input = r.nextBool()
            ? randomJunk(r)
            : [randomJunk(r), b64uJson(randomJson(r, 2)), randomJunk(r)]
                .join('.');
        await onlyRejects(input, () => Jws.decompose(input));
      }
    });

    test('SdJwt.parse + resolveClaims', () async {
      final r = Random(4);
      for (var i = 0; i < iterations; i++) {
        final input = r.nextBool() ? randomJunk(r) : randomCompact(r);
        await onlyRejects(input, () {
          final vc = SdJwt.parse(input); // may throw SdJwtError — allowed
          vc.resolveClaims(); // exercise depth/dup/collision guards
        });
      }
    });

    test('Oid4vpClient.parseRequest', () async {
      final r = Random(5);
      final client = Oid4vpClient(FakeOid4vcHttp((_) => HttpResp(404, '')));
      const header = {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'};
      for (var i = 0; i < iterations; i++) {
        final body = randomJson(r, 3);
        final payload = body is Map<String, dynamic> ? body : const {'x': 1};
        final jwt = '${Jws.signingInput(header, payload)}.${b64uJson('sig')}';
        final input = r.nextBool() ? randomJunk(r) : jwt;
        await onlyRejects(input, () => client.parseRequest(input));
      }
    });

    test('Oid4vciClient.parseOffer (no network)', () async {
      final r = Random(6);
      // Answer any fetch (credential_offer_uri path) with junk, so the parser —
      // not the network — is what we are fuzzing.
      final client = Oid4vciClient(
        FakeOid4vcHttp((_) {
          return HttpResp(r.nextBool() ? 200 : 404, randomJunk(r));
        }),
      );
      for (var i = 0; i < iterations; i++) {
        final input = switch (r.nextInt(3)) {
          0 => randomJunk(r),
          1 => jsonEncode(randomJson(r, 3)),
          _ =>
            'openid-credential-offer://?credential_offer=${Uri.encodeComponent(jsonEncode(randomJson(r, 3)))}',
        };
        await onlyRejects(input, () => client.parseOffer(input));
      }
    });
  });

  group('round-trip / invariants', () {
    test('Disclosure.forClaim round-trips salt/name/value', () {
      final r = Random(7);
      for (var i = 0; i < 200; i++) {
        final salt = 'salt${r.nextInt(1 << 32)}';
        final name = 'claim${r.nextInt(10000)}';
        final value = randomJson(r, 3);
        final d = Disclosure.forClaim(salt: salt, name: name, value: value);
        final parsed = Disclosure.parse(d.encoded);
        expect(parsed.salt, salt);
        expect(parsed.name, name);
        expect(parsed.value, value);
        // Digest is a pure function of the encoded bytes.
        expect(parsed.digest(sha256), d.digest(sha256));
      }
    });

    test('SdJwt.issue -> parse -> resolveClaims preserves every claim',
        () async {
      final signer = SoftwareEs256Signer.generate(random: Random(8));
      final r = Random(9);
      for (var i = 0; i < 40; i++) {
        // Flat string claims keep equality checks unambiguous.
        final claims = <String, dynamic>{
          'iss': 'https://issuer.example',
          'vct': 'https://vct.example/type',
          for (var j = 0; j < r.nextInt(8); j++)
            'c${r.nextInt(1000)}': 'v${r.nextInt(1 << 30)}',
        };
        // Disclose a random subset selectively.
        final names = claims.keys.where((k) => k.startsWith('c')).toList();
        final sd = <String>{
          for (final n in names)
            if (r.nextBool()) n,
        };
        final compact = await SdJwt.issue(
          claims: claims,
          header: const {'typ': 'dc+sd-jwt'},
          selectivelyDisclosable: sd,
          signer: signer,
          saltGenerator: () => 'salt${r.nextInt(1 << 32)}',
        );
        final resolved = SdJwt.parse(compact).resolveClaims();
        for (final entry in claims.entries) {
          expect(resolved[entry.key], entry.value, reason: entry.key);
        }
      }
    });
  });
}
