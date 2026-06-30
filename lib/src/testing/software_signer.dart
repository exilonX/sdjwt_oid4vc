import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import '../core/b64u.dart';
import '../core/es256_signer.dart';

/// An in-memory [Es256Signer] for tests and examples — a real P-256 key that
/// produces real, verifiable ES256 signatures, with no hardware involved.
///
/// Signatures are deterministic (RFC 6979) and normalised to low-S, so the
/// same input always yields the same output and third-party verifiers that
/// reject high-S signatures still accept them.
class SoftwareEs256Signer implements Es256Signer {
  SoftwareEs256Signer._(this._private, this._public, this._attestor);

  /// Generates a fresh key. Pass a seeded [random] for reproducible keys, and
  /// [attestor] to exercise the optional [attest] path.
  factory SoftwareEs256Signer.generate({
    Random? random,
    KeyAttestation? Function(String nonce)? attestor,
  }) {
    final entropy = random ?? Random.secure();
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => entropy.nextInt(256)),
    );
    final generator = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(ECCurve_secp256r1()),
          FortunaRandom()..seed(KeyParameter(seed)),
        ),
      );
    final pair = generator.generateKeyPair();
    return SoftwareEs256Signer._(pair.privateKey, pair.publicKey, attestor);
  }

  final ECPrivateKey _private;
  final ECPublicKey _public;
  final KeyAttestation? Function(String nonce)? _attestor;

  @override
  Future<Map<String, dynamic>> publicJwk() async => publicJwkSync();

  /// Synchronous accessor for the public JWK — handy when acting as a test
  /// issuer (e.g. serving a `jwt-vc-issuer` JWK set).
  Map<String, dynamic> publicJwkSync() {
    final q = _public.Q!;
    return {
      'kty': 'EC',
      'crv': 'P-256',
      'x': b64uEncode(_be32(q.x!.toBigInteger()!)),
      'y': b64uEncode(_be32(q.y!.toBigInteger()!)),
    };
  }

  @override
  Future<String> signEs256(String signingInput) async =>
      b64uEncode(signBytes(utf8.encode(signingInput)));

  /// Signs raw [message] bytes with ES256 (low-S), returning the 64-byte `R‖S`.
  /// Useful when acting as a test issuer signing non-JOSE bytes — e.g. an X.509
  /// TBSCertificate when building a chain fixture. [signEs256] is the
  /// JOSE-string variant most callers want.
  Uint8List signBytes(List<int> message) {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(true, PrivateKeyParameter<ECPrivateKey>(_private));
    final signature = signer.generateSignature(
      Uint8List.fromList(message),
    ) as ECSignature;

    final n = _private.parameters!.n;
    final s = signature.s.compareTo(n >> 1) > 0 ? n - signature.s : signature.s;
    return Uint8List.fromList([..._be32(signature.r), ..._be32(s)]);
  }

  @override
  Future<KeyAttestation?> attest(String nonce) async => _attestor?.call(nonce);

  /// Big-endian, fixed 32-byte encoding of a P-256 scalar/coordinate.
  static Uint8List _be32(BigInt value) {
    final out = Uint8List(32);
    final mask = BigInt.from(0xff);
    var x = value;
    for (var i = 31; i >= 0; i--) {
      out[i] = (x & mask).toInt();
      x >>= 8;
    }
    return out;
  }
}
