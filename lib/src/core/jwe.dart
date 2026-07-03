import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart'; // also re-exports ECDHBasicAgreement
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import 'b64u.dart';
import 'ec.dart';

/// Compact-JWE encryption for OpenID4VP `direct_post.jwt` responses.
///
/// Only the one shape the EUDI reference verifier (and OpenID4VP 1.0 Final's
/// privacy default) uses: **`alg: ECDH-ES`** (direct key agreement, no key-wrap)
/// with **AES-GCM** content encryption. This is the single place in the library
/// that *generates* a key — an ephemeral P-256 keypair per response — so it is
/// kept isolated and unexported, like `ec.dart`.
///
/// Not exported.

/// AES-GCM content-encryption algorithms and their key sizes (bits).
const Map<String, int> _encKeyBits = {'A128GCM': 128, 'A256GCM': 256};

/// Encrypts [plaintext] into a compact JWE for [recipientJwk] using ECDH-ES
/// (direct) key agreement + AES-GCM ([enc] = `A128GCM` or `A256GCM`).
///
/// Writes `epk` (the ephemeral public JWK), `kid` (the recipient key id, when
/// given) and `apv` (already `base64url(nonce)`) into the protected header;
/// `apu` is omitted. The encrypted-key segment is empty (direct: the Concat-KDF
/// output *is* the CEK). Pass a seeded [random] for reproducible output in tests.
///
/// Throws [FormatException] if [enc] is unsupported or [recipientJwk] is not a
/// usable P-256 key.
String encryptCompactJweEcdhEs({
  required Map<String, dynamic> recipientJwk,
  required String enc,
  required String? kid,
  required List<int> plaintext,
  required String apv,
  Random? random,
}) {
  final keyBits = _encKeyBits[enc];
  if (keyBits == null) {
    throw FormatException('Unsupported JWE enc: $enc');
  }
  final recipient = ecPublicKeyFromJwk(recipientJwk); // FormatException if bad
  final rnd = random ?? Random.secure();

  // 1. Ephemeral P-256 keypair; its public point becomes `epk`.
  final pair = _generateEphemeral(rnd);
  final ephemeralPrivate = pair.privateKey as ECPrivateKey;
  final ephemeralPublic = pair.publicKey as ECPublicKey;

  // 2. ECDH agreement -> Z (the shared X coordinate), fixed 32 bytes.
  final agreement = ECDHBasicAgreement()..init(ephemeralPrivate);
  final z = _be32(agreement.calculateAgreement(recipient));

  // 3. Concat-KDF -> CEK. For ECDH-ES direct the AlgorithmID is `enc`.
  final cek = concatKdf(
    sharedSecret: z,
    keyBits: keyBits,
    algorithmId: enc,
    apu: const [], // apu omitted for a non-mdoc response
    apv: b64uDecode(apv), // raw nonce bytes (== what apv base64url-encodes)
  );

  // 4. Protected header.
  final header = <String, dynamic>{
    'alg': 'ECDH-ES',
    'enc': enc,
    if (kid != null) 'kid': kid,
    'epk': {
      'kty': 'EC',
      'crv': 'P-256',
      'x': b64uEncode(_be32(ephemeralPublic.Q!.x!.toBigInteger()!)),
      'y': b64uEncode(_be32(ephemeralPublic.Q!.y!.toBigInteger()!)),
    },
    'apv': apv,
  };
  final encodedHeader = b64uEncode(utf8.encode(jsonEncode(header)));

  // 5. AES-GCM: 96-bit IV, 128-bit tag, AAD = ASCII(base64url(header)).
  final iv = _randomBytes(rnd, 12);
  final gcm = GCMBlockCipher(AESEngine())
    ..init(
      true,
      AEADParameters(
        KeyParameter(cek),
        128,
        iv,
        Uint8List.fromList(ascii.encode(encodedHeader)),
      ),
    );
  final out = gcm.process(Uint8List.fromList(plaintext));
  final ciphertext = out.sublist(0, out.length - 16);
  final tag = out.sublist(out.length - 16);

  // 6. Compact assembly, with an empty encrypted-key segment.
  return '$encodedHeader..${b64uEncode(iv)}'
      '.${b64uEncode(ciphertext)}.${b64uEncode(tag)}';
}

/// Concat-KDF (NIST SP 800-56A single-pass, RFC 7518 §4.6.2) deriving a
/// [keyBits]-bit key from [sharedSecret].
///
/// A single SHA-256 pass covers `keyBits` up to 256. [algorithmId] is the
/// `AlgorithmID` OtherInfo field (the `enc` value for ECDH-ES direct); [apu] and
/// [apv] are the PartyUInfo/PartyVInfo bytes. Public for the RFC 7518 Appendix C
/// known-answer test.
Uint8List concatKdf({
  required Uint8List sharedSecret,
  required int keyBits,
  required String algorithmId,
  required List<int> apu,
  required List<int> apv,
}) {
  final input = BytesBuilder()
    ..add(_uint32be(1)) // round counter
    ..add(sharedSecret)
    ..add(_lengthPrefixed(ascii.encode(algorithmId))) // AlgorithmID
    ..add(_lengthPrefixed(apu)) // PartyUInfo
    ..add(_lengthPrefixed(apv)) // PartyVInfo
    ..add(_uint32be(keyBits)); // SuppPubInfo (keydatalen); SuppPrivInfo empty
  final digest = SHA256Digest().process(input.toBytes());
  return Uint8List.fromList(digest.sublist(0, keyBits ~/ 8));
}

AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeral(Random random) {
  final seed = Uint8List.fromList(
    List<int>.generate(32, (_) => random.nextInt(256)),
  );
  final generator = ECKeyGenerator()
    ..init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(p256),
        FortunaRandom()..seed(KeyParameter(seed)),
      ),
    );
  return generator.generateKeyPair();
}

Uint8List _randomBytes(Random random, int length) =>
    Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));

Uint8List _lengthPrefixed(List<int> data) => Uint8List.fromList(
      [..._uint32be(data.length), ...data],
    );

Uint8List _uint32be(int value) => Uint8List(4)
  ..[0] = (value >> 24) & 0xff
  ..[1] = (value >> 16) & 0xff
  ..[2] = (value >> 8) & 0xff
  ..[3] = value & 0xff;

/// Big-endian, fixed 32-byte encoding of a P-256 scalar/coordinate.
Uint8List _be32(BigInt value) {
  final out = Uint8List(32);
  final mask = BigInt.from(0xff);
  var x = value;
  for (var i = 31; i >= 0; i--) {
    out[i] = (x & mask).toInt();
    x >>= 8;
  }
  return out;
}
