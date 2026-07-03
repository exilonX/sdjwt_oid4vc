import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:sdjwt_oid4vc/src/core/b64u.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/src/core/jwe.dart';

/// Test-side counterpart of the JWE encrypter: a deterministic recipient EC
/// keypair (the "verifier") and an ECDH-ES/AES-GCM decrypter, used to prove
/// `encryptCompactJweEcdhEs` produces something a real recipient can open.

/// Big-endian, fixed 32-byte encoding of a P-256 coordinate/scalar.
Uint8List be32(BigInt v) {
  final out = Uint8List(32);
  final mask = BigInt.from(0xff);
  var x = v;
  for (var i = 31; i >= 0; i--) {
    out[i] = (x & mask).toInt();
    x >>= 8;
  }
  return out;
}

/// A deterministic recipient EC keypair (from [seed]) plus its public
/// `use:enc` JWK — what a verifier publishes in `client_metadata.jwks`.
({ECPrivateKey private, Map<String, dynamic> jwk}) recipient(
  int seed, {
  String? kid,
}) {
  final rnd = Random(seed);
  final s = Uint8List.fromList(List<int>.generate(32, (_) => rnd.nextInt(256)));
  final gen = ECKeyGenerator()
    ..init(
      ParametersWithRandom(
        ECKeyGeneratorParameters(ECCurve_secp256r1()),
        FortunaRandom()..seed(KeyParameter(s)),
      ),
    );
  // Typed as the generic pair so the downcast is needed (thus warning-free) on
  // both pointycastle 3.9.x (generic) and 4.x (narrowed).
  final AsymmetricKeyPair<PublicKey, PrivateKey> pair = gen.generateKeyPair();
  final priv = pair.privateKey as ECPrivateKey;
  final pub = pair.publicKey as ECPublicKey;
  return (
    private: priv,
    jwk: {
      'kty': 'EC',
      'crv': 'P-256',
      'x': b64uEncode(be32(pub.Q!.x!.toBigInteger()!)),
      'y': b64uEncode(be32(pub.Q!.y!.toBigInteger()!)),
      'alg': 'ECDH-ES',
      'use': 'enc',
      if (kid != null) 'kid': kid,
    },
  );
}

/// Decrypts a compact ECDH-ES (direct) + AES-GCM JWE with [recipientPrivate] —
/// the verifier's side. Returns the recovered plaintext bytes.
List<int> decryptJwe(String compact, ECPrivateKey recipientPrivate) {
  final parts = compact.split('.');
  final header =
      jsonDecode(utf8.decode(b64uDecode(parts[0]))) as Map<String, dynamic>;
  final enc = header['enc'] as String;
  final epk = (header['epk'] as Map).cast<String, dynamic>();
  final apv = header['apv'] as String;

  final agreement = ECDHBasicAgreement()..init(recipientPrivate);
  final z = be32(agreement.calculateAgreement(ecPublicKeyFromJwk(epk)));
  final cek = concatKdf(
    sharedSecret: z,
    keyBits: enc == 'A128GCM' ? 128 : 256,
    algorithmId: enc,
    apu: const [],
    apv: b64uDecode(apv),
  );
  final gcm = GCMBlockCipher(AESEngine())
    ..init(
      false,
      AEADParameters(
        KeyParameter(cek),
        128,
        b64uDecode(parts[2]),
        Uint8List.fromList(ascii.encode(parts[0])),
      ),
    );
  return gcm.process(
    Uint8List.fromList([...b64uDecode(parts[3]), ...b64uDecode(parts[4])]),
  );
}
