import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import '../keys/derivation_artefacts.dart';
import '../keys/derivation_service.dart';
Map supportedHashAlgorithms = {
  "sha1":  Sha1(),
  "sha224":  Sha224(),
  "sh384":  Sha384(),
  "sha256":  Sha256(),
  "sha512":  Sha512()
};
/// Currently the only supported key derivation strategy
/// https://en.wikipedia.org/wiki/Pbkdf2
class Pbkdf2Hmac implements DerivationService {
  Future<List<int>> deriveKey(
      {required String passphrase, required DerivationArtefacts artefacts, String hashAlgorithm = "sha256"}) async {
    late HashAlgorithm algorithm;
    if (supportedHashAlgorithms.containsKey(hashAlgorithm)){
      algorithm = supportedHashAlgorithms[hashAlgorithm];
    }
    else{
      throw UnsupportedError('$hashAlgorithm is not an algorithm supported');
    }
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac(algorithm),
      iterations: artefacts.iterations,
      bits: artefacts.length * 8,
    );

    final secretKey = SecretKey(utf8.encode(passphrase));

    return pbkdf2
        .deriveKey(secretKey: secretKey, nonce: artefacts.salt)
        .then((value) => value.extractBytes());
  }
}
