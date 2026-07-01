import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  group('CredentialOffer.fromJson', () {
    test('reads issuer, config ids and the pre-authorized grant', () {
      final offer = CredentialOffer.fromJson({
        'credential_issuer': 'https://issuer.example',
        'credential_configuration_ids': ['example_credential'],
        'grants': {
          preAuthorizedCodeGrant: {
            'pre-authorized_code': 'PAC',
            'tx_code': {
              'length': 6,
              'input_mode': 'numeric',
              'description': 'Code sent by email',
            },
          },
        },
      });
      expect(offer.issuer, 'https://issuer.example');
      expect(offer.configIds, ['example_credential']);
      expect(offer.preAuthCode, 'PAC');
      expect(offer.txCodeRequired, isTrue);
      expect(offer.txCodeLength, 6);
      expect(offer.txCodeInputMode, 'numeric');
      expect(offer.txCodeDescription, 'Code sent by email');
    });

    test('tolerates a missing grant / ids and a tx_code without length', () {
      final offer = CredentialOffer.fromJson({
        'credential_issuer': 'https://issuer.example',
        'grants': {
          preAuthorizedCodeGrant: {
            'pre-authorized_code': 'PAC',
            'tx_code': <String, dynamic>{},
          },
        },
      });
      expect(offer.configIds, isEmpty);
      expect(offer.preAuthCode, 'PAC');
      expect(offer.txCodeRequired, isTrue);
      expect(offer.txCodeLength, isNull);
    });

    test('throws when credential_issuer is missing', () {
      expect(
        () => CredentialOffer.fromJson(const {}),
        throwsA(isA<OfferParseError>()),
      );
    });
  });

  group('TokenResponse.fromJson', () {
    test('reads access_token and optional c_nonce', () {
      final withNonce =
          TokenResponse.fromJson(const {'access_token': 'AT', 'c_nonce': 'CN'});
      expect(withNonce.accessToken, 'AT');
      expect(withNonce.cNonce, 'CN');

      final withoutNonce = TokenResponse.fromJson(const {'access_token': 'AT'});
      expect(withoutNonce.cNonce, isNull);
    });

    test('throws when access_token is missing', () {
      expect(
        () => TokenResponse.fromJson(const {}),
        throwsA(isA<TokenError>()),
      );
    });
  });
}
