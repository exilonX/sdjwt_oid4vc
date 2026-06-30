import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/src/core/ec.dart';
import 'package:sdjwt_oid4vc/testing.dart';
import 'package:test/test.dart';

import '../support/der_cert.dart';
import '../support/fake_http.dart';
import '../support/util.dart';

/// End-to-end: issuer issues → holder redeems over OID4VCI → verifier requests
/// → holder presents over OID4VP → verifier checks everything. Issuer key,
/// holder key and verifier are distinct, mirroring the real trust model.
void main() {
  test('issue → redeem → present → verify, disclosing only what is asked',
      () async {
    final issuerSigner = SoftwareEs256Signer.generate(random: Random(100));
    final holderSigner = SoftwareEs256Signer.generate(random: Random(200));
    const issuer = 'https://issuer.example/im';
    const vct = 'https://issuer.example/extras/v1';
    const verifier = 'https://verifier.example';

    // --- Issuer mints the credential (holder key bound via cnf, issuer x5c).
    final issued = await SdJwt.issue(
      claims: {
        'iss': issuer,
        'vct': vct,
        'cnf': {'jwk': holderSigner.publicJwkSync()},
        'given_name': 'Ada',
        'family_name': 'Byron',
        'employment_status': 'active',
        'exp': 4102444800, // year 2100
      },
      header: {
        'x5c': [buildX5cLeafFromJwk(issuerSigner.publicJwkSync())],
      },
      selectivelyDisclosable: const {
        'given_name',
        'family_name',
        'employment_status',
      },
      signer: issuerSigner,
    );

    // --- Holder redeems an offer over OID4VCI (issuer endpoint returns `issued`).
    final issuerHttp = FakeOid4vcHttp((req) {
      switch (req.url.path) {
        case '/.well-known/openid-credential-issuer/im':
          return jsonResponse({
            'credential_issuer': issuer,
            'credential_endpoint': '$issuer/credential',
            'token_endpoint': '$issuer/token',
          });
        case '/im/token':
          return jsonResponse({'access_token': 'AT', 'c_nonce': 'CN'});
        case '/im/credential':
          return jsonResponse({'credential': issued});
        default:
          return HttpResp(404, 'no route: ${req.url.path}');
      }
    });
    final offer = jsonEncode({
      'credential_issuer': issuer,
      'credential_configuration_ids': ['extras_salariat'],
      'grants': {
        preAuthorizedCodeGrant: {
          'pre-authorized_code': 'PAC',
          'tx_code': {'length': 4},
        },
      },
    });
    final compact = await Oid4vciClient(issuerHttp).redeemOffer(
      offerUriOrJson: offer,
      txCode: '1234',
      signer: holderSigner,
    );
    expect(compact, issued);

    // --- Holder trusts the issuer signature before storing.
    final credential = SdJwt.parse(compact);
    expect(await credential.verifyIssuer(IssuerTrust.signatureOnly()), isTrue);
    expect(credential.isExpired, isFalse);

    // --- Verifier asks only for employment_status.
    final vp = Oid4vpClient(
      FakeOid4vcHttp((_) => HttpResp(404, '')),
      now: fixedClock(1700),
    );
    final request = vp.parseRequest(
      _requestJwt({
        'client_id': verifier,
        'nonce': 'verifier-nonce',
        'response_uri': '$verifier/response',
        'dcql_query': {
          'credentials': [
            {
              'id': 'c1',
              'format': 'dc+sd-jwt',
              'meta': {
                'vct_values': [vct],
              },
              'claims': [
                {
                  'path': ['employment_status'],
                },
              ],
            },
          ],
        },
      }),
    );

    final match = vp.match(request, [credential]);
    expect(match, isNotNull);
    expect(match!.requestedClaims, {'employment_status'});

    // --- Holder presents, signing the KB-JWT with the holder key.
    final vpToken = await vp.buildVpToken(
      credential: match.credential,
      revealClaims: match.requestedClaims,
      req: request,
      signer: holderSigner,
    );

    // --- Verifier checks the presentation.
    final presented = SdJwt.parse(vpToken);
    final claims = presented.resolveClaims();
    expect(claims['employment_status'], 'active');
    expect(
      claims.containsKey('given_name'),
      isFalse,
      reason: 'selective disclosure: undisclosed claims stay hidden',
    );

    // Issuer signature still valid on the presented credential.
    expect(await presented.verifyIssuer(IssuerTrust.signatureOnly()), isTrue);

    // KB-JWT is fresh, bound to this verifier, and signed by the holder key.
    final kb = Jws.decompose(presented.kbJwt!);
    expect(kb.payload['nonce'], 'verifier-nonce');
    expect(kb.payload['aud'], verifier);
    final prefix =
        vpToken.substring(0, vpToken.length - presented.kbJwt!.length);
    expect(kb.payload['sd_hash'], KbJwt.sdHash(prefix, sha256));
    expect(
      verifyEs256WithJwk(
        signingInput: kb.signingInput,
        signature: kb.signature,
        jwk: presented.confirmationJwk!,
      ),
      isTrue,
    );
  });
}

String _requestJwt(Map<String, dynamic> payload) {
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'},
    payload,
  );
  return '$signingInput.${b64uEncode(const [1, 2, 3])}';
}
