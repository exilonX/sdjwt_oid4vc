// A self-contained walk-through of the holder side of the protocol.
//
// Run it with:  dart run example/sdjwt_oid4vc_example.dart
//
// It plays all three roles in-process so it needs no network and no hardware:
//   * an "issuer" mints an SD-JWT VC (normally a server does this),
//   * the holder verifies, stores, and later presents it,
//   * a "verifier" checks the presentation.
//
// In a real wallet you would NOT issue here — you would call
// `Oid4vciClient.redeemOffer(...)` against a live issuer, supplying only an
// [Es256Signer]. See `example/README.md` for the `attested_secure_keys`
// (hardware) adaptor.

import 'dart:convert';

import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';

Future<void> main() async {
  // The holder key. In production this is hardware-backed; here it is an
  // in-memory signer behind the same Es256Signer interface.
  final holder = SoftwareEs256Signer.generate();

  // --- Issuance (server-side in reality) -----------------------------------
  // The issuer binds the holder key via `cnf` and makes three fields
  // selectively disclosable.
  final issuer = SoftwareEs256Signer.generate();
  const issuerId = 'https://issuer.example';
  final compact = await SdJwt.issue(
    claims: {
      'iss': issuerId,
      'vct': 'https://issuer.example/extras-salariat/v1',
      'cnf': {'jwk': holder.publicJwkSync()},
      'given_name': 'Ada',
      'family_name': 'Lovelace',
      'employment_status': 'active',
    },
    header: const {'kid': 'issuer-1'},
    selectivelyDisclosable: {'given_name', 'family_name', 'employment_status'},
    signer: issuer,
  );
  print('Issued SD-JWT VC (${compact.length} chars).');

  // --- Holder: parse, verify the issuer, inspect --------------------------
  final credential = SdJwt.parse(compact);

  // Resolve the issuer key from its (here in-memory) jwt-vc-issuer metadata.
  final trusted = await credential.verifyIssuer(
    IssuerTrust.issuerMetadata(),
    http: _IssuerDirectory(issuerId, issuer.publicJwkSync()),
  );
  print('Issuer signature trusted: $trusted');
  print('vct:           ${credential.vct}');
  print('disclosable:   ${credential.disclosures.map((d) => d.name).toList()}');
  print('full claims:   ${credential.resolveClaims()}');

  // --- Verifier: ask for ONLY the employment status -----------------------
  final vp = Oid4vpClient(DefaultOid4vcHttp());
  final request = vp.parseRequest(_buildRequestObject());
  final match = vp.match(request, [credential]);
  if (match == null) {
    print('No held credential satisfies the request.');
    return;
  }
  print('Verifier asked for: ${match.requestedClaims}');

  // --- Holder: present, signing a fresh KB-JWT with the holder key --------
  final vpToken = await vp.buildVpToken(
    credential: match.credential,
    revealClaims: match.requestedClaims,
    req: request,
    signer: holder,
  );

  // --- Verifier: see exactly what was disclosed (and nothing more) --------
  final presented = SdJwt.parse(vpToken);
  final shown = presented.resolveClaims();
  print('Presented claims:   $shown');
  print('given_name hidden?  ${!shown.containsKey('given_name')}');
}

/// Builds the verifier's Request Object asking for `employment_status` of the
/// extras-salariat credential. Its signature is not verified by the holder
/// library (Relying-Party trust is the app's job), so a placeholder is fine.
String _buildRequestObject() {
  final payload = {
    'client_id': 'https://verifier.example',
    'nonce': 'nonce-${DateTime.now().millisecondsSinceEpoch}',
    'response_uri': 'https://verifier.example/response',
    'dcql_query': {
      'credentials': [
        {
          'id': 'c1',
          'format': 'dc+sd-jwt',
          'meta': {
            'vct_values': ['https://issuer.example/extras-salariat/v1'],
          },
          'claims': [
            {
              'path': ['employment_status'],
            },
          ],
        },
      ],
    },
  };
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'},
    payload,
  );
  return '$signingInput.${b64uEncode(const [0])}';
}

/// A one-route [Oid4vcHttp] that serves the issuer's JWK set in memory, so the
/// example verifies a real signature without a network. A real wallet just
/// uses [DefaultOid4vcHttp].
class _IssuerDirectory implements Oid4vcHttp {
  _IssuerDirectory(this.issuerId, this.jwk);

  final String issuerId;
  final Map<String, dynamic> jwk;

  @override
  Future<HttpResp> get(Uri url, {Map<String, String>? headers}) async {
    return HttpResp(
      200,
      jsonEncode({
        'issuer': issuerId,
        'jwks': {
          'keys': [
            {...jwk, 'kid': 'issuer-1'},
          ],
        },
      }),
    );
  }

  @override
  Future<HttpResp> postForm(
    Uri url,
    Map<String, String> form, {
    Map<String, String>? headers,
  }) =>
      throw UnimplementedError();

  @override
  Future<HttpResp> postJson(
    Uri url,
    Object body, {
    Map<String, String>? headers,
  }) =>
      throw UnimplementedError();
}
