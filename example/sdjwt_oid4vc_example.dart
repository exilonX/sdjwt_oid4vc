// SD-JWT VC + OpenID4VCI/OpenID4VP — the holder (wallet) side, end to end.
//
// PURPOSE
// This library is what an EUDI-style wallet imports to:
//   1. receive a Verifiable Credential from an issuer (OpenID4VCI),
//   2. prove the issuer signed it (and that it is currently valid),
//   3. check it has not been revoked (Token Status List),
//   4. authenticate a verifier and present only the claims it asks for, with
//      holder key binding (OpenID4VP).
// It is holder-only, key-agnostic (you inject an `Es256Signer` — hardware in
// production) and HTTP-agnostic (inject an `Oid4vcHttp`, or use the default).
//
// This file plays issuer + holder + verifier in one process, so it runs with no
// network and no hardware:
//
//   dart run example/sdjwt_oid4vc_example.dart
//
// The calls a real wallet makes are flagged inline with  [WALLET USES] .

import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:sdjwt_oid4vc/testing.dart';

const _issuerId = 'https://issuer.example';
const _vct = 'https://issuer.example/extras-salariat/v1';
const _verifierId = 'https://verifier.example';
const _statusUri = 'https://issuer.example/status/1';

int _epoch(DateTime dt) => dt.toUtc().millisecondsSinceEpoch ~/ 1000;

Future<void> main() async {
  // The three independent keys of the EUDI trust model. In a real wallet the
  // holder key is hardware-backed behind the same `Es256Signer` interface.
  final holder = SoftwareEs256Signer.generate(); // (3) holder key
  final issuer = SoftwareEs256Signer.generate(); // (1) issuer seal
  final verifier = SoftwareEs256Signer.generate(); // (2) relying-party key

  // An in-memory directory serving the issuer's keys + status list, so the
  // example needs no network. A real wallet just passes `DefaultOid4vcHttp()`.
  final http = _Directory(issuer, await _statusListToken(issuer));

  // --- 1. Issuance --------------------------------------------------------
  // A real wallet does NOT mint here — it redeems an offer, supplying only the
  // holder signer:
  //   final compact = await Oid4vciClient(DefaultOid4vcHttp())
  //       .redeemOffer(offerUriOrJson: deepLink, txCode: code, signer: holder);
  // [WALLET USES] Oid4vciClient.redeemOffer
  final compact = await SdJwt.issue(
    claims: {
      'iss': _issuerId,
      'vct': _vct,
      'cnf': {'jwk': holder.publicJwkSync()}, // binds the holder key
      'iat': _epoch(DateTime.utc(2024)),
      'exp': _epoch(DateTime.utc(2099)), // validity window
      'given_name': 'Ada',
      'family_name': 'Lovelace',
      'employment_status': 'active',
      'status': {
        'status_list': {'uri': _statusUri, 'idx': 0}, // revocation pointer
      },
    },
    header: const {'kid': 'issuer-1'},
    selectivelyDisclosable: {'given_name', 'family_name', 'employment_status'},
    signer: issuer,
  );
  // [WALLET USES] SdJwt.parse — turn the stored compact string into a credential.
  final credential = SdJwt.parse(compact);
  print('1. Received credential: vct=${credential.vct}');

  // --- 2. Trust the issuer ------------------------------------------------
  // [WALLET USES] SdJwtVc.verifyIssuer — prove the issuer signed it and (with
  // enforceValidity) that it is inside its nbf..exp window right now.
  final trusted = await credential.verifyIssuer(
    IssuerTrust.issuerMetadata(), // key from <iss>/.well-known/jwt-vc-issuer
    http: http,
    enforceValidity: true,
    now: () => _epoch(DateTime.utc(2030)),
  );
  print('2. Issuer signature valid & in-window: $trusted');
  // With issuer *certificates* instead of metadata, choose a trust mode:
  //   IssuerTrust.signatureOnly()                          // integrity only
  //   IssuerTrust.x5cChain(trustAnchors: euTrustedListDer) // chain to the LOTL

  // --- 3. Revocation (Token Status List) ----------------------------------
  // [WALLET USES] SdJwtVc.statusListRef + StatusListResolver.resolve
  final status = await StatusListResolver(http).resolve(
    credential.statusListRef!,
    trust:
        IssuerTrust.issuerMetadata(), // also verifies the status token's seal
  );
  print('3. Revocation status: ${status.kind} (valid? ${status.isValid})');

  // --- 4. Authenticate the verifier --------------------------------------
  // The verifier sends a *signed* request object (JAR). Authenticate it before
  // presenting anything.
  final vp = Oid4vpClient(http);
  // [WALLET USES] Oid4vpClient.parseRequest / fetchRequest
  final request = vp.parseRequest(await _verifierRequest(verifier));
  // [WALLET USES] PresentationRequest.signature — the request's signing material.
  final rpAuthentic =
      request.signature!.verifyWithJwk(verifier.publicJwkSync());
  print('4. Verifier (RP) request signature authentic: $rpAuthentic');
  // In production: take request.signature.x5c, validate that certificate against
  // your reader trust list, check its SAN against request.clientIdValue, then
  // confirm integrity with request.signature.verifyWithX5cLeaf().

  // --- 5. Present only what was asked ------------------------------------
  // [WALLET USES] Oid4vpClient.match — pick the credential + claims for the query.
  final match = vp.match(request, [credential])!;
  print('5. Verifier asked for: ${match.requestedClaims}');
  // [WALLET USES] Oid4vpClient.buildVpToken — selective disclosure + a fresh
  // KB-JWT bound to the verifier's nonce/audience and signed by the holder key.
  // (For nested/array claims, use credential.present(disclosePaths: ...).)
  final vpToken = await vp.buildVpToken(
    credential: match.credential,
    revealClaims: match.requestedClaims,
    req: request,
    signer: holder,
  );
  // [WALLET USES] Oid4vpClient.submit — POST the vp_token to the response_uri:
  //   await vp.submit(req: request, vpToken: vpToken);

  // --- 6. What the verifier receives -------------------------------------
  final shown = SdJwt.parse(vpToken).resolveClaims();
  print('6. Disclosed: employment_status=${shown['employment_status']}');
  print('   given_name hidden?  ${!shown.containsKey('given_name')}');
  print('   family_name hidden? ${!shown.containsKey('family_name')}');
}

/// Builds a signed status list token where index 0 is "valid" (bit 0). The
/// issuer signs it; a real issuer publishes it at the credential's status URI.
Future<String> _statusListToken(SoftwareEs256Signer issuer) async {
  final lst =
      b64uEncode(const ZLibEncoder().encode([0x00])); // 1 byte, all zero
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'statuslist+jwt'},
    {
      'iss': _issuerId,
      'sub': _statusUri,
      'status_list': {'bits': 1, 'lst': lst},
    },
  );
  return '$signingInput.${await issuer.signEs256(signingInput)}';
}

/// Builds the verifier's signed Request Object (JAR) asking for one claim.
Future<String> _verifierRequest(SoftwareEs256Signer verifier) async {
  final signingInput = Jws.signingInput(
    const {'alg': 'ES256', 'typ': 'oauth-authz-req+jwt'},
    {
      'client_id': _verifierId,
      'nonce': 'verifier-nonce-1',
      'response_uri': '$_verifierId/response',
      'dcql_query': {
        'credentials': [
          {
            'id': 'c1',
            'format': 'dc+sd-jwt',
            'meta': {
              'vct_values': [_vct],
            },
            'claims': [
              {
                'path': ['employment_status'],
              },
            ],
          },
        ],
      },
    },
  );
  return '$signingInput.${await verifier.signEs256(signingInput)}';
}

/// A two-route [Oid4vcHttp] serving the issuer's JWK set and its status list in
/// memory, so the example verifies real signatures with no network. A real
/// wallet uses [DefaultOid4vcHttp].
class _Directory implements Oid4vcHttp {
  _Directory(this._issuer, this._statusListToken);

  final SoftwareEs256Signer _issuer;
  final String _statusListToken;

  @override
  Future<HttpResp> get(Uri url, {Map<String, String>? headers}) async {
    if (url.path == '/status/1') return HttpResp(200, _statusListToken);
    // Everything else: the jwt-vc-issuer metadata (the issuer's JWK set).
    return HttpResp(
      200,
      jsonEncode({
        'issuer': _issuerId,
        'jwks': {
          'keys': [
            {..._issuer.publicJwkSync(), 'kid': 'issuer-1'},
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
