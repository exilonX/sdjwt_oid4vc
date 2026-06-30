import 'package:sdjwt_oid4vc/sdjwt_oid4vc.dart';
import 'package:test/test.dart';

void main() {
  test('factories map to their modes', () {
    expect(IssuerTrust.signatureOnly().mode, IssuerTrustMode.x5cSignatureOnly);
    expect(IssuerTrust.issuerMetadata().mode, IssuerTrustMode.issuerMetadata);
  });
}
