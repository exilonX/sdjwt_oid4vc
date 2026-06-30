/// How [SdJwtVc.verifyIssuer] should resolve the issuer's public key.
enum IssuerTrustMode {
  /// Take the key from the SD-JWT header `x5c` leaf certificate and verify the
  /// signature only — **no** chain or Trusted-List validation. This is the
  /// pilot mode: the verifier we control is trust-all in dev.
  x5cSignatureOnly,

  /// Resolve the key from the issuer's `/.well-known/jwt-vc-issuer` metadata
  /// (JWK set), keyed by the header `kid` when present.
  issuerMetadata,
}

/// The trust policy used when verifying an SD-JWT VC's issuer signature.
///
/// Kept deliberately small: the pilot verifies signatures, not trust chains.
/// Real Trusted-List / LOTL validation is governance that lives outside this
/// library.
class IssuerTrust {
  const IssuerTrust._(this.mode);

  /// Verify the signature against the key in the header `x5c` leaf.
  factory IssuerTrust.signatureOnly() =>
      const IssuerTrust._(IssuerTrustMode.x5cSignatureOnly);

  /// Resolve the key from `<iss>/.well-known/jwt-vc-issuer`. Requires an
  /// [Oid4vcHttp] to be passed to [SdJwtVc.verifyIssuer].
  factory IssuerTrust.issuerMetadata() =>
      const IssuerTrust._(IssuerTrustMode.issuerMetadata);

  final IssuerTrustMode mode;
}
