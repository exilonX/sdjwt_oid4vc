/// How [SdJwtVc.verifyIssuer] should resolve and trust the issuer's public key.
enum IssuerTrustMode {
  /// Take the key from the SD-JWT header `x5c` leaf certificate and verify the
  /// signature only — **no** chain or Trusted-List validation. The pilot /
  /// dev-trust-all mode: proves integrity, not that the certificate is trusted.
  x5cSignatureOnly,

  /// Validate the header `x5c` chain up to one of a provided set of trust
  /// anchors, then verify the credential with the (validated) leaf key.
  x5cChain,

  /// Resolve the key from the issuer's `/.well-known/jwt-vc-issuer` metadata
  /// (JWK set), keyed by the header `kid` when present.
  issuerMetadata,
}

/// The trust policy used when verifying an SD-JWT VC's issuer signature.
///
/// [signatureOnly] proves integrity; [x5cChain] adds certificate-chain
/// validation against caller-supplied anchors. The **Trusted List** itself —
/// *which* anchors (the EU LOTL), how it is fetched and rotated — is governance
/// data the app provides; this library only consumes the anchors. Chain
/// validation here covers link signatures, anchoring, and validity windows;
/// revocation (CRL/OCSP) and name/policy constraints are out of scope.
class IssuerTrust {
  const IssuerTrust._(this.mode, {this.trustAnchors = const []});

  /// Verify the signature against the key in the header `x5c` leaf, with no
  /// chain validation.
  factory IssuerTrust.signatureOnly() =>
      const IssuerTrust._(IssuerTrustMode.x5cSignatureOnly);

  /// Validate the header `x5c` chain to one of [trustAnchors] (each a base64
  /// DER certificate, as in `x5c`), checking each certificate's validity window
  /// at verification time, then verify with the leaf key.
  factory IssuerTrust.x5cChain({required List<String> trustAnchors}) =>
      IssuerTrust._(IssuerTrustMode.x5cChain, trustAnchors: trustAnchors);

  /// Resolve the key from `<iss>/.well-known/jwt-vc-issuer`. Requires an
  /// [Oid4vcHttp] to be passed to [SdJwtVc.verifyIssuer].
  factory IssuerTrust.issuerMetadata() =>
      const IssuerTrust._(IssuerTrustMode.issuerMetadata);

  final IssuerTrustMode mode;

  /// Trust anchors for [IssuerTrustMode.x5cChain] (base64 DER certificates).
  final List<String> trustAnchors;
}
