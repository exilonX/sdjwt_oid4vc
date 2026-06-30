/// SD-JWT VC + OpenID4VCI/OpenID4VP protocol library for Dart wallets
/// (holder role).
///
/// The two things a host app must provide are an [Es256Signer] (the holder key)
/// and — optionally — an [Oid4vcHttp] (defaults to [DefaultOid4vcHttp]).
/// Everything else is pure, deterministic logic.
library;

// core — injected contracts and shared helpers
export 'src/core/b64u.dart';
export 'src/core/clock.dart';
export 'src/core/errors.dart';
export 'src/core/es256_signer.dart';
export 'src/core/http.dart';
export 'src/core/jwk.dart';
export 'src/core/jws.dart' show Jws, JwsParts;
// oid4vci — issuance (holder)
export 'src/oid4vci/models.dart';
export 'src/oid4vci/vci_client.dart';
// oid4vp — presentation (holder)
export 'src/oid4vp/dcql.dart';
export 'src/oid4vp/models.dart';
export 'src/oid4vp/vp_client.dart';
// sdjwt — the SD-JWT VC codec
export 'src/sdjwt/disclosure.dart';
export 'src/sdjwt/issuer_trust.dart';
export 'src/sdjwt/kb_jwt.dart';
export 'src/sdjwt/sd_jwt.dart';
export 'src/sdjwt/status_list.dart';
