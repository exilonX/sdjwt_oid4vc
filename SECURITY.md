# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.

Use GitHub's **private vulnerability reporting**: the **Security** tab of this
repository → **Report a vulnerability**. Include a description, the affected
version/commit, and a minimal reproduction if you can. We aim to acknowledge
within a few business days and to coordinate a fix and disclosure timeline with
you.

## What's in scope

This is the **holder/wallet** side of SD-JWT VC + OpenID4VCI/OpenID4VP. Highest
interest:

- issuer-signature verification and X.509 chain validation
  (`lib/src/core/ec.dart`, `lib/src/sdjwt/issuer_verifier.dart`),
- disclosure / KB-JWT handling and selective disclosure (`lib/src/sdjwt/`),
- anything that could cause a crash, a mis-verification, or over-disclosure on
  attacker-controlled input (credentials, request objects, status lists).

## Out of scope (by design)

The consuming app owns these — see [README.md](README.md) / [CONTEXT.md](CONTEXT.md):

- trust-anchor / EU Trusted List (LOTL) data and Relying-Party trust policy,
- private-key storage (an `Es256Signer` is injected),
- certificate revocation (CRL/OCSP).

## Supported versions

Pre-1.0: only the latest `0.1.x` pre-release is supported. This table will list
supported lines once `1.0.0` ships.
