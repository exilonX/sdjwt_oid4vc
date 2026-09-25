# EUDI live fixtures

Unmodified responses from the public EUDI reference deployments. They are used
by `test/integration/eudi_fixtures_test.dart` to pin the library to the wire
format that is actually deployed. Captured on **2026-09-25**.

| File | Source |
|---|---|
| `issuer_metadata.json` | `GET https://backend.issuer.eudiw.dev/.well-known/openid-credential-issuer` |
| `authorization_server_metadata.json` | `GET https://backend.issuer.eudiw.dev/.well-known/oauth-authorization-server`. The AS is `…/oidc`, but the RFC 8414 location `/.well-known/oauth-authorization-server/oidc` returns 404. |
| `authorization_request_uri.txt` | `authorization_request_uri` returned by `POST https://verifier-backend.eudiw.dev/ui/presentations/v2` |
| `request_object.jwt` | `GET` of that request's `request_uri` (`application/oauth-authz-req+jwt`) |

The verifier transaction was started with:

```json
{"type": "vp_token", "nonce": "sdjwt-oid4vc-fixture-nonce",
 "response_mode": "direct_post.jwt", "profile": "haip",
 "request_uri_method": "get", "jar_mode": "by_reference",
 "intended_use_id": "TEST-01",
 "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
   "meta": {"vct_values": ["urn:eudi:pid:1"]},
   "claims": [{"path": ["family_name"]}, {"path": ["given_name"]},
              {"path": ["place_of_birth", "locality"]}]}]}}
```

The transaction has expired, so these files contain no live secrets. The
encryption key in `client_metadata` was ephemeral.

Still to capture, on a device (needs a real wallet run): a credential offer, an
issued PID SD-JWT VC with its issuer `x5c`, and its Token Status List.
