# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

OAuth2/OIDC Debugger — a two-service web application for testing and debugging OAuth2 and OIDC flows against real identity providers. Supports Authorization Code, Implicit, Client Credentials, Resource Owner Password, and Refresh grants, plus all three OIDC authentication flows (Authorization Code, Implicit, Hybrid).

## Architecture

The project is split into two independent Node.js services:

- **`/api/`** — Express backend (port 4000). Proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata.
- **`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `debugger2.html`.
- **`/common/data.js`** — Shared `convertToOAuth2Format()` function used by both services to normalize grant parameters (including PKCE and custom params).
- **`/waltid/`** — Configuration for a **walt.id `issuer-api2`** container (`waltid/config/*.conf`) plus the dependency-free CORS proxy in front of it (`waltid/cors-proxy.js`, run by a stock `node` image; walt.id's services send no CORS headers, so a browser wallet cannot read their responses — the issuer listens on 7006 and the proxy serves 7005, which is what `baseUrl` names), a real OpenID4VCI 1.0 Credential Issuer the test suite runs the SD-JWT VC workflow against for interoperability (`tests/sd_jwt_vc_waltid.js`). It is its own authorization server and authenticates End-Users at the suite's Keycloak. Its signing key is generated per run by `generateWaltidIssuerKey()` in `common/common.sh`, and `renderWaltidConfig()` writes it (and the URLs) into `waltid/generated-config/` — gitignored — which the container mounts. Nothing depends on how walt.id's own config loader expands `${VAR}`: it did not, and the service died before it listened, leaving only a 502 from the proxy. The issuer image is built with Jib and has **no shell**, so it can carry no `CMD-SHELL` healthcheck — the proxy carries one probe for the whole chain. Its Credential Issuer Identifier has a path (`…/openid4vci`), which is what forces RFC 8414 well-known **path insertion**.
- **`/sts/`** — A mock Security Token Service used by the test suite. It speaks WS-Trust; hosts a bare-minimum **OID4VCI Credential Issuer** (`/.well-known/openid-credential-issuer`, `/.well-known/jwt-vc-issuer`, `/oid4vci/nonce`, `/oid4vci/credential`) that mints SD-JWT VCs per RFC 9901; hosts the issuer side of an OID4VCI **Credential Offer** for use cases H.1, H.2 and H.3 (`/issuer`, `/issuer/offer[?mode=cross-device|deferred]` which renders a real QR code and a Transaction Code, `/oid4vci/credential-offer/:id`, `/oid4vci/deferred_credential`, sending the End-User to `OID4VCI_WALLET_URL`); implements the **pre-authorized code grant** with `tx_code` enforcement; and acts as a **mock OAuth 2.0 authorization server** — an RFC 8414 metadata document plus every endpoint it advertises (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, `/oauth2/register`, `/oauth2/jwks`). It selects its configuration (log level) with `CONFIG_FILE` like the other services (`sts/env/*.js`), and at the default `debug` level it logs every endpoint call (path, request/response headers and bodies, status, elapsed time) and every assertion/JWT/SD-JWT VC before and after signing or encryption. The authorization endpoint shows a **login screen** (`/oauth2/login`, Keycloak's field ids) and the username typed there becomes the identity in every token; no password is ever checked. All tokens are RS256 JWTs signed with the STS key, so they verify against the advertised JWKS. The debugger's full OAuth2 / OIDC workflow can therefore run against it with no identity provider.

### Shared client modules

Several page bundles share modules rather than duplicating behaviour:

| Module | Shared by | What it holds |
|---|---|---|
| `metadata_client.js` | `debugger.js`, `sd_jwt_vc_issuance_*.js` | fetching/tabulating a metadata document, its provenance note, base64url + Web Crypto JWS verification, the `signed_metadata` verdict, and **where an issuer's metadata lives** (`wellKnownCandidates`/`fetchWellKnown`: RFC 8414 inserts the well-known before the issuer's path, OIDC Discovery appends it — both are tried, insertion first) |
| `op_metadata.js` | `debugger.js`, `debugger2.js`, `sd_jwt_vc_issuance_1.js` | the OpenID Provider metadata members (and, separately, the RFC 8414-only ones) with their defaults and `-->not defined<--` notes |
| `vci_metadata.js` | `sd_jwt_vc_issuance_*.js` | the OID4VCI credential issuer metadata members (element ids and storage keys prefixed `vci_`) |
| `sd_jwt_vc.js` | `sd_jwt_vc_issuance_*.js`, `debugger.js`, `debugger2.js` | the issuance workflow's storage keys and hand-off flag, plus SD-JWT parsing and digest computation |
| `op_history.js` | `saml_history.js`, `wstrust_history.js` | the Operations History log |
| `xmldsig.js` | the SAML and WS-Trust pages | in-browser XML Signature / XML Encryption |

The **SD-JWT VC issuance workflow** (`sd-jwt-vc-issuance-{0,1,2,3}.html`) reuses the OIDC Authorization Code flow on `debugger.html` / `debugger2.html`: the `?sdjwtvc=1` query parameter marks the flow active, and `debugger2.html` returns to step 2 once it has the tokens. Both debugger pages behave exactly as before without that parameter. Step 1's authorization-server pane deliberately writes the **same localStorage keys** the debugger pages read.

Step 0 chooses which OID4VCI **Appendix H use case** to run. The list lives in one place — `USE_CASES` in `client/src/sd_jwt_vc.js` — and both the chooser's cards and the badge every other page shows are generated from it, so they cannot disagree; `setUseCase()` redraws the badge itself, because an arriving Credential Offer changes the use case after the page has already been laid out. **H.6** (wallet-initiated) is what the workflow has always done. **H.1** (issuer-initiated) starts at the issuer's own page, comes back to step 1 with a Credential Offer in `credential_offer` or `credential_offer_uri`, and carries the offer's `issuer_state` into the authorization request (`debugger.js` appends it as a custom authorization parameter). **H.2** (cross-device) and **H.3** (deferred) start at the issuer's QR screen, arrive through step 1's *Receive a Credential Offer* pane (the wallet is on another device, so nothing navigates it), and use the `pre-authorized_code` grant — no authorization request, so step 1 hands off straight to step 2, which owns the Token Request and the `tx_code`. H.3 adds the deferred pane: a `202` Credential Response with a `transaction_id`, polled at `deferred_credential_endpoint` until the credential arrives.

### Frontend Build

Client-side JavaScript lives in `/client/src/` and is compiled into `/client/public/js/` using **browserify** with the **envify** transform (substitutes `process.env.*` at build time). Each feature page has its own standalone bundle:

| Source | Bundle | Page |
|---|---|---|
| `debugger.js` | `debugger.js` | Authorization/Implicit initiation |
| `debugger2.js` | `debugger2.js` | Token exchange + results |
| `token_detail.js` | `token_detail.js` | JWT inspection/validation |
| `introspection.js` | `introspection.js` | Token introspection |
| `userinfo.js` | `userinfo.js` | Userinfo endpoint |
| `jwks.js` | `jwks.js` | JWKS endpoint |
| `logout.js` | `logout.js` | OIDC logout |
| `sd_jwt_vc_issuance_0.js` | `sd_jwt_vc_issuance_0.js` | SD-JWT VC issuance step 0, the use-case chooser (`sd-jwt-vc-issuance-0.html`) |
| `sd_jwt_vc_issuance_1.js` | `sd_jwt_vc_issuance_1.js` | SD-JWT VC issuance step 1 (`sd-jwt-vc-issuance-1.html`) |
| `sd_jwt_vc_issuance_2.js` | `sd_jwt_vc_issuance_2.js` | SD-JWT VC issuance step 2 (`sd-jwt-vc-issuance-2.html`) |
| `sd_jwt_vc_issuance_3.js` | `sd_jwt_vc_issuance_3.js` | SD-JWT VC issuance step 3 (`sd-jwt-vc-issuance-3.html`) |

The browserify build runs inside Docker. There is no local build script — to rebuild bundles you must use Docker.

### Versioning

The app version is **M.N.O**: `M.N` comes from the repo-root `VERSION` file (currently `0.9`), and `O` is a per-build number generated by `client/version.js` (the UTC build instant, `YYYYMMDDHHMMSS`, or `BUILD_NUMBER` if set). It is stamped at build time — `client/Dockerfile` runs `node version.js --stamp public`, and `client/build.js` writes `dist/version.json` — then substituted into the `{{VERSION}}` / `{{BUILD_INFO}}` placeholders in the footer partial and the error pages (by `build.js` at build time, by `server.js` at request time). The four `package.json` files (`api`, `client`, `tests`, `sts`) carry the same M.N as `M.N.0` (semver requires three parts). Bump a release by editing `VERSION`, then `node client/version.js --sync-manifests`; `--check-manifests` reports drift and `build.js` warns about it.

### Configuration

Environment-specific config files live at:
- `/api/env/{local.js,test.js,docker-tests.js}`
- `/client/src/env/{local.js,test.js,docker-tests.js}`

The active config is selected via the `CONFIG_FILE` environment variable. For local development, this is `./env/local.js`.

## Running the App

```bash
# Start all services (api + client)
CONFIG_FILE=./env/local.js docker-compose up

# Rebuild images first
CONFIG_FILE=./env/local.js docker-compose build
```

Access the app at `http://localhost:3000`.

## Running Tests

Tests use Selenium WebDriver with Chrome. A Keycloak test IdP is spun up automatically:

```bash
# Full battery of tests entirely in containers
./docker-run-tests.sh

# Tests from local shell, dependencies still in containers
./local-run-tests.sh
```

Individual test files in `/tests/`:
- `oauth2_authorization_code.js`
- `oauth2_client_credentials.js`
- `oauth2_implicit.js`
- `oidc_authorization_code.js`
- `sd_jwt_vc_issuance.js` (the OID4VCI / SD-JWT VC workflow; needs the STS mock and Keycloak)
- `sd_jwt_vc_waltid.js` (the same workflow against walt.id's `issuer-api2` — the interoperability check; needs the `waltid-issuer` container and Keycloak, and is skipped when `WALTID_ISSUER_URL` is unset)
- `oauth2_sts_endpoints.js` (the STS mock's authorization server endpoints; no browser)

**The SAML SP key pair is never committed.** `generateSpKeyPair()` in `common/common.sh` generates a fresh self-signed RSA pair per run and exports `SAML_SP_PRIVATE_KEY` / `SAML_SP_CERT` (read by the tests through `common/sp_keypair.js`) and `SAML_SP_SIGNING_CERT` (registered on the Keycloak SAML client). It lives only in the run's environment — the containerized suite generates its own inside the tests container. Do not reintroduce a key pair under `tests/fixtures/` (gitignored, along with `sp-key.pem` / `sp-cert.pem`).

There is no linting toolchain configured in this project.

## Key Implementation Notes

- **State persistence**: All user configuration (endpoints, client IDs, scopes, etc.) is stored in browser `localStorage` — passwords are intentionally excluded.
- **Token endpoint calls**: Can be made from the browser (client-side) or proxied through the API service (server-side). The UI lets users choose.
- **XSS prevention**: DOMPurify is used on the client when rendering token/claim data to the DOM.
- **SSL**: Server-side SSL certificate validation can be disabled for testing against self-signed certs.
