# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

OAuth2/OIDC Debugger — a two-service web application for testing and debugging OAuth2, OIDC, SAML, WS-Trust and SD-JWT VC (issuance and presentation) flows against real identity providers, issuers and verifiers. Supports Authorization Code, Implicit, Client Credentials, Resource Owner Password, and Refresh grants, plus all three OIDC authentication flows (Authorization Code, Implicit, Hybrid).

## Architecture

The project is split into two independent Node.js services:

- **`/api/`** — Express backend (port 4000). Proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata.
- **`/client/`** — Express frontend (port 3000). Serves static HTML/JS pages and handles the OAuth2 redirect callback at `/callback`, forwarding query params to `debugger2.html`.
- **`/common/data.js`** — Shared `convertToOAuth2Format()` function used by both services to normalize grant parameters (including PKCE and custom params).
- **`/waltid/`** — Configuration for a **walt.id `issuer-api2`** container (`waltid/config/*.conf`) plus the dependency-free CORS proxy in front of it (`waltid/cors-proxy.js`, run by a stock `node` image; walt.id's services send no CORS headers, so a browser wallet cannot read their responses — the issuer listens on 7006 and the proxy serves 7005, which is what `baseUrl` names), a real OpenID4VCI 1.0 Credential Issuer the test suite runs the SD-JWT VC workflow against for interoperability (`tests/sd_jwt_vc_waltid.js`). It is its own authorization server and authenticates End-Users at the suite's Keycloak. Its signing key is generated per run by `generateWaltidIssuerKey()` in `common/common.sh`, and `renderWaltidConfig()` writes it (and the URLs) into `waltid/generated-config/` — gitignored — which the container mounts. Nothing depends on how walt.id's own config loader expands `${VAR}`: it did not, and the service died before it listened, leaving only a 502 from the proxy. The issuer image is built with Jib and has **no shell**, so it can carry no `CMD-SHELL` healthcheck — the proxy carries one probe for the whole chain. Its Credential Issuer Identifier has a path (`…/openid4vci`), which is what forces RFC 8414 well-known **path insertion**.
- **`/sts/`** — A mock Security Token Service used by the test suite. It speaks WS-Trust; hosts a bare-minimum **OID4VCI Credential Issuer** (`/.well-known/openid-credential-issuer`, `/.well-known/jwt-vc-issuer`, `/oid4vci/nonce`, `/oid4vci/credential`) that mints SD-JWT VCs per RFC 9901; hosts the issuer side of an OID4VCI **Credential Offer** for use cases H.1, H.2 and H.3 (`/issuer`, `/issuer/offer[?mode=cross-device|deferred]` which renders a real QR code and a Transaction Code, `/oid4vci/credential-offer/:id`, `/oid4vci/deferred_credential`, sending the End-User to `OID4VCI_WALLET_URL`); implements the **pre-authorized code grant** with `tx_code` enforcement, **`authorization_details`** → `credential_identifiers` → `credential_identifier` (with the section 8.2 mutual exclusion enforced), **batch issuance** (one `c_nonce` per request, not per proof), **credential response encryption** (RSA-OAEP-256 JWE), and a **Notification Endpoint** that validates and records what it is told (plus a non-spec `GET /oid4vci/notification/:id` so a test can check the notification landed); hosts a **mock OID4VP Verifier** (`/oid4vp/verifier` and `/oid4vp/start` build an Authorization Request with `response_type=vp_token`, a DCQL query, a fresh `nonce` and `response_mode=direct_post`, by value or as a signed Request Object at `/oid4vp/request/:id`, with a QR screen for cross-device; `POST /oid4vp/response` is the Response URI and **verifies the presentation properly** — issuer signature, every Disclosure's digest against `_sd`, the KB-JWT's `typ`/`alg`/`nonce`/`aud`/`iat`/`sd_hash` and its signature against the credential's `cnf.jwk`, the validity window, and whether the claims it asked for arrived — recording a per-check verdict readable at the non-spec `GET /oid4vp/result/:state`); and acts as a **mock OAuth 2.0 authorization server** — an RFC 8414 metadata document plus every endpoint it advertises (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, `/oauth2/register`, `/oauth2/jwks`). It selects its configuration (log level) with `CONFIG_FILE` like the other services (`sts/env/*.js`), and at the default `debug` level it logs every endpoint call (path, request/response headers and bodies, status, elapsed time) and every assertion/JWT/SD-JWT VC before and after signing or encryption. The authorization endpoint shows a **login screen** (`/oauth2/login`, Keycloak's field ids) and the username typed there becomes the identity in every token; no password is ever checked. All tokens are RS256 JWTs signed with the STS key, so they verify against the advertised JWKS. The debugger's full OAuth2 / OIDC workflow can therefore run against it with no identity provider.

### Shared client modules

Several page bundles share modules rather than duplicating behaviour:

| Module | Shared by | What it holds |
|---|---|---|
| `metadata_client.js` | `debugger.js`, `sd_jwt_vc_issuance_*.js` | fetching/tabulating a metadata document, its provenance note, base64url + Web Crypto JWS verification, the `signed_metadata` verdict, and **where an issuer's metadata lives** (`wellKnownCandidates`/`fetchWellKnown`: RFC 8414 inserts the well-known before the issuer's path, OIDC Discovery appends it — both are tried, insertion first) |
| `op_metadata.js` | `debugger.js`, `debugger2.js`, `sd_jwt_vc_issuance_1.js` | the OpenID Provider metadata members (and, separately, the RFC 8414-only ones) with their defaults and `-->not defined<--` notes |
| `vci_metadata.js` | `sd_jwt_vc_issuance_*.js` | the OID4VCI credential issuer metadata members (element ids and storage keys prefixed `vci_`) |
| `sd_jwt_vc.js` | `sd_jwt_vc_issuance_*.js`, `debugger.js`, `debugger2.js` | the issuance workflow's storage keys and hand-off flag, plus SD-JWT parsing and digest computation |
| `sd_jwt_vp.js` | `sd_jwt_vc_presentation_*.js` | the PRESENTATION workflow's storage keys and flows, the OID4VP request parameters and DCQL helpers (`requestedClaims`, `requiresKeyBinding`), and the artifact itself: `presentedPrefix`, `sdHash`, `signKbJwt` and `buildPresentation`, which assemble the SD-JWT+KB. It reuses `sd_jwt_vc.js` for parsing and digests, because a presentation is the same credential with a different last element |
| `vci_wallet.js` | `sd_jwt_vc_issuance_2.js`, `sd_jwt_vc_issuance_4.js` | the wallet's half of a **Credential Request**, with no DOM in it: holder key pairs, the `c_nonce`, the `openid4vci-proof+jwt` proof of possession, the request body, the text of an assembled HTTP call, and reading a Credential Response (JSON or the section 10 JWE). Extracted because step 4 refreshes a credential by making *the same call* step 2 makes — on the wire a refresh is not a different request, so it must not be a second implementation |
| `op_history.js` | `saml_history.js`, `wstrust_history.js` | the Operations History log |
| `xmldsig.js` | the SAML and WS-Trust pages | in-browser XML Signature / XML Encryption |
| `jose_jwe.js` | `jwt_tools.js`, the OID4VCI issuance panes | in-browser **JWE** (RFC 7516/7518): RSA-OAEP(-256), ECDH-ES direct and +A*KW, A*GCM, the Concat KDF, flexible key input (CryptoKey / JWK object / JWK text / PEM), and a **Web Crypto capability probe** — Chrome rejects AES-192, so options needing it are marked unusable rather than failing with an OperationError. Extracted from `jwt_tools.js` because OID4VCI section 10 has both sides encrypting, and the KDF must exist once. Tested directly by `tests/jose_jwe.js` against an independent reading of RFC 7518 section 4.6 |

The **SD-JWT VC issuance workflow** (`sd-jwt-vc-issuance-{0,1,2,3,4}.html`) reuses the OIDC Authorization Code flow on `debugger.html` / `debugger2.html`: the `?sdjwtvc=1` query parameter marks the flow active, and `debugger2.html` returns to step 2 once it has the tokens. Both debugger pages behave exactly as before without that parameter. Step 1's authorization-server pane deliberately writes the **same localStorage keys** the debugger pages read.

Step 0 chooses which OID4VCI **Appendix H use case** to run. The list lives in one place — `USE_CASES` in `client/src/sd_jwt_vc.js` — and both the chooser's cards and the badge every other page shows are generated from it, so they cannot disagree; `setUseCase()` redraws the badge itself, because an arriving Credential Offer changes the use case after the page has already been laid out. **H.6** (wallet-initiated) is what the workflow has always done. **H.1** (issuer-initiated) starts at the issuer's own page, comes back to step 1 with a Credential Offer in `credential_offer` or `credential_offer_uri`, and carries the offer's `issuer_state` into the authorization request (`debugger.js` appends it as a custom authorization parameter). **H.2** (cross-device) and **H.3** (deferred) start at the issuer's QR screen, arrive through step 1's *Receive a Credential Offer* pane (the wallet is on another device, so nothing navigates it), and use the `pre-authorized_code` grant — no authorization request, so step 1 hands off straight to step 2, which owns the Token Request and the `tx_code`. H.3 adds the deferred pane: a `202` Credential Response with a `transaction_id`, polled at `deferred_credential_endpoint` until the credential arrives.

Step 4 (`sd-jwt-vc-issuance-4.html`) **refreshes** a credential the wallet already holds — OID4VCI **section 14.5**, *Refreshing Issued Credentials* — in the two calls that mechanism is made of: `grant_type=refresh_token` at the token endpoint (RFC 6749 section 6, so nothing about it is OID4VCI-specific), then the same Credential Request step 2 makes, which is why both pages build it with `vci_wallet.js`. Section **14.3** is the reason the refresh half is optional rather than required: the Credential Endpoint may be asked again with an access token that is still valid, which is the only route left after the pre-authorized code grant (H.2/H.3), since that grant issues no refresh token.

Every page of the workflow opens with the **same row of links to every step** — `partials/sd_jwt_vc_steps.html`, included at the top of the container, above the page title, with each page marking its own `vc_step_N` as current from its bundle. It is deliberately **one row**: `ol.vc-steps` is `flex-wrap: nowrap` with items that may shrink (`flex: 1 1 0; min-width: 0`), because with the wrapping it had before, adding step 4 pushed the fifth link onto a second line. Captions in the partial are kept short for the same reason, and `stepLinksOnEveryPage()` in `tests/sd_jwt_vc_issuance.js` asserts geometrically — all five items on one top edge, the row one item tall, above the title, no horizontal page scroll — on all five pages.

**Layout trap on these panes.** Everything they display is base64url with no break opportunity in it, and `bootstrap.css` sets `code { white-space: nowrap }` — so a long `c_nonce` or access token used to run off to the right of the pane, and in the Approve pane's list it pushed the whole page sideways. `sd_jwt_vc.css` fixes it at the root: `.dbg-pane code` overrides the `nowrap`, `.vc-token-table` is `table-layout: fixed` (the cell decides the width, as the disclosure tables already did), and `pre.vc-json` / `textarea.vc-token` are both `width: 100%; box-sizing: border-box` so a `<pre>` and a `<textarea>` in one pane come out the same size. `panesContainTheirContent()` in `tests/sd_jwt_vc_issuance.js` plants an over-long value into every `<code>` on all four pages and fails if anything is wider than its pane or the page scrolls horizontally.

Step 4 also carries a **Credential History** pane, the counterpart of `debugger2.html`'s Token History — recording rather more than debugger2 does: **every attempt**, one row each, newest first. `sd_jwt_vc.js` holds the store; a row has a `kind` (`issuance` / `token_refresh` / `credential_request` / `deferred_poll`), an `outcome` (`success` / `failed` / `deferred` / `pending` / `kept` / `discarded`) and a `detail` saying what the issuer actually said. `recordHistoryEntry()` appends one row per attempt and returns its id; `updateHistoryEntry()` resolves it later (`pending` → `kept` or `discarded`), so a retry, a refusal and a discarded credential are all on record without any of them becoming a second row for the same call. Every row is numbered in `#` by the order the attempts were made — there is no unnumbered row — while `Gen` carries the generation number, which only the `kept` rows with a credential have: those are the **generations** (`heldGenerations()` numbers them, `activeGeneration()` says which is in hand) and `◀ Older` / `Newer ▶` / Oldest / Latest move over *that subset* (a log row is not a place to be, and says `log only`). The list is the newest `HISTORY_LIMIT` (100) attempts in a **fixed-height scrolling box** with a sticky header (`#vc_history_table` in `sd_jwt_vc.css`): a 100-row log would otherwise push the panes below it off the screen and the pane's height would jump on every attempt. Trimming at `HISTORY_LIMIT` drops the oldest **log** rows first and only touches a generation when nothing else is left, so an audit trail never costs the ability to go back to a credential. `HISTORY_INDEX` holds the active row's **id**, not an index, so a log row appearing between two generations cannot shift it. A credential the issuer has just returned shows up there immediately as a `vc-history-pending` row (outcome `pending`) marked *not kept yet*, with Keep/Discard on it — the pane has to react to the **retrieval**, not only to keeping, or it reads as broken; and keeping deliberately **does not navigate** (`replaceCredential()` calls `reloadHeldCredential()` in place and offers a *Verify in step 3* button), because the pane the holder acted in is the pane that has to show what the action did. Activating a generation is a real state change, not a highlight: it writes `CREDENTIAL`/`CREDENTIALS`/`CREDENTIAL_META` **and that generation's holder key pair**, because a credential whose `cnf` key the wallet no longer has cannot be presented at all — which is also why each entry stores its own key pair, and why *Clear History* writes an empty list rather than removing the key (`hasCredentialHistory()` distinguishes "cleared on purpose" from "never recorded", and only the latter backfills the credential in hand as generation 1). A discarded refresh stays in the log as a `discarded` row — the attempt happened — but its credential and private key are stripped, because discarded has to mean discarded, and it is not a generation: the wallet never held it. Three things the page must get right, all of them wallet behaviour the spec leaves open: the refreshed credential is kept **apart** from the one in hand until the holder chooses (section 14.5 warns about a wallet holding two credentials of the same type and not knowing which is current); what the issuer changed is **read off the two credentials** rather than assumed, because the issuer decides whether to update the signature only or the claim values too — and the salts, Disclosures and digests are new either way, so the comparison is of claim *values*; and choosing to bind a **new holder key** must not overwrite `HOLDER_PRIVATE_JWK` until that credential is kept, or the credential still in hand loses the key it needs to be presented (the pending pair parks in `REFRESHED_HOLDER_*`, and the replaced credential's pair in `PREVIOUS_HOLDER_*`).

The **SD-JWT VC presentation workflow** (`sd-jwt-vc-presentation-{0,1,2,3}.html`, bundles `sdjwtvp0..3`) is the other half: a Verifier asks for some of a credential over **OID4VP 1.0** and the wallet answers with an **SD-JWT+KB** (RFC 9901 section 4.3). It is reached from its own landing-page card and presents whatever credential the issuance workflow left in `localStorage` — the two workflows meet at those keys and nowhere else. Step 0 chooses the flow (request by value with the `redirect_uri` client identifier prefix, a **signed** Request Object by reference for a pre-registered client, or cross-device by QR code) and all three *start at the verifier*, because a presentation is something a verifier asks for. Step 1 reads the request — fetching and verifying the Request Object when it is passed by reference — and decodes the **DCQL** query into claim paths shown against what the credential actually holds; nothing is disclosed there. Step 2 is the point of the format: a checkbox per Disclosure, defaulting to exactly what was asked for, and it builds the presentation in front of you — the issuer-signed JWT, the selected Disclosures, and a **Key Binding JWT** whose `nonce` is the request's, whose `aud` is the verifier's Client Identifier, and whose `sd_hash` covers exactly the bytes being sent. Step 3 shows the verifier's verdict check by check next to the wallet's own re-check of those bytes, and names any **over-disclosure**: a verifier accepts extra claims silently, so only the wallet can care.

Three things that are easy to get wrong here, and are therefore tested: `sd_hash` is computed over `<Issuer-signed JWT>~<Disclosure>*~` **including the trailing tilde**, so it commits to the exact byte string; the KB-JWT must verify against the credential's own `cnf.jwk` and not a key the presenter nominates; and the `vp_token` is a JSON object **keyed by the DCQL credential query id**, each value an array of presentations (OID4VP section 8.1), not a bare string.

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
| `sd_jwt_vc_issuance_4.js` | `sd_jwt_vc_issuance_4.js` | SD-JWT VC issuance step 4, the credential refresh (`sd-jwt-vc-issuance-4.html`) |
| `sd_jwt_vc_presentation_0.js` | `sd_jwt_vc_presentation_0.js` | SD-JWT VC presentation step 0, the flow chooser (`sd-jwt-vc-presentation-0.html`) |
| `sd_jwt_vc_presentation_1.js` | `sd_jwt_vc_presentation_1.js` | SD-JWT VC presentation step 1, the verifier's request (`sd-jwt-vc-presentation-1.html`) |
| `sd_jwt_vc_presentation_2.js` | `sd_jwt_vc_presentation_2.js` | SD-JWT VC presentation step 2, choose and present (`sd-jwt-vc-presentation-2.html`) |
| `sd_jwt_vc_presentation_3.js` | `sd_jwt_vc_presentation_3.js` | SD-JWT VC presentation step 3, the verdict (`sd-jwt-vc-presentation-3.html`) |

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
- `sd_jwt_vc_presentation.js` (the OID4VP / SD-JWT VC presentation workflow: the four pages against the mock Verifier, plus five negatives — a replayed presentation, a KB-JWT signed by the wrong key, an invented Disclosure, one removed after signing, and a claim the verifier asked for withheld. Needs only the STS mock)
- `sd_jwt_vc_waltid.js` (the same workflow against walt.id's `issuer-api2` — the interoperability check; needs the `waltid-issuer` container and Keycloak, and is skipped when `WALTID_ISSUER_URL` is unset)
- `oauth2_sts_endpoints.js` (the STS mock's authorization server endpoints; no browser)

**The SAML SP key pair is never committed.** `generateSpKeyPair()` in `common/common.sh` generates a fresh self-signed RSA pair per run and exports `SAML_SP_PRIVATE_KEY` / `SAML_SP_CERT` (read by the tests through `common/sp_keypair.js`) and `SAML_SP_SIGNING_CERT` (registered on the Keycloak SAML client). It lives only in the run's environment — the containerized suite generates its own inside the tests container. Do not reintroduce a key pair under `tests/fixtures/` (gitignored, along with `sp-key.pem` / `sp-cert.pem`).

There is no linting toolchain configured in this project.

## Key Implementation Notes

- **State persistence**: All user configuration (endpoints, client IDs, scopes, etc.) is stored in browser `localStorage` — passwords are intentionally excluded.
- **Token endpoint calls**: Can be made from the browser (client-side) or proxied through the API service (server-side). The UI lets users choose.
- **XSS prevention**: DOMPurify is used on the client when rendering token/claim data to the DOM.
- **SSL**: Server-side SSL certificate validation can be disabled for testing against self-signed certs.
