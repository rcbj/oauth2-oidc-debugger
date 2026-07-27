// File: sd_jwt_vc_issuance.js
//
// The SD-JWT VC issuance workflow, end to end:
//
//   step 1 (sd-jwt-vc-issuance-1.html)
//     retrieve the OID4VCI Credential Issuer Metadata, validate its
//     signed_metadata, populate the Configuration Parameters pane from it;
//     retrieve the authorization server's RFC 8414 metadata and populate the
//     same pane from that, under the localStorage names debugger.html uses;
//     then hand off with ?sdjwtvc=1.
//
//   the OIDC leg (debugger.html -> Keycloak -> debugger2.html)
//     the user authenticates and the authorization code is exchanged for
//     tokens WITHOUT further interaction, because the workflow drives it.
//
//   step 2 (sd-jwt-vc-issuance-2.html)
//     the tokens are shown, a holder key pair is generated, and approving the
//     issuance fetches a c_nonce, signs an openid4vci-proof+jwt and POSTs the
//     Credential Request.
//
//   step 3 (sd-jwt-vc-issuance-3.html)
//     the returned SD-JWT VC is parsed and verified: issuer signature, media
//     type, vct, cnf binding to the holder key, and every Disclosure's digest
//     against _sd. The credential is independently re-checked here in the test,
//     so a page that merely CLAIMS the credential is fine cannot pass.
//
//   negatives
//     denying issuance sends nothing; a replayed c_nonce and a request with no
//     access token are both refused by the issuer.
//
// Needs the mock credential issuer (the STS service) and Keycloak, as the other
// STS-backed tests do: WSTRUST_STS_URL locates the issuer,
// OID4VCI_ISSUER_URL overrides it outright, and KEYCLOAK_BASE_URL the IdP.

const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const logging = require("selenium-webdriver/lib/logging");
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require('commander');
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'sd_jwt_vc_issuance',
                                level: appconfig.LOG_LEVEL || 'info' });
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "http://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;
var fetchWait = Math.max(waitTime, 20000);

var stsUrl = process.env.WSTRUST_STS_URL || "http://localhost:8081/sts";
var issuerBase = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var issuerMetadataUrl = issuerBase + "/.well-known/openid-credential-issuer";
var keycloakBase = process.env.KEYCLOAK_BASE_URL || "http://localhost:8080";
var realmBase = keycloakBase + "/realms/debugger-testing";
var asMetadataUrl = realmBase + "/.well-known/oauth-authorization-server";
// The OIDC Authorization Code public client the debugger suite provisions. Its
// user has the same name and password.
var clientId = process.env.SD_JWT_VC_CLIENT_ID || "oidc-authorization-code-public";

var EXPECTED_VCT = "urn:idptools:sd-jwt-vc:identity";
var SD_JWT_VC_TYP = "dc+sd-jwt";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function b64u(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString("utf8")); }

function httpJson(url, options) {
  options = options || {};
  return fetch(url, options).then(function (r) {
    return r.text().then(function (text) {
      var body = null;
      try { body = JSON.parse(text); } catch (e) { /* not JSON */ }
      return { status: r.status, ok: r.ok, body: body, raw: text };
    });
  });
}

async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await driver.sleep(120);
  try { await e.click(); } catch (err) { await driver.executeScript("arguments[0].click();", e); }
  await driver.sleep(250);
}

function text(driver, id) {
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]); return e ? e.textContent.trim() : null;", id);
}
function value(driver, id) {
  return driver.executeScript(
    "var e = document.getElementById(arguments[0]); return e ? e.value : null;", id);
}
async function waitForStatus(driver, id, predicate, message) {
  var last = "";
  await driver.wait(async function () {
    last = (await text(driver, id)) || "";
    return predicate(last);
  }, fetchWait, message + " (last status: " + last + ")");
  return last;
}
function severeErrors(driver) {
  return driver.manage().logs().get(logging.Type.BROWSER).then(function (entries) {
    return entries.filter(function (e) { return e.level.name === "SEVERE"; })
      // A favicon that is not there is not a page error.
      .filter(function (e) { return !/favicon/.test(e.message); })
      .map(function (e) { return e.message; });
  });
}

// ---------------------------------------------------------------------------
// Step 1 — discovery and configuration
// ---------------------------------------------------------------------------
async function stepOne(driver) {
  log.info("=== Step 1: discover the issuer ===");
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
  await driver.executeScript("window.localStorage.clear();");
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
  await driver.sleep(500);

  // The Configuration Parameters pane must cover BOTH documents, not just one.
  var coverage = await driver.executeScript(
    "return { rows: document.querySelectorAll('#config_rows tr').length," +
    "         fields: document.querySelectorAll('#config_rows input, #config_rows select').length," +
    "         groups: document.querySelectorAll('#config_rows tr.vc-group-heading').length };");
  assert.ok(coverage.groups >= 4,
    "the Configuration Parameters pane should be grouped by document, got " + coverage.groups + " groups.");
  assert.ok(coverage.fields > 50,
    "the pane should carry every member both documents define, got " + coverage.fields + " fields.");
  log.info("[step1] Configuration Parameters pane: " + coverage.fields + " fields in " +
           coverage.groups + " groups.");

  // The RFC 8414 pane starts on the configured authorization server metadata
  // endpoint, so the workflow is usable without pasting a URL in.
  var asDefault = await value(driver, "oidc_discovery_endpoint");
  assert.ok(asDefault && asDefault.indexOf("/.well-known/oauth-authorization-server") !== -1,
    "the RFC 8414 pane should default to an RFC 8414 endpoint, got: " + JSON.stringify(asDefault));
  log.info("[step1] the RFC 8414 pane defaults to " + asDefault + ".");

  // ---- pane 1: the credential issuer metadata -----------------------------
  await driver.executeScript(
    "document.getElementById('vci_metadata_endpoint').value = arguments[0];", issuerMetadataUrl);
  await click(driver, By.id("vci_retrieve_button"));
  await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); }, "the credential issuer metadata was not retrieved");

  var note = await driver.executeScript(
    "var n = document.querySelector('#vci_metadata_table .discovery-info-note');" +
    "return n ? n.textContent.trim() : '';");
  assert.ok(note.indexOf("OID4VCI Credential Issuer Metadata") !== -1 && note.indexOf(issuerMetadataUrl) !== -1,
    "the table should say which document it is showing and where it came from. Got: " + note);
  var rows = await driver.executeScript(
    "return document.querySelectorAll('#vci_metadata_table tr').length;");
  assert.ok(rows > 5, "the credential issuer metadata table should list the document's members, got " + rows);
  log.info("[step1] " + note);

  // Its signed_metadata must verify — the same check debugger.html runs on an
  // RFC 8414 document, against keys resolved the SD-JWT VC way.
  await click(driver, By.id("vci_validate_signed_metadata_button"));
  var verdict = await waitForStatus(driver, "vci_signed_metadata_status",
    function (s) { return /^(VALID|INVALID|Could not)/.test(s); },
    "the credential issuer signed_metadata produced no verdict");
  assert.ok(verdict.indexOf("VALID") === 0,
    "the credential issuer's signed_metadata should verify. Got: " + verdict);
  assert.ok(verdict.indexOf("iss matches the issuer") !== -1,
    "the verdict should confirm iss is the credential issuer. Got: " + verdict);
  log.info("[step1] signed_metadata: " + verdict);

  // Retrieving fills the pane on its own; the Populate button only re-applies
  // the document. Check the values BEFORE clicking it.
  var onRetrieveAlone = await driver.executeScript(
    "return ['vci_credential_endpoint','vci_nonce_endpoint','vci_vct']" +
    "  .map(function (i) { return document.getElementById(i).value; });");
  assert.ok(onRetrieveAlone.every(Boolean),
    "retrieving the credential issuer metadata should populate the pane without a further click. Got: " +
    JSON.stringify(onRetrieveAlone));
  log.info("[step1] OK — retrieving the issuer metadata populated the pane on its own.");

  await click(driver, By.id("vci_populate_button"));
  await driver.sleep(400);
  var populated = await driver.executeScript(
    "return ['vci_credential_issuer','vci_credential_endpoint','vci_nonce_endpoint'," +
    "        'vci_credential_configuration_id','vci_format','vci_vct']" +
    "  .map(function (i) { return document.getElementById(i).value; });");
  assert.strictEqual(populated[0], issuerBase, "credential_issuer should be the mock issuer.");
  assert.strictEqual(populated[1], issuerBase + "/oid4vci/credential", "credential_endpoint should be populated.");
  assert.strictEqual(populated[2], issuerBase + "/oid4vci/nonce", "nonce_endpoint should be populated.");
  assert.strictEqual(populated[4], "dc+sd-jwt", "the credential format should be dc+sd-jwt.");
  assert.strictEqual(populated[5], EXPECTED_VCT, "the vct should come from the credential configuration.");
  log.info("[step1] OID4VCI values populated: " + populated.join(", "));

  // A member whose value is a JSON structure is pretty-printed, in the table and
  // in the pane. A flat array of scalars stays on one line.
  var cells = await driver.executeScript(
    "var rows = document.querySelectorAll('#vci_metadata_table tr'), out = {};" +
    "for (var i = 1; i < rows.length; i++) {" +
    "  var td = rows[i].querySelectorAll('td');" +
    "  out[td[0].textContent.trim()] = { pretty: !!td[1].querySelector('pre.metadata-json')," +
    "                                    text: td[1].textContent };" +
    "} return out;");
  var structured = ["credential_configurations_supported", "display", "credential_response_encryption",
                    "batch_credential_issuance"];
  structured.forEach(function (member) {
    assert.ok(cells[member], "the table should list " + member + ".");
    assert.ok(cells[member].pretty,
      member + " is a JSON structure and should be pretty-printed in the table.");
    assert.ok(cells[member].text.indexOf("\n  ") !== -1,
      member + " should be indented, not one line. Got: " + cells[member].text.slice(0, 60));
    JSON.parse(cells[member].text);   // throws if the pretty printing mangled it
  });
  assert.strictEqual(cells.credential_endpoint.pretty, false,
    "a plain string should not be turned into a JSON block.");
  assert.strictEqual(cells.authorization_servers.pretty, false,
    "a flat array of scalars should stay on one line rather than becoming taller.");
  log.info("[step1] OK — " + structured.length + " structured members are pretty-printed in the table; " +
           "strings and flat arrays are not.");

  var jsonFields = await driver.executeScript(
    "var out = {};" +
    "['vci_display','vci_batch_credential_issuance','vci_credential_response_encryption'," +
    " 'vci_credential_issuer','vci_authorization_servers'].forEach(function (id) {" +
    "  var e = document.getElementById(id);" +
    "  out[id] = { tag: e.tagName, rows: e.rows || 0, value: e.value };" +
    "}); return out;");
  ["vci_display", "vci_batch_credential_issuance", "vci_credential_response_encryption"].forEach(function (id) {
    assert.strictEqual(jsonFields[id].tag, "TEXTAREA",
      id + " holds JSON, so it needs a textarea — a one-line input cannot show it. Got: " + jsonFields[id].tag);
    assert.ok(jsonFields[id].value.indexOf("\n  ") !== -1,
      id + " should hold pretty-printed JSON. Got: " + jsonFields[id].value.slice(0, 60));
    JSON.parse(jsonFields[id].value);
    assert.ok(jsonFields[id].rows >= 3, id + " should be tall enough to read.");
  });
  assert.strictEqual(jsonFields.vci_credential_issuer.tag, "INPUT",
    "a scalar member should stay a one-line input.");
  assert.strictEqual(jsonFields.vci_authorization_servers.tag, "INPUT",
    "a flat array should stay a one-line input.");
  log.info("[step1] OK — the JSON members are pretty-printed textareas, the scalar ones plain inputs.");

  // ... and that survives a reload, where the values come back out of local
  // storage as plain strings.
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vci_display")), waitTime);
  await driver.sleep(700);
  var afterReload = await driver.executeScript(
    "var e = document.getElementById('vci_display');" +
    "return { tag: e.tagName, value: e.value };");
  assert.strictEqual(afterReload.tag, "TEXTAREA", "the JSON field should still be a textarea after a reload.");
  assert.ok(afterReload.value.indexOf("\n  ") !== -1, "and should still be pretty-printed.");
  log.info("[step1] OK — pretty-printed JSON survives a reload.");

  // The issuer names its authorization server, so pane 2's URL is offered.
  var asUrl = await value(driver, "oidc_discovery_endpoint");
  assert.ok(asUrl && asUrl.indexOf("/.well-known/oauth-authorization-server") !== -1,
    "retrieving the issuer metadata should offer its authorization server's RFC 8414 URL, got: " + asUrl);
  log.info("[step1] authorization server URL defaulted to " + asUrl);

  // ---- pane 2: the authorization server metadata --------------------------
  await driver.executeScript(
    "document.getElementById('oidc_discovery_endpoint').value = arguments[0];", asMetadataUrl);
  await click(driver, By.id("as_retrieve_button"));
  await waitForStatus(driver, "as_signed_metadata_status",
    function (s) { return /^Retrieved/.test(s); }, "the authorization server metadata was not retrieved");
  // Same for the authorization server document: every endpoint field the
  // document defines is filled by the retrieval itself.
  var endpointsOnRetrieve = await driver.executeScript(
    "var out = {};" +
    "['authorization_endpoint','token_endpoint','jwks_endpoint','registration_endpoint'," +
    " 'introspection_endpoint','revocation_endpoint','device_authorization_endpoint'," +
    " 'oidc_userinfo_endpoint'].forEach(function (i) {" +
    "  out[i] = document.getElementById(i).value;" +
    "}); return out;");
  var unfilled = Object.keys(endpointsOnRetrieve).filter(function (id) { return !endpointsOnRetrieve[id]; });
  assert.strictEqual(unfilled.length, 0,
    "retrieving the RFC 8414 document should populate every endpoint field it defines, without a further " +
    "click. These are still empty: " + unfilled.join(", "));
  log.info("[step1] OK — retrieving the RFC 8414 document filled all " +
           Object.keys(endpointsOnRetrieve).length + " endpoint fields on its own.");

  await click(driver, By.id("as_populate_button"));
  await driver.sleep(400);

  var oidcValues = await driver.executeScript(
    "return { authorization_endpoint: document.getElementById('authorization_endpoint').value," +
    "         token_endpoint: document.getElementById('token_endpoint').value," +
    "         issuer: document.getElementById('issuer').value," +
    "         scope: document.getElementById('scope').value };");
  assert.ok(oidcValues.authorization_endpoint.indexOf(realmBase) === 0,
    "the authorization endpoint should come from the authorization server metadata, got: " +
    oidcValues.authorization_endpoint);
  assert.ok(oidcValues.token_endpoint.indexOf(realmBase) === 0,
    "the token endpoint should come from the authorization server metadata.");
  assert.strictEqual(oidcValues.issuer, realmBase, "the issuer should be the realm.");
  log.info("[step1] authorization server values populated: " + JSON.stringify(oidcValues));

  // The six members RFC 8414 adds to OIDC Discovery's set have fields here (and
  // on the debugger pages) too: the ones this server publishes are populated,
  // and the one it does not is marked rather than left blank and ambiguous.
  var rfc8414Only = await driver.executeScript(
    "var out = {};" +
    "['revocation_endpoint_auth_methods_supported','introspection_endpoint_auth_methods_supported'," +
    " 'code_challenge_methods_supported','signed_metadata'].forEach(function (i) {" +
    "  var e = document.getElementById(i);" +
    "  out[i] = e ? { value: e.value, note: e.placeholder || '' } : null;" +
    "}); return out;");
  Object.keys(rfc8414Only).forEach(function (id) {
    assert.ok(rfc8414Only[id], "the pane should carry the RFC 8414 member " + id + ".");
  });
  assert.ok(rfc8414Only.code_challenge_methods_supported.value.indexOf("S256") !== -1,
    "code_challenge_methods_supported should be populated from the document. Got: " +
    rfc8414Only.code_challenge_methods_supported.value);
  assert.ok(rfc8414Only.revocation_endpoint_auth_methods_supported.value,
    "revocation_endpoint_auth_methods_supported should be populated from the document.");
  assert.strictEqual(rfc8414Only.signed_metadata.value, "",
    "this authorization server publishes no signed_metadata, so the field should be empty.");
  assert.strictEqual(rfc8414Only.signed_metadata.note, "-->not defined<--",
    "a member the document omits should be marked, not left blank. Got: " +
    JSON.stringify(rfc8414Only.signed_metadata));
  log.info("[step1] OK — the RFC 8414-only members are populated, and signed_metadata is marked not defined.");

  // The whole point of pane 2: this is the SAME storage debugger.html reads.
  var shared = await driver.executeScript(
    "return { authorization_endpoint: localStorage.getItem('authorization_endpoint')," +
    "         token_endpoint: localStorage.getItem('token_endpoint')," +
    "         document: !!localStorage.getItem('discovery_info')," +
    "         source: localStorage.getItem('metadata_source') };");
  assert.strictEqual(shared.authorization_endpoint, oidcValues.authorization_endpoint,
    "the authorization endpoint must be stored under the name debugger.html reads.");
  assert.strictEqual(shared.token_endpoint, oidcValues.token_endpoint,
    "the token endpoint must be stored under the name debugger.html reads.");
  assert.ok(shared.document, "the retrieved document must be stored under debugger.html's discovery_info key.");
  assert.strictEqual(shared.source, "rfc8414", "the stored metadata source should say RFC 8414.");
  log.info("[step1] OK — the configuration is shared with debugger.html.");

  // ---- the client settings the authorization request needs ----------------
  // The redirect URI is the deployment's own /callback — the debugger pages pin
  // it to their configured origin, and this pane defaults it the same way.
  var redirectUri = await value(driver, "redirect_uri");
  assert.ok(redirectUri && /\/callback$/.test(redirectUri),
    "the pane should default the redirect URI to this deployment's /callback, got: " + redirectUri);
  await driver.executeScript(
    "document.getElementById('client_id').value = arguments[0];" +
    "document.getElementById('scope').value = 'openid profile email';", clientId);
  await click(driver, By.id("config_save_button"));
  await driver.sleep(300);
  assert.strictEqual(await text(driver, "config_status"), "Saved.", "the configuration should save.");

  var summary = await text(driver, "handoff_credential");
  assert.ok(summary.indexOf("IdentityCredential") !== -1 && summary.indexOf(EXPECTED_VCT) !== -1,
    "the hand-off pane should say which credential will be requested, got: " + summary);
  log.info("[step1] OK — hand-off summary: " + summary);
}

// ---------------------------------------------------------------------------
// The OIDC leg — driven by the workflow, so the only interaction is the login
// ---------------------------------------------------------------------------
async function oidcLeg(driver) {
  log.info("=== The OIDC Authorization Code leg ===");
  var handoffUrl = await text(driver, "handoff_url");
  assert.ok(handoffUrl.indexOf("/debugger.html?sdjwtvc=1") !== -1,
    "the hand-off pane should name the URL it goes to, got: " + handoffUrl);
  await click(driver, By.id("start_issuance_button"));

  // debugger.html is only a waypoint: it marks the workflow active and issues
  // the authorization request straight away, so the next thing to appear is
  // the IdP's login form.
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the workflow should have started the authorization request without a further click.");
  var url = await driver.getCurrentUrl();
  assert.ok(url.indexOf(realmBase + "/protocol/openid-connect/auth") === 0,
    "the browser should be at the authorization endpoint from the metadata, got: " + url);
  assert.ok(url.indexOf("client_id=" + encodeURIComponent(clientId)) !== -1,
    "the authorization request should carry the configured client_id, got: " + url);
  assert.ok(url.indexOf("response_type=code") !== -1,
    "the workflow should use the Authorization Code flow, got: " + url);
  log.info("[oidc] the authorization request started on its own and reached the IdP.");
  await driver.findElement(By.id("username")).sendKeys(clientId);
  await driver.findElement(By.id("password")).sendKeys(clientId);
  await click(driver, By.id("kc-login"));

  // ... through debugger2.html, which exchanges the code and comes back.
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-2.html"), fetchWait,
    "debugger2.html should have exchanged the code for tokens and returned to step 2.");
  log.info("[oidc] OK — debugger2.html exchanged the code and returned to step 2.");
}

// ---------------------------------------------------------------------------
// Step 2 — the tokens, the approval, and the credential request
// ---------------------------------------------------------------------------
async function stepTwo(driver) {
  log.info("=== Step 2: approve and request the credential ===");
  await driver.wait(until.elementLocated(By.id("vc_access_token")), waitTime);
  await driver.sleep(600);

  var accessToken = await value(driver, "vc_access_token");
  var idToken = await value(driver, "vc_id_token");
  assert.ok(accessToken && accessToken.split(".").length === 3,
    "step 2 should show the access token the OIDC leg obtained.");
  assert.ok(idToken && idToken.split(".").length === 3, "step 2 should show the ID token.");
  var idClaims = jsonFromB64u(idToken.split(".")[1]);
  assert.strictEqual(idClaims.azp, clientId, "the ID token should belong to the client under test.");
  log.info("[step2] tokens present; the authenticated user is " + idClaims.preferred_username + ".");

  // The holder key pair is generated in the browser, before any approval.
  var holderJwk = JSON.parse(await text(driver, "vc_holder_jwk"));
  assert.strictEqual(holderJwk.kty, "EC", "the holder key should be an EC key.");
  assert.strictEqual(holderJwk.crv, "P-256", "the holder key should be P-256 (ES256).");
  assert.ok(!holderJwk.d, "the PUBLIC holder key must not carry the private component d.");
  log.info("[step2] holder key generated: " + holderJwk.kty + " " + holderJwk.crv + ".");

  // The whole request is built up front, so the pane shows what Approve will
  // send rather than filling in after the fact — by which point this page has
  // already handed over to step 3.
  var preview = await driver.executeScript(
    "return { nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         proof: document.getElementById('vc_proof_jwt').value," +
    "         body: document.getElementById('vc_request_body').textContent.trim() };");
  assert.ok(preview.nonce && preview.nonce !== "—",
    "the c_nonce should be fetched and shown before approving. Got: " + JSON.stringify(preview.nonce));
  assert.strictEqual(preview.proof.split(".").length, 3,
    "the proof of possession should be signed and shown before approving. Got: " + preview.proof.slice(0, 40));
  var proofHeader = jsonFromB64u(preview.proof.split(".")[0]);
  var proofClaims = jsonFromB64u(preview.proof.split(".")[1]);
  // The pane also shows that proof taken back out of the request body and
  // decoded, so the header and payload can be read without copying it anywhere.
  var decoded = await driver.executeScript(
    "return { header: document.getElementById('jwt_header').value," +
    "         payload: document.getElementById('jwt_payload').value };");
  assert.deepStrictEqual(JSON.parse(decoded.header), proofHeader,
    "the JWT Header box should be the decoded header of the proof in proofs.jwt.");
  assert.deepStrictEqual(JSON.parse(decoded.payload), proofClaims,
    "the JWT Payload box should be the decoded payload of the proof in proofs.jwt.");
  assert.ok(decoded.header.indexOf("\n  ") !== -1 && decoded.payload.indexOf("\n  ") !== -1,
    "both should be pretty-printed.");
  log.info("[step2] OK — the proof from proofs.jwt is decoded into the JWT Header and JWT Payload boxes.");
  assert.strictEqual(proofHeader.typ, "openid4vci-proof+jwt", "the proof should carry the OID4VCI proof type.");
  assert.strictEqual(proofHeader.alg, "ES256", "the proof should be signed ES256.");
  assert.deepStrictEqual(proofHeader.jwk, holderJwk, "the proof should carry the holder public key.");
  assert.strictEqual(proofClaims.nonce, preview.nonce, "the proof should carry the c_nonce that was fetched.");
  assert.strictEqual(proofClaims.aud, await text(driver, "vc_credential_issuer"),
    "the proof's audience must be the credential issuer. Got: " + proofClaims.aud);
  var requestBody = JSON.parse(preview.body);
  assert.strictEqual(requestBody.credential_configuration_id, "IdentityCredential",
    "the request body should name the credential being asked for.");
  assert.deepStrictEqual(requestBody.proofs.jwt, [preview.proof],
    "the request body should carry the proof shown above it.");
  log.info("[step2] OK — the c_nonce, the signed proof and the request body are all shown before approving.");

  // The Approve pane spells out the whole call: method, URL, headers, body.
  var assembled = await value(driver, "vc_approval_request");
  assert.ok(assembled, "the Approve pane should show the call that Approve will make.");
  var endpoint = await text(driver, "vc_credential_endpoint");
  var firstLine = assembled.split("\n")[0];
  assert.strictEqual(firstLine, "POST " + endpoint,
    "the first line should be the method and the full URL. Got: " + firstLine);
  assert.ok(/^Content-Type: application\/json$/m.test(assembled),
    "the assembled call should show the content type. Got: " + assembled.slice(0, 120));
  assert.ok(assembled.indexOf("Authorization: Bearer " + (await value(driver, "vc_access_token"))) !== -1,
    "the assembled call should show the access token being presented as a Bearer credential.");
  var assembledBody = JSON.parse(assembled.slice(assembled.indexOf("\n{") + 1));
  assert.deepStrictEqual(assembledBody, requestBody,
    "the body in the assembled call should be the request body shown above it.");
  log.info("[step2] OK — the Approve pane shows the assembled call: " + firstLine +
           " with " + assembled.split("\n").length + " lines.");

  // Denying must send nothing at all.
  await click(driver, By.id("vc_deny_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-1.html"), waitTime,
    "denying should return to step 1.");
  var afterDeny = await driver.executeScript("return localStorage.getItem('sdjwtvc_credential');");
  assert.strictEqual(afterDeny, null, "denying must not obtain a credential.");
  log.info("[step2] OK — Deny returned to step 1 with no credential.");

  // Back to step 2 to approve. The tokens are still in storage, so the page
  // stands on its own.
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.sleep(600);
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-3.html"), fetchWait,
    "approving should obtain the credential and open step 3.");
  log.info("[step2] OK — approving fetched a nonce, signed a proof, and got a credential.");
  return { accessToken: accessToken, holderJwk: holderJwk, idClaims: idClaims };
}

// ---------------------------------------------------------------------------
// Step 3 — the credential, checked by the page AND by this test
// ---------------------------------------------------------------------------
async function stepThree(driver, context) {
  log.info("=== Step 3: the issued credential ===");
  await driver.wait(until.elementLocated(By.id("vc_credential_raw")), waitTime);
  await driver.sleep(900);

  var raw = await value(driver, "vc_credential_raw");
  assert.ok(raw, "step 3 should show the credential.");

  // ---- what the page says --------------------------------------------------
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { name: td[0].textContent.trim(), result: td[1].textContent.trim(), detail: td[2].textContent.trim() };" +
    "});");
  assert.ok(checks.length >= 7, "step 3 should report its checks, got " + checks.length + ".");
  var failed = checks.filter(function (c) { return c.result === "FAILED"; });
  assert.strictEqual(failed.length, 0,
    "no check should fail: " + failed.map(function (c) { return c.name + " — " + c.detail; }).join("; "));
  var signature = checks.filter(function (c) { return c.name === "Issuer signature"; })[0];
  assert.ok(signature && signature.result === "OK",
    "the page must verify the issuer signature against the issuer's published keys. Got: " +
    JSON.stringify(signature));
  var binding = checks.filter(function (c) { return c.name === "Key binding (cnf)"; })[0];
  assert.ok(binding && binding.detail.indexOf("the holder key generated in step 2") !== -1,
    "the credential must be bound to the holder key from step 2. Got: " + JSON.stringify(binding));
  var digests = checks.filter(function (c) { return c.name === "Disclosure digests"; })[0];
  assert.ok(digests && digests.result === "OK",
    "every Disclosure's digest must be found in _sd. Got: " + JSON.stringify(digests));
  log.info("[step3] the page's checks all pass (" + checks.length + " of them).");

  var disclosureRows = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_disclosures tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { claim: td[1].textContent.trim(), value: td[2].textContent.trim()," +
    "           salt: td[3].textContent.trim(), digest: td[4].textContent.trim()," +
    "           inSd: td[5].textContent.trim() };" +
    "});");
  assert.ok(disclosureRows.length >= 4,
    "the issuer offers several selectively-disclosable claims, got " + disclosureRows.length + ".");
  assert.ok(disclosureRows.every(function (r) { return r.inSd === "yes"; }),
    "every Disclosure shown should be matched to a digest in _sd.");
  log.info("[step3] disclosures shown: " +
           disclosureRows.map(function (r) { return r.claim; }).join(", "));

  // ---- what the CREDENTIAL says, checked here, independently ---------------
  var parts = raw.split("~");
  assert.ok(raw.endsWith("~"),
    "RFC 9901: the Combined Serialization must end in ~ when there is no Key Binding JWT.");
  var issuerJwt = parts[0];
  var encodedDisclosures = parts.slice(1).filter(Boolean);
  var header = jsonFromB64u(issuerJwt.split(".")[0]);
  var payload = jsonFromB64u(issuerJwt.split(".")[1]);

  assert.strictEqual(header.typ, SD_JWT_VC_TYP, "the issuer-signed JWT should carry typ " + SD_JWT_VC_TYP + ".");
  assert.strictEqual(payload.vct, EXPECTED_VCT, "the credential's vct should be the configured one.");
  assert.strictEqual(payload.iss, issuerBase, "the credential should be issued by the mock credential issuer.");
  assert.strictEqual(payload._sd_alg, "sha-256", "_sd_alg should be sha-256.");
  assert.ok(Array.isArray(payload._sd) && payload._sd.length >= encodedDisclosures.length,
    "_sd should carry at least one digest per Disclosure.");
  assert.ok(payload.cnf && payload.cnf.jwk, "the credential should be bound to a holder key (cnf.jwk).");
  assert.strictEqual(payload.cnf.jwk.x, context.holderJwk.x,
    "cnf.jwk must be the holder key generated in the browser.");
  assert.strictEqual(payload.cnf.jwk.y, context.holderJwk.y, "cnf.jwk must be the holder key (y).");
  assert.ok(payload.exp > Math.floor(Date.now() / 1000), "the credential should not already be expired.");

  // Each Disclosure hashes to a digest in _sd — recomputed here rather than
  // trusting the page's arithmetic.
  var seen = {};
  encodedDisclosures.forEach(function (enc) {
    var digest = b64u(crypto.createHash("sha256").update(enc, "ascii").digest());
    assert.ok(payload._sd.indexOf(digest) >= 0,
      "the digest of Disclosure " + enc + " is not in _sd.");
    var arr = JSON.parse(b64uDecode(enc).toString("utf8"));
    assert.strictEqual(arr.length, 3, "an object-property Disclosure is [salt, name, value].");
    assert.ok(b64uDecode(arr[0]).length >= 16, "a Disclosure salt should carry at least 128 bits of entropy.");
    seen[arr[1]] = arr[2];
  });
  assert.ok(payload._sd.length > encodedDisclosures.length,
    "the issuer should add at least one decoy digest, so _sd does not reveal the claim count.");
  log.info("[step3] the credential carries " + encodedDisclosures.length + " Disclosure(s) and " +
           (payload._sd.length - encodedDisclosures.length) + " decoy digest(s).");

  // The credential describes whoever authenticated.
  assert.ok(!("given_name" in payload), "given_name must NOT be a plain claim — it is selectively disclosable.");
  assert.ok("given_name" in seen && "email" in seen,
    "the credential should disclose the identity claims the issuer advertised, got: " +
    Object.keys(seen).join(", "));
  var expectedEmail = context.idClaims.email;
  if (expectedEmail) {
    assert.strictEqual(seen.email, expectedEmail,
      "the credential should describe the user who authenticated (" + expectedEmail + ").");
  }
  log.info("[step3] the credential describes " + seen.email + ".");

  // The issuer's signature, verified here against its published JWKS.
  var jwtVcIssuer = await httpJson(issuerBase + "/.well-known/jwt-vc-issuer");
  assert.ok(jwtVcIssuer.ok && jwtVcIssuer.body.jwks_uri,
    "the issuer must publish JWT VC Issuer Metadata naming its jwks_uri.");
  var jwks = await httpJson(jwtVcIssuer.body.jwks_uri);
  var key = crypto.createPublicKey({ key: jwks.body.keys[0], format: "jwk" });
  var signed = issuerJwt.split(".").slice(0, 2).join(".");
  assert.ok(crypto.verify("sha256", Buffer.from(signed), key, b64uDecode(issuerJwt.split(".")[2])),
    "the credential's issuer signature must verify against the issuer's published key.");
  log.info("[step3] OK — the issuer signature verifies independently of the page.");

  // The resulting claim set is what a verifier would see.
  var claims = JSON.parse(await text(driver, "vc_claims"));
  assert.ok(!("_sd" in claims) && !("_sd_alg" in claims),
    "the resulting claim set should not carry the SD-JWT machinery.");
  Object.keys(seen).forEach(function (name) {
    assert.deepStrictEqual(claims[name], seen[name],
      "the resulting claim set should include the disclosed claim " + name + ".");
  });
  log.info("[step3] OK — the resulting claim set matches the disclosures.");
}

// ---------------------------------------------------------------------------
// The Inspect links on step 2 lead to the JWT detail page, which has to show
// the token step 2 is showing and come BACK to step 2 — not to debugger2.html,
// which is where it goes by default.
// ---------------------------------------------------------------------------
async function inspectLinksReturnHere(driver) {
  log.info("=== The Inspect links on step 2 ===");
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_access_token")), waitTime);
  await driver.sleep(400);
  var onPage2 = {
    access: await value(driver, "vc_access_token"),
    id: await value(driver, "vc_id_token")
  };
  assert.ok(onPage2.access && onPage2.id, "step 2 should be showing the tokens for this check.");

  for (const which of ["access", "id"]) {
    var index = which === "access" ? 0 : 1;
    var links = await driver.findElements(By.linkText("Inspect"));
    assert.ok(links.length > index, "step 2 should offer an Inspect link for the " + which + " token.");
    var href = await links[index].getAttribute("href");
    assert.ok(href.indexOf("from=sd-jwt-vc-issuance-2.html") !== -1,
      "the Inspect link should name the page it came from, so the detail page can come back. Got: " + href);
    await driver.executeScript("arguments[0].click();", links[index]);
    await driver.wait(until.elementLocated(By.id("jwt_payload")), waitTime);
    await driver.sleep(500);

    // The detail page must be decoding the token step 2 was showing.
    var shown = JSON.parse(await value(driver, "jwt_payload"));
    var expected = jsonFromB64u(onPage2[which].split(".")[1]);
    assert.deepStrictEqual(shown, expected,
      "the detail page should decode the " + which + " token step 2 is showing.");

    var returnLinks = await driver.findElements(By.css("a.return_link"));
    assert.ok(returnLinks.length, "the detail page should offer a return link.");
    var target = await returnLinks[0].getAttribute("href");
    assert.ok(/sd-jwt-vc-issuance-2\.html$/.test(target),
      "the return link should come back to step 2, got: " + target);
    assert.ok(/step 2/i.test(await returnLinks[0].getText()),
      "the return link should say where it goes: " + (await returnLinks[0].getText()));
    await driver.executeScript("arguments[0].click();", returnLinks[0]);
    await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime,
      "the return link did not come back to step 2.");
    log.info("[inspect] OK — the " + which + " token is decoded there and the link returns to step 2.");
  }

  // Everything else still returns to debugger2.html, and the parameter cannot
  // be turned into a redirect somewhere else.
  for (const query of ["?type=access", "?type=access&from=https://evil.example.com", "?type=access&from=nope"]) {
    await driver.get(baseUrl + "/token_detail.html" + query);
    await driver.wait(until.elementLocated(By.css("a.return_link")), waitTime);
    await driver.sleep(200);
    var link = (await driver.findElements(By.css("a.return_link")))[0];
    assert.ok(/\/debugger2\.html\?redirectFromTokenDetail=true$/.test(await link.getAttribute("href")),
      "with " + query + " the return link should stay on the default. Got: " + (await link.getAttribute("href")));
  }
  log.info("[inspect] OK — an unknown or hostile from= falls back to debugger2.html.");
}

// ---------------------------------------------------------------------------
// Step 2 stands on its own: opened directly, with an issuer configured but no
// tokens yet, it still shows the request it would make. Only the access token
// is missing, and it says so.
// ---------------------------------------------------------------------------
async function stepTwoWithoutTokens(driver) {
  log.info("=== Step 2 opened directly, before authenticating ===");
  await driver.executeScript(
    "localStorage.removeItem('token_access_token');" +
    "localStorage.removeItem('token_id_token');" +
    "localStorage.removeItem('token_refresh_token');");
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "with no access token, step 2 still has to show the request it would make.");

  var state = await driver.executeScript(
    "return { nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         body: document.getElementById('vc_request_body').textContent.trim()," +
    "         tokens: document.getElementById('tokens_status').textContent.trim()," +
    "         approval: document.getElementById('vc_approval_status').textContent.trim() };");
  assert.ok(state.nonce && state.nonce.indexOf("—") !== 0,
    "the c_nonce should be fetched even before authenticating. Got: " + JSON.stringify(state.nonce));
  assert.ok(JSON.parse(state.body).proofs.jwt[0], "the request body should be built and shown.");
  assert.ok(/no access token/i.test(state.tokens),
    "the tokens pane should say the access token is missing. Got: " + state.tokens);
  assert.ok(/no access token/i.test(state.approval),
    "the approval status should say what is missing rather than showing three blank boxes. Got: " +
    state.approval);
  log.info("[step2] OK — the request is shown without tokens, and the missing token is named.");
}

// ---------------------------------------------------------------------------
// Preparing the request up front means the c_nonce in it can be spent — or can
// expire — before the user gets around to approving. The page has to notice and
// rebuild rather than fail. Here the nonce is spent behind the page's back,
// using the holder key it generated, and Approve must still work.
//
// Runs AFTER the browser-console check: the first attempt legitimately earns a
// 400 from the issuer, which Chrome logs as a page error.
// ---------------------------------------------------------------------------
async function staleProofRecovery(driver) {
  log.info("=== A proof that went stale before Approve ===");
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-2.html");
  await driver.wait(until.elementLocated(By.id("vc_approve_button")), waitTime);
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 never prepared a proof.");
  await driver.sleep(300);

  var state = await driver.executeScript(
    "return { privateJwk: localStorage.getItem('sdjwtvc_holder_private_jwk')," +
    "         nonce: document.getElementById('vc_nonce').textContent.trim()," +
    "         issuer: document.getElementById('vc_credential_issuer').textContent.trim()," +
    "         endpoint: document.getElementById('vc_credential_endpoint').textContent.trim() };");

  // Spend the page's nonce: a second proof over the same nonce, signed with the
  // same holder key, sent straight to the issuer.
  var priv = crypto.createPrivateKey({ key: JSON.parse(state.privateJwk), format: "jwk" });
  var pub = crypto.createPublicKey(priv).export({ format: "jwk" });
  var head = b64u(JSON.stringify({ typ: "openid4vci-proof+jwt", alg: "ES256",
    jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y } }));
  var claims = b64u(JSON.stringify({ iss: clientId, aud: state.issuer,
    iat: Math.floor(Date.now() / 1000), nonce: state.nonce }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: priv, dsaEncoding: "ieee-p1363" }));
  var stolen = await httpJson(state.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer spender" },
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims + "." + sig] } })
  });
  assert.ok(stolen.ok, "the setup for this check failed: the issuer refused the second proof (" + stolen.raw + ").");

  // The page's own proof is now unusable. Approving must still get a credential.
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-3.html"), fetchWait,
    "approving with a spent c_nonce should rebuild the proof and retry, not fail.");
  var credential = await value(driver, "vc_credential_raw");
  assert.ok(credential && credential.indexOf("~") > 0,
    "the retry should have produced a credential.");
  log.info("[stale proof] OK — a spent c_nonce is rebuilt and the request retried.");
}

// ---------------------------------------------------------------------------
// The issuer's own defences — a mock that accepts anything would make the
// checks above meaningless.
// ---------------------------------------------------------------------------
async function issuerNegatives() {
  log.info("=== The credential endpoint's checks ===");
  var meta = (await httpJson(issuerMetadataUrl)).body;

  var noAuth = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}"
  });
  assert.strictEqual(noAuth.status, 401, "a credential request with no access token must be refused.");
  assert.strictEqual(noAuth.body.error, "invalid_token", "the refusal should be invalid_token.");

  var noProof = await httpJson(meta.credential_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer whatever" },
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential" })
  });
  assert.strictEqual(noProof.status, 400, "a credential request with no proof must be refused.");
  assert.strictEqual(noProof.body.error, "invalid_proof", "the refusal should be invalid_proof.");

  // A well-formed proof, then the same proof again: the nonce is single use.
  var pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = pair.publicKey.export({ format: "jwk" });
  var nonce = (await httpJson(meta.nonce_endpoint, { method: "POST" })).body.c_nonce;
  var head = b64u(JSON.stringify({ typ: "openid4vci-proof+jwt", alg: "ES256", jwk: jwk }));
  var claims = b64u(JSON.stringify({
    iss: clientId, aud: meta.credential_issuer, iat: Math.floor(Date.now() / 1000), nonce: nonce
  }));
  var sig = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var proof = head + "." + claims + "." + sig;
  var body = JSON.stringify({ credential_configuration_id: "IdentityCredential", proofs: { jwt: [proof] } });
  var headers = { "Content-Type": "application/json", "Authorization": "Bearer opaque-token" };

  var first = await httpJson(meta.credential_endpoint, { method: "POST", headers: headers, body: body });
  assert.ok(first.ok, "a well-formed request should be accepted, got HTTP " + first.status + " " + first.raw);
  var replay = await httpJson(meta.credential_endpoint, { method: "POST", headers: headers, body: body });
  assert.strictEqual(replay.status, 400, "replaying a c_nonce must be refused.");
  assert.strictEqual(replay.body.error, "invalid_proof", "a replayed nonce should be an invalid_proof.");

  // A proof whose signature does not match the key in its own header.
  var nonce2 = (await httpJson(meta.nonce_endpoint, { method: "POST" })).body.c_nonce;
  var claims2 = b64u(JSON.stringify({
    iss: clientId, aud: meta.credential_issuer, iat: Math.floor(Date.now() / 1000), nonce: nonce2
  }));
  var tampered = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: headers,
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims2 + "." + sig] } })
  });
  assert.strictEqual(tampered.status, 400, "a proof with a bad signature must be refused.");
  assert.ok(/signature does not verify/.test(tampered.body.error_description || ""),
    "the refusal should name the signature. Got: " + tampered.body.error_description);

  // A proof for someone else's audience.
  var nonce3 = (await httpJson(meta.nonce_endpoint, { method: "POST" })).body.c_nonce;
  var claims3 = b64u(JSON.stringify({
    iss: clientId, aud: "https://another.example.com", iat: Math.floor(Date.now() / 1000), nonce: nonce3
  }));
  var sig3 = b64u(crypto.sign("sha256", Buffer.from(head + "." + claims3),
    { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  var wrongAud = await httpJson(meta.credential_endpoint, {
    method: "POST", headers: headers,
    body: JSON.stringify({ credential_configuration_id: "IdentityCredential",
                           proofs: { jwt: [head + "." + claims3 + "." + sig3] } })
  });
  assert.strictEqual(wrongAud.status, 400, "a proof addressed to another issuer must be refused.");
  log.info("[issuer] OK — no token, no proof, replayed nonce, bad signature and wrong audience are all refused.");
}

// ---------------------------------------------------------------------------
// The query parameter is what puts debugger.html into this workflow. With no
// configuration to run on it must SAY so rather than silently doing nothing —
// which is also the only way to observe the parameter's effect without racing
// the redirect it normally causes.
async function handoffParameterCheck(driver) {
  log.info("=== The ?sdjwtvc=1 hand-off parameter ===");
  await driver.get(baseUrl + "/debugger.html");
  await driver.wait(until.elementLocated(By.id("oidc_discovery_endpoint")), waitTime);
  // Empty the two values the hand-off needs, but leave the page "initialized"
  // so it does not helpfully put its dummy defaults back — an unconfigured
  // hand-off is what is under test here.
  await driver.executeScript(
    "window.localStorage.clear();" +
    "localStorage.setItem('initialized', true);" +
    "localStorage.setItem('debugger_initialized', true);" +
    "localStorage.setItem('authorization_endpoint', '');" +
    "localStorage.setItem('client_id', '');");
  await driver.get(baseUrl + "/debugger.html?sdjwtvc=1");
  await driver.wait(until.elementLocated(By.id("sdjwtvc_banner")), waitTime,
    "debugger.html should say when it is being driven by the SD-JWT VC workflow.");
  await driver.sleep(900);
  var banner = await text(driver, "sdjwtvc_banner");
  assert.ok(/SD-JWT VC issuance/.test(banner), "the banner should name the workflow. Got: " + banner);
  assert.ok(/not configured|not started/.test(banner),
    "with nothing configured the banner should say the flow was not started. Got: " + banner);
  assert.ok((await driver.getCurrentUrl()).indexOf("debugger.html") !== -1,
    "an unconfigured hand-off must not redirect anywhere.");
  var flag = await driver.executeScript("return localStorage.getItem('sdjwtvc_flow');");
  assert.strictEqual(flag, "active", "the parameter should mark the workflow active.");

  // And with no parameter, none of it happens.
  await driver.get(baseUrl + "/debugger.html");
  await driver.sleep(700);
  var banners = await driver.executeScript("return document.querySelectorAll('.vc-handoff-banner').length;");
  assert.strictEqual(banners, 0, "without the parameter debugger.html must behave exactly as before.");
  await driver.executeScript("window.localStorage.clear();");
  log.info("[handoff] OK — the parameter drives the page, and its absence changes nothing.");
}

// ---------------------------------------------------------------------------
async function test() {
  log.info("Starting Test run. issuer=" + issuerMetadataUrl + ", as=" + asMetadataUrl);
  await issuerNegatives();

  var prefs = new logging.Preferences();
  prefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  var options = new chrome.Options().setLoggingPrefs(prefs)
    .addArguments("--window-size=1500,1400");
  if (headless) {
    options.addArguments("--headless=new", "--no-sandbox", "--disable-dev-shm-usage");
  }
  var driver = await new Builder().forBrowser("chrome").setChromeOptions(options).build();
  try {
    await handoffParameterCheck(driver);
    await stepOne(driver);
    await oidcLeg(driver);
    var context = await stepTwo(driver);
    await stepThree(driver, context);

    var errors = await severeErrors(driver);
    assert.strictEqual(errors.length, 0,
      "the workflow logged browser errors:\n" + errors.join("\n"));
    log.info("[browser] OK — no console errors across the workflow.");

    await staleProofRecovery(driver);
    await inspectLinksReturnHere(driver);
    await stepTwoWithoutTokens(driver);
    log.info("Test completed successfully.");
  } finally {
    await driver.quit();
  }
}

const program = new Command();
program.addOption(new Option('-u, --url <url>', 'base url of the debugger under test'));
program.addOption(new Option('-h, --headless <headless>', 'run headless (true/false)'));
program.parse(process.argv);
const opts = program.opts();
if (opts.url) { baseUrl = opts.url; log.info("Setting url to " + baseUrl); }
if (opts.headless === "false") { headless = false; }

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
