// File: sd_jwt_vc_issuance.js
//
// The SD-JWT VC issuance workflow, end to end:
//
//   step 0 (sd-jwt-vc-issuance-0.html)
//     the use-case chooser: which OID4VCI Appendix H flow to run. The
//     wallet-initiated one (H.6) is what most of this file drives; the
//     issuer-initiated Credential Offer (H.1) has its own section at the end.
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
// OID4VCI's pre-authorized code grant, used by the cross-device use cases.
var PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

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
      try {
        body = JSON.parse(text);
      } catch (e) {
        // Not JSON: the caller gets the raw text instead.
      }
      return { status: r.status, ok: r.ok, body: body, raw: text };
    });
  });
}

async function click(driver, locator) {
  await driver.wait(until.elementLocated(locator), waitTime);
  var e = driver.findElement(locator);
  await driver.executeScript("arguments[0].scrollIntoView({ block: 'center' });", e);
  await driver.sleep(120);
  try {
    await e.click();
  } catch (err) {
    // Something is overlapping the element; click it through the DOM instead.
    await driver.executeScript("arguments[0].click();", e);
  }
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
// OID4VCI Appendix H.1, Credential Offer - Same-Device.
//
// "While browsing the university's home page, the End-User finds a link 'request
// your digital diploma' ... and is redirected to a digital Wallet. The Wallet
// notifies the End-User that a Credential Issuer offered to issue a diploma
// Credential."
//
// So this starts at the ISSUER, not at the wallet, and the whole thing runs on
// the STS mock, which is the credential issuer, the authorization server and the
// issuer's web page at once. Nothing is configured beforehand: a fresh browser
// gets everything from the offer.
// ---------------------------------------------------------------------------
// Point the wallet at the WRONG issuer before the offer arrives. Clearing the
// settings is not enough to prove an offer configured anything: the fields fall
// back to this deployment's defaults, which name the same issuer the offer came
// from, so the assertions would pass either way (a mutation of applyOffer()
// proved exactly that). Deliberately wrong values cannot be satisfied by
// accident — whatever is right afterwards was put there by the offer.
var WRONG_ISSUER = "http://localhost:8181/not-the-offering-issuer";

async function misconfigureTheWallet(driver) {
  log.debug("Entering misconfigureTheWallet().");
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("vci_metadata_endpoint")), waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "var wrong = {" +
    "  vci_metadata_endpoint: arguments[0] + '/.well-known/openid-credential-issuer'," +
    "  vci_credential_issuer: arguments[0]," +
    "  vci_credential_endpoint: arguments[0] + '/credential'," +
    "  vci_deferred_credential_endpoint: arguments[0] + '/deferred_credential'," +
    "  vci_credential_configuration_id: 'NotTheOfferedCredential'," +
    "  authorization_endpoint: arguments[0] + '/authorize'," +
    "  token_endpoint: arguments[0] + '/token'" +
    "};" +
    "Object.keys(wrong).forEach(function (k) { window.localStorage.setItem(k, wrong[k]); });",
    WRONG_ISSUER);
  log.debug("Leaving misconfigureTheWallet(). The wallet now points at " + WRONG_ISSUER + ".");
}

async function credentialOfferSameDevice(driver) {
  log.info("=== H.1: Credential Offer - Same-Device ===");

  // ---- step 0: the chooser ------------------------------------------------
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")), waitTime);
  // Start with no use case chosen and no offer in hand — and then say which
  // issuer this wallet is configured for, because that is what step 0 needs to
  // know to send the End-User to the issuer's own page. Leaving it to whatever
  // an earlier section happened to store (or to the build-time default) is how
  // this section silently starts testing a different issuer.
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")), waitTime);
  await driver.sleep(300);

  var cards = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('button.vc-usecase')).map(function (b) {" +
    "  return { id: b.id, disabled: b.disabled," +
    "           spec: b.querySelector('.vc-usecase-spec').textContent.trim()," +
    "           title: b.querySelector('.vc-usecase-title').textContent.trim()," +
    "           summary: b.querySelector('.vc-usecase-summary').textContent.trim()," +
    "           mechanics: b.querySelector('.vc-usecase-mechanics').textContent.trim() };" +
    "});");
  assert.strictEqual(cards.length, 4, "step 0 should offer all four use cases, got " + cards.length + ".");
  assert.deepStrictEqual(cards.map(function (c) { return c.spec; }), ["H.6", "H.1", "H.2", "H.3"],
    "the use cases should be listed by their Appendix H section.");
  cards.forEach(function (c) {
    assert.ok(c.summary.length > 40, c.spec + " should be described, not just named.");
    assert.ok(c.mechanics.length > 20, c.spec + " should say what it does on the wire.");
  });
  assert.deepStrictEqual(cards.filter(function (c) { return !c.disabled; }).map(function (c) { return c.spec; }),
    ["H.6", "H.1", "H.2", "H.3"], "every use case this workflow implements should be choosable.");
  assert.strictEqual(cards.filter(function (c) { return c.disabled; }).length, 0,
    "nothing on step 0 should be listed as unavailable now that all four are implemented.");
  log.info("[H.1] OK — step 0 describes all four use cases, and all four are choosable.");

  // ---- the issuer's web page ----------------------------------------------
  await click(driver, By.id("vc_usecase_offer-same-device"));
  await driver.wait(until.urlContains("/issuer"), fetchWait,
    "choosing the offer use case should take the End-User to the ISSUER, not the wallet.");
  var issuerPage = await driver.getCurrentUrl();
  assert.ok(issuerPage.indexOf(issuerBase) === 0,
    "the issuer page should belong to the configured credential issuer. Got: " + issuerPage);
  assert.ok((await driver.findElements(By.linkText("Request your digital diploma"))).length,
    "the issuer page should carry the offer link H.1 describes.");
  log.info("[H.1] OK — the flow starts on the issuer page at " + issuerPage + ".");

  // Everything the offer is supposed to supply is pointed somewhere WRONG
  // first, so the assertions below cannot be satisfied by what step 1 left
  // behind or by this deployment's defaults.
  await misconfigureTheWallet(driver);
  await driver.get(issuerPage);
  await driver.wait(until.elementLocated(By.linkText("Request your digital diploma")), waitTime);

  // ---- following the link hands the wallet an offer ------------------------
  await click(driver, By.linkText("Request your digital diploma"));
  await driver.wait(until.elementLocated(By.id("pane_offer")), fetchWait,
    "the link should take the End-User back to the wallet with a Credential Offer.");
  await driver.wait(async function () {
    return !!(await value(driver, "authorization_endpoint"));
  }, fetchWait, "the wallet should discover the offering issuer and its authorization server by itself.");
  await driver.sleep(300);

  var shown = await driver.executeScript(
    "return { url: location.href," +
    "         visible: document.getElementById('pane_offer').style.display !== 'none'," +
    "         grant: document.getElementById('offer_grant').textContent.trim()," +
    "         source: document.getElementById('offer_source').textContent.trim()," +
    "         json: document.getElementById('offer_json').textContent," +
    "         badge: (document.getElementById('vc_use_case_badge') || {}).textContent || '' };");
  assert.ok(shown.visible, "the offer pane should be shown when an offer arrives.");
  assert.ok(shown.url.indexOf("credential_offer=") !== -1,
    "the offer should arrive in the URL, by value. Got: " + shown.url.slice(0, 80));
  var offer = JSON.parse(shown.json);
  assert.strictEqual(offer.credential_issuer, issuerBase, "the offer should name the issuer.");
  assert.deepStrictEqual(offer.credential_configuration_ids, ["IdentityCredential"],
    "the offer should name the credential on offer.");
  var issuerState = ((offer.grants || {}).authorization_code || {}).issuer_state;
  assert.ok(issuerState, "an H.1 offer uses the authorization_code grant and carries an issuer_state.");
  assert.ok(shown.grant.indexOf("authorization_code") === 0 && shown.grant.indexOf(issuerState) !== -1,
    "the pane should show the grant and its issuer_state. Got: " + shown.grant);
  assert.ok(shown.source.indexOf("by value") !== -1,
    "the pane should say how the offer arrived. Got: " + shown.source);
  assert.ok(shown.badge.indexOf("H.1") !== -1,
    "every page should say which use case is running. Got: " + shown.badge);

  var applied = await driver.executeScript(
    "return { metadataUrl: document.getElementById('vci_metadata_endpoint').value," +
    "         credentialId: document.getElementById('vci_credential_configuration_id').value," +
    "         credentialEndpoint: document.getElementById('vci_credential_endpoint').value," +
    "         authorization: document.getElementById('authorization_endpoint').value," +
    "         token: document.getElementById('token_endpoint').value };");
  assert.strictEqual(applied.metadataUrl, issuerBase + "/.well-known/openid-credential-issuer",
    "the offer should point the metadata URL at the offering issuer.");
  assert.strictEqual(applied.credentialId, "IdentityCredential",
    "the offered credential should be the one selected.");
  assert.ok(applied.credentialEndpoint && applied.authorization && applied.token,
    "the wallet should have discovered the issuer AND its authorization server: " + JSON.stringify(applied));
  log.info("[H.1] OK — the offer is shown as received, and it configured the issuer, the credential and " +
           "the authorization server with nothing typed in.");

  // ---- authorize: the issuer_state must go back with the request ----------
  //
  // Which authorization server this reaches depends on what the issuer's
  // metadata advertises: the STS mock itself when it is standalone, or Keycloak
  // in the containerized suite. The issuer_state assertion holds either way; the
  // ones about what the login screen SAYS only make sense for the mock, which is
  // the one that knows it issued the offer.
  var mockIsTheAs = applied.authorization.indexOf(issuerBase) === 0;
  var signInUser = mockIsTheAs ? "diploma.student" : clientId;
  var signInPassword = mockIsTheAs ? "any-password" : clientId;

  // An earlier part of this run signed in at that authorization server, and the
  // session would carry straight through without a prompt — correct behaviour,
  // but it hides the authorization request this section exists to inspect.
  // (driver.manage().deleteAllCookies() is no help: it only clears the origin
  // the browser is currently on, which is the wallet, not the server.)
  var logoutUrl = applied.authorization
    .replace(/\/protocol\/openid-connect\/auth$/, "/protocol/openid-connect/logout")
    .replace(/\/oauth2\/authorize$/, "/oauth2/logout");
  log.info("[H.1] Signing out of " + logoutUrl + " so the authorization request is made afresh.");
  await driver.get(logoutUrl);
  await driver.sleep(600);
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("start_issuance_button")), waitTime);
  await driver.sleep(400);

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("username")), fetchWait,
    "the workflow should reach the authorization server's login screen.");
  var authzUrl = await driver.getCurrentUrl();
  assert.ok(authzUrl.indexOf("issuer_state=" + issuerState) !== -1,
    "the authorization request MUST carry the offer's issuer_state (OID4VCI section 4.1.1). Got: " + authzUrl);
  if (mockIsTheAs) {
    var loginText = await driver.executeScript("return document.body.innerText;");
    assert.ok(loginText.indexOf(issuerState) !== -1,
      "the authorization server should show the issuer_state it received.");
    assert.ok(loginText.indexOf("from a Credential Offer this issuer made") !== -1,
      "the authorization server should recognise its own issuer_state.");
    log.info("[H.1] OK — issuer_state travelled into the authorization request, and the issuer " +
             "recognised it as its own.");
  } else {
    log.info("[H.1] OK — issuer_state travelled into the authorization request (the authorization " +
             "server here is " + applied.authorization.split("/protocol")[0] + ", not the mock, so what it " +
             "displays is not asserted).");
  }

  // ---- and then the flow the other use case already proved ----------------
  await driver.findElement(By.id("username")).sendKeys(signInUser);
  await driver.findElement(By.id("password")).sendKeys(signInPassword);
  await click(driver, By.id("kc-login"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-2.html"), fetchWait,
    "after signing in the workflow should come back to step 2.");
  await driver.wait(async function () {
    return !!(await value(driver, "vc_proof_jwt"));
  }, fetchWait, "step 2 should prepare the credential request.");
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-3.html"), fetchWait,
    "approving should produce the credential.");
  await driver.sleep(900);

  var credential = await value(driver, "vc_credential_raw");
  assert.ok(credential, "H.1 should end with a credential.");
  var payload = jsonFromB64u(credential.split("~")[0].split(".")[1]);
  assert.strictEqual(payload.iss, issuerBase, "the credential should come from the issuer that made the offer.");
  assert.strictEqual(payload.vct, EXPECTED_VCT, "it should be the credential that was offered.");
  assert.ok(String(payload.sub).length > 0 && String(payload.username || payload.sub).length > 0,
    "the credential should describe a subject. Got: " + payload.sub);
  if (mockIsTheAs) {
    assert.ok(String(payload.sub).indexOf(signInUser) !== -1,
      "it should describe the user who signed in. Got: " + payload.sub);
  }
  var failed = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks tbody tr'))" +
    "  .filter(function (tr) { return tr.querySelectorAll('td')[1].textContent.trim() === 'FAILED'; })" +
    "  .map(function (tr) { return tr.querySelectorAll('td')[0].textContent.trim(); });");
  assert.strictEqual(failed.length, 0, "no check should fail on the H.1 credential: " + failed.join(", "));
  log.info("[H.1] OK — the offered credential was issued to " + payload.sub + " and verifies.");

  // ---- the offer can also travel by reference -----------------------------
  await driver.get(issuerBase + "/issuer");
  await click(driver, By.linkText("Request it (offer by reference)"));
  await driver.wait(until.elementLocated(By.id("pane_offer")), fetchWait);
  await driver.wait(async function () {
    return (await text(driver, "offer_issuer")) === issuerBase;
  }, fetchWait, "an offer passed by reference should be fetched and shown.");
  var byRef = await driver.executeScript(
    "return { url: location.href, source: document.getElementById('offer_source').textContent.trim() };");
  assert.ok(byRef.url.indexOf("credential_offer_uri=") !== -1,
    "the by-reference link should pass credential_offer_uri. Got: " + byRef.url.slice(0, 90));
  assert.ok(byRef.source.indexOf("by reference") !== -1,
    "the pane should say the offer was fetched by reference. Got: " + byRef.source);
  log.info("[H.1] OK — an offer passed by reference (credential_offer_uri) is fetched and shown too.");

  // ---- discarding it returns to the wallet-initiated use case -------------
  await click(driver, By.id("offer_discard_button"));
  await driver.sleep(300);
  var afterDiscard = await driver.executeScript(
    "return { visible: document.getElementById('pane_offer').style.display !== 'none'," +
    "         badge: (document.getElementById('vc_use_case_badge') || {}).textContent || ''," +
    "         stored: localStorage.getItem('sdjwtvc_credential_offer') };");
  assert.strictEqual(afterDiscard.visible, false, "discarding should hide the offer pane.");
  assert.strictEqual(afterDiscard.stored, null, "discarding should forget the offer.");
  assert.ok(afterDiscard.badge.indexOf("H.6") !== -1,
    "discarding should fall back to the wallet-initiated use case. Got: " + afterDiscard.badge);
  log.info("[H.1] OK — the offer can be discarded, and the workflow falls back to wallet-initiated.");
}

// ---------------------------------------------------------------------------
// The issuer's own defences — a mock that accepts anything would make the
// checks above meaningless.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// H.2 — Credential Offer, cross-device.
//
// The issuer shows a QR code on its own screen; the wallet is somewhere else,
// so nothing navigates it here. The offer carries a pre-authorized code instead
// of sending anyone to a login page — there is NO authorization request at all
// — and a Transaction Code that reached the End-User by a different channel is
// what ties the wallet on the other device to them.
//
// The Transaction Code is the part worth being strict about: it is the only
// thing standing between a photographed QR code and someone else's credential,
// so this section checks that the wallet refuses to send without it, that the
// issuer refuses a wrong one, and that the code is single use.
// ---------------------------------------------------------------------------
async function crossDeviceOffer(driver) {
  log.info("=== H.2: Credential Offer - Cross-Device ===");

  // Step 0 needs to know which issuer to send the End-User to; the offer that
  // comes back is what configures everything else.
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")), waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_usecase_offer-cross-device")), waitTime);
  await click(driver, By.id("vc_usecase_offer-cross-device"));

  // ---- the issuer's screen -------------------------------------------------
  await driver.wait(until.elementLocated(By.id("tx_code")), fetchWait,
    "the cross-device use case should show the issuer's QR screen, not send the browser to the wallet.");
  var screen = await driver.executeScript(
    "var qr = document.getElementById('offer_qr');" +
    "return { url: location.href," +
    "         txCode: document.getElementById('tx_code').textContent.trim()," +
    "         offerUri: document.getElementById('offer_uri').textContent.trim()," +
    "         qr: qr ? qr.src.slice(0, 21) : ''," +
    "         page: document.body.textContent };");
  assert.ok(screen.url.indexOf(issuerBase) === 0,
    "the QR screen belongs to the issuer, not the wallet. Got: " + screen.url);
  assert.strictEqual(screen.qr, "data:image/png;base64",
    "a cross-device offer is handed over as a QR code, so there should be one on the issuer's screen.");
  assert.ok(/^\d{5}$/.test(screen.txCode),
    "the issuer should display a Transaction Code on its own screen. Got: " + screen.txCode);
  assert.ok(screen.offerUri.indexOf("openid-credential-offer://") === 0,
    "the QR code should carry the openid-credential-offer URI OID4VCI registers. Got: " +
    screen.offerUri.slice(0, 60));
  assert.ok(screen.page.indexOf(screen.txCode) !== -1 &&
            screen.offerUri.indexOf(screen.txCode) === -1,
    "the Transaction Code must be shown on the screen and NOT travel in the offer — that separation is " +
    "the whole point of it.");
  log.info("[H.2] OK — the issuer shows a QR code and a Transaction Code that is not in the offer.");

  // ---- the wallet takes the scanned offer ---------------------------------
  // Poisoned first, so what the pane shows afterwards can only have come from
  // the offer itself (see misconfigureTheWallet).
  await misconfigureTheWallet(driver);
  await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];", screen.offerUri);
  await click(driver, By.id("scan_offer_button"));
  // The expected value, not just any value: the wallet was pointed at a wrong
  // issuer on purpose, so "not empty" is already true.
  await driver.wait(async function () {
    return (await value(driver, "vci_credential_endpoint")) === issuerBase + "/oid4vci/credential";
  }, fetchWait, "taking the offer should discover the issuer it names.");
  await driver.sleep(400);

  var taken = await driver.executeScript(
    "return { offerShown: document.getElementById('pane_offer').style.display !== 'none'," +
    "         grant: document.getElementById('offer_grant').textContent.trim()," +
    "         metadataUrl: document.getElementById('vci_metadata_endpoint').value," +
    "         credentialEndpoint: document.getElementById('vci_credential_endpoint').value," +
    "         badge: (document.getElementById('vc_use_case_badge') || {}).textContent || '' };");
  assert.ok(taken.offerShown, "the offer pane should show what was scanned.");
  assert.ok(taken.grant.indexOf("pre-authorized_code") !== -1,
    "the offer should be shown as using the pre-authorized code grant. Got: " + taken.grant);
  assert.ok(/Transaction Code is required/.test(taken.grant),
    "the pane should say a Transaction Code is required before anything is sent. Got: " + taken.grant);
  assert.strictEqual(taken.metadataUrl, issuerBase + "/.well-known/openid-credential-issuer",
    "the scanned offer names only the issuer, so the wallet has to derive its metadata URL.");
  assert.strictEqual(taken.credentialEndpoint, issuerBase + "/oid4vci/credential",
    "the wallet should have read the issuer's metadata off the back of the offer.");
  assert.ok(taken.badge.indexOf("H.2") !== -1,
    "the workflow should say which use case it is running. Got: " + taken.badge);
  log.info("[H.2] OK — a pasted offer configured the wallet, with the issuer poisoned beforehand.");

  // ---- no authorization request --------------------------------------------
  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-2.html"), fetchWait,
    "a pre-authorized offer must NOT go through the authorization server — the End-User was already " +
    "identified, so the workflow should go straight to the Token Request.");
  await driver.wait(async function () {
    return !!(await text(driver, "vc_pre_authorized_code"));
  }, fetchWait, "step 2 should show the pre-authorized code it is about to redeem.");

  var pane = await driver.executeScript(
    "return { shown: document.getElementById('pane_pre_authorized').style.display !== 'none'," +
    "         code: document.getElementById('vc_pre_authorized_code').textContent.trim()," +
    "         hint: document.getElementById('vc_tx_code_hint').textContent.trim()," +
    "         request: document.getElementById('vc_token_request').value," +
    "         accessToken: document.getElementById('vc_access_token').value };");
  assert.ok(pane.shown, "the Token Request pane should be shown for a pre-authorized offer.");
  assert.ok(pane.code && pane.code.length > 10, "the pre-authorized code should be shown. Got: " + pane.code);
  assert.ok(/5 digits/.test(pane.hint),
    "the pane should say what Transaction Code the issuer wants. Got: " + pane.hint);
  assert.ok(pane.request.indexOf("grant_type=" + encodeURIComponent(PRE_AUTHORIZED_GRANT)) !== -1,
    "the assembled call should use the pre-authorized code grant. Got: " + pane.request.slice(0, 200));
  assert.ok(pane.request.indexOf("POST " + issuerBase + "/oauth2/token") === 0,
    "the assembled call should name the token endpoint. Got: " + pane.request.slice(0, 80));
  assert.strictEqual(pane.accessToken, "",
    "there should be no access token yet: nothing has been redeemed.");
  log.info("[H.2] OK — step 2 shows the Token Request before sending it, and there is no access token yet.");

  // ---- the Transaction Code is not optional --------------------------------
  await click(driver, By.id("vc_token_request_button"));
  await driver.sleep(500);
  var refusedLocally = await text(driver, "vc_token_status");
  assert.ok(/Transaction Code/i.test(refusedLocally) && /type it in/i.test(refusedLocally),
    "with no Transaction Code typed the wallet should refuse to send at all. Got: " + refusedLocally);
  assert.strictEqual(await value(driver, "vc_access_token"), "",
    "nothing should have been issued.");

  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = '00000'; sdjwtvc2.onTxCodeChange();");
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return /refused/i.test((await text(driver, "vc_token_status")) || "");
  }, fetchWait, "the issuer should refuse a wrong Transaction Code.");
  var refusedByIssuer = await text(driver, "vc_token_status");
  assert.ok(/not correct|invalid/i.test(refusedByIssuer),
    "the refusal should say the Transaction Code is wrong. Got: " + refusedByIssuer);
  assert.strictEqual(await value(driver, "vc_access_token"), "",
    "a wrong Transaction Code must not produce an access token.");
  log.info("[H.2] OK — no Transaction Code is refused by the wallet, a wrong one by the issuer.");

  // ---- the right one -------------------------------------------------------
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; sdjwtvc2.onTxCodeChange();", screen.txCode);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the right Transaction Code should redeem the pre-authorized code for an access token.");
  var accessToken = await value(driver, "vc_access_token");
  var claims = jsonFromB64u(accessToken.split(".")[1]);
  assert.ok(String(claims.sub || "").indexOf("urn:sts-mock:user:") === 0,
    "the access token should describe the End-User the issuer already knew about. Got: " + claims.sub);
  log.info("[H.2] OK — the pre-authorized code was redeemed for an access token describing " + claims.sub + ".");

  // The code is single use: a second redemption of the same offer must fail.
  var replay = await httpJson(issuerBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent(PRE_AUTHORIZED_GRANT) +
          "&pre-authorized_code=" + encodeURIComponent(pane.code) +
          "&tx_code=" + encodeURIComponent(screen.txCode)
  });
  assert.strictEqual(replay.status, 400,
    "a pre-authorized code is single use; replaying it should be refused. Got HTTP " + replay.status);
  assert.ok(/already-used|Unknown/i.test(replay.raw),
    "the refusal should say the code has been used. Got: " + replay.raw.slice(0, 160));
  log.info("[H.2] OK — the pre-authorized code cannot be redeemed twice.");

  // ---- and the credential --------------------------------------------------
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-3.html"), fetchWait,
    "approving should get the credential the offer was for.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "H.2");
  log.info("[H.2] OK — the offered credential was issued with no authorization request anywhere in the flow.");
}

// ---------------------------------------------------------------------------
// H.3 — Credential Offer, cross-device and deferred.
//
// Everything H.2 does, and then the issuer cannot produce the credential yet:
// the Credential Response is 202 with a transaction_id, and the wallet collects
// the credential from the Deferred Credential Endpoint once it is ready
// (OID4VCI section 9).
// ---------------------------------------------------------------------------
async function deferredIssuance(driver) {
  log.info("=== H.3: Credential Offer - Cross-Device & Deferred ===");

  var meta = (await httpJson(issuerMetadataUrl)).body;
  assert.ok(meta.deferred_credential_endpoint,
    "an issuer that can defer says so with deferred_credential_endpoint; this one should.");

  await driver.get(baseUrl + "/sd-jwt-vc-issuance-0.html");
  await driver.wait(until.elementLocated(By.css("button.vc-usecase")), waitTime);
  await driver.executeScript(
    "window.localStorage.clear();" +
    "window.localStorage.setItem('vci_credential_issuer', arguments[0]);" +
    "window.localStorage.setItem('vci_metadata_endpoint', arguments[0] + " +
    "  '/.well-known/openid-credential-issuer');", issuerBase);
  await driver.navigate().refresh();
  await driver.wait(until.elementLocated(By.id("vc_usecase_offer-deferred")), waitTime);
  await click(driver, By.id("vc_usecase_offer-deferred"));

  await driver.wait(until.elementLocated(By.id("tx_code")), fetchWait,
    "the deferred use case also starts at the issuer's QR screen.");
  var screen = await driver.executeScript(
    "return { txCode: document.getElementById('tx_code').textContent.trim()," +
    "         offerUri: document.getElementById('offer_uri').textContent.trim() };");

  await driver.get(baseUrl + "/sd-jwt-vc-issuance-1.html");
  await driver.wait(until.elementLocated(By.id("scan_offer_input")), waitTime);
  await driver.executeScript(
    "document.getElementById('scan_offer_input').value = arguments[0];", screen.offerUri);
  await click(driver, By.id("scan_offer_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vci_deferred_credential_endpoint"));
  }, fetchWait, "the wallet should read the deferred endpoint out of the issuer's metadata.");
  assert.strictEqual(await value(driver, "vci_deferred_credential_endpoint"),
    issuerBase + "/oid4vci/deferred_credential",
    "the deferred endpoint should be the one the issuer publishes.");

  await click(driver, By.id("start_issuance_button"));
  await driver.wait(until.elementLocated(By.id("vc_tx_code")), fetchWait);
  await driver.executeScript(
    "document.getElementById('vc_tx_code').value = arguments[0]; sdjwtvc2.onTxCodeChange();", screen.txCode);
  await click(driver, By.id("vc_token_request_button"));
  await driver.wait(async function () {
    return !!(await value(driver, "vc_access_token"));
  }, fetchWait, "the Transaction Code should redeem the pre-authorized code.");

  // ---- the issuer defers ---------------------------------------------------
  await click(driver, By.id("vc_approve_button"));
  await driver.wait(async function () {
    return await driver.executeScript(
      "var e = document.getElementById('pane_deferred'); return !!e && e.style.display !== 'none';");
  }, fetchWait, "a 202 with a transaction_id should put the workflow into the deferred pane.");

  var deferred = await driver.executeScript(
    "return { transactionId: document.getElementById('vc_transaction_id').textContent.trim()," +
    "         endpoint: document.getElementById('vc_deferred_endpoint').textContent.trim()," +
    "         request: document.getElementById('vc_deferred_request').value," +
    "         response: document.getElementById('vc_response_body').textContent };");
  assert.ok(deferred.transactionId && deferred.transactionId !== "—",
    "the deferred pane should show the transaction_id the issuer returned.");
  assert.strictEqual(deferred.endpoint, issuerBase + "/oid4vci/deferred_credential",
    "it should name the endpoint it is going to poll.");
  assert.ok(deferred.request.indexOf("POST " + issuerBase + "/oid4vci/deferred_credential") === 0,
    "the assembled Deferred Credential Request should be shown. Got: " + deferred.request.slice(0, 80));
  assert.ok(deferred.request.indexOf('"transaction_id"') !== -1,
    "the request body is the transaction_id (OID4VCI section 9.1). Got: " + deferred.request);
  assert.ok(deferred.request.indexOf("Authorization: Bearer ") !== -1,
    "the deferred request must present the access token too.");
  assert.ok(deferred.response.indexOf(deferred.transactionId) !== -1,
    "the Credential Response that deferred the issuance should still be on screen. Got: " +
    deferred.response.slice(0, 160));
  log.info("[H.3] OK — the issuer deferred the issuance and the wallet showed the transaction it will poll.");

  // A transaction_id this issuer never made must be refused, or "pending" and
  // "there is no such thing" would be indistinguishable to a wallet.
  var bogus = await httpJson(issuerBase + "/oid4vci/deferred_credential", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (await value(driver, "vc_access_token"))
    },
    body: JSON.stringify({ transaction_id: "not-a-transaction-this-issuer-made" })
  });
  assert.strictEqual(bogus.status, 400,
    "an unknown transaction_id should be refused. Got HTTP " + bogus.status);
  assert.ok(bogus.body && bogus.body.error === "invalid_transaction_id",
    "OID4VCI section 9.3 names that error invalid_transaction_id. Got: " + bogus.raw.slice(0, 160));

  // ---- the wallet waits, and collects --------------------------------------
  await driver.wait(until.urlContains("sd-jwt-vc-issuance-3.html"), fetchWait,
    "the wallet should keep polling until the issuer has the credential ready.");
  await driver.sleep(800);
  await assertStepThreeIsHappy(driver, "H.3");

  var record = await driver.executeScript(
    "return JSON.parse(window.localStorage.getItem('sdjwtvc_credential_meta') || '{}');");
  assert.strictEqual(record.deferred, true,
    "the workflow should record that this credential came from a deferred issuance.");
  assert.ok(record.deferredAttempts >= 1,
    "it should record how many attempts that took. Got: " + record.deferredAttempts);
  assert.strictEqual(record.deferredEndpoint, issuerBase + "/oid4vci/deferred_credential",
    "and where it collected the credential from.");
  log.info("[H.3] OK — the credential was collected from the deferred endpoint after " +
           record.deferredAttempts + " attempt(s), and the workflow says so.");

  // Spent: the issuer invalidates the transaction_id once the credential has
  // been handed over, so the same poll must not yield a second copy.
  var replay = await httpJson(issuerBase + "/oid4vci/deferred_credential", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": "Bearer replayed" },
    body: JSON.stringify({ transaction_id: deferred.transactionId })
  });
  assert.strictEqual(replay.status, 400,
    "a collected transaction_id must stop working (OID4VCI section 9). Got HTTP " + replay.status);
  assert.ok(replay.body && replay.body.error === "invalid_transaction_id",
    "and the error should be invalid_transaction_id. Got: " + JSON.stringify(replay.body));
  log.info("[H.3] OK — the transaction_id stopped working once the credential had been collected.");
}

// Step 3's verdicts, for a credential that a working issuer has just issued.
async function assertStepThreeIsHappy(driver, label) {
  log.debug("Entering assertStepThreeIsHappy(). label=" + label);
  var checks = await driver.executeScript(
    "return Array.prototype.slice.call(document.querySelectorAll('#vc_checks tbody tr')).map(function (tr) {" +
    "  var td = tr.querySelectorAll('td');" +
    "  return { name: td[0].textContent.trim(), result: td[1].textContent.trim()," +
    "           detail: td[2].textContent.trim() };" +
    "});");
  assert.ok(checks.length >= 7, "step 3 should report its checks, got " + checks.length + ".");
  var failed = checks.filter(function (c) { return c.result === "FAILED"; });
  assert.strictEqual(failed.length, 0,
    label + ": no check should fail — " +
    failed.map(function (c) { return c.name + " — " + c.detail; }).join("; "));
  var signature = checks.filter(function (c) { return c.name === "Issuer signature"; })[0];
  assert.ok(signature && signature.result === "OK",
    label + ": the issuer signature should verify. Got: " + JSON.stringify(signature));
  var binding = checks.filter(function (c) { return c.name === "Key binding (cnf)"; })[0];
  assert.ok(binding && binding.result === "OK",
    label + ": the credential should be bound to the holder key. Got: " + JSON.stringify(binding));
  log.debug("Leaving assertStepThreeIsHappy().");
}

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
    await credentialOfferSameDevice(driver);
    await crossDeviceOffer(driver);
    await deferredIssuance(driver);
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
