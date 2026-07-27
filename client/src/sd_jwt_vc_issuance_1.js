// File: sd_jwt_vc_issuance_1.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 1: discover the issuer and settle the configuration.
//
// Four panes:
//
//   1. Credential Issuer Metadata (OID4VCI) — retrieve, tabulate, validate its
//      signed_metadata, and pick which credential to ask for.
//   2. Authorization Server Metadata (RFC 8414) — the same pane debugger.html
//      has, writing to the SAME localStorage keys, so what is retrieved here
//      configures the OAuth2 / OIDC workflow that step 2 hands off to.
//   3. Configuration Parameters — every member both documents can define,
//      generated from the member lists so the pane cannot drift from them.
//   4. The hand-off to debugger.html?sdjwtvc=1.
//
// The fetch / table / signature-validation machinery is metadata_client.js,
// shared with debugger.html. The member lists are op_metadata.js (OpenID
// Provider + the RFC 8414-only members) and vci_metadata.js (credential issuer).
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var opMetadata = require("./op_metadata");
var vciMetadata = require("./vci_metadata");
var sdJwtVc = require("./sd_jwt_vc");

var log = bunyan.createLogger({ name: 'sd_jwt_vc_issuance_1',
                                level: appconfig.LOG_LEVEL || 'info' });

// --- storage keys -----------------------------------------------------------
// The credential issuer document is this page's own; the authorization server
// document is deliberately the one debugger.html uses.
var VCI_STORE = metadataClient.createStore("vci_info", "vci_info_source");
var AS_STORE = metadataClient.createStore(opMetadata.DISCOVERY_INFO_KEY, "discovery_info_source");
var VCI_URL_KEY = "vci_metadata_endpoint";

var VCI_DOC_LABEL = "OID4VCI Credential Issuer Metadata";
var AS_DOC_LABEL = "OAuth 2.0 Authorization Server Metadata (RFC 8414)";
var VCI_WELL_KNOWN = "/.well-known/openid-credential-issuer";
var AS_WELL_KNOWN = "/.well-known/oauth-authorization-server";
var JWT_VC_ISSUER_WELL_KNOWN = "/.well-known/jwt-vc-issuer";

// The two documents currently on display.
var vciInfo = {};
var asInfo = {};

// ---------------------------------------------------------------------------
// The plain fields the Configuration Parameters pane carries besides the
// metadata member lists: the OAuth 2.0 client settings the authorization
// request needs, and the endpoints the debugger pane has always had under its
// own element ids. Ids and localStorage keys match debugger.html exactly.
// ---------------------------------------------------------------------------
var CLIENT_FIELDS = [
  { name: "client_id", dflt: "oidc-authorization-code-public",
    desc: "The OAuth 2.0 client the authorization request is made with. In OID4VCI terms this is the wallet." },
  { name: "redirect_uri", dflt: "",
    desc: "Where the authorization server sends the authorization code: this deployment's /callback, which forwards to debugger2.html. The debugger pages pin this to their own configured origin, so an edit here is only honoured if it points at that origin." },
  { name: "scope", dflt: "openid profile email",
    desc: "The scopes the authorization request asks for. Add the credential configuration's scope value to ask the authorization server for authorization to issue that credential." }
];

// `member` is the metadata member name; `name` is the element id and storage
// key, which for two of them is not the same thing (debugger.html has always
// called them that, and these fields exist to stay compatible with it).
var ENDPOINT_FIELDS = [
  { name: "authorization_endpoint", member: "authorization_endpoint", dflt: "", desc: "Where the user is sent to authenticate and authorize issuance. Populated from the authorization server metadata." },
  { name: "token_endpoint", member: "token_endpoint", dflt: "", desc: "Where debugger2.html exchanges the authorization code for tokens. Populated from the authorization server metadata." },
  { name: "oidc_userinfo_endpoint", member: "userinfo_endpoint", dflt: "", desc: "The OIDC userinfo endpoint (userinfo_endpoint). Not used by issuance, but part of the metadata document." },
  { name: "jwks_endpoint", member: "jwks_uri", dflt: "", desc: "The authorization server's JWKS (jwks_uri) — the keys its tokens are signed with." },
  { name: "registration_endpoint", member: "registration_endpoint", dflt: "", desc: "The OIDC Dynamic Client Registration endpoint (registration_endpoint)." },
  { name: "introspection_endpoint", member: "introspection_endpoint", dflt: "", desc: "The token introspection endpoint (RFC 7662)." },
  { name: "revocation_endpoint", member: "revocation_endpoint", dflt: "", desc: "The token revocation endpoint (RFC 7009)." },
  { name: "device_authorization_endpoint", member: "device_authorization_endpoint", dflt: "", desc: "The device authorization endpoint (RFC 8628)." }
];

function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ""; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? "" : v); }
function status(id, text, cls) {
  var e = el(id);
  if (!e) return;
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
}
function esc(v) { return metadataClient.escapeHtmlText(v); }

// ---------------------------------------------------------------------------
// Pane 3 — the generated rows.
// ---------------------------------------------------------------------------
function fieldRow(id, label, desc, type) {
  var input;
  if (type === "boolean") {
    input = '<select class="stored" id="' + esc(id) + '" name="' + esc(id) + '">' +
              '<option value="true">true</option>' +
              '<option value="false">false</option>' +
            '</select>';
  } else if (type === "json") {
    // These members are JSON structures, shown pretty-printed. (A scalar value
    // swaps the textarea back to an input — see metadata_client.setMetadataField.)
    input = '<textarea class="stored metadata-json-field" id="' + esc(id) + '" name="' + esc(id) +
            '" rows="3" spellcheck="false"></textarea>';
  } else {
    input = '<input class="stored" type="text" id="' + esc(id) + '" name="' + esc(id) + '" max="512" />';
  }
  return '<tr>' +
           '<td><div class="tooltip"><label>' + esc(label) + ': </label>' +
             '<span class="tooltiptext">' + esc(desc) + '</span></div></td>' +
           '<td>' + input + '</td>' +
         '</tr>';
}

function groupRow(title, subtitle) {
  return '<tr class="vc-group-heading"><td colspan="2">' + esc(title) +
         (subtitle ? ' <span>' + esc(subtitle) + '</span>' : '') + '</td></tr>';
}

function buildConfigRows() {
  var html = "";

  html += groupRow("OAuth 2.0 client", "used by the authorization request in step 2");
  CLIENT_FIELDS.forEach(function (f) { html += fieldRow(f.name, f.name, f.desc); });

  html += groupRow("Authorization server endpoints", "OpenID Connect Discovery 1.0 / RFC 8414");
  ENDPOINT_FIELDS.forEach(function (f) { html += fieldRow(f.name, f.name, f.desc); });

  html += groupRow("Authorization server metadata", "the remaining members of the RFC 8414 document");
  opMetadata.OP_METADATA.forEach(function (m) {
    html += fieldRow(m.name, m.name,
      "Authorization server / OpenID Provider metadata member " + m.name +
      ". Populated from the retrieved metadata document; override it here.", m.type);
  });
  opMetadata.AS_ONLY_METADATA.forEach(function (m) {
    html += fieldRow(m.name, m.name,
      "RFC 8414 metadata member " + m.name +
      " (defined by RFC 8414, not by OpenID Connect Discovery 1.0).", m.type);
  });

  html += groupRow("Credential issuer metadata", "OID4VCI Credential Issuer Metadata");
  vciMetadata.VCI_METADATA.forEach(function (m) {
    html += fieldRow(vciMetadata.idFor(m.name), m.name, m.desc, m.type);
  });

  html += groupRow("Credential configuration", "the chosen entry of credential_configurations_supported");
  vciMetadata.VCI_CONFIG_METADATA.forEach(function (m) {
    html += fieldRow(vciMetadata.idFor(m.name), m.name, m.desc, m.type);
  });

  var body = el("config_rows");
  if (body) body.innerHTML = html;
}

// --- reading and writing the pane ------------------------------------------
function plainFields() { return CLIENT_FIELDS.concat(ENDPOINT_FIELDS); }

function loadConfiguration() {
  plainFields().forEach(function (f) {
    var v = sdJwtVc.get(f.name);
    setVal(f.name, (v === null || v === undefined) ? defaultFor(f) : v);
  });
  opMetadata.loadFromLocalStorage();
  vciMetadata.loadFromLocalStorage();
}

function defaultFor(f) {
  // The same rule debugger.html and debugger2.html apply: the redirect URI is
  // this deployment's own /callback. They re-default anything that does not
  // start with it, so offering a different value here would only mislead.
  if (f.name === "redirect_uri") {
    return (appconfig.uiUrl || window.location.origin) + "/callback";
  }
  return f.dflt;
}

function saveConfiguration() {
  plainFields().forEach(function (f) { sdJwtVc.set(f.name, val(f.name)); });
  // debugger2.html reads the client id and scope it posts to the token endpoint
  // from their own keys, so keep those in step with the client fields here.
  sdJwtVc.set("token_client_id", val("client_id"));
  sdJwtVc.set("token_scope", val("scope"));
  opMetadata.writeToLocalStorage();
  vciMetadata.writeToLocalStorage();
  // debugger.html writes ITS dummy defaults over everything on what it thinks
  // is a first visit. This configuration is not a first visit, and the whole
  // point of sharing the storage is that the debugger pages run on it.
  sdJwtVc.set("initialized", true);
  sdJwtVc.set("debugger_initialized", true);
  updateHandoffSummary();
  status("config_status", "Saved.", "vc-ok");
  return false;
}

function clearConfiguration() {
  plainFields().forEach(function (f) { setVal(f.name, ""); sdJwtVc.set(f.name, ""); });
  opMetadata.clearFields();
  opMetadata.clearStorage();
  vciMetadata.clearFields();
  vciMetadata.clearStorage();
  updateHandoffSummary();
  status("config_status", "Cleared — every parameter is now empty, here and in local storage.", "vc-ok");
  return false;
}

function restoreDefaults() {
  plainFields().forEach(function (f) { setVal(f.name, defaultFor(f)); });
  opMetadata.ALL_METADATA.forEach(function (m) {
    metadataClient.setMetadataField(m.name, m.dflt);
    opMetadata.markNotDefined(m.name, false);
  });
  vciMetadata.VCI_METADATA.concat(vciMetadata.VCI_CONFIG_METADATA).forEach(function (m) {
    metadataClient.setMetadataField(vciMetadata.idFor(m.name), m.dflt);
  });
  saveConfiguration();
  status("config_status", "Defaults restored.", "vc-ok");
  return false;
}

// ---------------------------------------------------------------------------
// Pane 1 — the credential issuer metadata document.
// ---------------------------------------------------------------------------
function renderVciTable() {
  var provenance = VCI_STORE.readProvenance();
  var html = metadataClient.buildInfoTable(vciInfo, provenance);
  el("vci_metadata_table").innerHTML = html;
  el("vci_metadata_populate").innerHTML =
    '<input class="btn_vci_populate_meta_data btn2" id="vci_populate_button" type="button"' +
    ' value="Populate Meta Data" onclick="return sdjwtvc1.populateFromVci();" />';
}

function renderCredentialConfigurations() {
  var select = el("vci_credential_configuration_select");
  var row = el("vci_configuration_row");
  if (!select || !row) return;
  var configs = (vciInfo && vciInfo.credential_configurations_supported) || {};
  var ids = Object.keys(configs);
  if (!ids.length) {
    row.style.display = "none";
    select.innerHTML = "";
    return;
  }
  var chosen = val(vciMetadata.idFor("credential_configuration_id")) || ids[0];
  select.innerHTML = ids.map(function (id) {
    var cfg = configs[id] || {};
    var label = id + (cfg.format ? " (" + cfg.format + ")" : "");
    return '<option value="' + esc(id) + '"' + (id === chosen ? ' selected="selected"' : '') + '>' +
           esc(label) + '</option>';
  }).join("");
  row.style.display = "";
}

function retrieveVciMetadata() {
  var url = val(VCI_URL_KEY);
  sdJwtVc.set(VCI_URL_KEY, url);
  if (!isUrl(url)) {
    status("vci_signed_metadata_status", "That is not a valid URL.", "vc-bad");
    return false;
  }
  status("vci_signed_metadata_status", "Retrieving " + url + " …", "vc-pending");
  metadataClient.fetchJson(url)
    .then(function (doc) {
      vciInfo = doc || {};
      VCI_STORE.save(vciInfo, { docLabel: VCI_DOC_LABEL, url: url });
      renderVciTable();
      renderCredentialConfigurations();
      defaultAuthorizationServerUrl();
      // Retrieving a document is what configures this workflow, so the
      // Configuration Parameters pane is filled in straight away. The Populate
      // Meta Data button below the table re-applies the document afterwards
      // (e.g. to undo a hand-edit, or after choosing another credential).
      var used = populateFromVciDocument();
      status("vci_signed_metadata_status",
        "Retrieved " + Object.keys(vciInfo).length + " members; " +
        Object.keys(vciInfo.credential_configurations_supported || {}).length +
        ' credential configuration(s) offered. Configuration Parameters populated (credential "' +
        used + '").', "vc-ok");
      log.debug("credential issuer metadata: " + JSON.stringify(vciInfo));
    })
    .catch(function (e) {
      status("vci_signed_metadata_status", "Could not retrieve the metadata: " + e.message, "vc-bad");
    });
  return false;
}

// Once the issuer says which authorization server protects it, offer that
// server's RFC 8414 endpoint in pane 2 — unless the user has already put
// something else there.
function defaultAuthorizationServerUrl() {
  var servers = vciInfo.authorization_servers;
  var as = (Object.prototype.toString.call(servers) === "[object Array]" && servers.length)
    ? servers[0] : "";
  if (!as) return;
  var current = val("oidc_discovery_endpoint");
  if (current && current.indexOf(AS_WELL_KNOWN) < 0) return;
  if (current && current.indexOf(as) === 0) return;
  setVal("oidc_discovery_endpoint", as.replace(/\/+$/, "") + AS_WELL_KNOWN);
  sdJwtVc.set("oidc_discovery_endpoint", val("oidc_discovery_endpoint"));
}

function clearVciMetadata() {
  vciInfo = {};
  VCI_STORE.forget();
  sdJwtVc.set(VCI_URL_KEY, "");
  setVal(VCI_URL_KEY, "");
  el("vci_metadata_table").innerHTML = "";
  el("vci_metadata_populate").innerHTML = "";
  el("vci_configuration_row").style.display = "none";
  vciMetadata.clearFields();
  vciMetadata.clearStorage();
  updateHandoffSummary();
  status("vci_signed_metadata_status", "Cleared.", "vc-ok");
  return false;
}

// Fill the OID4VCI half of the Configuration Parameters pane from the document
// on display and the credential currently chosen. Returns which credential.
function populateFromVciDocument() {
  var select = el("vci_credential_configuration_select");
  var chosen = select && select.value ? select.value : "";
  var used = vciMetadata.populateFromMetadata(vciInfo, chosen);
  updateHandoffSummary();
  return used;
}

function populateFromVci() {
  if (!vciInfo || !Object.keys(vciInfo).length) {
    status("vci_signed_metadata_status", "Retrieve the credential issuer metadata first.", "vc-bad");
    return false;
  }
  var used = populateFromVciDocument();
  status("vci_signed_metadata_status",
    'Configuration Parameters populated from the credential issuer metadata (credential "' + used + '").',
    "vc-ok");
  return false;
}

function onCredentialConfigurationChange() {
  // Only re-populate the credential-configuration half; the issuer-level values
  // are unaffected by which credential is chosen.
  if (vciInfo && Object.keys(vciInfo).length) populateFromVci();
  return false;
}

// The issuer's signing keys: a jwks_uri in the document if it has one,
// otherwise SD-JWT VC key resolution — /.well-known/jwt-vc-issuer under the
// credential issuer identifier, whose document carries the jwks_uri.
function resolveIssuerJwksUri(doc) {
  if (doc && doc.jwks_uri) return Promise.resolve(doc.jwks_uri);
  var issuer = (doc && doc.credential_issuer) || "";
  if (!issuer) return Promise.resolve("");
  return metadataClient.fetchJson(issuer.replace(/\/+$/, "") + JWT_VC_ISSUER_WELL_KNOWN)
    .then(function (m) { return (m && m.jwks_uri) || ""; })
    .catch(function () { return ""; });
}

function validateVciSignature() {
  var out = function (text, cls) { status("vci_signed_metadata_status", text, cls); };
  if (!vciInfo || !Object.keys(vciInfo).length) {
    out("Retrieve the credential issuer metadata first.", "vc-bad");
    return false;
  }
  out("Resolving the issuer's keys …", "vc-pending");
  resolveIssuerJwksUri(vciInfo)
    .then(function (jwksUri) {
      return metadataClient.validateSignedMetadata(vciInfo, {
        issuerMember: "credential_issuer",
        jwksUri: jwksUri,
        noSignedMetadataNote: "(signed_metadata is optional in OID4VCI.)",
        progress: function (t) { out(t, "vc-pending"); }
      });
    })
    .then(function (verdict) {
      out(verdict, verdict.indexOf("VALID") === 0 ? "vc-ok" : "vc-bad");
    });
  return false;
}

// ---------------------------------------------------------------------------
// Pane 2 — the authorization server metadata document.
//
// Same document, same storage keys and same table markup as the Metadata
// Retrieval pane on debugger.html, so retrieving it here configures that page
// too.
// ---------------------------------------------------------------------------
function renderAsTable() {
  var provenance = AS_STORE.readProvenance();
  el("discovery_info_table").innerHTML = metadataClient.buildInfoTable(asInfo, provenance);
  el("discovery_info_meta_data_populate").innerHTML =
    '<input class="btn_oidc_populate_meta_data btn2" id="as_populate_button" type="button"' +
    ' value="Populate Meta Data" onclick="return sdjwtvc1.populateFromAs();" />';
}

function retrieveAsMetadata() {
  var url = val("oidc_discovery_endpoint");
  sdJwtVc.set("oidc_discovery_endpoint", url);
  if (!isUrl(url)) {
    status("as_signed_metadata_status", "That is not a valid URL.", "vc-bad");
    return false;
  }
  status("as_signed_metadata_status", "Retrieving " + url + " …", "vc-pending");
  metadataClient.fetchJson(url)
    .then(function (doc) {
      asInfo = doc || {};
      AS_STORE.save(asInfo, { source: "rfc8414", docLabel: AS_DOC_LABEL, url: url });
      // debugger.html reads this to decide which source its radio shows.
      sdJwtVc.set("metadata_source", "rfc8414");
      renderAsTable();
      populateFromAsDocument();
      status("as_signed_metadata_status",
        "Retrieved " + Object.keys(asInfo).length + " members and populated the Configuration Parameters " +
        "pane. This document — and those values — are now what debugger.html shows too.",
        "vc-ok");
    })
    .catch(function (e) {
      status("as_signed_metadata_status", "Could not retrieve the metadata: " + e.message, "vc-bad");
    });
  return false;
}

function clearAsMetadata() {
  asInfo = {};
  AS_STORE.forget();
  el("discovery_info_table").innerHTML = "";
  el("discovery_info_meta_data_populate").innerHTML = "";
  setVal("oidc_discovery_endpoint", "");
  sdJwtVc.set("oidc_discovery_endpoint", "");
  ENDPOINT_FIELDS.forEach(function (f) { setVal(f.name, ""); sdJwtVc.set(f.name, ""); });
  opMetadata.clearFields();
  opMetadata.clearStorage();
  opMetadata.clearNotes();
  updateHandoffSummary();
  status("as_signed_metadata_status", "Cleared — here and on the debugger pages.", "vc-ok");
  return false;
}

function populateFromAs() {
  if (!asInfo || !Object.keys(asInfo).length) {
    status("as_signed_metadata_status", "Retrieve the authorization server metadata first.", "vc-bad");
    return false;
  }
  populateFromAsDocument();
  status("as_signed_metadata_status",
    "Configuration Parameters populated. debugger.html will run with these values.", "vc-ok");
  return false;
}

// Fill the authorization server half of the Configuration Parameters pane from
// the document on display: the endpoints that live under their own element ids,
// the scope, and every other member the document defines.
function populateFromAsDocument() {
  ENDPOINT_FIELDS.forEach(function (f) {
    var v = opMetadata.toField(asInfo[f.member]);
    setVal(f.name, v);
    sdJwtVc.set(f.name, v);
    opMetadata.markNotDefined(f.name, !Object.prototype.hasOwnProperty.call(asInfo, f.member));
  });
  populateScope();
  // ... and everything else the document defines — both the OpenID Provider
  // members and the six RFC 8414 adds, which populateFromDiscovery covers.
  opMetadata.populateFromDiscovery(asInfo);
  sdJwtVc.set("debugger_initialized", true);
  // The debugger pages write their dummy defaults over everything on what they
  // think is a first visit; this configuration is not one.
  sdJwtVc.set("initialized", true);
  updateHandoffSummary();
}

// The scope the authorization request will ask for.
//
// NOT simply scopes_supported: that is everything the SERVER knows about, and
// asking for scopes the client is not allowed usually earns an invalid_scope
// instead of an authorization code. So an existing value is left alone, an
// empty one gets the usual OIDC three (limited to what the server advertises),
// and the chosen credential configuration's own scope — the OID4VCI way of
// asking for authorization to issue that credential — is appended when the
// server advertises it.
function populateScope() {
  var supported = asInfo.scopes_supported;
  var have = (Object.prototype.toString.call(supported) === "[object Array]") ? supported : [];
  var current = (val("scope") || "").split(/\s+/).filter(Boolean);
  if (!current.length) {
    current = ["openid", "profile", "email"].filter(function (s) {
      return !have.length || have.indexOf(s) >= 0;
    });
  }
  var credentialScope = val(vciMetadata.idFor("scope"));
  if (credentialScope && have.indexOf(credentialScope) >= 0 && current.indexOf(credentialScope) < 0) {
    current.push(credentialScope);
  }
  var scopes = current.join(" ");
  setVal("scope", scopes);
  sdJwtVc.set("scope", scopes);
  sdJwtVc.set("token_scope", scopes);
}

function validateAsSignature() {
  var out = function (text, cls) { status("as_signed_metadata_status", text, cls); };
  metadataClient.validateSignedMetadata(asInfo || {}, {
    issuerMember: "issuer",
    noSignedMetadataNote: "(signed_metadata is an RFC 8414 member; OIDC Discovery does not define it.)",
    progress: function (t) { out(t, "vc-pending"); }
  }).then(function (verdict) {
    out(verdict, verdict.indexOf("VALID") === 0 ? "vc-ok" : "vc-bad");
  });
  return false;
}

// ---------------------------------------------------------------------------
// Pane 4 — the hand-off.
// ---------------------------------------------------------------------------
function updateHandoffSummary() {
  var authz = val("authorization_endpoint");
  var cfg = vciMetadata.currentRequestConfig();
  var e = el("handoff_authorization_endpoint");
  if (e) e.textContent = authz || "—";
  e = el("handoff_credential");
  if (e) {
    e.textContent = cfg.credentialConfigurationId
      ? cfg.credentialConfigurationId + " (" + (cfg.format || "?") + ", vct " + (cfg.vct || "?") + ")"
      : "—";
  }
}

function startIssuance() {
  saveConfiguration();
  var missing = [];
  if (!val("authorization_endpoint")) missing.push("authorization_endpoint");
  if (!val("token_endpoint")) missing.push("token_endpoint");
  if (!val("client_id")) missing.push("client_id");
  if (!val(vciMetadata.idFor("credential_endpoint"))) missing.push("credential_endpoint");
  if (missing.length) {
    status("handoff_status",
      "Cannot start: " + missing.join(", ") + " " + (missing.length === 1 ? "is" : "are") +
      " empty. Retrieve the metadata documents above (or fill the fields in by hand) first.", "vc-bad");
    return false;
  }
  // debugger.html runs whichever grant its select says; this workflow needs the
  // OIDC Authorization Code flow.
  sdJwtVc.set("authorization_grant_type", "oidc_authorization_code_flow");
  sdJwtVc.startFlow();
  status("handoff_status", "Starting the OIDC Authorization Code flow …", "vc-pending");
  window.location.href = "/debugger.html?sdjwtvc=1";
  return false;
}

// ---------------------------------------------------------------------------
function isUrl(url) {
  try { return Boolean(new URL(url)); } catch (e) { return false; }
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

function clickLink() { return true; }

function onload() {
  buildConfigRows();
  loadConfiguration();

  // The metadata URLs.
  var storedVciUrl = sdJwtVc.get(VCI_URL_KEY);
  setVal(VCI_URL_KEY, (storedVciUrl === null || storedVciUrl === undefined)
    ? (appconfig.oid4vciIssuerUrlDefault || "") + VCI_WELL_KNOWN
    : storedVciUrl);
  // The RFC 8414 pane defaults to the mock authorization server the STS service
  // publishes (empty where there is no such service). A stored value wins —
  // including the empty string a Clear leaves behind, so a clear survives a
  // reload instead of the default coming back.
  var storedAsUrl = sdJwtVc.get("oidc_discovery_endpoint");
  setVal("oidc_discovery_endpoint",
    (storedAsUrl === null || storedAsUrl === undefined)
      ? (appconfig.rfc8414MetadataUrlDefault || "")
      : storedAsUrl);

  // Whatever was retrieved last time, so the tables survive a reload.
  vciInfo = VCI_STORE.read() || {};
  if (Object.keys(vciInfo).length) { renderVciTable(); renderCredentialConfigurations(); }
  asInfo = AS_STORE.read() || {};
  if (Object.keys(asInfo).length) {
    renderAsTable();
    opMetadata.applyNotes(asInfo);
  }

  var step = document.getElementById("vc_step_1");
  if (step) step.className = "vc-step-current";
  updateHandoffSummary();
  log.debug("SD-JWT VC issuance step 1 ready.");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  retrieveVciMetadata: retrieveVciMetadata,
  clearVciMetadata: clearVciMetadata,
  populateFromVci: populateFromVci,
  onCredentialConfigurationChange: onCredentialConfigurationChange,
  validateVciSignature: validateVciSignature,
  retrieveAsMetadata: retrieveAsMetadata,
  clearAsMetadata: clearAsMetadata,
  populateFromAs: populateFromAs,
  validateAsSignature: validateAsSignature,
  saveConfiguration: saveConfiguration,
  clearConfiguration: clearConfiguration,
  restoreDefaults: restoreDefaults,
  startIssuance: startIssuance,
  updateHandoffSummary: updateHandoffSummary,
  togglePane: togglePane,
  clickLink: clickLink,
  onload: onload
};
