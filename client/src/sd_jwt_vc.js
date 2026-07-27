// File: sd_jwt_vc.js
//
// ---------------------------------------------------------------------------
// State and parsing shared by the three SD-JWT VC issuance pages.
//
//   sd-jwt-vc-issuance-1.html  discovery + configuration, then hands off to the
//                              OIDC Authorization Code flow on debugger.html
//   sd-jwt-vc-issuance-2.html  the tokens that came back, the user's approval,
//                              and the OID4VCI Credential Request
//   sd-jwt-vc-issuance-3.html  the issued SD-JWT VC
//
// The workflow crosses four page loads and an identity provider round trip, so
// everything that has to survive that lives in localStorage under one set of
// keys, defined here once.
// ---------------------------------------------------------------------------

var metadataClient = require("./metadata_client");
var vciMetadata = require("./vci_metadata");

var KEYS = {
  // "active" while the workflow is driving debugger.html / debugger2.html.
  FLOW: "sdjwtvc_flow",
  // Where debugger2.html should send the browser once it has the tokens.
  RETURN: "sdjwtvc_return",
  // The compact SD-JWT VC returned by the credential endpoint.
  CREDENTIAL: "sdjwtvc_credential",
  // How it was obtained: { issuer, endpoint, configurationId, vct, requestedAt,
  //                        notificationId, request }
  CREDENTIAL_META: "sdjwtvc_credential_meta",
  // The holder key pair the proof of possession is signed with (JWK; the
  // private half never leaves the browser).
  HOLDER_JWK: "sdjwtvc_holder_jwk",
  HOLDER_PRIVATE_JWK: "sdjwtvc_holder_private_jwk"
};

var FLOW_ACTIVE = "active";
var STEP2_URL = "/sd-jwt-vc-issuance-2.html";
var STEP3_URL = "/sd-jwt-vc-issuance-3.html";

function ls() {
  try { return window.localStorage; } catch (e) { return null; }
}
function get(key) { var s = ls(); return s ? s.getItem(key) : null; }
function set(key, value) { var s = ls(); if (s) { try { s.setItem(key, value); } catch (e) { /* quota */ } } }
function remove(key) { var s = ls(); if (s) { try { s.removeItem(key); } catch (e) { /* no storage */ } } }

function getJson(key) {
  var raw = get(key);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}
function setJson(key, value) { set(key, JSON.stringify(value)); }

// --- the hand-off to the OIDC pages ----------------------------------------
function startFlow() {
  set(KEYS.FLOW, FLOW_ACTIVE);
  set(KEYS.RETURN, STEP2_URL);
}
function isFlowActive() { return get(KEYS.FLOW) === FLOW_ACTIVE; }
// Consumed by debugger2.html the moment it forwards, so a later, unrelated
// token exchange on that page does not get redirected too.
function endFlow() { remove(KEYS.FLOW); }
function returnUrl() { return get(KEYS.RETURN) || STEP2_URL; }

// --- what the Credential Request needs --------------------------------------
// Read from localStorage rather than the DOM: steps 2 and 3 do not carry the
// Configuration Parameters pane, but they run on what it saved.
function storedRequestConfig() {
  function v(name) { return get(vciMetadata.idFor(name)) || ""; }
  return {
    credentialIssuer: v("credential_issuer"),
    credentialEndpoint: v("credential_endpoint"),
    nonceEndpoint: v("nonce_endpoint"),
    notificationEndpoint: v("notification_endpoint"),
    credentialConfigurationId: v("credential_configuration_id"),
    format: v("format"),
    vct: v("vct"),
    proofAlgs: v("proof_signing_alg_values_supported")
  };
}

// ---------------------------------------------------------------------------
// SD-JWT parsing — RFC 9901 section 4.
//
// Combined Serialization is
//
//   <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<Key Binding JWT>]
//
// with the trailing ~ REQUIRED when there is no Key Binding JWT. So an empty
// last part means "no KB-JWT", and a non-empty one is the KB-JWT.
//
// A Disclosure is base64url(JSON), either [salt, claim name, claim value] for
// an object property or [salt, value] for an array element.
// ---------------------------------------------------------------------------
function parseSdJwt(serialized) {
  var raw = String(serialized || "").trim();
  if (!raw) throw new Error("There is no credential to parse.");
  var parts = raw.split("~");
  var issuerJwt = parts.shift();
  var kbJwt = "";
  if (parts.length && parts[parts.length - 1] !== "") {
    kbJwt = parts.pop();
  } else if (parts.length) {
    parts.pop(); // the required trailing empty part
  }
  var jwtParts = String(issuerJwt).split(".");
  if (jwtParts.length !== 3) throw new Error("The issuer-signed part is not a three-part JWS.");

  var header, payload;
  try { header = metadataClient.b64uToJson(jwtParts[0]); }
  catch (e) { throw new Error("Cannot read the issuer-signed JWT header: " + e.message); }
  try { payload = metadataClient.b64uToJson(jwtParts[1]); }
  catch (e) { throw new Error("Cannot read the issuer-signed JWT payload: " + e.message); }

  var disclosures = parts.filter(function (p) { return p !== ""; }).map(function (encoded) {
    var d = { encoded: encoded, salt: "", name: null, value: undefined, arrayElement: false, error: "" };
    try {
      var arr = metadataClient.b64uToJson(encoded);
      if (Object.prototype.toString.call(arr) !== "[object Array]") {
        throw new Error("a Disclosure must be a JSON array");
      }
      d.salt = arr[0];
      if (arr.length === 3) { d.name = arr[1]; d.value = arr[2]; }
      else if (arr.length === 2) { d.arrayElement = true; d.value = arr[1]; }
      else { throw new Error("a Disclosure has 2 (array element) or 3 (object property) members, got " + arr.length); }
    } catch (e) {
      d.error = e.message;
    }
    return d;
  });

  return {
    serialized: raw,
    issuerJwt: issuerJwt,
    header: header,
    payload: payload,
    signature: jwtParts[2],
    disclosures: disclosures,
    kbJwt: kbJwt
  };
}

// The digest that an SD-JWT's _sd array carries for a Disclosure: the hash of
// the US-ASCII of the base64url-encoded Disclosure, base64url-encoded.
// _sd_alg defaults to sha-256 (RFC 9901 section 4.1.1).
function digestForDisclosure(encoded, sdAlg) {
  var alg = String(sdAlg || "sha-256").toLowerCase();
  var webcrypto = { "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" }[alg];
  if (!webcrypto) return Promise.reject(new Error('unsupported _sd_alg "' + sdAlg + '".'));
  var bytes = new Uint8Array(String(encoded).length);
  for (var i = 0; i < encoded.length; i++) { bytes[i] = encoded.charCodeAt(i) & 0xff; }
  return crypto.subtle.digest(webcrypto, bytes).then(function (buf) {
    return metadataClient.bytesToB64u(buf);
  });
}

// Every _sd digest in the payload, at any nesting depth, plus the {"...": digest}
// form used for selectively-disclosable ARRAY elements.
function collectSdDigests(node, out) {
  out = out || [];
  if (!node || typeof node !== "object") return out;
  if (Object.prototype.toString.call(node) === "[object Array]") {
    node.forEach(function (item) {
      if (item && typeof item === "object" && typeof item["..."] === "string") out.push(item["..."]);
      else collectSdDigests(item, out);
    });
    return out;
  }
  Object.keys(node).forEach(function (k) {
    if (k === "_sd" && Object.prototype.toString.call(node[k]) === "[object Array]") {
      node[k].forEach(function (d) { if (typeof d === "string") out.push(d); });
    } else if (typeof node[k] === "object") {
      collectSdDigests(node[k], out);
    }
  });
  return out;
}

// The claim set a verifier would end up with: the always-visible claims of the
// payload (minus the SD-JWT machinery) plus every disclosed claim.
function disclosedClaims(parsed) {
  var claims = {};
  Object.keys(parsed.payload || {}).forEach(function (k) {
    if (k === "_sd" || k === "_sd_alg") return;
    claims[k] = parsed.payload[k];
  });
  (parsed.disclosures || []).forEach(function (d) {
    if (d.error || d.arrayElement || d.name === null) return;
    claims[d.name] = d.value;
  });
  return claims;
}

module.exports = {
  KEYS: KEYS,
  STEP2_URL: STEP2_URL,
  STEP3_URL: STEP3_URL,
  get: get,
  set: set,
  remove: remove,
  getJson: getJson,
  setJson: setJson,
  startFlow: startFlow,
  isFlowActive: isFlowActive,
  endFlow: endFlow,
  returnUrl: returnUrl,
  storedRequestConfig: storedRequestConfig,
  parseSdJwt: parseSdJwt,
  digestForDisclosure: digestForDisclosure,
  collectSdDigests: collectSdDigests,
  disclosedClaims: disclosedClaims
};
