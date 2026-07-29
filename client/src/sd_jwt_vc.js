// File: sd_jwt_vc.js
//
// ---------------------------------------------------------------------------
// State and parsing shared by the SD-JWT VC issuance pages.
//
//   sd-jwt-vc-issuance-1.html  discovery + configuration, then hands off to the
//                              OIDC Authorization Code flow on debugger.html
//   sd-jwt-vc-issuance-2.html  the tokens that came back, the user's approval,
//                              and the OID4VCI Credential Request
//   sd-jwt-vc-issuance-3.html  the issued SD-JWT VC
//   sd-jwt-vc-issuance-4.html  refreshing it: a Refresh Token for a fresh
//                              Access Token, then the Credential Endpoint again
//                              (OID4VCI section 14.5)
//
// The workflow crosses several page loads and an identity provider round trip,
// so everything that has to survive that lives in localStorage under one set of
// keys, defined here once.
// ---------------------------------------------------------------------------


var bunyan = require("bunyan");
// The log level comes from the same configuration the pages use. A consumer
// outside the browser bundles (the node-based tests load this module directly)
// may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "sd_jwt_vc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var metadataClient = require("./metadata_client");
var vciMetadata = require("./vci_metadata");

var KEYS = {
  // "active" while the workflow is driving debugger.html / debugger2.html.
  FLOW: "sdjwtvc_flow",
  // Where debugger2.html should send the browser once it has the tokens.
  RETURN: "sdjwtvc_return",
  // The compact SD-JWT VC returned by the credential endpoint. When a batch was
  // requested this is the first of them; CREDENTIALS has them all, in the order
  // the proofs were sent.
  CREDENTIAL: "sdjwtvc_credential",
  CREDENTIALS: "sdjwtvc_credentials",
  // How it was obtained: { issuer, endpoint, configurationId, vct, requestedAt,
  //                        notificationId, request }
  CREDENTIAL_META: "sdjwtvc_credential_meta",
  // The holder key pair the proof of possession is signed with (JWK; the
  // private half never leaves the browser).
  HOLDER_JWK: "sdjwtvc_holder_jwk",
  HOLDER_PRIVATE_JWK: "sdjwtvc_holder_private_jwk",
  // Which OID4VCI Appendix H use case the workflow is running.
  USE_CASE: "sdjwtvc_use_case",
  // The Credential Offer, when the use case has one: { offer, source, receivedAt }.
  OFFER: "sdjwtvc_credential_offer",
  // ---- refreshing (step 4, OID4VCI section 14.5) --------------------------
  // What the issuer returned to the refresh request, held SEPARATELY from the
  // credential in hand: section 14.5 leaves it to the wallet to decide whether
  // to keep the old one, and a wallet that overwrites before the holder has
  // looked has made that decision for them.
  REFRESHED_CREDENTIAL: "sdjwtvc_refreshed_credential",
  REFRESHED_CREDENTIALS: "sdjwtvc_refreshed_credentials",
  REFRESHED_META: "sdjwtvc_refreshed_credential_meta",
  // The key a refresh bound the new credential to, when it was asked to bind a
  // NEW one. It becomes the wallet's holder key only if that credential is kept:
  // overwriting HOLDER_PRIVATE_JWK before then would throw away the private half
  // of the key the credential still in hand is bound to, leaving it impossible to
  // present.
  REFRESHED_HOLDER_JWK: "sdjwtvc_refreshed_holder_jwk",
  REFRESHED_HOLDER_PRIVATE_JWK: "sdjwtvc_refreshed_holder_private_jwk",
  // The credential that WAS in hand when a refresh replaced it, so what changed
  // is still there to look at afterwards — with the key it is bound to, because a
  // credential without its holder key cannot be presented at all.
  PREVIOUS_CREDENTIAL: "sdjwtvc_previous_credential",
  PREVIOUS_META: "sdjwtvc_previous_credential_meta",
  PREVIOUS_HOLDER_JWK: "sdjwtvc_previous_holder_jwk",
  PREVIOUS_HOLDER_PRIVATE_JWK: "sdjwtvc_previous_holder_private_jwk",
  // Every credential the wallet has held, oldest first, and which of them is the
  // one in hand. See the credential history below.
  HISTORY: "sdjwtvc_credential_history",
  HISTORY_INDEX: "sdjwtvc_credential_history_index",
  // How many generations the list has had to forget, so it can say so.
  HISTORY_DROPPED: "sdjwtvc_credential_history_dropped"
};

// ---------------------------------------------------------------------------
// Which use case the workflow is running.
//
// OID4VCI Appendix H describes several; they differ on the wire in how the
// issuance is started and which grant is used, so the workflow carries the
// choice rather than guessing. Step 0 (sd-jwt-vc-issuance-0.html) is where it
// is made; every later page shows which one is running.
//
//   id           the value stored under KEYS.USE_CASE
//   label        the short name shown in the badge
//   spec         the Appendix H section
//   available    false for the ones not implemented yet — step 0 shows them,
//                clearly, rather than pretending they are not coming
// ---------------------------------------------------------------------------
var USE_CASES = [
  {
    id: "wallet-initiated",
    spec: "H.6",
    label: "Wallet-initiated",
    title: "Start from the wallet",
    summary: "You know which issuer you want. The wallet retrieves its metadata, you pick a credential, " +
             "and the wallet asks for it.",
    detail: "Nothing is offered to you: the wallet drives the whole thing. This is what the workflow did " +
            "before the other use cases existed, and it is the plain Authorization Code flow with no " +
            "Credential Offer involved.",
    mechanics: "Issuer metadata by URL → Authorization Code + PKCE → Credential Request.",
    available: true
  },
  {
    id: "offer-same-device",
    spec: "H.1",
    label: "Credential Offer — same device",
    title: "The issuer offers you a credential",
    summary: "You are on the issuer's web page and follow a link that offers you a credential. It hands " +
             "your wallet a Credential Offer, on this same device.",
    detail: "The issuer builds a Credential Offer naming itself, the credential on offer, and an " +
            "issuer_state that ties what follows back to the offer. Your wallet shows you what was " +
            "offered before anything is requested.",
    mechanics: "Credential Offer (by value or by reference) → Authorization Code + PKCE with issuer_state → " +
               "Credential Request.",
    available: true
  },
  {
    id: "offer-cross-device",
    spec: "H.2",
    label: "Credential Offer — cross device",
    title: "Scan a code, type a transaction code",
    summary: "The issuer shows a QR code on another screen. Your wallet scans it and you type a short " +
             "transaction code sent to you separately.",
    detail: "The offer carries a pre-authorized code instead of sending you to a login page, so there is " +
            "no authorization request at all — the transaction code is what proves it is really you.",
    mechanics: "Credential Offer with a pre-authorized_code grant + tx_code → Token Request → " +
               "Credential Request.",
    available: true
  },
  {
    id: "offer-deferred",
    spec: "H.3",
    label: "Credential Offer — deferred",
    title: "The credential is not ready yet",
    summary: "The issuer accepts your request but needs time — background checks, a human in the loop — " +
             "and your wallet collects the credential later.",
    detail: "The credential endpoint answers with a transaction identifier instead of a credential, and " +
            "the wallet comes back to the deferred endpoint until it is ready.",
    mechanics: "Credential Request → transaction_id → Deferred Credential Request → Credential.",
    available: true
  }
];

var DEFAULT_USE_CASE = "wallet-initiated";

function useCases() { return USE_CASES; }

function useCaseById(id) {
  for (var i = 0; i < USE_CASES.length; i++) {
    if (USE_CASES[i].id === id) return USE_CASES[i];
  }
  return null;
}

function currentUseCase() {
  return useCaseById(get(KEYS.USE_CASE)) || useCaseById(DEFAULT_USE_CASE);
}

function setUseCase(id) {
  var uc = useCaseById(id);
  if (!uc) return null;
  set(KEYS.USE_CASE, uc.id);
  // The use case can change part-way through a page's life — an arriving
  // Credential Offer switches it after the badge has already been drawn — so
  // redraw it here rather than leaving every caller to remember.
  if (typeof document !== "undefined" && document.getElementById("vc_use_case_badge")) {
    renderUseCaseBadge();
  }
  return uc;
}

// Show which use case is running, in the step indicator every page includes.
function renderUseCaseBadge() {
  var host = document.getElementById("vc_steps");
  if (!host) return null;
  var uc = currentUseCase();
  var existing = document.getElementById("vc_use_case_badge");
  if (existing) existing.parentNode.removeChild(existing);
  var badge = document.createElement("p");
  badge.id = "vc_use_case_badge";
  badge.className = "vc-use-case-badge";
  badge.innerHTML = 'Use case: <strong>' + uc.spec + ' &middot; ' + uc.label + '</strong> — ' +
                    uc.mechanics + ' <a href="/sd-jwt-vc-issuance-0.html">change</a>';
  host.parentNode.insertBefore(badge, host.nextSibling);
  return uc;
}

// ---------------------------------------------------------------------------
// The Credential Offer (OID4VCI section 4), for the use cases that have one.
// ---------------------------------------------------------------------------
function storeOffer(offer, source) {
  setJson(KEYS.OFFER, { offer: offer, source: source, receivedAt: new Date().toISOString() });
}

function storedOffer() { return getJson(KEYS.OFFER); }

function forgetOffer() { remove(KEYS.OFFER); }

// The pre-authorized code grant, if that is what the offer carries. An offer has
// one grant or the other: authorization_code sends the End-User through the
// authorization server, pre-authorized_code says that already happened
// somewhere else and this code is the proof of it.
//
// Every one of these reads the STORED offer when called with no argument, the
// same way offerIssuerState() does — a page usually wants "the offer in hand".
var PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

function offerOrStored(offer) {
  if (offer) return offer;
  var stored = storedOffer();
  return (stored && stored.offer) || null;
}

function preAuthorizedGrant(offer) {
  var grants = (offerOrStored(offer) || {}).grants || {};
  return grants[PRE_AUTHORIZED_GRANT] || null;
}

// The Transaction Code the offer says is required — its SHAPE, never its value:
// the value reaches the End-User by another channel entirely, which is the
// point of it. { input_mode, length, description } or null.
function offerTxCode(offer) {
  var grant = preAuthorizedGrant(offer);
  return (grant && grant.tx_code) || null;
}

function offerPreAuthorizedCode(offer) {
  var grant = preAuthorizedGrant(offer);
  return (grant && grant["pre-authorized_code"]) || "";
}

// The issuer_state an authorization_code offer carries, if there is one. The
// authorization request has to send it back.
function offerIssuerState() {
  var stored = storedOffer();
  var grants = stored && stored.offer && stored.offer.grants;
  var authz = grants && grants.authorization_code;
  return (authz && authz.issuer_state) || "";
}

var FLOW_ACTIVE = "active";
var STEP2_URL = "/sd-jwt-vc-issuance-2.html";
var STEP3_URL = "/sd-jwt-vc-issuance-3.html";
var STEP4_URL = "/sd-jwt-vc-issuance-4.html";

function ls() {
  try {
    return window.localStorage;
  } catch (e) {
    // Blocked (private mode, third-party restrictions): the workflow degrades to
    // "nothing was remembered" rather than failing.
    return null;
  }
}
function get(key) {
  var s = ls();
  return s ? s.getItem(key) : null;
}

function set(key, value) {
  var s = ls();
  if (!s) return;
  try {
    s.setItem(key, value);
  } catch (e) {
    // Over quota, or storage disabled: there is nothing to fall back to.
  }
}

function remove(key) {
  var s = ls();
  if (!s) return;
  try {
    s.removeItem(key);
  } catch (e) {
    // No storage in this context; nothing to remove.
  }
}

function getJson(key) {
  var raw = get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    // A value written by an older build, or hand-edited: treat it as absent.
    return null;
  }
}
function setJson(key, value) { set(key, JSON.stringify(value)); }

// ---------------------------------------------------------------------------
// The credential history.
//
// A credential is not one object over its life: the issuance produces one, and
// every refresh (OID4VCI section 14.5) produces another that may replace it. A
// wallet that keeps only the newest cannot answer "what did I hold before this,
// and what changed" — which is the question a debugger exists to answer — so
// every credential the wallet has HELD is recorded here, oldest first, and step 4
// navigates them. It is the same idea as the Token History pane on
// debugger2.html, for credentials instead of token sets.
//
// Only credentials the wallet actually held are in it. One the holder looked at
// and discarded was never held, and recording it would make this a log of what
// the issuer offered rather than of what the wallet has.
//
// Each entry carries its own holder key pair, because a credential whose cnf key
// the wallet has lost cannot be presented at all: going back to an earlier
// generation has to bring that key with it.
// ---------------------------------------------------------------------------
var HISTORY_LIMIT = 20;

function credentialHistory() {
  var history = getJson(KEYS.HISTORY);
  return Object.prototype.toString.call(history) === "[object Array]" ? history : [];
}

// Which generation is the one in hand. Out-of-range (or absent) means the newest,
// which is what has just been recorded.
function activeCredentialIndex() {
  var history = credentialHistory();
  var raw = parseInt(get(KEYS.HISTORY_INDEX), 10);
  if (isNaN(raw) || raw < 0 || raw >= history.length) return history.length ? history.length - 1 : -1;
  return raw;
}

// How many generations fell off the end of the list. Kept so the pane can say so:
// a history that silently forgets reads as a complete one.
function droppedGenerations() {
  var n = parseInt(get(KEYS.HISTORY_DROPPED) || "0", 10);
  return isNaN(n) ? 0 : n;
}

// The few things the history table shows about a credential, read off it once
// when it is recorded rather than on every render.
function summarizeCredential(serialized) {
  log.debug("Entering summarizeCredential().");
  var summary = { vct: "", iat: 0, nbf: 0, exp: 0, disclosures: 0, boundKey: "", signature: "" };
  var parsed;
  try {
    parsed = parseSdJwt(serialized);
  } catch (e) {
    // A credential this build cannot parse is still one the wallet held; it goes
    // in the history with an empty summary rather than being dropped.
    log.debug("Leaving summarizeCredential(). Unparseable: " + e.message);
    return summary;
  }
  var payload = parsed.payload || {};
  summary.vct = payload.vct || "";
  summary.iat = payload.iat || 0;
  summary.nbf = payload.nbf || 0;
  summary.exp = payload.exp || 0;
  summary.disclosures = (parsed.disclosures || []).length;
  summary.boundKey = (payload.cnf && payload.cnf.jwk && payload.cnf.jwk.x) || "";
  summary.signature = parsed.signature || "";
  log.debug("Leaving summarizeCredential(). vct=" + summary.vct);
  return summary;
}

// Record a credential the wallet has taken into its hand, and make it the active
// generation. `entry` is { source, credential, credentials, meta, holderJwk,
// holderPrivateJwk }.
function recordCredentialGeneration(entry) {
  log.debug("Entering recordCredentialGeneration(). source=" + (entry && entry.source));
  var history = credentialHistory();
  var credential = (entry && entry.credential) || "";
  if (!credential) {
    log.debug("Leaving recordCredentialGeneration(). There is no credential to record.");
    return -1;
  }
  // The same bytes twice in a row are one generation, not two: a page that
  // re-stores what it already stored (a reload, a retried click) must not make
  // the history say the wallet was issued two credentials.
  if (history.length && history[history.length - 1].credential === credential) {
    set(KEYS.HISTORY_INDEX, String(history.length - 1));
    log.debug("Leaving recordCredentialGeneration(). Already the newest generation.");
    return history.length - 1;
  }
  history.push({
    at: new Date().toISOString(),
    source: entry.source || "issued",
    credential: credential,
    credentials: entry.credentials && entry.credentials.length ? entry.credentials : [credential],
    meta: entry.meta || {},
    holderJwk: entry.holderJwk || null,
    holderPrivateJwk: entry.holderPrivateJwk || null,
    summary: summarizeCredential(credential)
  });
  var dropped = 0;
  while (history.length > HISTORY_LIMIT) {
    history.shift();
    dropped++;
  }
  if (dropped) {
    set(KEYS.HISTORY_DROPPED, String(droppedGenerations() + dropped));
    log.debug("recordCredentialGeneration(): dropped " + dropped + " generation(s) past the limit of " +
              HISTORY_LIMIT + ".");
  }
  setJson(KEYS.HISTORY, history);
  set(KEYS.HISTORY_INDEX, String(history.length - 1));
  log.debug("Leaving recordCredentialGeneration(). Generation " + history.length + " recorded.");
  return history.length - 1;
}

// Make an earlier (or later) generation the credential the wallet holds — with
// its holder key, or the credential could not be presented.
function activateCredentialGeneration(index) {
  log.debug("Entering activateCredentialGeneration(). index=" + index);
  var history = credentialHistory();
  if (index < 0 || index >= history.length) {
    log.debug("Leaving activateCredentialGeneration(). No such generation.");
    return null;
  }
  var entry = history[index];
  set(KEYS.CREDENTIAL, entry.credential);
  setJson(KEYS.CREDENTIALS, entry.credentials || [entry.credential]);
  setJson(KEYS.CREDENTIAL_META, entry.meta || {});
  if (entry.holderJwk && entry.holderPrivateJwk) {
    setJson(KEYS.HOLDER_JWK, entry.holderJwk);
    setJson(KEYS.HOLDER_PRIVATE_JWK, entry.holderPrivateJwk);
  }
  set(KEYS.HISTORY_INDEX, String(index));
  log.debug("Leaving activateCredentialGeneration(). Generation " + (index + 1) + " is now in hand.");
  return entry;
}

// Forget the list, not the credential: whatever is in hand stays in hand.
//
// An EMPTY list is written rather than the key removed, because "cleared on
// purpose" and "nothing was ever recorded" are different: only the second should
// make a page backfill the credential in hand as generation 1. hasCredentialHistory()
// is that distinction.
function clearCredentialHistory() {
  log.debug("Entering clearCredentialHistory().");
  setJson(KEYS.HISTORY, []);
  remove(KEYS.HISTORY_INDEX);
  remove(KEYS.HISTORY_DROPPED);
  log.debug("Leaving clearCredentialHistory().");
}

// Whether this browser has ever recorded a generation — as opposed to holding an
// empty list because someone cleared it.
function hasCredentialHistory() { return get(KEYS.HISTORY) !== null; }

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
  log.debug("Entering storedRequestConfig().");
  function v(name) { return get(vciMetadata.idFor(name)) || ""; }
  log.debug("Leaving storedRequestConfig().");
  return {
    credentialIssuer: v("credential_issuer"),
    credentialEndpoint: v("credential_endpoint"),
    nonceEndpoint: v("nonce_endpoint"),
    notificationEndpoint: v("notification_endpoint"),
    // OPTIONAL, and absent from issuers that cannot defer an issuance at all.
    deferredCredentialEndpoint: v("deferred_credential_endpoint"),
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
  log.debug("Entering parseSdJwt().");
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
  try {
    header = metadataClient.b64uToJson(jwtParts[0]);
  } catch (e) {
    throw new Error("Cannot read the issuer-signed JWT header: " + e.message);
  }
  try {
    payload = metadataClient.b64uToJson(jwtParts[1]);
  } catch (e) {
    throw new Error("Cannot read the issuer-signed JWT payload: " + e.message);
  }

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

  log.debug("Leaving parseSdJwt().");
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
  log.debug("Entering collectSdDigests().");
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
  log.debug("Leaving collectSdDigests().");
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
  USE_CASES: USE_CASES,
  DEFAULT_USE_CASE: DEFAULT_USE_CASE,
  useCases: useCases,
  useCaseById: useCaseById,
  currentUseCase: currentUseCase,
  setUseCase: setUseCase,
  renderUseCaseBadge: renderUseCaseBadge,
  storeOffer: storeOffer,
  storedOffer: storedOffer,
  forgetOffer: forgetOffer,
  offerIssuerState: offerIssuerState,
  PRE_AUTHORIZED_GRANT: PRE_AUTHORIZED_GRANT,
  preAuthorizedGrant: preAuthorizedGrant,
  offerTxCode: offerTxCode,
  offerPreAuthorizedCode: offerPreAuthorizedCode,
  STEP2_URL: STEP2_URL,
  STEP3_URL: STEP3_URL,
  STEP4_URL: STEP4_URL,
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
  HISTORY_LIMIT: HISTORY_LIMIT,
  credentialHistory: credentialHistory,
  hasCredentialHistory: hasCredentialHistory,
  activeCredentialIndex: activeCredentialIndex,
  droppedGenerations: droppedGenerations,
  summarizeCredential: summarizeCredential,
  recordCredentialGeneration: recordCredentialGeneration,
  activateCredentialGeneration: activateCredentialGeneration,
  clearCredentialHistory: clearCredentialHistory,
  parseSdJwt: parseSdJwt,
  digestForDisclosure: digestForDisclosure,
  collectSdDigests: collectSdDigests,
  disclosedClaims: disclosedClaims
};
