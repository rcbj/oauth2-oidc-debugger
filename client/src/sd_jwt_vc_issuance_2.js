// File: sd_jwt_vc_issuance_2.js
//
// ---------------------------------------------------------------------------
// SD-JWT VC issuance, step 2: the tokens, the user's approval, and the OID4VCI
// Credential Request.
//
// By the time this page loads, the OIDC Authorization Code flow has run on
// debugger.html / debugger2.html and left its tokens in local storage. This
// page plays the rest of the wallet's part:
//
//   1. generate a holder key pair (in the browser; the private half never
//      leaves it),
//   2. ask the issuer's Nonce Endpoint for a c_nonce,
//   3. sign a proof of possession (typ openid4vci-proof+jwt) with the holder
//      key, naming the credential issuer as its audience,
//   4. POST the Credential Request to the Credential Endpoint with the access
//      token as a Bearer credential,
//   5. keep the SD-JWT VC that comes back and go to step 3.
//
// Steps 2-4 only happen when the user approves.
// ---------------------------------------------------------------------------

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");

var log = bunyan.createLogger({ name: 'sd_jwt_vc_issuance_2',
                                level: appconfig.LOG_LEVEL || 'info' });

var PROOF_TYP = "openid4vci-proof+jwt";
var PROOF_ALG = "ES256";

// The request as it currently stands: what step 1 configured, plus what this
// page generates.
var request = {
  config: null,
  holderPublicJwk: null,
  holderPrivateJwk: null,
  nonce: "",
  proof: "",
  body: null
};

function el(id) { return document.getElementById(id); }
function setText(id, text) { var e = el(id); if (e) e.textContent = (text == null ? "" : String(text)); }
function setJson(id, value) {
  var e = el(id);
  if (e) e.textContent = (value === null || value === undefined) ? "—" : JSON.stringify(value, null, 2);
}
function setValue(id, v) { var e = el(id); if (e) e.value = (v == null ? "" : v); }
function status(id, text, cls) {
  var e = el(id);
  if (!e) return;
  e.textContent = text;
  e.className = "vc-status" + (cls ? " " + cls : "");
}

// --- the holder key ---------------------------------------------------------
// ES256, because it is what OID4VCI wallets use and what the mock issuer
// advertises in proof_signing_alg_values_supported.
function generateHolderKey() {
  log.debug("Entering generateHolderKey().");
  log.debug("Leaving generateHolderKey().");
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    .then(function (pair) {
      return Promise.all([
        crypto.subtle.exportKey("jwk", pair.publicKey),
        crypto.subtle.exportKey("jwk", pair.privateKey)
      ]);
    })
    .then(function (jwks) {
      // Only the members that identify the key: a stray key_ops/ext/alg makes a
      // strict JWK consumer unhappy, and the issuer echoes this object straight
      // into the credential's cnf claim.
      var pub = { kty: jwks[0].kty, crv: jwks[0].crv, x: jwks[0].x, y: jwks[0].y };
      request.holderPublicJwk = pub;
      request.holderPrivateJwk = jwks[1];
      sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_JWK, pub);
      sdJwtVc.setJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK, jwks[1]);
      return pub;
    });
}

function loadOrGenerateHolderKey() {
  var pub = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_JWK);
  var priv = sdJwtVc.getJson(sdJwtVc.KEYS.HOLDER_PRIVATE_JWK);
  if (pub && priv) {
    request.holderPublicJwk = pub;
    request.holderPrivateJwk = priv;
    return Promise.resolve(pub);
  }
  return generateHolderKey();
}

function regenerateHolderKey() {
  log.debug("Entering regenerateHolderKey().");
  generateHolderKey().then(function (pub) {
    setJson("vc_holder_jwk", pub);
    // A new key invalidates the proof built for the old one, so build another.
    request.proof = "";
    setValue("vc_proof_jwt", "");
    renderProofJwt(null);
    setJson("vc_request_body", null);
    setValue("vc_approval_request", "");
    return prepareRequest().then(function (ok) {
      if (ok) {
        status("vc_approval_status",
          "A new holder key pair was generated, and the proof of possession rebuilt for it.", "vc-ok");
      }
    });
  }).catch(function (e) {
    status("vc_approval_status", "Could not generate a holder key pair: " + e.message, "vc-bad");
  });
  log.debug("Leaving regenerateHolderKey().");
  return false;
}

// --- the proof of possession ------------------------------------------------
function signProof(nonce) {
  log.debug("Entering signProof().");
  var header = { typ: PROOF_TYP, alg: PROOF_ALG, jwk: request.holderPublicJwk };
  var payload = {
    iss: sdJwtVc.get("client_id") || "",
    aud: request.config.credentialIssuer,
    iat: Math.floor(Date.now() / 1000)
  };
  if (nonce) payload.nonce = nonce;
  var signingInput = metadataClient.utf8ToB64u(JSON.stringify(header)) + "." +
                     metadataClient.utf8ToB64u(JSON.stringify(payload));
  log.debug("Leaving signProof().");
  return crypto.subtle.importKey("jwk", request.holderPrivateJwk,
      { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
    .then(function (key) {
      return crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, key,
        new TextEncoder().encode(signingInput));
    })
    .then(function (sig) {
      // Web Crypto returns the raw r||s pair, which is exactly the JWS ES256
      // signature encoding.
      request.proof = signingInput + "." + metadataClient.bytesToB64u(sig);
      setValue("vc_proof_jwt", request.proof);
      return request.proof;
    });
}

function fetchNonce() {
  log.debug("Entering fetchNonce().");
  var url = request.config.nonceEndpoint;
  if (!url) {
    // The Nonce Endpoint is optional. Without one there is no c_nonce to carry.
    request.nonce = "";
    setText("vc_nonce", "— (this issuer publishes no nonce_endpoint)");
    return Promise.resolve("");
  }
  log.debug("Leaving fetchNonce().");
  return fetch(url, { method: "POST", headers: { "Content-Length": "0" } })
    .then(function (r) {
      if (!r.ok) throw new Error("the nonce endpoint returned HTTP " + r.status + ".");
      return r.json();
    })
    .then(function (body) {
      request.nonce = body.c_nonce || "";
      setText("vc_nonce", request.nonce || "— (the nonce endpoint returned no c_nonce)");
      return request.nonce;
    })
    .catch(function (e) {
      request.nonce = "";
      setText("vc_nonce", "— (could not fetch one: " + e.message + ")");
      throw e;
    });
}

// ---------------------------------------------------------------------------
// Build the whole request up front, so the pane above shows what WILL be sent
// rather than filling in after the fact — by which point this page has already
// handed over to step 3.
//
// A c_nonce is short-lived and single use, so what is built here can go stale
// while the user reads it; approveIssuance() rebuilds and retries once if the
// issuer says so.
// ---------------------------------------------------------------------------
function prepareRequest() {
  log.debug("Entering prepareRequest().");
  if (!request.config.credentialEndpoint) {
    setText("vc_nonce", "— (no issuer is configured)");
    setValue("vc_proof_jwt", "");
    renderProofJwt(null);
    setJson("vc_request_body", null);
    setValue("vc_approval_request", "");
    status("vc_approval_status",
      "No credential_endpoint is configured, so there is no request to build. Retrieve the credential " +
      "issuer metadata in step 1.", "vc-bad");
    return Promise.resolve(false);
  }
  log.debug("Leaving prepareRequest().");
  return fetchNonce()
    .then(function (nonce) { return signProof(nonce); })
    .then(function () {
      buildRequestBody();
      return true;
    })
    .catch(function (e) {
      log.error("could not prepare the credential request: " + e.message);
      status("vc_approval_status",
        "Could not prepare the credential request: " + e.message +
        " Approving will try again.", "vc-bad");
      return false;
    });
}

function buildRequestBody() {
  var body = { credential_configuration_id: request.config.credentialConfigurationId };
  // OID4VCI 1.0: proofs is an object keyed by proof type, each an array.
  body.proofs = { jwt: [request.proof] };
  request.body = body;
  setJson("vc_request_body", body);
  renderProofJwt(body);
  renderAssembledCall();
  return body;
}

// ---------------------------------------------------------------------------
// The proof JWT, taken back out of the request body's proofs.jwt and decoded
// into its header and payload — read from the body rather than from the
// variable it was built in, so what is shown is literally what is being sent.
// ---------------------------------------------------------------------------
function renderProofJwt(body) {
  log.debug("Entering renderProofJwt().");
  var jwt = body && body.proofs && body.proofs.jwt && body.proofs.jwt[0];
  if (!jwt) {
    setValue("jwt_header", "");
    setValue("jwt_payload", "");
    return;
  }
  var parts = String(jwt).split(".");
  try {
    setValue("jwt_header", JSON.stringify(metadataClient.b64uToJson(parts[0]), null, 2));
    setValue("jwt_payload", JSON.stringify(metadataClient.b64uToJson(parts[1]), null, 2));
  } catch (e) {
    log.error("could not decode the proof JWT: " + e.message);
    setValue("jwt_header", "Could not decode the proof JWT: " + e.message);
    setValue("jwt_payload", "");
  }
  log.debug("Leaving renderProofJwt().");
}

// ---------------------------------------------------------------------------
// The call Approve will make, spelled out: method, full URL, headers and body.
//
// The Authorization header is part of it — presenting the access token as a
// Bearer credential IS how the request is authorized — so leaving it out would
// not be the whole call.
// ---------------------------------------------------------------------------
function renderAssembledCall() {
  log.debug("Entering renderAssembledCall().");
  var endpoint = request.config ? request.config.credentialEndpoint : "";
  if (!endpoint || !request.body) {
    setValue("vc_approval_request", "");
    return "";
  }
  var accessToken = sdJwtVc.get("token_access_token") || "";
  var body = JSON.stringify(request.body, null, 2);
  var lines = [
    "POST " + endpoint,
    "Content-Type: application/json",
    "Authorization: Bearer " + (accessToken || "(no access token yet — authenticate in step 1)"),
    "Content-Length: " + body.length,
    "",
    body
  ];
  var text = lines.join("\n");
  setValue("vc_approval_request", text);
  log.debug("Leaving renderAssembledCall().");
  return text;
}

// ---------------------------------------------------------------------------
// The Token Request, for an offer that carries a pre-authorized code
// (OID4VCI Appendix H.2 / H.3).
//
// There was no authorization request and nobody signed in: the End-User was
// identified by the issuer through some other channel days or minutes ago, and
// the code in the offer is what that produced. When the offer says a
// Transaction Code is required, it must be presented too — and it reached the
// End-User separately from the offer, which is what stops a photographed QR
// code from being enough on its own.
// ---------------------------------------------------------------------------
function preAuthorizedOffer() {
  var code = sdJwtVc.offerPreAuthorizedCode();
  if (!code) return null;
  return { code: code, txCode: sdJwtVc.offerTxCode() };
}

function tokenRequestBody() {
  log.debug("Entering tokenRequestBody().");
  var offer = preAuthorizedOffer();
  if (!offer) {
    log.debug("Leaving tokenRequestBody(). There is no pre-authorized offer.");
    return null;
  }
  var params = {
    grant_type: sdJwtVc.PRE_AUTHORIZED_GRANT,
    "pre-authorized_code": offer.code
  };
  var clientId = sdJwtVc.get("client_id") || "";
  if (clientId) params.client_id = clientId;
  var typed = (el("vc_tx_code") && el("vc_tx_code").value || "").trim();
  if (typed) params.tx_code = typed;
  log.debug("Leaving tokenRequestBody().");
  return params;
}

function encodeForm(params) {
  var out = [];
  Object.keys(params).forEach(function (k) {
    out.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
  });
  return out.join("&");
}

function renderTokenRequest() {
  log.debug("Entering renderTokenRequest().");
  var params = tokenRequestBody();
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  if (!params) {
    setValue("vc_token_request", "");
    log.debug("Leaving renderTokenRequest(). Nothing to render.");
    return "";
  }
  var body = encodeForm(params);
  var text = [
    "POST " + (endpoint || "(no token_endpoint is configured — retrieve the metadata in step 1)"),
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Length: " + body.length,
    "",
    body
  ].join("\n");
  setValue("vc_token_request", text);
  log.debug("Leaving renderTokenRequest().");
  return text;
}

function onTxCodeChange() {
  renderTokenRequest();
  return true;
}

// Show the pane, and say what the offer demands before anything is sent.
function showPreAuthorizedPane() {
  log.debug("Entering showPreAuthorizedPane().");
  var offer = preAuthorizedOffer();
  var pane = el("pane_pre_authorized");
  if (!pane) return false;
  if (!offer) {
    pane.style.display = "none";
    log.debug("Leaving showPreAuthorizedPane(). Not a pre-authorized issuance.");
    return false;
  }
  pane.style.display = "";
  setText("vc_pre_authorized_code", offer.code);
  var row = el("vc_tx_code_row");
  if (offer.txCode) {
    if (row) row.style.display = "";
    var hint = "The issuer requires a Transaction Code" +
      (offer.txCode.length ? " of " + offer.txCode.length + " " : " ") +
      (offer.txCode.input_mode === "numeric" ? "digits" : "characters") + ". " +
      (offer.txCode.description || "");
    setText("vc_tx_code_hint", hint.trim());
    if (el("vc_tx_code") && offer.txCode.length) el("vc_tx_code").maxLength = offer.txCode.length;
  } else if (row) {
    row.style.display = "none";
  }
  renderTokenRequest();
  status("vc_token_status", offer.txCode
    ? "Type the Transaction Code the issuer showed you, then send the Token Request."
    : "Send the Token Request to redeem the pre-authorized code.", "vc-pending");
  log.debug("Leaving showPreAuthorizedPane().");
  return true;
}

function sendTokenRequest() {
  log.debug("Entering sendTokenRequest().");
  var params = tokenRequestBody();
  var endpoint = sdJwtVc.get("token_endpoint") || "";
  if (!params) {
    status("vc_token_status", "There is no pre-authorized offer to redeem.", "vc-bad");
    return false;
  }
  if (!endpoint) {
    status("vc_token_status",
      "No token_endpoint is configured. Retrieve the authorization server metadata in step 1.", "vc-bad");
    return false;
  }
  var offer = preAuthorizedOffer();
  if (offer.txCode && !params.tx_code) {
    status("vc_token_status",
      "This offer requires the Transaction Code the issuer displayed. Type it in first.", "vc-bad");
    log.debug("Leaving sendTokenRequest(). No tx_code was typed.");
    return false;
  }

  el("vc_token_request_button").disabled = true;
  status("vc_token_status", "Redeeming the pre-authorized code …", "vc-pending");
  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: encodeForm(params)
  })
    .then(function (r) {
      return r.text().then(function (text) {
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is what gets shown.
        }
        return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
      });
    })
    .then(function (response) {
      var box = el("vc_token_response");
      if (box) {
        box.style.display = "block";
        box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      }
      if (!response.ok || !response.body || !response.body.access_token) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vc_token_status", "The token endpoint refused the request: " + err, "vc-bad");
        el("vc_token_request_button").disabled = false;
        log.debug("Leaving sendTokenRequest(). Refused: " + err);
        return;
      }
      // Stored under the same names the OIDC leg uses, so everything downstream
      // — this page, token_detail.html — reads it without knowing which flow
      // produced it.
      sdJwtVc.set("token_access_token", response.body.access_token);
      if (response.body.id_token) sdJwtVc.set("token_id_token", response.body.id_token);
      if (response.body.refresh_token) sdJwtVc.set("token_refresh_token", response.body.refresh_token);
      status("vc_token_status",
        "An access token was issued. The credential request below can now be authorized with it.", "vc-ok");
      showTokens();
      renderAssembledCall();
      status("vc_approval_status",
        "Ready: the proof of possession is signed and the request below is what Approve will send.", "vc-ok");
    })
    .catch(function (e) {
      log.error("the token request failed: " + e.message);
      status("vc_token_status", "The token request failed: " + e.message, "vc-bad");
      el("vc_token_request_button").disabled = false;
    });
  log.debug("Leaving sendTokenRequest().");
  return false;
}

// --- the credential request -------------------------------------------------
function approveIssuance() {
  log.debug("Entering approveIssuance().");
  var accessToken = sdJwtVc.get("token_access_token") || "";
  if (!accessToken) {
    status("vc_approval_status",
      "There is no access token to present. Run step 1 and authenticate first.", "vc-bad");
    return false;
  }
  if (!request.config.credentialEndpoint) {
    status("vc_approval_status",
      "No credential_endpoint is configured. Retrieve the credential issuer metadata in step 1.", "vc-bad");
    return false;
  }
  el("vc_approve_button").disabled = true;

  var send = function () {
    status("vc_approval_status", "Sending the Credential Request …", "vc-pending");
    return fetch(request.config.credentialEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + accessToken
      },
      body: JSON.stringify(request.body || buildRequestBody())
    }).then(function (r) {
      return r.text().then(function (text) {
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: keep the default.
        }
        return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
      });
    });
  };

  // The proof shown above was built when the page loaded; if it is not there
  // (or the issuer rejects it as stale — a c_nonce is single use and expires)
  // build a fresh one and send once more.
  var ready = request.proof ? Promise.resolve(true) : prepareRequest();
  ready
    .then(send)
    .then(function (response) {
      if (response.ok || !response.body || response.body.error !== "invalid_proof") return response;
      log.debug("the issuer rejected the proof; rebuilding it with a fresh nonce and retrying once.");
      status("vc_approval_status",
        "The proof had gone stale (a c_nonce is single use) — rebuilding it and trying again …", "vc-pending");
      return prepareRequest().then(send);
    })
    .then(function (response) {
      var box = el("vc_response_body");
      box.style.display = "block";
      box.textContent = response.body ? JSON.stringify(response.body, null, 2) : response.raw;
      if (!response.ok) {
        var err = (response.body && (response.body.error_description || response.body.error)) ||
                  ("HTTP " + response.statusCode);
        status("vc_approval_status", "The issuer refused the request: " + err, "vc-bad");
        el("vc_approve_button").disabled = false;
        return;
      }
      // The issuer may not be able to issue immediately (OID4VCI section 8.3):
      // then the response is a transaction_id, and the credential is collected
      // from the Deferred Credential Endpoint instead.
      if (response.body && response.body.transaction_id && !extractCredential(response.body)) {
        beginDeferred(response.body, response.statusCode);
        return;
      }
      var credential = extractCredential(response.body);
      if (!credential) {
        status("vc_approval_status",
          "The issuer answered, but the response carries no credential.", "vc-bad");
        el("vc_approve_button").disabled = false;
        return;
      }
      keepCredential(credential, response.body, {});
      status("vc_approval_status", "Credential issued. Opening step 3 …", "vc-ok");
      window.location.href = sdJwtVc.STEP3_URL;
    })
    .catch(function (e) {
      log.error("credential request failed: " + e.message);
      status("vc_approval_status", "The credential request failed: " + e.message, "vc-bad");
      el("vc_approve_button").disabled = false;
    });
  log.debug("Leaving approveIssuance().");
  return false;
}

// Everything that has to be remembered about an issued credential, wherever it
// finally came from — the credential endpoint or the deferred one.
function keepCredential(credential, responseBody, extra) {
  log.debug("Entering keepCredential().");
  sdJwtVc.set(sdJwtVc.KEYS.CREDENTIAL, credential);
  var meta = {
    issuer: request.config.credentialIssuer,
    endpoint: request.config.credentialEndpoint,
    configurationId: request.config.credentialConfigurationId,
    format: request.config.format,
    vct: request.config.vct,
    requestedAt: new Date().toISOString(),
    notificationId: (responseBody && responseBody.notification_id) || "",
    request: request.body,
    holderJwk: request.holderPublicJwk
  };
  Object.keys(extra || {}).forEach(function (k) { meta[k] = extra[k]; });
  sdJwtVc.setJson(sdJwtVc.KEYS.CREDENTIAL_META, meta);
  log.debug("Leaving keepCredential().");
}

// ---------------------------------------------------------------------------
// Deferred issuance (OID4VCI section 9, Appendix H.3).
//
// The Credential Response carried a transaction_id instead of a credential, so
// the wallet keeps coming back to the Deferred Credential Endpoint until it
// gets one. `interval` is the issuer saying how long to wait between attempts;
// every attempt is shown, because a wallet that silently spins is exactly what
// a debugger should not be.
// ---------------------------------------------------------------------------
var deferred = {
  transactionId: "",
  intervalSeconds: 0,
  attempts: [],
  timer: 0,
  polling: false
};

function deferredEndpoint() {
  return (request.config && request.config.deferredCredentialEndpoint) ||
         sdJwtVc.get("vci_deferred_credential_endpoint") || "";
}

function renderDeferredRequest() {
  log.debug("Entering renderDeferredRequest().");
  var endpoint = deferredEndpoint();
  var body = JSON.stringify({ transaction_id: deferred.transactionId }, null, 2);
  var accessToken = sdJwtVc.get("token_access_token") || "";
  setValue("vc_deferred_request", [
    "POST " + (endpoint || "(this issuer publishes no deferred_credential_endpoint)"),
    "Content-Type: application/json",
    "Authorization: Bearer " + (accessToken || "(no access token)"),
    "Content-Length: " + body.length,
    "",
    body
  ].join("\n"));
  log.debug("Leaving renderDeferredRequest().");
}

function renderDeferredAttempts() {
  var e = el("vc_deferred_attempts");
  if (!e) return;
  e.textContent = deferred.attempts.length
    ? deferred.attempts.map(function (a, i) {
        return (i + 1) + ". " + a.at + "  HTTP " + a.status + "  " + a.summary;
      }).join("\n")
    : "—";
}

function beginDeferred(body, statusCode) {
  log.debug("Entering beginDeferred(). transaction_id=" + body.transaction_id);
  deferred.transactionId = String(body.transaction_id);
  deferred.intervalSeconds = Number(body.interval) || 5;
  deferred.attempts = [];
  var pane = el("pane_deferred");
  if (pane) pane.style.display = "";
  setText("vc_transaction_id", deferred.transactionId);
  setText("vc_deferred_endpoint", deferredEndpoint() || "— none published —");
  renderDeferredRequest();
  renderDeferredAttempts();
  status("vc_approval_status",
    "The issuer answered " + statusCode + ": it cannot issue this credential yet. Collecting it from the " +
    "Deferred Credential Endpoint …", "vc-pending");

  if (!deferredEndpoint()) {
    status("vc_deferred_status",
      "The issuer deferred the issuance but publishes no deferred_credential_endpoint, so there is nowhere " +
      "to collect the credential from. That is the issuer's bug, not the wallet's.", "vc-bad");
    log.debug("Leaving beginDeferred(). No endpoint to poll.");
    return;
  }
  status("vc_deferred_status",
    "Waiting for the issuer. It asked for " + deferred.intervalSeconds +
    "s between attempts; the wallet will keep checking.", "vc-pending");
  scheduleDeferredPoll(0);
  log.debug("Leaving beginDeferred().");
}

function scheduleDeferredPoll(delaySeconds) {
  if (deferred.timer) window.clearTimeout(deferred.timer);
  deferred.timer = window.setTimeout(function () {
    pollDeferred();
  }, Math.max(0, delaySeconds) * 1000);
}

function pollDeferred() {
  log.debug("Entering pollDeferred().");
  if (!deferred.transactionId) {
    status("vc_deferred_status", "There is no deferred issuance in progress.", "vc-bad");
    return false;
  }
  if (deferred.polling) {
    log.debug("Leaving pollDeferred(). A poll is already in flight.");
    return false;
  }
  var endpoint = deferredEndpoint();
  if (!endpoint) {
    status("vc_deferred_status", "This issuer publishes no deferred_credential_endpoint.", "vc-bad");
    return false;
  }
  deferred.polling = true;
  renderDeferredRequest();
  fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (sdJwtVc.get("token_access_token") || "")
    },
    body: JSON.stringify({ transaction_id: deferred.transactionId })
  })
    .then(function (r) {
      return r.text().then(function (text) {
        var parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          // Not JSON: the raw text is recorded instead.
        }
        return { ok: r.ok, statusCode: r.status, body: parsed, raw: text };
      });
    })
    .then(function (response) {
      deferred.polling = false;
      var credential = extractCredential(response.body);
      var summary;
      if (credential) {
        summary = "the credential was issued";
      } else if (response.body && response.body.transaction_id) {
        summary = "still pending (interval " + (response.body.interval || deferred.intervalSeconds) + "s)";
      } else {
        summary = (response.body && (response.body.error_description || response.body.error)) || response.raw;
      }
      deferred.attempts.push({
        at: new Date().toISOString(),
        status: response.statusCode,
        summary: String(summary).slice(0, 200)
      });
      renderDeferredAttempts();

      if (credential) {
        keepCredential(credential, response.body, {
          deferred: true,
          transactionId: deferred.transactionId,
          deferredEndpoint: endpoint,
          deferredAttempts: deferred.attempts.length
        });
        // Spent: the issuer invalidates it once the credential is collected.
        deferred.transactionId = "";
        status("vc_deferred_status",
          "The credential was issued after " + deferred.attempts.length +
          (deferred.attempts.length === 1 ? " attempt." : " attempts."), "vc-ok");
        status("vc_approval_status", "Credential issued. Opening step 3 …", "vc-ok");
        window.location.href = sdJwtVc.STEP3_URL;
        return;
      }

      if (response.statusCode === 202 && response.body && response.body.transaction_id) {
        var wait = Number(response.body.interval) || deferred.intervalSeconds;
        deferred.intervalSeconds = wait;
        status("vc_deferred_status",
          "Attempt " + deferred.attempts.length + ": the issuer is still working on it. Checking again in " +
          wait + "s.", "vc-pending");
        scheduleDeferredPoll(wait);
        return;
      }

      var err = (response.body && (response.body.error_description || response.body.error)) ||
                ("HTTP " + response.statusCode);
      status("vc_deferred_status", "The deferred request was refused: " + err, "vc-bad");
      log.debug("Leaving pollDeferred(). Refused: " + err);
    })
    .catch(function (e) {
      deferred.polling = false;
      log.error("the deferred credential request failed: " + e.message);
      deferred.attempts.push({ at: new Date().toISOString(), status: 0, summary: e.message });
      renderDeferredAttempts();
      status("vc_deferred_status", "The deferred request failed: " + e.message +
             " Use “Check again now” to retry.", "vc-bad");
    });
  log.debug("Leaving pollDeferred().");
  return false;
}

// OID4VCI 1.0 returns credentials: [{credential: "..."}]. Earlier drafts
// returned a bare `credential` string, and some implementations put plain
// strings in the array — accept all three.
function extractCredential(body) {
  if (!body) return "";
  if (typeof body.credential === "string") return body.credential;
  var list = body.credentials;
  if (Object.prototype.toString.call(list) === "[object Array]" && list.length) {
    var first = list[0];
    if (typeof first === "string") return first;
    if (first && typeof first.credential === "string") return first.credential;
  }
  return "";
}

function denyIssuance() {
  sdJwtVc.endFlow();
  status("vc_approval_status",
    "Issuance denied. Nothing was sent to the issuer. Returning to step 1 …", "vc-pending");
  window.setTimeout(function () { window.location.href = "/sd-jwt-vc-issuance-1.html"; }, 1200);
  return false;
}

// --- page state -------------------------------------------------------------
function showTokens() {
  log.debug("Entering showTokens().");
  var access = sdJwtVc.get("token_access_token") || "";
  var id = sdJwtVc.get("token_id_token") || "";
  var refresh = sdJwtVc.get("token_refresh_token") || "";
  setValue("vc_access_token", access);
  setValue("vc_id_token", id);
  setValue("vc_refresh_token", refresh);

  var claims = null;
  try {
    if (id && id.split(".").length === 3) claims = metadataClient.b64uToJson(id.split(".")[1]);
  } catch (e) {
    // not a JWT
  }
  setJson("vc_id_token_claims", claims);

  if (!access) {
    status("tokens_status",
      "No access token found. Step 2 runs on the tokens the OIDC flow leaves behind — " +
      "start from step 1 and authenticate.", "vc-bad");
  } else {
    status("tokens_status", "Access token present" + (id ? " with an ID token." : "."), "vc-ok");
  }
  log.debug("Leaving showTokens().");
  return claims;
}

function showRequestConfig(idTokenClaims) {
  log.debug("Entering showRequestConfig().");
  var cfg = sdJwtVc.storedRequestConfig();
  request.config = cfg;
  setText("vc_credential_endpoint", cfg.credentialEndpoint || "—");
  setText("vc_credential_issuer", cfg.credentialIssuer || "—");
  setText("vc_credential_config",
    (cfg.credentialConfigurationId || "—") + " (" + (cfg.format || "?") + ", vct " + (cfg.vct || "?") + ")");
  setText("vc_approval_issuer", cfg.credentialIssuer || "—");
  setText("vc_approval_credential", (cfg.credentialConfigurationId || "—") + " / " + (cfg.vct || "?"));
  var subject = (idTokenClaims && (idTokenClaims.preferred_username || idTokenClaims.email ||
                                   idTokenClaims.sub)) || "the authenticated user";
  setText("vc_approval_subject", subject);

  // What the issuer said this credential can carry, straight from the metadata
  // document step 1 retrieved.
  var claimNames = [];
  var doc = sdJwtVc.getJson("vci_info");
  var cfgs = (doc && doc.credential_configurations_supported) || {};
  var chosen = cfgs[cfg.credentialConfigurationId];
  if (chosen && Object.prototype.toString.call(chosen.claims) === "[object Array]") {
    claimNames = chosen.claims.map(function (c) {
      return Object.prototype.toString.call(c.path) === "[object Array]" ? c.path.join(".") : String(c.path);
    });
  }
  setText("vc_approval_claims", claimNames.length ? claimNames.join(", ") : "not stated in the metadata");
  log.debug("Leaving showRequestConfig().");
}

function togglePane(id) {
  var fs = el(id);
  if (fs) fs.style.display = (fs.style.display === "none") ? "block" : "none";
  return false;
}

function onload() {
  log.debug("Entering onload().");
  // The hand-off has done its job; from here the workflow is on its own pages.
  sdJwtVc.endFlow();
  sdJwtVc.renderUseCaseBadge();
  var step = document.getElementById("vc_step_2");
  if (step) step.className = "vc-step-current";
  var done = document.getElementById("vc_step_1");
  if (done) done.className = "vc-step-done";
  var zero = document.getElementById("vc_step_0");
  if (zero) zero.className = "vc-step-done";

  var claims = showTokens();
  showRequestConfig(claims);
  // A pre-authorized offer has no OIDC leg behind it: the token request is
  // this page's job, and it is shown before it is sent like everything else.
  showPreAuthorizedPane();
  loadOrGenerateHolderKey()
    .then(function (pub) {
      setJson("vc_holder_jwk", pub);
      // Build the request now, so the pane shows what approving will send.
      // Deliberately NOT conditional on having an access token: the proof of
      // possession is signed with the holder key and addressed to the issuer,
      // neither of which comes from the OIDC leg. Someone who opens this page
      // directly still gets to see the request the workflow would make.
      return prepareRequest();
    })
    .then(function (ready) {
      if (!ready) return;
      status("vc_approval_status", sdJwtVc.get("token_access_token")
        ? "Ready: the proof of possession is signed and the request below is what Approve will send."
        : "The request below is ready, but there is no access token to authorize it with — " +
          "start from step 1 and authenticate.",
        sdJwtVc.get("token_access_token") ? "vc-ok" : "vc-pending");
    })
    .catch(function (e) {
      status("vc_approval_status", "Could not prepare the credential request: " + e.message, "vc-bad");
    });
  log.debug("SD-JWT VC issuance step 2 ready.");
  log.debug("Leaving onload().");
}

if (typeof window !== "undefined") {
  window.addEventListener("load", onload);
}

module.exports = {
  approveIssuance: approveIssuance,
  sendTokenRequest: sendTokenRequest,
  onTxCodeChange: onTxCodeChange,
  showPreAuthorizedPane: showPreAuthorizedPane,
  pollDeferred: pollDeferred,
  renderProofJwt: renderProofJwt,
  renderAssembledCall: renderAssembledCall,
  denyIssuance: denyIssuance,
  regenerateHolderKey: regenerateHolderKey,
  togglePane: togglePane,
  extractCredential: extractCredential,
  onload: onload
};
