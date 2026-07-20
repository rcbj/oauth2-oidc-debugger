// File: saml_tools.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Test Tools — configuration page.
//
//   Pane 1 (IdP Metadata): load a SAML 2.0 metadata document (via the API
//     metadata proxy, to avoid browser CORS to the IdP), parse it, and populate
//     the SSO/SLO endpoint URLs (HTTP-POST / HTTP-Redirect / HTTP-Artifact),
//     the Artifact Resolution Service, the advertised NameIDFormat values, the
//     IdP entityID, and the signer certificate.
//   Pane 2 (SP / Request): choose protocol version + binding, an optional
//     username hint (structure constrained by the selected NameIDFormat),
//     generate an SP RSA key pair + self-signed certificate, build the
//     AuthnRequest, and (Call) sign it and send it to the IdP.
//
// SAML request signing is performed entirely IN THE BROWSER (no server round
// trip): the Redirect binding signs the query string, and the POST binding
// produces an enveloped XML-DSIG, both with node-forge + a small Canonical XML
// (C14N) implementation (deflate-raw via the native CompressionStream). The API
// is only involved for the artifact RESPONSE binding, where the ACS must run a
// SOAP ArtifactResolve (a server back-channel) — the browser registers the SP
// context via /samlartifactctx, then still signs+sends the request itself. Only
// SAML 2.0 is functional; 1.0/1.1 are reference-only (IdP-initiated, no signed
// SP request).
//
// Everything the user configures is persisted to localStorage (keyed by element
// id) so it survives a page reload — including, per design, the generated SP
// private key. That key is a throwaway test key; do not reuse a production key.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var forge = require("node-forge");
var log = bunyan.createLogger({ name: 'saml_tools', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// SAML 2.0 binding URIs.
var BINDING = {
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  artifact: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
  soap: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
};
var SIG_ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
var STORE_PREFIX = "samltools_";
var NAMEID_OPTIONS_KEY = STORE_PREFIX + "nameid_options";

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function el(id) { return document.getElementById(id); }
function val(id) { var e = el(id); return e ? e.value : ''; }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(id, msg) { setVal(id, msg); }
function show(id, on) { var e = el(id); if (e) { if (on) e.classList.remove('saml-hidden'); else e.classList.add('saml-hidden'); } }

// RFC 4122-ish id suitable for an XML ID (must be an NCName: start with letter/_)
function genId() {
  var b = new Uint8Array(16);
  (window.crypto || window.msCrypto).getRandomValues(b);
  var hex = '';
  for (var i = 0; i < b.length; i++) { hex += ('0' + b[i].toString(16)).slice(-2); }
  return '_' + hex;
}

// ---------------------------------------------------------------------------
// localStorage persistence — every .stored element is saved by its id.
// ---------------------------------------------------------------------------
function persistedEls() { return document.querySelectorAll('.stored'); }
function saveState() {
  if (!window.localStorage) return;
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (els[i].id) localStorage.setItem(STORE_PREFIX + els[i].id, els[i].value);
  }
}
function restoreState() {
  if (!window.localStorage) return;
  // NameIDFormat <select> options come from metadata; rebuild them first so the
  // saved selection has a matching <option>.
  var savedOpts = localStorage.getItem(NAMEID_OPTIONS_KEY);
  if (savedOpts) {
    try { populateNameIdOptions(JSON.parse(savedOpts)); } catch (e) { /* ignore */ }
  }
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    if (!els[i].id) continue;
    var v = localStorage.getItem(STORE_PREFIX + els[i].id);
    if (v !== null) els[i].value = v;
  }
}

// ---------------------------------------------------------------------------
// Metadata loading + parsing
// ---------------------------------------------------------------------------
function loadMetadata() {
  var url = val('saml_metadata_url').trim();
  if (!url) { setStatus('saml_metadata_status', 'Enter a metadata URL first.'); return false; }
  if (!appconfig.backendAvailable) {
    setStatus('saml_metadata_status', 'API backend required (metadata proxy) — not available on this deployment.');
    return false;
  }
  setStatus('saml_metadata_status', 'Loading…');
  var proxy = appconfig.apiUrl + '/samlmetadata?url=' + encodeURIComponent(btoa(url));
  fetch(proxy)
    .then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.text();
    })
    .then(function (xmlText) {
      try {
        parseMetadata(xmlText);
        setStatus('saml_metadata_status', 'Loaded and parsed.');
        saveState();
      } catch (e) {
        log.error('parseMetadata: ' + e.message);
        setStatus('saml_metadata_status', 'Parse error: ' + e.message);
      }
    })
    .catch(function (e) {
      log.error('loadMetadata: ' + e.message);
      setStatus('saml_metadata_status', 'Load failed: ' + e.message);
    });
  return false;
}

// Namespace-agnostic element lookup (metadata uses md:/ds: prefixes).
function tags(root, localName) {
  return root.getElementsByTagNameNS('*', localName);
}

function parseMetadata(xmlText) {
  var doc = new DOMParser().parseFromString(xmlText, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    throw new Error('malformed XML');
  }
  var ed = tags(doc, 'EntityDescriptor')[0];
  if (!ed) throw new Error('no EntityDescriptor');
  setVal('saml_idp_entity_id', ed.getAttribute('entityID') || '');

  var idp = tags(doc, 'IDPSSODescriptor')[0] || ed;

  // SSO endpoints by binding.
  var ssoPost = '', ssoRedirect = '', ssoArtifact = '';
  var ssos = tags(idp, 'SingleSignOnService');
  for (var i = 0; i < ssos.length; i++) {
    var b = ssos[i].getAttribute('Binding'), loc = ssos[i].getAttribute('Location');
    if (b === BINDING.post) ssoPost = loc;
    else if (b === BINDING.redirect) ssoRedirect = loc;
    else if (b === BINDING.artifact) ssoArtifact = loc;
  }
  setVal('saml_sso_post', ssoPost);
  setVal('saml_sso_redirect', ssoRedirect);
  setVal('saml_sso_artifact', ssoArtifact);

  // SLO endpoints by binding.
  var sloPost = '', sloRedirect = '', sloArtifact = '';
  var slos = tags(idp, 'SingleLogoutService');
  for (var j = 0; j < slos.length; j++) {
    var sb = slos[j].getAttribute('Binding'), sloc = slos[j].getAttribute('Location');
    if (sb === BINDING.post) sloPost = sloc;
    else if (sb === BINDING.redirect) sloRedirect = sloc;
    else if (sb === BINDING.artifact) sloArtifact = sloc;
  }
  setVal('saml_slo_post', sloPost);
  setVal('saml_slo_redirect', sloRedirect);
  setVal('saml_slo_artifact', sloArtifact);

  // Artifact Resolution Service (SOAP back-channel).
  var ars = tags(idp, 'ArtifactResolutionService')[0];
  setVal('saml_ars', ars ? (ars.getAttribute('Location') || '') : '');

  // NameIDFormat list.
  var nifs = tags(idp, 'NameIDFormat');
  var formats = [];
  for (var k = 0; k < nifs.length; k++) {
    var t = (nifs[k].textContent || '').trim();
    if (t) formats.push(t);
  }
  populateNameIdOptions(formats);
  if (window.localStorage) localStorage.setItem(NAMEID_OPTIONS_KEY, JSON.stringify(formats));

  // Signer certificate: KeyDescriptor[use=signing] X509Certificate. Fall back to
  // any KeyDescriptor if none is explicitly marked "signing".
  var signerCert = '';
  var kds = tags(idp, 'KeyDescriptor');
  for (var m = 0; m < kds.length; m++) {
    var use = kds[m].getAttribute('use');
    if (use === 'signing' || use === '' || use === null) {
      var certEl = tags(kds[m], 'X509Certificate')[0];
      if (certEl) {
        signerCert = (certEl.textContent || '').replace(/\s+/g, '');
        if (use === 'signing') break; // prefer an explicit signing key
      }
    }
  }
  setVal('saml_signer_cert', signerCert);
  onNameIdFormatChange();
}

function populateNameIdOptions(formats) {
  var sel = el('saml_nameid_format');
  if (!sel) return;
  sel.innerHTML = '';
  // Default "nothing chosen": the AuthnRequest still sends a <NameIDPolicy> (with
  // AllowCreate) but WITHOUT a Format, so the IdP picks its default and cannot
  // reject the request with InvalidNameIDPolicy. Selecting a specific format
  // below sends that Format explicitly.
  var def = document.createElement('option');
  def.value = '';
  def.text = '(none — send NameIDPolicy without a Format; let the IdP choose)';
  sel.appendChild(def);
  if (formats && formats.length) {
    for (var i = 0; i < formats.length; i++) {
      var opt = document.createElement('option');
      opt.value = formats[i];
      opt.text = shortNameId(formats[i]);
      sel.appendChild(opt);
    }
  }
  sel.value = ''; // default to "none chosen"
}

// Trim the long urn:...:nameid-format:xxx to its last segment for display.
function shortNameId(fmt) {
  var idx = fmt.lastIndexOf(':');
  return idx >= 0 ? fmt.substring(idx + 1) + '  (' + fmt + ')' : fmt;
}

// ---------------------------------------------------------------------------
// NameIDFormat -> username-hint restriction
// ---------------------------------------------------------------------------
function hintRuleFor(fmt) {
  var f = (fmt || '').toLowerCase();
  if (f.indexOf('emailaddress') >= 0) {
    return { placeholder: 'user@example.com', help: 'emailAddress format: enter an email address.',
             test: function (v) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v); }, allowed: true };
  }
  if (f.indexOf('x509subjectname') >= 0) {
    return { placeholder: 'CN=User,O=Org,C=US', help: 'X509SubjectName format: enter an X.500 distinguished name.',
             test: function (v) { return /=/.test(v); }, allowed: true };
  }
  if (f.indexOf('windowsdomainqualifiedname') >= 0) {
    return { placeholder: 'DOMAIN\\user', help: 'WindowsDomainQualifiedName: enter DOMAIN\\username.',
             test: function (v) { return /\\/.test(v); }, allowed: true };
  }
  if (f.indexOf('persistent') >= 0 || f.indexOf('transient') >= 0) {
    return { placeholder: '(hint not applicable)', help: 'persistent/transient identifiers are IdP-assigned — a username hint does not apply and will be ignored.',
             test: function () { return true; }, allowed: false };
  }
  // unspecified, kerberos, entity, or unknown -> free text
  return { placeholder: 'username', help: 'unspecified format: any value is allowed.',
           test: function () { return true; }, allowed: true };
}

function onNameIdFormatChange() {
  var rule = hintRuleFor(val('saml_nameid_format'));
  var hint = el('saml_username_hint');
  if (hint) {
    hint.placeholder = rule.placeholder;
    hint.disabled = !rule.allowed;
  }
  setVal('saml_hint_help', rule.help);
  validateHint();
  saveState();
  return false;
}

function validateHint() {
  var rule = hintRuleFor(val('saml_nameid_format'));
  var v = val('saml_username_hint').trim();
  var hint = el('saml_username_hint');
  if (!hint) return true;
  if (!v || !rule.allowed) { hint.style.borderColor = ''; return true; }
  var ok = rule.test(v);
  hint.style.borderColor = ok ? '' : '#e0a800';
  setVal('saml_hint_help', rule.help + (ok ? '' : '  ⚠ value does not match the selected format.'));
  saveState();
  return ok;
}

function onVersionChange() {
  var v = val('saml_version');
  show('saml_version_warning', v !== '2.0');
  saveState();
  return false;
}

// ---------------------------------------------------------------------------
// SP key-pair generation (RSA via node-forge) + self-signed certificate
// ---------------------------------------------------------------------------
function generateKeys() {
  var bits = parseInt(val('saml_key_bits'), 10) || 2048;
  setStatus('saml_call_status', 'Generating ' + bits + '-bit RSA key pair…');
  // Defer so the status paints before the (synchronous, slow) keygen runs.
  setTimeout(function () {
    try {
      var kp = forge.pki.rsa.generateKeyPair({ bits: bits, e: 0x10001 });
      setVal('saml_sp_private_key', forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n');
      // The SP's public credential is presented as its self-signed certificate.
      // The field id keeps the legacy "saml_sp_public_key" name (localStorage /
      // stored-state compatibility), but it holds the certificate PEM.
      setVal('saml_sp_public_key', spSelfSignedCertPem(kp));
      setStatus('saml_call_status', 'Key pair generated.');
      saveState();
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setStatus('saml_call_status', 'Key generation error: ' + e.message);
    }
  }, 20);
  return false;
}

function spSelfSignedCertPem(kp) {
  var cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  var attrs = [{ name: 'commonName', value: val('saml_sp_entity_id') || 'saml-debugger-sp' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(cert).trim() + '\n';
}

function downloadKeys() {
  var priv = val('saml_sp_private_key');
  if (!priv) { setStatus('saml_call_status', 'Generate a key pair first.'); return false; }
  triggerDownload('sp-private-key.pem', priv, 'application/x-pem-file');
  triggerDownload('sp-certificate.pem', val('saml_sp_public_key'), 'application/x-pem-file');
  return false;
}

function triggerDownload(filename, data, mime) {
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

// ---------------------------------------------------------------------------
// SP metadata (EntityDescriptor) — describes this debugger as a Service
// Provider so it can be registered on the IdP.
// ---------------------------------------------------------------------------
function certPemToB64(pem) {
  return String(pem || '')
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

function buildSpMetadata() {
  var entityId = val('saml_sp_entity_id');
  var acs = val('saml_acs_url');
  var slo = appconfig.sloUrl || '';
  var fmt = val('saml_nameid_format');
  var certB64 = certPemToB64(val('saml_sp_public_key'));

  var keyDescriptor = certB64
    ? '\n    <md:KeyDescriptor use="signing">' +
      '\n      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
      '\n        <ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data>' +
      '\n      </ds:KeyInfo>' +
      '\n    </md:KeyDescriptor>'
    : '';
  var sloSvc = slo
    ? '\n    <md:SingleLogoutService Binding="' + BINDING.post + '" Location="' + xmlEscape(slo) + '"/>' +
      '\n    <md:SingleLogoutService Binding="' + BINDING.redirect + '" Location="' + xmlEscape(slo) + '"/>'
    : '';
  var nameIdFmt = fmt ? '\n    <md:NameIDFormat>' + xmlEscape(fmt) + '</md:NameIDFormat>' : '';
  var acsSvc = acs
    ? '\n    <md:AssertionConsumerService Binding="' + BINDING.post + '" Location="' + xmlEscape(acs) + '" index="0" isDefault="true"/>' +
      '\n    <md:AssertionConsumerService Binding="' + BINDING.artifact + '" Location="' + xmlEscape(acs) + '" index="1"/>'
    : '';

  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '\n<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="' + xmlEscape(entityId) + '">' +
         '\n  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"' +
         ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
         keyDescriptor + sloSvc + nameIdFmt + acsSvc +
         '\n  </md:SPSSODescriptor>' +
         '\n</md:EntityDescriptor>\n';
}

function downloadSpMetadata() {
  if (!val('saml_sp_entity_id')) { setStatus('saml_call_status', 'Set the SP entityID first.'); return false; }
  triggerDownload('sp-metadata.xml', buildSpMetadata(), 'application/samlmetadata+xml');
  setStatus('saml_call_status', 'SP metadata downloaded.');
  return false;
}

// ---------------------------------------------------------------------------
// AuthnRequest construction
// ---------------------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function ssoDestination(binding) {
  // The AuthnRequest itself is delivered via HTTP-POST or HTTP-Redirect. The
  // "artifact" choice affects only how the *response* comes back (ProtocolBinding
  // = HTTP-Artifact), so the request is still sent to the Redirect SSO endpoint.
  if (binding === 'post') return val('saml_sso_post');
  return val('saml_sso_redirect');
}

// Response comes back to the ACS; for artifact request flows the response also
// uses artifact, otherwise POST (our ACS is a POST endpoint).
function responseProtocolBinding(binding) {
  return binding === 'artifact' ? BINDING.artifact : BINDING.post;
}

function buildAuthnRequest() {
  var version = val('saml_version');
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  var acs = val('saml_acs_url');
  var issuer = val('saml_sp_entity_id');
  var fmt = val('saml_nameid_format');
  var hint = val('saml_username_hint').trim();
  var rule = hintRuleFor(fmt);

  if (version !== '2.0') {
    return '<!-- SAML ' + version + ' has no SP-initiated AuthnRequest. SAML 1.x Web SSO\n' +
           '     is IdP-initiated (Browser/Artifact or Browser/POST) with no signed SP\n' +
           '     request, and SAML 2.0 IdPs (e.g. Keycloak) will not accept a 1.x request.\n' +
           '     Switch to SAML 2.0 to build and send a real request. -->';
  }

  var id = genId();
  var instant = new Date().toISOString();
  var subject = '';
  if (hint && rule.allowed) {
    subject = '\n  <saml:Subject><saml:NameID' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') +
              '>' + xmlEscape(hint) + '</saml:NameID></saml:Subject>';
  }
  var nameIdPolicy = '\n  <samlp:NameIDPolicy' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') + ' AllowCreate="true"/>';

  return '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '"' +
         (dest ? ' Destination="' + xmlEscape(dest) + '"' : '') +
         ' ProtocolBinding="' + responseProtocolBinding(binding) + '"' +
         (acs ? ' AssertionConsumerServiceURL="' + xmlEscape(acs) + '"' : '') + '>' +
         '\n  <saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
         subject + nameIdPolicy +
         '\n</samlp:AuthnRequest>';
}

// ---------------------------------------------------------------------------
// Client-side request signing (no server round-trip).
//   * Redirect binding: DEFLATE (deflate-raw) + base64 + RSA-SHA256 over the
//     query string — a detached signature per saml-bindings-2.0-os §3.4.4.1.
//   * POST binding: enveloped XML-DSIG (RSA-SHA256) using EXCLUSIVE Canonical
//     XML 1.0, computed here with node-forge + the C14N implementation below.
// node-forge is already bundled (key generation); the only extra primitive is
// deflate-raw, provided by the native CompressionStream.
//
// Exclusive (not inclusive) C14N is required: the verifier (Keycloak/Santuario)
// canonicalizes <ds:SignedInfo> as it sits nested inside <ds:Signature> inside
// <samlp:AuthnRequest xmlns:samlp=… xmlns:saml=…>. Inclusive C14N would pull
// those inherited saml/samlp declarations onto SignedInfo — but we sign it
// standalone (only ds in scope), so the two byte streams would differ and the
// signature would never verify. Exclusive C14N renders only the namespaces a
// subtree *visibly utilizes* (SignedInfo → just ds), so standalone == nested.
// ---------------------------------------------------------------------------
var DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
var C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';
var TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
var DS_NS = 'http://www.w3.org/2000/09/xmldsig#';

function bytesToBase64(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function utf8ToBase64(str) { return btoa(unescape(encodeURIComponent(str))); }

// DEFLATE (raw, no zlib header) via the native CompressionStream (async).
function deflateRaw(str) {
  if (typeof CompressionStream === 'undefined') {
    return Promise.reject(new Error('This browser lacks CompressionStream; cannot DEFLATE for the redirect binding.'));
  }
  var cs = new CompressionStream('deflate-raw');
  var writer = cs.writable.getWriter();
  writer.write(new TextEncoder().encode(str));
  writer.close();
  return new Response(cs.readable).arrayBuffer().then(function (buf) { return new Uint8Array(buf); });
}

function sha256Base64(str) {
  var md = forge.md.sha256.create();
  md.update(str, 'utf8');
  return forge.util.encode64(md.digest().getBytes());
}

// HTTP-Redirect binding: sign the query string. Returns { location, queryString }.
function signRedirect(xml, dest, relayState) {
  return deflateRaw(xml).then(function (bytes) {
    var qs = 'SAMLRequest=' + encodeURIComponent(bytesToBase64(bytes));
    if (relayState) qs += '&RelayState=' + encodeURIComponent(relayState);
    qs += '&SigAlg=' + encodeURIComponent(SIG_ALG_RSA_SHA256);
    var pk = forge.pki.privateKeyFromPem(val('saml_sp_private_key'));
    var md = forge.md.sha256.create();
    md.update(qs, 'utf8'); // the query string is ASCII
    qs += '&Signature=' + encodeURIComponent(forge.util.encode64(pk.sign(md)));
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') + qs) : qs;
    return { location: location, queryString: qs };
  });
}

// HTTP-POST binding: enveloped XML-DSIG. Returns the signed XML string. The
// <Signature> is placed after <Issuer> per the SAML schema.
function signPostEnveloped(xml) {
  var certB64 = certPemToB64(val('saml_sp_public_key'));
  var doc = new DOMParser().parseFromString(xml, 'application/xml');
  var root = doc.documentElement;
  var id = root.getAttribute('ID') || '';

  // Reference digest: c14n(root) — no <Signature> present yet, which is exactly
  // what the enveloped-signature transform reproduces at verification time.
  var digest = sha256Base64(canonicalize(root));

  var signedInfo = '<ds:SignedInfo xmlns:ds="' + DS_NS + '">' +
    '<ds:CanonicalizationMethod Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '<ds:SignatureMethod Algorithm="' + SIG_ALG_RSA_SHA256 + '"/>' +
    '<ds:Reference URI="#' + id + '">' +
    '<ds:Transforms>' +
    '<ds:Transform Algorithm="' + TRANSFORM_ENVELOPED + '"/>' +
    '<ds:Transform Algorithm="' + C14N_EXCLUSIVE + '"/>' +
    '</ds:Transforms>' +
    '<ds:DigestMethod Algorithm="' + DIGEST_SHA256 + '"/>' +
    '<ds:DigestValue>' + digest + '</ds:DigestValue>' +
    '</ds:Reference></ds:SignedInfo>';

  // Sign c14n(SignedInfo).
  var siCanon = canonicalize(new DOMParser().parseFromString(signedInfo, 'application/xml').documentElement);
  var pk = forge.pki.privateKeyFromPem(val('saml_sp_private_key'));
  var md = forge.md.sha256.create();
  md.update(siCanon, 'utf8');
  var sigVal = forge.util.encode64(pk.sign(md));

  var signature = '<ds:Signature xmlns:ds="' + DS_NS + '">' + signedInfo +
    '<ds:SignatureValue>' + sigVal + '</ds:SignatureValue>' +
    '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
    '</ds:Signature>';

  var sigNode = doc.importNode(new DOMParser().parseFromString(signature, 'application/xml').documentElement, true);
  var issuer = null, kids = root.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === 'Issuer') { issuer = kids[i]; break; }
  }
  if (issuer) root.insertBefore(sigNode, issuer.nextSibling);
  else root.insertBefore(sigNode, root.firstChild);
  return new XMLSerializer().serializeToString(doc);
}

// --- Exclusive Canonical XML 1.0 (omit-comments) over a DOM element ----------
// Exclusive C14N (xml-exc-c14n#) renders on each element only the namespace
// declarations that element *visibly utilizes* — the prefix of its own name and
// the prefixes of its namespace-qualified attributes — and only when not already
// output (same prefix→uri) by an ancestor. This makes a subtree canonicalize
// identically whether processed standalone or nested (the property SAML relies
// on for the detached SignedInfo signature). No InclusiveNamespaces PrefixList
// is emitted (we never set one). The documents here use no default namespace.
function canonicalize(apex) { return c14nSerialize(apex, {}); }

// All in-scope namespace declarations for `el` (walking ancestors), prefix→uri.
function c14nInScopeNs(el) {
  var map = {};
  var chain = [], n = el;
  while (n && n.nodeType === 1) { chain.unshift(n); n = n.parentNode; }
  chain.forEach(function (e) {
    for (var i = 0; i < e.attributes.length; i++) {
      var a = e.attributes[i];
      if (a.name === 'xmlns') map[''] = a.value;
      else if (a.name.indexOf('xmlns:') === 0) map[a.name.slice(6)] = a.value;
    }
  });
  return map;
}
function c14nTextEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
}
function c14nAttrEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
}
// `rendered` maps prefix→uri already output by an ancestor and still in scope.
function c14nSerialize(el, rendered) {
  var inscope = c14nInScopeNs(el);

  // Prefixes visibly utilized by THIS element: its own prefix, plus the prefix
  // of each namespace-qualified attribute. Unprefixed attributes don't count.
  var utilized = {};
  utilized[el.prefix || ''] = true;
  var attrs = [];
  for (var i = 0; i < el.attributes.length; i++) {
    var a = el.attributes[i];
    if (a.name === 'xmlns' || a.name.indexOf('xmlns:') === 0) continue;
    if (a.prefix) utilized[a.prefix] = true;
    attrs.push(a);
  }

  var childRendered = {};
  for (var k in rendered) { if (rendered.hasOwnProperty(k)) childRendered[k] = rendered[k]; }
  var nsOut = [];
  Object.keys(utilized).forEach(function (prefix) {
    var uri = inscope.hasOwnProperty(prefix) ? inscope[prefix] : (prefix === '' ? '' : undefined);
    if (uri === undefined) return;                                  // prefix not bound
    if (prefix === '' && uri === '' && !rendered.hasOwnProperty('')) return; // no default ns in scope
    if (childRendered[prefix] !== uri) {
      nsOut.push({ prefix: prefix, uri: uri });
      childRendered[prefix] = uri;
    }
  });
  nsOut.sort(function (a, b) {
    if (a.prefix === b.prefix) return 0;
    if (a.prefix === '') return -1;
    if (b.prefix === '') return 1;
    return a.prefix < b.prefix ? -1 : 1;
  });

  var out = '<' + el.nodeName;
  nsOut.forEach(function (n) {
    out += ' ' + (n.prefix ? ('xmlns:' + n.prefix) : 'xmlns') + '="' + c14nAttrEscape(n.uri) + '"';
  });
  attrs.sort(function (a, b) {
    var au = a.namespaceURI || '', bu = b.namespaceURI || '';
    if (au !== bu) return au < bu ? -1 : 1;
    var al = a.localName || a.name, bl = b.localName || b.name;
    return al < bl ? -1 : (al > bl ? 1 : 0);
  });
  attrs.forEach(function (a) { out += ' ' + a.name + '="' + c14nAttrEscape(a.value) + '"'; });
  out += '>';
  var child = el.firstChild;
  while (child) {
    if (child.nodeType === 1) out += c14nSerialize(child, childRendered);
    else if (child.nodeType === 3 || child.nodeType === 4) out += c14nTextEscape(child.nodeValue);
    child = child.nextSibling;
  }
  return out + '</' + el.nodeName + '>';
}

function buildRequestUi() {
  if (!validateHint()) {
    setStatus('saml_call_status', 'Username hint does not match the selected NameIDFormat.');
    return false;
  }
  var xml = buildAuthnRequest();
  setVal('saml_authn_request', xml);
  saveState();

  if (val('saml_version') !== '2.0') {
    setStatus('saml_call_status', 'SAML 1.x is reference-only — see the request box.');
    return false;
  }

  var priv = val('saml_sp_private_key');
  var binding = val('saml_binding');

  // No key pair yet → show the unsigned request.
  if (!priv) {
    setStatus('saml_call_status', 'AuthnRequest built (unsigned — generate an SP key pair to sign).');
    return false;
  }

  if (binding === 'post') {
    // POST binding: enveloped XML-DSIG inside the document — show the signed XML.
    try {
      setVal('saml_authn_request', signPostEnveloped(xml));
      setStatus('saml_call_status', 'AuthnRequest built and signed in-browser (enveloped XML-DSIG).');
    } catch (e) {
      log.error('buildRequestUi post sign: ' + e.message);
      setStatus('saml_call_status', 'AuthnRequest built (unsigned). Signing failed: ' + e.message);
    }
    return false;
  }

  // Redirect (and artifact, which is sent via redirect): detached query-string
  // signature per the HTTP-Redirect binding — show the full signed request URL.
  setStatus('saml_call_status', 'Signing redirect request…');
  signRedirect(xml, ssoDestination(binding), 'saml_tools')
    .then(function (res) {
      setVal('saml_authn_request', res.location);
      setStatus('saml_call_status', ssoDestination(binding)
        ? 'Signed redirect request built in-browser — SAMLRequest + SigAlg + Signature in the URL.'
        : 'Signed redirect query string built in-browser (load metadata to include the destination URL).');
    })
    .catch(function (e) {
      log.error('buildRequestUi redirect sign: ' + e.message);
      setStatus('saml_call_status', 'AuthnRequest built (unsigned). Signing failed: ' + e.message);
    });
  return false;
}

// ---------------------------------------------------------------------------
// Call the IdP: build + sign the AuthnRequest in the browser, then send it.
// POST and Redirect are fully client-side. The Artifact response binding still
// needs the API — not to sign the request, but so the ACS can perform the SOAP
// ArtifactResolve later; we register the SP context, then sign+send in-browser.
// ---------------------------------------------------------------------------
function callIdp() {
  if (val('saml_version') !== '2.0') {
    setStatus('saml_call_status', 'Only SAML 2.0 can be sent. SAML 1.x is IdP-initiated (reference only).');
    return false;
  }
  var priv = val('saml_sp_private_key');
  if (!priv) { setStatus('saml_call_status', 'Generate an SP key pair first.'); return false; }
  var binding = val('saml_binding');
  var dest = ssoDestination(binding);
  if (!dest) { setStatus('saml_call_status', 'No IdP endpoint for the selected binding — load metadata first.'); return false; }
  if (!validateHint()) { setStatus('saml_call_status', 'Username hint does not match the selected NameIDFormat.'); return false; }

  var xml = buildAuthnRequest();
  setVal('saml_authn_request', xml);
  saveState();

  if (binding === 'post') {
    try {
      var signed = signPostEnveloped(xml);
      setVal('saml_authn_request', signed);
      submitPostForm(dest, { SAMLRequest: utf8ToBase64(signed), RelayState: 'saml_tools' });
    } catch (e) {
      log.error('callIdp post: ' + e.message);
      setStatus('saml_call_status', 'Sign/send failed: ' + e.message);
    }
    return false;
  }

  if (binding === 'artifact') {
    // Register the SP context (ARS URL + key) so the ACS can resolve the
    // artifact via SOAP; then sign the redirect request in-browser and send it.
    if (!appconfig.backendAvailable) {
      setStatus('saml_call_status', 'Artifact binding needs the API backend (for artifact resolution).');
      return false;
    }
    setStatus('saml_call_status', 'Preparing artifact request…');
    fetch(appconfig.apiUrl + '/samlartifactctx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        arsUrl: val('saml_ars'), privateKeyPem: priv, certPem: val('saml_sp_public_key'),
        spEntityId: val('saml_sp_entity_id'), sigAlg: SIG_ALG_RSA_SHA256,
        // WS-Addressing headers for the SOAP ArtifactResolve envelope.
        wsa: {
          enabled: val('saml_wsa_enabled') === 'true',
          to: val('saml_wsa_to'),
          action: val('saml_wsa_action'),
          replyTo: val('saml_wsa_replyto'),
          from: val('saml_wsa_from'),
          messageId: val('saml_wsa_messageid')
        }
      })
    })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j && j.error ? j.error : ('HTTP ' + r.status)); } return j; }); })
      .then(function (ctx) { return signRedirect(xml, dest, ctx.relayState); })
      .then(function (res) { window.location.assign(res.location); })
      .catch(function (e) { log.error('callIdp artifact: ' + e.message); setStatus('saml_call_status', 'Artifact request failed: ' + e.message); });
    return false;
  }

  // Redirect binding — fully client-side.
  setStatus('saml_call_status', 'Signing request…');
  signRedirect(xml, dest, 'saml_tools')
    .then(function (res) { window.location.assign(res.location); })
    .catch(function (e) { log.error('callIdp: ' + e.message); setStatus('saml_call_status', 'Sign/send failed: ' + e.message); });
  return false;
}

// Auto-submit an HTTP-POST-binding request to the IdP SSO endpoint.
function submitPostForm(action, params) {
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = action;
  Object.keys(params).forEach(function (k) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = k;
    input.value = params[k];
    form.appendChild(input);
  });
  document.body.appendChild(form);
  form.submit();
}

// ---------------------------------------------------------------------------
// Single Logout — build + sign a LogoutRequest for the last-authenticated
// subject (NameID / SessionIndex saved by the response page) and send it.
// ---------------------------------------------------------------------------
function lastLogin(key) { return (window.localStorage && localStorage.getItem(key)) || ''; }

function buildLogoutRequest() {
  var slo = val('saml_slo_redirect') || val('saml_slo_post');
  var issuer = val('saml_sp_entity_id');
  var nameid = lastLogin('saml_last_nameid');
  var fmt = lastLogin('saml_last_nameid_format');
  var sidx = lastLogin('saml_last_session_index');
  return '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
         ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
         ' ID="' + genId() + '" Version="2.0" IssueInstant="' + new Date().toISOString() + '"' +
         (slo ? ' Destination="' + xmlEscape(slo) + '"' : '') + '>' +
         '\n  <saml:Issuer>' + xmlEscape(issuer) + '</saml:Issuer>' +
         '\n  <saml:NameID' + (fmt ? ' Format="' + xmlEscape(fmt) + '"' : '') + '>' + xmlEscape(nameid) + '</saml:NameID>' +
         (sidx ? '\n  <samlp:SessionIndex>' + xmlEscape(sidx) + '</samlp:SessionIndex>' : '') +
         '\n</samlp:LogoutRequest>';
}

function singleLogout() {
  if (val('saml_version') !== '2.0') { setStatus('saml_call_status', 'Single Logout requires SAML 2.0.'); return false; }
  var priv = val('saml_sp_private_key');
  if (!priv) { setStatus('saml_call_status', 'Generate an SP key pair first.'); return false; }
  if (!lastLogin('saml_last_nameid')) { setStatus('saml_call_status', 'No NameID from a prior login — complete an SSO first.'); return false; }
  var binding = val('saml_binding') === 'post' ? 'post' : 'redirect';
  var dest = binding === 'post' ? val('saml_slo_post') : val('saml_slo_redirect');
  if (!dest) { setStatus('saml_call_status', 'No SLO endpoint for the selected binding — load metadata first.'); return false; }

  var xml = buildLogoutRequest();
  setVal('saml_authn_request', xml);
  setStatus('saml_call_status', 'Signing LogoutRequest…');

  if (binding === 'post') {
    try {
      var signed = signPostEnveloped(xml);
      setVal('saml_authn_request', signed);
      submitPostForm(dest, { SAMLRequest: utf8ToBase64(signed), RelayState: 'slo' });
    } catch (e) {
      log.error('singleLogout post: ' + e.message);
      setStatus('saml_call_status', 'SLO failed: ' + e.message);
    }
    return false;
  }
  signRedirect(xml, dest, 'slo')
    .then(function (res) { window.location.assign(res.location); })
    .catch(function (e) { log.error('singleLogout: ' + e.message); setStatus('saml_call_status', 'SLO failed: ' + e.message); });
  return false;
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------
function copyField(id) {
  var e = el(id);
  if (!e) return false;
  var text = e.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    try { e.focus(); e.select(); document.execCommand('copy'); } catch (err) { log.error('copyField fallback: ' + err.message); }
  }
  return false;
}

// Open the certificate-details page for the cert in the given field (the IdP
// signer cert or the generated SP cert). The cert is handed over via
// localStorage ('saml_cert_view') and shown in a new tab.
function viewCertificate(fieldId) {
  var pem = val(fieldId);
  if (!pem) { setStatus('saml_metadata_status', 'No certificate to view yet.'); return false; }
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', pem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=saml_tools.html', '_blank');
  return false;
}

function setReturnLink() {
  var allowed = { 'debugger.html': '/debugger.html', 'debugger2.html': '/debugger2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/debugger.html';
  var link = el('return_link');
  if (link) link.setAttribute('href', target);
}

window.onload = function () {
  log.debug('Entering onload().');
  restoreState();
  setReturnLink();

  // Seed defaults where the user hasn't stored anything yet.
  if (!val('saml_metadata_url') && appconfig.samlMetadataUrlDefault) setVal('saml_metadata_url', appconfig.samlMetadataUrlDefault);
  if (!val('saml_sp_entity_id') && appconfig.spEntityId) setVal('saml_sp_entity_id', appconfig.spEntityId);
  if (!val('saml_acs_url') && appconfig.acsUrl) setVal('saml_acs_url', appconfig.acsUrl);

  show('saml_backend_notice', !appconfig.backendAvailable);
  onVersionChange();
  onNameIdFormatChange();

  // Persist on any change.
  var els = persistedEls();
  for (var i = 0; i < els.length; i++) {
    els[i].addEventListener('change', saveState);
    els[i].addEventListener('input', saveState);
  }
};

module.exports = {
  loadMetadata,
  onNameIdFormatChange,
  onVersionChange,
  validateHint,
  generateKeys,
  downloadKeys,
  downloadSpMetadata,
  buildRequestUi,
  callIdp,
  singleLogout,
  viewCertificate,
  copyField
};
