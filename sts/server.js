'use strict';
//
// WS-Trust 1.4 STS mock.
//
// A deliberately small, dependency-light Security Token Service that speaks
// enough WS-Trust to exercise the OAuth2/OIDC Debugger's WS-Trust workflow end
// to end in the test suite. It accepts a SOAP RequestSecurityToken (RST) and
// dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT / plain UsernameToken echo, per TokenType),
//               a Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A request carrying an
// OnBehalfOf/ActAs token (delegation) is also accepted. This is a TEST STS —
// it does not verify request signatures or enforce real policy.
//
// The project's real intent is to run against Apache CXF's WS-Trust STS; this
// mock is the CI fallback (see the plan / README) and the app can target either.
//
// Config via env:
//   CONFIG_FILE  the configuration module to load, chosen the same way as for the
//                api and client services (e.g. ./env/local.js). It supplies the
//                log level; env/docker-tests.js is what the containerized test
//                stack uses.
//   STS_PORT     listening port (default 8081)
//   STS_ISSUER   the WS-Trust issuer name (default the mock's own)
//
// Logging: everything this mock does is written to the log at DEBUG level — every
// endpoint call (path, request headers and body, response headers and body,
// status code and elapsed time), and every SAML assertion, JWT and SD-JWT VC both
// BEFORE and AFTER it was signed or encrypted. Drop the level to info (see
// env/test.js) for a quiet run.

const appconfig = require(process.env.CONFIG_FILE);
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');
const bunyan = require("bunyan"); 
const log = bunyan.createLogger({ name: 'sts', 
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// Logging helpers.
//
// This is a mock whose whole purpose is to show what it did, so everything it
// produces is written down at debug level: the artifact BEFORE it was signed or
// encrypted, the artifact AFTER, and — for every endpoint — the request that
// came in, the response that went back, the status code and how long it took.
// ---------------------------------------------------------------------------

// A security artifact, recorded before and after it was protected.
//
//   what   'SAML assertion' / 'JWT' / 'SD-JWT VC' ...
//   stage  'before signing' / 'after signing' / 'before encryption' / ...
//   value  the object or string itself, recorded in full
function logArtifact(what, stage, value) {
  log.debug({ artifact: what,
              stage: stage,
              value: (typeof value === 'string') ? value : JSON.stringify(value) },
            what + ' ' + stage + '.');
}

// Headers with nothing removed: this mock issues test credentials only, and the
// point of the log is to be able to see exactly what was exchanged.
function headersOf(source) {
  const out = {};
  Object.keys(source || {}).forEach(function (k) { out[k] = source[k]; });
  return out;
}

// Bodies arrive (and leave) as strings or objects; either way they go in whole.
function bodyOf(value) {
  if (value === undefined || value === null) return '';
  return (typeof value === 'string') ? value : JSON.stringify(value);
}

const PORT = parseInt(process.env.STS_PORT, 10) || 8081;
const ISSUER = process.env.STS_ISSUER || 'urn:wstrust:mock:sts';

const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';
const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';
const SAML2_TOKEN_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';
const STATUS_VALID = WST_NS + '/status/valid';
const STATUS_INVALID = WST_NS + '/status/invalid';

// --- STS signing key/cert (generated once at startup) ----------------------
function makeStsKeys() {
  const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = kp.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);
  const attrs = [{ name: 'commonName', value: 'ws-trust-mock-sts' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(kp.privateKey, forge.md.sha256.create());
  return {
    privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
    certPem: forge.pki.certificateToPem(cert),
    certB64: forge.pki.certificateToPem(cert)
      .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  };
}

const STS = makeStsKeys();

// --- helpers ---------------------------------------------------------------
function xmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

function genId() {
  return '_' + forge.util.bytesToHex(forge.random.getBytesSync(16));
}

function iso(offsetMin) {
  return new Date(Date.now() + (offsetMin || 0) * 60000).toISOString();
}

function firstByLocal(root, name) {
  const els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}

function textByLocal(root, name) {
  const e = firstByLocal(root, name);
  return e ? (e.textContent || '').trim() : '';
}

function soapNsFor(version) { return version === '1.1' ? SOAP11_NS : SOAP12_NS; }

// Sign a SAML assertion enveloped (signature after Issuer), like api/server.js.
function signAssertion(xml) {
  log.debug("Entering signAssertion().");
  logArtifact('SAML assertion', 'before signing', xml);
  const m = xml.match(/\bID="([^"]+)"/);
  const id = m ? m[1] : '';
  const sig = new SignedXml({ privateKey: STS.privateKeyPem, publicCert: STS.certPem });
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "/*[local-name(.)='Assertion']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    uri: id ? ('#' + id) : ''
  });
  sig.computeSignature(xml, {
    location: { reference: "/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' }
  });
  const signed = sig.getSignedXml();
  logArtifact('SAML assertion', 'after signing', signed);
  log.debug("Leaving signAssertion().");
  return signed;
}

function buildSamlAssertion(subject, audience, lifetimeMin) {
  log.debug("Entering buildSamlAssertion().");
  const id = genId();
  const now = iso(0);
  const exp = iso(lifetimeMin > 0 ? lifetimeMin : 60);
  const audienceEl = audience
    ? '<saml:AudienceRestriction><saml:Audience>' + xmlEscape(audience) + '</saml:Audience></saml:AudienceRestriction>'
    : '';
  const xml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
      ' ID="' + id + '" Version="2.0" IssueInstant="' + now + '">' +
      '<saml:Issuer>' + xmlEscape(ISSUER) + '</saml:Issuer>' +
      '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">' +
        xmlEscape(subject) + '</saml:NameID>' +
      '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>' +
      '<saml:Conditions NotBefore="' + now + '" NotOnOrAfter="' + exp + '">' + audienceEl + '</saml:Conditions>' +
      '<saml:AuthnStatement AuthnInstant="' + now + '" SessionIndex="' + id + '">' +
      '<saml:AuthnContext><saml:AuthnContextClassRef>' +
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
      '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>' +
      '<saml:AttributeStatement>' +
        '<saml:Attribute Name="name"><saml:AttributeValue>' + xmlEscape(subject) + '</saml:AttributeValue></saml:Attribute>' +
      '<saml:Attribute Name="issuedBy"><saml:AttributeValue>' + xmlEscape(ISSUER) + '</saml:AttributeValue></saml:Attribute>' +
      '</saml:AttributeStatement>' +
    '</saml:Assertion>';
  try { 
    log.debug("Leaving buildSamlAssertion().");
    return signAssertion(xml); 
  } catch (e) { 
    log.error('sign failed, returning unsigned: ' + e.message); 
    return xml; 
  }
}

function buildJwt(subject, audience, lifetimeMin) {
  // jsonwebtoken rejects an empty-string audience — only set it when present.
  log.debug("Entering buildJwt().");
  const opts = { 
    algorithm: 'RS256', 
    issuer: ISSUER, 
    expiresIn: (lifetimeMin > 0 ? lifetimeMin : 60) * 60 
  };
  if (audience) opts.audience = audience;
  const claims = { sub: subject, name: subject };
  logArtifact('WS-Trust JWT', 'before signing', { header: { alg: opts.algorithm }, payload: claims, options: opts });
  const signed = jwt.sign(claims, STS.privateKeyPem, opts);
  logArtifact('WS-Trust JWT', 'after signing', signed);
  log.debug("Leaving buildJwt().");
  return signed;
}

// Build the token element (what goes inside wst:RequestedSecurityToken).
function buildToken(tokenType, subject, audience, lifetimeMin) {
  log.debug("Entering buildToken(). tokenType=" + tokenType + ", subject=" + subject);
  if (tokenType === JWT_TOKEN_TYPE) {
    const raw = buildJwt(subject, audience, lifetimeMin);
    const token = { xml: '<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"' +
      ' ValueType="urn:ietf:params:oauth:token-type:jwt">' + raw + '</wsse:BinarySecurityToken>', ref: '', tokenType: JWT_TOKEN_TYPE };
    log.debug("Leaving buildToken(). Issued a JWT.");
    return token;
  }
  const assertion = buildSamlAssertion(subject, audience, lifetimeMin);
  const idm = assertion.match(/\bID="([^"]+)"/);
  const id = idm ? idm[1] : '';
  const ref = '<wst:RequestedAttachedReference><wsse:SecurityTokenReference' +
    ' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' +
    xmlEscape(id) + '</wsse:KeyIdentifier></wsse:SecurityTokenReference></wst:RequestedAttachedReference>';
  log.debug("Leaving buildToken(). Issued a SAML 2.0 assertion with ID " + id + ".");
  return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE };
}

// Encrypt an assertion to a recipient certificate (AES-256-GCM data key wrapped
// with RSA-OAEP-MGF1P/SHA-1), wrapped in <saml:EncryptedAssertion> — the shape
// the debugger's decryptXml consumes. Used when a request asks for encryption
// (?encrypt=1) and carries the recipient cert in its WS-Security signature.
function encryptAssertion(assertionXml, certPem) {
  log.debug("Entering encryptAssertion().");
  logArtifact('SAML assertion', 'before encryption', assertionXml);
  var XENC = 'http://www.w3.org/2001/04/xmlenc#';
  var X11 = 'http://www.w3.org/2009/xmlenc11#';
  var DS = 'http://www.w3.org/2000/09/xmldsig#';
  var cert = forge.pki.certificateFromPem(certPem);
  var pub = cert.publicKey;
  var key = forge.random.getBytesSync(32);
  var iv = forge.random.getBytesSync(12);
  var cipher = forge.cipher.createCipher('AES-GCM', key);
  cipher.start({ iv: iv, tagLength: 128 });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(assertionXml)));
  if (!cipher.finish()) throw new Error('assertion encryption failed');
  var cipherB64 = forge.util.encode64(iv + cipher.output.getBytes() + cipher.mode.tag.getBytes());
  var wrapped = pub.encrypt(key, 'RSA-OAEP', { md: forge.md.sha1.create(), mgf1: { md: forge.md.sha1.create() } });
  var wrappedB64 = forge.util.encode64(wrapped);
  var certB64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  var encrypted = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
    '<xenc:EncryptedData xmlns:xenc="' + XENC + '" Type="' + XENC + 'Element">' +
      '<xenc:EncryptionMethod Algorithm="' + X11 + 'aes256-gcm"/>' +
      '<ds:KeyInfo xmlns:ds="' + DS + '">' +
        '<xenc:EncryptedKey>' +
          '<xenc:EncryptionMethod Algorithm="' + XENC + 'rsa-oaep-mgf1p">' +
            '<ds:DigestMethod xmlns:ds="' + DS + '" Algorithm="' + DS + 'sha1"/></xenc:EncryptionMethod>' +
          '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' + certB64 + '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
          '<xenc:CipherData><xenc:CipherValue>' + wrappedB64 + '</xenc:CipherValue></xenc:CipherData>' +
        '</xenc:EncryptedKey>' +
      '</ds:KeyInfo>' +
      '<xenc:CipherData><xenc:CipherValue>' + cipherB64 + '</xenc:CipherValue></xenc:CipherData>' +
    '</xenc:EncryptedData></saml:EncryptedAssertion>';
  logArtifact('SAML assertion', 'after encryption (AES-256-GCM, key wrapped with RSA-OAEP-MGF1P)', encrypted);
  log.debug("Leaving encryptAssertion().");
  return encrypted;
}

function envelope(version, action, bodyInner) {
  log.debug("Entering envelope(). version=" + version + ", action=" + action);
  const soapNs = soapNsFor(version);
  const header = action
    ? '<soap:Header><wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">' + action + '</wsa:Action></soap:Header>'
    : '';
  log.debug("Leaving envelope().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + header +
    '<soap:Body>' + bodyInner + '</soap:Body></soap:Envelope>';
}

function soapFault(version, reason) {
  log.debug("Entering soapFault(). version=" + version + ", reason=" + reason);
  const soapNs = soapNsFor(version);
  const body = version === '1.1'
    ? '<soap:Fault><faultcode>soap:Client</faultcode><faultstring>' + xmlEscape(reason) + '</faultstring></soap:Fault>'
    : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value></soap:Code>' +
      '<soap:Reason><soap:Text xml:lang="en">' + xmlEscape(reason) + '</soap:Text></soap:Reason></soap:Fault>';
  log.debug("Leaving soapFault().");
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="' + soapNs + '">' + '<soap:Body>' + body + '</soap:Body></soap:Envelope>';
}

// --- request handling ------------------------------------------------------
function detectSoapVersion(doc, contentType) {
  log.debug("Entering detectSoapVersion().");
  const root = doc && doc.documentElement;
  log.debug("Leaving detectSoapVersion().");
  if (root && root.namespaceURI === SOAP11_NS) return '1.1';
  if (root && root.namespaceURI === SOAP12_NS) return '1.2';
  return /text\/xml/i.test(contentType || '') ? '1.1' : '1.2';
}

function authenticate(doc) {
  log.debug("Entering authenticate().");
  // OnBehalfOf / ActAs => delegated, accept and use the delegated subject if any.
  const obo = firstByLocal(doc, 'OnBehalfOf') || firstByLocal(doc, 'ActAs');
  if (obo) {
    const nameId = firstByLocal(obo, 'NameID') || firstByLocal(obo, 'NameIdentifier');
    log.debug("Leaving authenticate(). Delegated request (OnBehalfOf/ActAs).");
    return { ok: true, subject: (nameId && (nameId.textContent || '').trim()) || 'delegated-subject' };
  }
  const ut = firstByLocal(doc, 'UsernameToken');
  if (ut) {
    const user = textByLocal(ut, 'Username');
    const pass = textByLocal(ut, 'Password');
    if (!user || !pass) {
      log.debug("Leaving authenticate(). Incomplete UsernameToken.");
      return { ok: false, reason: 'UsernameToken requires a username and password.' };
    }
    if (pass === 'invalid') {
      log.debug("Leaving authenticate(). The reserved password was used, so this is a failure.");
      return { ok: false, reason: 'Authentication failed for user ' + user + '.' };
    }
    log.debug("Leaving authenticate(). UsernameToken accepted for " + user + ".");
    return { ok: true, subject: user };
  }
  // A SAML assertion presented directly as the credential.
  const assertion = firstByLocal(doc, 'Assertion');
  if (assertion) {
    const nameId = firstByLocal(assertion, 'NameID') || firstByLocal(assertion, 'NameIdentifier');
    log.debug("Leaving authenticate(). A SAML assertion was presented as the credential.");
    return { ok: true, subject: (nameId && (nameId.textContent || '').trim()) || 'saml-subject' };
  }
  // No credential — lenient (anonymous), so a "None" credential still issues.
  log.debug("Leaving authenticate(). No credential was presented; treating as anonymous.");
  return { ok: true, subject: 'anonymous' };
}

function handleRst(rawBody, contentType, options) {
  log.debug("Entering handleRst().");
  options = options || {};
  const doc = new DOMParser().parseFromString(rawBody || '', 'text/xml');
  const version = detectSoapVersion(doc, contentType);
  const requestType = textByLocal(doc, 'RequestType');
  // Operation from the LAST path segment of RequestType, so any WS-Trust
  // version's namespace works (2004/04, 2005/02, or ws-sx 200512).
  const op = requestType.split('/').pop().toLowerCase();
  // Echo the request's trust namespace in the response (whatever version the
  // client used); fall back to 200512.
  const rstEl = firstByLocal(doc, 'RequestSecurityToken');
  const trustNs = (rstEl && rstEl.namespaceURI) || WST_NS;
  const statusTokenType = trustNs + '/RSTR/Status';
  const statusValid = trustNs + '/status/valid';
  const statusInvalid = trustNs + '/status/invalid';
  const keyTypeReq = textByLocal(doc, 'KeyType') || (trustNs + '/Bearer');

  const tokenTypeReq = textByLocal(doc, 'TokenType');
  const appliesToEl = firstByLocal(doc, 'AppliesTo');
  const audience = appliesToEl ? (textByLocal(appliesToEl, 'Address') || (appliesToEl.textContent || '').trim()) : '';
  const lifetimeEl = firstByLocal(doc, 'Lifetime');
  let lifetimeMin = 60;
  if (lifetimeEl) {
    const created = textByLocal(lifetimeEl, 'Created');
    const expires = textByLocal(lifetimeEl, 'Expires');
    if (created && expires) {
      const diff = (Date.parse(expires) - Date.parse(created)) / 60000;
      if (diff > 0) lifetimeMin = Math.round(diff);
    }
  }

  if (op === 'validate') {
    const target = firstByLocal(doc, 'ValidateTarget');
    const hasToken = target && (firstByLocal(target, 'Assertion') || firstByLocal(target, 'BinarySecurityToken') || (target.textContent || '').trim());
    const code = hasToken ? statusValid : statusInvalid;
    const reason = hasToken ? 'The token is valid.' : 'No token to validate.';
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:TokenType>' + statusTokenType + '</wst:TokenType>' +
      '<wst:Status><wst:Code>' + code + '</wst:Code><wst:Reason>' + xmlEscape(reason) + '</wst:Reason></wst:Status>' +
      '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Validate answered with wst:Status.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/ValidateFinal', rstr) };
  }

  if (op === 'cancel') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' +
      '<wst:RequestedTokenCancelled/></wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Cancel answered with wst:RequestedTokenCancelled.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/CancelFinal', rstr) };
  }

  // Issue / Renew both mint (or re-mint) a token.
  const auth = authenticate(doc);
  if (!auth.ok) {
    log.debug("Leaving handleRst(). Authentication failed, answering with a SOAP Fault.");
    return { status: 500, version: version, body: soapFault(version, auth.reason || 'Authentication failed.') };
  }

  const tokenType = (tokenTypeReq === JWT_TOKEN_TYPE) ? JWT_TOKEN_TYPE : SAML2_TOKEN_TYPE;
  const tok = buildToken(tokenType, auth.subject, audience, lifetimeMin);

  // Optional encryption (?encrypt=1): encrypt the SAML assertion to the recipient
  // certificate carried in the request's WS-Security signature (X509Data).
  if (options.encrypt && tok.tokenType === SAML2_TOKEN_TYPE) {
    const x509 = firstByLocal(doc, 'X509Certificate');
    const recipB64 = x509 ? (x509.textContent || '').replace(/\s+/g, '') : '';
    if (recipB64) {
      const recipPem = '-----BEGIN CERTIFICATE-----\n' + (recipB64.match(/.{1,64}/g) || []).join('\n') + '\n-----END CERTIFICATE-----\n';
      try { tok.xml = encryptAssertion(tok.xml, recipPem); tok.ref = ''; }
      catch (e) {
        log.error('encrypt failed, returning plaintext: ' + e.message);
      }
    } else {
      log.error('?encrypt=1 requested but no recipient certificate in the request signature; returning plaintext.');
    }
  }
  const appliesToOut = audience
    ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"' +
      ' xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:EndpointReference><wsa:Address>' +
      xmlEscape(audience) + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
    : '';
  const rstrInner =
    '<wst:TokenType>' + tok.tokenType + '</wst:TokenType>' +
    '<wst:RequestedSecurityToken>' + tok.xml + '</wst:RequestedSecurityToken>' +
    appliesToOut +
    '<wst:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<wsu:Created>' + iso(0) + '</wsu:Created><wsu:Expires>' + iso(lifetimeMin) + '</wsu:Expires></wst:Lifetime>' +
    '<wst:KeyType>' + keyTypeReq + '</wst:KeyType>' +
    tok.ref;

  if (op === 'renew') {
    const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs + '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
    log.debug("Leaving handleRst(). Renew answered with a fresh token.");
    return { status: 200, version: version, body: envelope(version, trustNs + '/RSTR/RenewFinal', rstr) };
  }

  // Issue -> RSTR Collection (WS-Trust 1.3+; pre-OASIS clients tolerate it too).
  const rstrc = '<wst:RequestSecurityTokenResponseCollection xmlns:wst="' + trustNs + '">' +
    '<wst:RequestSecurityTokenResponse>' + rstrInner + '</wst:RequestSecurityTokenResponse>' +
    '</wst:RequestSecurityTokenResponseCollection>';
  log.debug("Leaving handleRst(). Issue answered with an RSTR Collection.");
  return { status: 200, version: version, body: envelope(version, trustNs + '/RSTRC/IssueFinal', rstrc) };
}

// --- express app -----------------------------------------------------------
const app = express();
// Chrome Private Network Access: when a PUBLIC page calls a LOCAL (loopback)
// server — which is exactly the live-site test setup, an HTTPS page on
// idptools.com calling this mock at http://localhost:8081 — Chrome may send a
// CORS preflight carrying Access-Control-Request-Private-Network and require
// this header on the response. Answer it so the call isn't blocked. Registered
// BEFORE cors() so the header is set before the preflight response is sent;
// a no-op for the containerized suite (both sides on the same bridge network).
app.use(function (req, res, next) {
  if (req.headers['access-control-request-private-network']) {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  next();
});

app.use(cors({ origin: '*' }));
app.options('*', cors({ origin: '*' }));

// Accept any content-type as raw text (SOAP arrives as text/xml or
// application/soap+xml).
app.use(bodyParser.text({ type: function () { return true; }, limit: '5mb' }));

// ---------------------------------------------------------------------------
// Record every call into every endpoint: the path, the request (headers and
// body), the response (headers, body and status), and how long it took.
//
// Registered AFTER the body parser on purpose: before that runs req.body is
// undefined, and every request would be recorded as empty.
//
// res.send / res.json / res.end are wrapped rather than hooked on 'finish',
// because by the time the response has been flushed the body is gone. Two
// entries are written per call — one when the request arrives, one when the
// answer goes out — so a request that never gets answered is still visible.
// ---------------------------------------------------------------------------
app.use(function (req, res, next) {
  const started = Date.now();
  const request = {
    path: req.originalUrl,
    method: req.method,
    query: req.query,
    headers: headersOf(req.headers),
    body: bodyOf(req.body)
  };
  log.debug({ request: request }, 'Request: ' + req.method + ' ' + req.originalUrl);

  let responseBody = '';
  const send = res.send;
  const json = res.json;
  const end = res.end;
  res.send = function (body) {
    responseBody = bodyOf(body);
    return send.apply(res, arguments);
  };
  res.json = function (body) {
    responseBody = bodyOf(body);
    return json.apply(res, arguments);
  };
  res.end = function (chunk) {
    if (!responseBody && chunk) responseBody = bodyOf(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk);
    return end.apply(res, arguments);
  };

  res.on('finish', function () {
    log.debug({ response: { path: req.originalUrl,
                            method: req.method,
                            status: res.statusCode,
                            durationMs: Date.now() - started,
                            headers: headersOf(res.getHeaders()),
                            body: responseBody } },
              'Response: ' + res.statusCode + ' ' + req.method + ' ' + req.originalUrl +
              ' in ' + (Date.now() - started) + 'ms');
  });
  next();
});


app.get('/healthcheck', function (req, res) {
  log.debug("Entering the healthcheck endpoint.");
  res.status(200).json({ message: 'Success' });
  log.debug("Leaving the healthcheck endpoint.");
});

app.get('/sts/cert', function (req, res) {
  log.debug("Entering the STS certificate endpoint.");
  res.type('text/plain').send(STS.certPem);
  log.debug("Leaving the STS certificate endpoint.");
});

app.get('/sts', function (req, res) {
  log.debug("Entering the STS description endpoint.");
  res.type('text/plain').send('WS-Trust STS mock. POST a SOAP RequestSecurityToken here.\nIssuer: ' + ISSUER + '\n');
  log.debug("Leaving the STS description endpoint.");
});

app.post('/sts', function (req, res) {
  log.debug("Entering the WS-Trust STS endpoint.");
  const contentType = req.headers['content-type'] || '';
  try {
    const encrypt = req.query.encrypt === '1' || req.query.encrypt === 'true';
    const result = handleRst(req.body || '', contentType, { encrypt: encrypt });
    const ct = result.version === '1.1' ? 'text/xml; charset=utf-8' : 'application/soap+xml; charset=utf-8';
    res.status(result.status).type(ct).send(result.body);
    log.debug("Leaving the WS-Trust STS endpoint. HTTP " + result.status + ".");
  } catch (e) {
    log.error('STS error: ' + (e && e.stack ? e.stack : e));
    res.status(500).type('application/soap+xml; charset=utf-8')
       .send(soapFault('1.2', 'STS error: ' + (e && e.message ? e.message : String(e))));
    log.debug("Leaving the WS-Trust STS endpoint. It failed.");
  }
});

// ---------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata
//
// A dummy metadata document with EVERY member RFC 8414 section 2 defines
// populated, so the debugger's Configuration Parameters pane can be filled from
// a real endpoint. Served at the well-known path from section 3, and also with
// an issuer path component appended (section 3.1) so both shapes resolve.
//
// The issuer and every endpoint are derived from the URL the request arrived
// on, so the document is self-consistent whether it is reached as
// http://localhost:8081 (host) or http://sts:8081 (compose network).
// ---------------------------------------------------------------------------
function baseUrlOf(req) {
  log.debug("Entering baseUrlOf().");
  const base = (req.protocol || 'http') + '://' + (req.get('host') || ('localhost:' + PORT));
  log.debug("Leaving baseUrlOf(). base=" + base);
  return base;
}

function asMetadata(req) {
  log.debug("Entering asMetadata().");
  const base = baseUrlOf(req);
  const metadata = {
    // --- REQUIRED ---
    issuer: base,
    authorization_endpoint: base + '/oauth2/authorize',
    token_endpoint: base + '/oauth2/token',
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'code id_token token'],
    // --- RECOMMENDED / OPTIONAL ---
    jwks_uri: base + '/oauth2/jwks',
    registration_endpoint: base + '/oauth2/register',
    scopes_supported: ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
    // Only what the token endpoint below actually implements — the metadata
    // should not promise a grant this server would refuse. (No device_code:
    // there is no device authorization endpoint to start that flow.)
    grant_types_supported: ['authorization_code', 'implicit', 'refresh_token', 'client_credentials',
                            'password', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post',
                                            'client_secret_jwt', 'private_key_jwt', 'none'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256', 'PS256', 'HS256'],
    service_documentation: base + '/docs',
    ui_locales_supported: ['en-US', 'en-GB', 'fr-CA', 'de-DE'],
    op_policy_uri: base + '/policy',
    op_tos_uri: base + '/tos',
    revocation_endpoint: base + '/oauth2/revoke',
    revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    revocation_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    introspection_endpoint: base + '/oauth2/introspect',
    introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
    introspection_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256', 'PS256'],
    code_challenge_methods_supported: ['S256', 'plain']
    // signed_metadata is added below — it is a JWT OF this object, so it cannot
    // be one of the claims it signs.
  };
  log.debug("Leaving asMetadata().");
  return metadata;
}

// RFC 8414 section 2.1: signed_metadata is a JWT whose claims are the metadata
// members, signed by the issuer, and carrying iss and sub. Genuinely signed
// with the STS key so it can be verified (public key at /sts/cert, JWKS below).
function signedMetadata(meta) {
  log.debug("Entering signedMetadata().");
  const claims = Object.assign({}, meta, { sub: meta.issuer });
  logArtifact('RFC 8414 signed_metadata', 'before signing', claims);
  try {
    const signed = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.issuer, expiresIn: 3600, keyid: 'sts-mock-1' });
    logArtifact('RFC 8414 signed_metadata', 'after signing', signed);
    log.debug("Leaving signedMetadata().");
    return signed;
  } catch (e) {
    log.error('signed_metadata: ' + e.message);
    log.debug("Leaving signedMetadata(). Nothing was signed.");
    return undefined;
  }
}

function sendAsMetadata(req, res) {
  log.debug("Entering sendAsMetadata().");
  const meta = asMetadata(req);
  const signed = signedMetadata(meta);
  if (signed) meta.signed_metadata = signed;
  res.status(200).type('application/json').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendAsMetadata().");
}

app.get('/.well-known/oauth-authorization-server', sendAsMetadata);
// Issuer-with-path form, e.g. /.well-known/oauth-authorization-server/tenant1.
app.get('/.well-known/oauth-authorization-server/*', sendAsMetadata);

// The JWKS the metadata advertises, so jwks_uri actually resolves: the STS
// signing key as a single RS256 JWK.
app.get('/oauth2/jwks', function (req, res) {
  log.debug("Entering the JWKS endpoint.");
  try {
    const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
    const b64u = function (hex) {
      return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    res.status(200).type('application/json').send(JSON.stringify({
      keys: [{
        kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'sts-mock-1',
        n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
        x5c: [STS.certB64]
      }]
    }, null, 2));
    log.debug("Leaving the JWKS endpoint.");
  } catch (e) {
    log.error('could not publish the JWKS: ' + e.message);
    res.status(500).type('application/json').send(JSON.stringify({ error: e.message }));
    log.debug("Leaving the JWKS endpoint. It failed.");
  }
});

// ===========================================================================
// OpenID for Verifiable Credential Issuance (OID4VCI) — mock Credential Issuer
//
// The bare minimum needed to drive the debugger's SD-JWT VC issuance workflow
// end to end:
//
//   GET  /.well-known/openid-credential-issuer   Credential Issuer Metadata
//   GET  /.well-known/jwt-vc-issuer              JWT VC Issuer Metadata (the
//                                                SD-JWT VC key-resolution
//                                                document: issuer + jwks_uri)
//   POST /oid4vci/nonce                          a fresh c_nonce
//   POST /oid4vci/credential                     the Credential Request; returns
//                                                an SD-JWT VC built per RFC 9901
//
// This is a TEST issuer. It checks that a request carries SOME bearer token but
// cannot validate one issued by the separate authorization server (Keycloak in
// the test suite), so it does not try; what it DOES check properly is the
// wallet's proof of possession, because that is the part the debugger produces
// and therefore the part worth verifying.
//
// The authorization server the metadata advertises is configurable
// (OID4VCI_AUTHORIZATION_SERVER), so the document can point the wallet at the
// real IdP while the credential endpoint stays here.
// ===========================================================================
const crypto = require('crypto');

const VCI_AS = process.env.OID4VCI_AUTHORIZATION_SERVER || '';
const VCI_CONFIG_ID = 'IdentityCredential';
const VCI_VCT = 'urn:idptools:sd-jwt-vc:identity';
const VCI_SCOPE = 'identity_credential';
// c_nonce values this issuer has handed out and not yet seen used. A nonce is
// single-use (RFC-conformant behaviour, and it makes replay visible in a test).
const vciNonces = new Map();
const VCI_NONCE_TTL_MS = 5 * 60 * 1000;

// base64url, in both directions. Deliberately without entering/leaving logs:
// these are called several times per token and would drown the log.
function b64u(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function jsonFromB64u(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

function vciMetadata(req) {
  log.debug("Entering vciMetadata().");
  const base = baseUrlOf(req);
  const authServer = VCI_AS || base;
  const meta = {
    // --- REQUIRED ---
    credential_issuer: base,
    credential_endpoint: base + '/oid4vci/credential',
    credential_configurations_supported: {},
    // --- OPTIONAL ---
    authorization_servers: [authServer],
    nonce_endpoint: base + '/oid4vci/nonce',
    notification_endpoint: base + '/oid4vci/notification',
    batch_credential_issuance: { batch_size: 4 },
    credential_response_encryption: {
      alg_values_supported: ['RSA-OAEP-256', 'ECDH-ES'],
      enc_values_supported: ['A128GCM', 'A256GCM'],
      encryption_required: false
    },
    display: [{
      name: 'IdP Tools Mock Credential Issuer',
      locale: 'en-US',
      logo: { uri: base + '/images/logo.png', alt_text: 'IdP Tools' }
    }]
  };
  meta.credential_configurations_supported[VCI_CONFIG_ID] = {
    format: 'dc+sd-jwt',
    scope: VCI_SCOPE,
    vct: VCI_VCT,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: ['RS256'],
    proof_types_supported: {
      jwt: { proof_signing_alg_values_supported: ['ES256', 'RS256'] }
    },
    display: [{
      name: 'Identity Credential',
      locale: 'en-US',
      background_color: '#12107c',
      text_color: '#FFFFFF'
    }],
    claims: [
      { path: ['given_name'], display: [{ locale: 'en-US', name: 'Given name' }] },
      { path: ['family_name'], display: [{ locale: 'en-US', name: 'Family name' }] },
      { path: ['email'], display: [{ locale: 'en-US', name: 'Email address' }] },
      { path: ['birthdate'], display: [{ locale: 'en-US', name: 'Date of birth' }] },
      { path: ['address', 'country'], display: [{ locale: 'en-US', name: 'Country' }] }
    ]
  };
  log.debug("Leaving vciMetadata().");
  return meta;
}

// OID4VCI adopts RFC 8414's signed_metadata: a JWT of the metadata signed by
// the issuer. Signed with the same STS key, so the debugger can verify it
// against /oauth2/jwks exactly as it verifies an RFC 8414 document.
function sendVciMetadata(req, res) {
  log.debug("Entering sendVciMetadata().");
  const meta = vciMetadata(req);
  const claims = Object.assign({}, meta, { sub: meta.credential_issuer });
  logArtifact('OID4VCI signed_metadata', 'before signing', claims);
  try {
    meta.signed_metadata = jwt.sign(claims, STS.privateKeyPem,
      { algorithm: 'RS256', issuer: meta.credential_issuer, expiresIn: 3600, keyid: 'sts-mock-1' });
    logArtifact('OID4VCI signed_metadata', 'after signing', meta.signed_metadata);
  } catch (e) {
    log.error('OID4VCI signed_metadata: ' + e.message);
  }
  res.status(200).type('application/json').send(JSON.stringify(meta, null, 2));
  log.debug("Leaving sendVciMetadata().");
}

app.get('/.well-known/openid-credential-issuer', sendVciMetadata);
app.get('/.well-known/openid-credential-issuer/*', sendVciMetadata);

// SD-JWT VC key resolution: how a verifier finds the issuer's public keys.
function sendJwtVcIssuerMetadata(req, res) {
  log.debug("Entering sendJwtVcIssuerMetadata().");
  const base = baseUrlOf(req);
  res.status(200).type('application/json').send(JSON.stringify({
    issuer: base,
    jwks_uri: base + '/oauth2/jwks'
  }, null, 2));
  log.debug("Leaving sendJwtVcIssuerMetadata().");
}

app.get('/.well-known/jwt-vc-issuer', sendJwtVcIssuerMetadata);
app.get('/.well-known/jwt-vc-issuer/*', sendJwtVcIssuerMetadata);

// ---------------------------------------------------------------------------
// Credential Offer (OID4VCI section 4) — the issuer-initiated half of issuance.
//
// Appendix H.1 "Credential Offer - Same-Device": the End-User is browsing the
// issuer's site, follows a "request your digital diploma" link, and is taken to
// their Wallet with a Credential Offer in hand. That is what these three
// endpoints are:
//
//   GET /issuer                     the issuer's web page, with the link
//   GET /issuer/offer               builds an offer and redirects to the wallet,
//                                   by value (credential_offer) or by reference
//                                   (credential_offer_uri)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// The offer names this issuer, the credential configuration(s) on offer, and the
// grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer can
// tie the two together.
//
// The Wallet a browser page can be sent to is a URL, not the openid-credential-offer://
// scheme a native wallet would register — OID4VCI_WALLET_URL says where it lives.
// ---------------------------------------------------------------------------
const WALLET_BASE_URL = process.env.OID4VCI_WALLET_URL || 'http://localhost:3000';
const credentialOffers = new Map();     // id -> { offer, issuerState, expires }
const issuerStates = new Map();         // issuer_state -> { configurationIds, expires }
const OFFER_TTL_MS = 10 * 60 * 1000;

function buildCredentialOffer(req, configurationIds) {
  log.debug("Entering buildCredentialOffer().");
  const base = baseUrlOf(req);
  const issuerState = randomId(18);
  issuerStates.set(issuerState, {
    configurationIds: configurationIds,
    expires: Date.now() + OFFER_TTL_MS
  });
  const offer = {
    credential_issuer: base,
    credential_configuration_ids: configurationIds,
    grants: {
      authorization_code: { issuer_state: issuerState }
    }
  };
  logArtifact('OID4VCI Credential Offer', 'as built', offer);
  log.debug("Leaving buildCredentialOffer(). issuer_state=" + issuerState);
  return { offer: offer, issuerState: issuerState };
}

// The issuer's own web page — where H.1 starts.
app.get('/issuer', function (req, res) {
  log.debug("Entering the issuer web page.");
  const base = baseUrlOf(req);
  const configId = VCI_CONFIG_ID;
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Mock University — digital diploma</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:520px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Mock University</h1>' +
    '<p>Congratulations on your graduation. Your diploma is available as a digital credential ' +
    '(<code>' + xmlEscape(configId) + '</code>) that you can keep in your wallet.</p>' +
    '<p><a class="cta" href="/issuer/offer">Request your digital diploma</a>' +
    '<a class="cta secondary" href="/issuer/offer?by=reference">Request it (offer by reference)</a></p>' +
    '<div class="meta">This is the Credential Issuer\'s web page in OID4VCI Appendix H.1. Following the link ' +
    'builds a Credential Offer and sends you to your wallet at <code>' + xmlEscape(WALLET_BASE_URL) + '</code>. ' +
    'The issuer is <code>' + xmlEscape(base) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the issuer web page.");
});

// The link on that page: build the offer and send the End-User to their wallet.
app.get('/issuer/offer', function (req, res) {
  log.debug("Entering the credential offer endpoint.");
  const base = baseUrlOf(req);
  const configurationIds = req.query.credential_configuration_ids
    ? String(req.query.credential_configuration_ids).split(',').filter(Boolean)
    : [VCI_CONFIG_ID];
  const built = buildCredentialOffer(req, configurationIds);
  const wallet = String(req.query.wallet || WALLET_BASE_URL).replace(/\/+$/, '') +
                 '/sd-jwt-vc-issuance-1.html';

  // Sweep expired offers/states while we are here.
  const now = Date.now();
  credentialOffers.forEach(function (v, k) { if (v.expires < now) credentialOffers.delete(k); });
  issuerStates.forEach(function (v, k) { if (v.expires < now) issuerStates.delete(k); });

  let target;
  if (String(req.query.by || '') === 'reference') {
    // By reference: the wallet fetches the offer from credential_offer_uri.
    const id = randomId(12);
    credentialOffers.set(id, { offer: built.offer, expires: now + OFFER_TTL_MS });
    const offerUri = base + '/oid4vci/credential-offer/' + id;
    target = wallet + '?credential_offer_uri=' + encodeURIComponent(offerUri);
    log.debug("The offer is passed by reference: " + offerUri);
  } else {
    // By value: the offer travels in the URL, URL-encoded JSON.
    target = wallet + '?credential_offer=' + encodeURIComponent(JSON.stringify(built.offer));
    log.debug("The offer is passed by value.");
  }
  res.redirect(302, target);
  log.debug("Leaving the credential offer endpoint. Sent the End-User to " + wallet + ".");
});

app.get('/oid4vci/credential-offer/:id', function (req, res) {
  log.debug("Entering the credential offer retrieval endpoint. id=" + req.params.id);
  const record = credentialOffers.get(req.params.id);
  if (!record || record.expires < Date.now()) {
    credentialOffers.delete(req.params.id);
    log.debug("Leaving the credential offer retrieval endpoint. No such offer.");
    return vciError(res, 404, 'invalid_request', 'No such Credential Offer, or it has expired.');
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record.offer, null, 2));
  log.debug("Leaving the credential offer retrieval endpoint.");
});

// --- Nonce Endpoint ---------------------------------------------------------
app.post('/oid4vci/nonce', function (req, res) {
  log.debug("Entering the OID4VCI nonce endpoint.");
  const nonce = b64u(crypto.randomBytes(24));
  const now = Date.now();
  vciNonces.set(nonce, now + VCI_NONCE_TTL_MS);
  // Opportunistic sweep, so a long-running mock does not grow without bound.
  vciNonces.forEach(function (expires, key) { if (expires < now) vciNonces.delete(key); });
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify({
    c_nonce: nonce,
    c_nonce_expires_in: VCI_NONCE_TTL_MS / 1000
  }));
  log.debug("Leaving the OID4VCI nonce endpoint. Handed out one c_nonce; " +
            vciNonces.size + " now outstanding.");
});

// --- the wallet's proof of possession --------------------------------------
// A JWT proof (OID4VCI): typ openid4vci-proof+jwt, the holder's public key in
// the header as a JWK, and claims binding it to this issuer and to a c_nonce
// this issuer handed out. Returns the holder JWK on success.
function verifyProofJwt(proofJwt, credentialIssuer) {
  log.debug("Entering verifyProofJwt().");
  logArtifact('OID4VCI proof of possession', 'as received', proofJwt);
  const parts = String(proofJwt || '').split('.');
  if (parts.length !== 3) throw new Error('the proof is not a three-part JWS.');
  let header, claims;
  try {
    header = jsonFromB64u(parts[0]);
    claims = jsonFromB64u(parts[1]);
  } catch (e) {
    throw new Error('the proof is not a readable JWT: ' + e.message);
  }

  if (header.typ !== 'openid4vci-proof+jwt') {
    throw new Error('the proof typ must be openid4vci-proof+jwt, got "' + header.typ + '".');
  }
  if (!header.jwk) throw new Error('the proof header carries no jwk (this issuer binds to a JWK).');
  if (['ES256', 'RS256'].indexOf(header.alg) < 0) {
    throw new Error('unsupported proof alg "' + header.alg + '".');
  }
  if (claims.aud !== credentialIssuer) {
    throw new Error('the proof aud ("' + claims.aud + '") is not this credential issuer ("' +
                    credentialIssuer + '").');
  }
  if (!claims.iat || Math.abs(Date.now() / 1000 - claims.iat) > 600) {
    throw new Error('the proof iat is missing or too far from now.');
  }
  const expires = vciNonces.get(claims.nonce);
  if (!expires) throw new Error('the proof nonce is not one this issuer handed out (or was already used).');
  vciNonces.delete(claims.nonce);
  if (expires < Date.now()) throw new Error('the proof nonce has expired.');

  let key;
  try {
    key = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
  } catch (e) {
    throw new Error('the proof header jwk is not a usable public key: ' + e.message);
  }
  const data = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  const sig = b64uDecode(parts[2]);
  const opts = (header.alg === 'ES256')
    ? { key: key, dsaEncoding: 'ieee-p1363' }
    : { key: key };
  if (!crypto.verify('sha256', data, opts, sig)) {
    throw new Error('the proof signature does not verify with the key in its own header.');
  }
  logArtifact('OID4VCI proof of possession', 'verified', { header: header, payload: claims });
  log.debug("Leaving verifyProofJwt(). The proof is good.");
  return header.jwk;
}

// --- SD-JWT VC construction (RFC 9901) --------------------------------------
// A Disclosure is base64url(JSON [salt, claim name, claim value]); the digest
// that goes in _sd is base64url(SHA-256(the ASCII of that base64url string)).
function makeDisclosure(name, value) {
  log.debug("Entering makeDisclosure(). name=" + name);
  const salt = b64u(crypto.randomBytes(16));
  const encoded = b64u(Buffer.from(JSON.stringify([salt, name, value]), 'utf8'));
  const digest = b64u(crypto.createHash('sha256').update(encoded, 'ascii').digest());
  log.debug("Leaving makeDisclosure(). digest=" + digest);
  return { salt: salt, name: name, value: value, encoded: encoded, digest: digest };
}

function buildSdJwtVc(subjectClaims, holderJwk, credentialIssuer) {
  log.debug("Entering buildSdJwtVc().");
  logArtifact('SD-JWT VC', 'the claims it will assert, before any of them are hidden',
              { subjectClaims: subjectClaims, holderJwk: holderJwk, credentialIssuer: credentialIssuer });
  const now = Math.floor(Date.now() / 1000);
  // Everything the holder can choose to disclose, one Disclosure each. sub is
  // not among them: it stays a plain claim, so the credential always says who
  // it is about.
  const disclosures = Object.keys(subjectClaims)
    .filter(function (name) { return name !== 'sub'; })
    .map(function (name) { return makeDisclosure(name, subjectClaims[name]); });
  // A decoy digest: RFC 9901 section 4.2.5 — hash a random value so the count
  // of _sd entries does not reveal how many claims there really are.
  const decoy = b64u(crypto.createHash('sha256').update(b64u(crypto.randomBytes(16)), 'ascii').digest());
  const digests = disclosures.map(function (d) { return d.digest; }).concat([decoy]).sort();

  const payload = {
    iss: credentialIssuer,
    nbf: now,
    exp: now + 30 * 24 * 3600,
    vct: VCI_VCT,
    sub: subjectClaims.sub || 'urn:uuid:' + crypto.randomUUID(),
    cnf: { jwk: holderJwk },
    _sd_alg: 'sha-256',
    _sd: digests
  };
  logArtifact('SD-JWT VC', 'before signing',
              { header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: 'sts-mock-1' },
                payload: payload,
                disclosures: disclosures.map(function (d) {
                  return { name: d.name, value: d.value, salt: d.salt, digest: d.digest, encoded: d.encoded };
                }),
                decoyDigest: decoy });

  // iat is added by the signer (jsonwebtoken drops a payload iat when it is
  // told not to timestamp, so it is left to do it).
  const issuerJwt = jwt.sign(payload, STS.privateKeyPem, {
    algorithm: 'RS256',
    header: { alg: 'RS256', typ: 'dc+sd-jwt', kid: 'sts-mock-1' }
  });
  logArtifact('SD-JWT VC issuer-signed JWT', 'after signing', issuerJwt);

  // Combined Serialization: <JWT>~<D1>~...~<Dn>~ (the trailing ~ is required
  // when no Key Binding JWT is present).
  const serialized = [issuerJwt].concat(disclosures.map(function (d) { return d.encoded; })).join('~') + '~';
  logArtifact('SD-JWT VC', 'after signing, as it will be sent (Combined Serialization)', serialized);
  log.debug("Leaving buildSdJwtVc(). " + disclosures.length + " disclosure(s) plus 1 decoy digest.");
  return { credential: serialized, disclosures: disclosures, payload: payload, decoy: decoy };
}

// The claims the credential asserts. Lifted from the access token when it is a
// JWT (so the credential describes whoever actually authenticated), with
// mock-issuer defaults for anything the token does not carry.
function subjectClaimsFrom(accessToken) {
  log.debug("Entering subjectClaimsFrom().");
  let t = {};
  try {
    const parts = String(accessToken || '').split('.');
    if (parts.length === 3) t = jsonFromB64u(parts[1]) || {};
  } catch (e) {
    // An opaque token — the mock defaults it is.
    log.debug("The access token is not a readable JWT; using the default claims.");
  }
  const user = t.preferred_username || t.sub || 'mock-holder';
  log.debug("Leaving subjectClaimsFrom(). The credential will describe " + user + ".");
  return {
    sub: t.sub || ('urn:uuid:' + crypto.randomUUID()),
    given_name: t.given_name || user,
    family_name: t.family_name || 'Holder',
    email: t.email || (user + '@example.com'),
    birthdate: '1979-04-01',
    nationality: 'US',
    address: { street_address: '100 Main St', locality: 'Springfield', region: 'IL', country: 'US' }
  };
}

function vciError(res, status, error, description) {
  log.debug("Entering vciError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').send(JSON.stringify({
    error: error, error_description: description
  }));
  log.debug("Leaving vciError().");
}

app.post('/oid4vci/credential', function (req, res) {
  log.debug("Entering the OID4VCI credential endpoint.");
  const auth = req.headers['authorization'] || '';
  if (!/^Bearer\s+\S+/i.test(auth)) {
    res.set('WWW-Authenticate', 'Bearer');
    return vciError(res, 401, 'invalid_token', 'A Bearer access token is required.');
  }
  const accessToken = auth.replace(/^Bearer\s+/i, '').trim();

  let body = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  } catch (e) {
    log.error('the credential request body is not JSON: ' + e.message);
    return vciError(res, 400, 'invalid_request', 'The request body is not JSON: ' + e.message);
  }

  const configId = body.credential_configuration_id || body.credential_identifier;
  if (configId && configId !== VCI_CONFIG_ID) {
    return vciError(res, 400, 'unsupported_credential_type',
      'This issuer only offers credential_configuration_id "' + VCI_CONFIG_ID + '".');
  }

  // OID4VCI 1.0 sends proofs.jwt[]; the earlier single-proof form is accepted
  // too, since wallets in the wild still send it.
  let proofJwt = null;
  if (body.proofs && Array.isArray(body.proofs.jwt) && body.proofs.jwt.length) proofJwt = body.proofs.jwt[0];
  else if (body.proof && body.proof.jwt) proofJwt = body.proof.jwt;
  if (!proofJwt) {
    return vciError(res, 400, 'invalid_proof', 'A JWT proof of possession is required (proofs.jwt).');
  }

  let holderJwk;
  try {
    holderJwk = verifyProofJwt(proofJwt, vciMetadata(req).credential_issuer);
  } catch (e) {
    log.error('the proof of possession was refused: ' + e.message);
    return vciError(res, 400, 'invalid_proof', e.message);
  }

  const built = buildSdJwtVc(subjectClaimsFrom(accessToken), holderJwk, vciMetadata(req).credential_issuer);
  const response = {
    credentials: [{ credential: built.credential }],
    notification_id: b64u(crypto.randomBytes(12))
  };
  logArtifact('OID4VCI Credential Response', 'as returned', response);
  res.set('Cache-Control', 'no-store');
  res.status(200).type('application/json').send(JSON.stringify(response));
  log.debug("Leaving the OID4VCI credential endpoint. Issued a " + built.disclosures.length +
            "-disclosure SD-JWT VC.");
});

// Accepts the wallet's notification of what it did with the credential
// (OID4VCI section 10). Nothing to record in a mock — 204 and done.
app.post('/oid4vci/notification', function (req, res) {
  log.debug("Entering the OID4VCI notification endpoint.");
  res.status(204).end();
  log.debug("Leaving the OID4VCI notification endpoint.");
});

// ===========================================================================
// The endpoints the RFC 8414 metadata advertises.
//
// A dummy authorization server: every endpoint in the metadata document answers,
// and every token it issues is a real RS256 JWT signed with the STS key, so it
// verifies against the JWKS the same document points at (/oauth2/jwks).
//
//   GET  /oauth2/authorize   authorization endpoint (code / implicit / hybrid)
//   POST /oauth2/token       authorization_code, refresh_token, password,
//                            client_credentials, token-exchange
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
//   GET  /oauth2/jwks        the signing key (above, with the metadata)
//   GET  /docs /policy /tos  the documents the metadata links to
//
// It authenticates NOBODY: the authorization endpoint issues a code for whoever
// asks (the "user" is the login_hint, or a fixed mock subject), and any client
// secret is accepted. That is the point — it exists so the debugger's panes have
// something complete to talk to, not to enforce anything. What it does do
// properly is the mechanics a client can check: PKCE verification, single-use
// authorization codes, real signatures, honest introspection, and revocation
// that actually takes effect.
// ===========================================================================
// Whoever signs in at the login screen. No password is ever checked; the
// username they type is the identity every token then describes.
function userFor(username) {
  log.debug("Entering userFor(). username=" + username);
  const name = String(username || 'mock-user');
  const user = {
    sub: 'urn:sts-mock:user:' + name,
    username: name,
    preferred_username: name,
    name: name + ' (mock)',
    given_name: name,
    family_name: 'Mock',
    email: name + '@sts-mock.example',
    email_verified: true
  };
  log.debug("Leaving userFor(). sub=" + user.sub);
  return user;
}

const SESSION_COOKIE = 'sts_mock_session';
const SESSION_TTL_MS = 60 * 60 * 1000;
const LOGIN_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL = 3600;
const REFRESH_TOKEN_TTL = 30 * 24 * 3600;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const authzCodes = new Map();       // code -> the authorization request it came from
const sessions = new Map();         // session id -> the signed-in user
const pendingLogins = new Map();    // login id -> the authorization request being interrupted
const revokedJtis = new Set();      // tokens revoked via /oauth2/revoke
const registeredClients = new Map();// client_id -> { metadata, registrationAccessToken }

// Small and called constantly: no entering/leaving logs, they would drown the log.
function nowSec() { return Math.floor(Date.now() / 1000); }
function randomId(bytes) { return b64u(crypto.randomBytes(bytes || 24)); }

// Request bodies arrive as raw text (the SOAP parser takes every content type),
// so form-encoded and JSON are both decoded here.
function parseBody(req) {
  log.debug("Entering parseBody(). content-type=" + (req.headers['content-type'] || '(none)'));
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String(req.headers['content-type'] || '');
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw || '{}');
      log.debug("Leaving parseBody(). Parsed a JSON body.");
      return parsed;
    } catch (e) {
      log.error('the request body is not JSON: ' + e.message);
      log.debug("Leaving parseBody(). Nothing could be parsed.");
      return {};
    }
  }
  const out = {};
  new URLSearchParams(raw).forEach(function (v, k) { out[k] = v; });
  log.debug("Leaving parseBody(). Parsed a form-encoded body with " +
            Object.keys(out).length + " parameter(s).");
  return out;
}

// Client credentials from either client_secret_basic or client_secret_post. No
// secret is ever checked; what matters is which client is being claimed.
function clientFrom(req, body) {
  log.debug("Entering clientFrom().");
  const auth = req.headers['authorization'] || '';
  if (/^Basic\s+/i.test(auth)) {
    try {
      const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      const client = { client_id: decodeURIComponent(i < 0 ? decoded : decoded.slice(0, i)) };
      log.debug("Leaving clientFrom(). client_secret_basic named " + client.client_id + ".");
      return client;
    } catch (e) {
      log.error('could not read the Basic credential: ' + e.message);
      // Fall through to the form parameter.
    }
  }
  log.debug("Leaving clientFrom(). client_id from the body: " + (body.client_id || '(none)'));
  return { client_id: body.client_id || '' };
}

function oauthError(res, status, error, description) {
  log.debug("Entering oauthError(). status=" + status + ", error=" + error);
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify({ error: error, error_description: description }));
  log.debug("Leaving oauthError().");
}

// --- token minting ----------------------------------------------------------
// Every OAuth token this server issues goes through here, so this is where each
// one is recorded: the claim set before it is signed, and the JWT after.
function signJwt(payload) {
  log.debug("Entering signJwt(). typ=" + (payload.typ || '(none)'));
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'before signing',
              { header: { alg: 'RS256', kid: 'sts-mock-1' }, payload: payload });
  const signed = jwt.sign(payload, STS.privateKeyPem, { algorithm: 'RS256', keyid: 'sts-mock-1' });
  logArtifact('OAuth token (' + (payload.typ || 'unknown') + ')', 'after signing', signed);
  log.debug("Leaving signJwt().");
  return signed;
}

function accessToken(base, opts) {
  log.debug("Entering accessToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.audience || base + '/resource',
    client_id: opts.client_id, scope: opts.scope || '', typ: 'Bearer',
    jti: randomId(16), iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL,
    username: user.username
  };
  if (opts.act) payload.act = opts.act;
  const token = signJwt(payload);
  log.debug("Leaving accessToken().");
  return token;
}

function refreshToken(base, opts) {
  log.debug("Entering refreshToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const token = signJwt({
    // username travels with the refresh token, so refreshing keeps describing
    // the person who actually signed in.
    iss: base, sub: opts.sub || user.sub, aud: base, client_id: opts.client_id,
    scope: opts.scope || '', typ: 'Refresh', jti: randomId(16), username: user.username,
    iat: iat, nbf: iat, exp: iat + REFRESH_TOKEN_TTL
  });
  log.debug("Leaving refreshToken().");
  return token;
}

// OIDC section 3.1.3.6: at_hash / c_hash are the base64url of the left half of
// the SHA-256 of the ASCII of the token.
function halfHash(value) {
  log.debug("Entering halfHash().");
  const h = crypto.createHash('sha256').update(String(value), 'ascii').digest();
  log.debug("Leaving halfHash().");
  return b64u(h.subarray(0, h.length / 2));
}

function idToken(base, opts) {
  log.debug("Entering idToken().");
  const iat = nowSec();
  const user = opts.user || userFor(opts.username);
  const payload = {
    iss: base, sub: opts.sub || user.sub, aud: opts.client_id, typ: 'ID',
    iat: iat, nbf: iat, exp: iat + ACCESS_TOKEN_TTL, auth_time: opts.auth_time || iat,
    azp: opts.client_id, jti: randomId(16),
    name: user.name, given_name: user.given_name, family_name: user.family_name,
    preferred_username: user.preferred_username, email: user.email,
    email_verified: user.email_verified
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.access_token) payload.at_hash = halfHash(opts.access_token);
  if (opts.code) payload.c_hash = halfHash(opts.code);
  const token = signJwt(payload);
  log.debug("Leaving idToken().");
  return token;
}

function hasScope(scope, name) {
  return String(scope || '').split(/\s+/).indexOf(name) >= 0;
}

function tokenSet(base, opts) {
  log.debug("Entering tokenSet(). scope=" + (opts.scope || '(none)'));
  const access = accessToken(base, opts);
  const body = {
    access_token: access,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: opts.scope || ''
  };
  if (opts.withRefresh !== false) body.refresh_token = refreshToken(base, opts);
  if (hasScope(opts.scope, 'openid')) {
    body.id_token = idToken(base, Object.assign({}, opts, { access_token: access }));
  }
  log.debug("Leaving tokenSet(). Issued: " + Object.keys(body).join(', '));
  return body;
}

// --- authorization endpoint + login screen ----------------------------------
// A browser flow, so it behaves like one: an unauthenticated request is shown a
// login screen, and only once the user has signed in does the endpoint issue
// the authorization code (or the implicit/hybrid tokens) and redirect back to
// the client.
//
//   GET  /oauth2/authorize   no session  -> the login screen
//                            session     -> issue and redirect to redirect_uri
//   POST /oauth2/login       signs the user in, then redirects BACK to
//                            /oauth2/authorize with the original request, which
//                            then proceeds as normal
//
// No password is checked — the username typed in is simply who the tokens then
// describe. A session cookie means the next authorization request does not
// prompt again; prompt=login forces it to.
function cookiesOf(req) {
  log.debug("Entering cookiesOf().");
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(function (part) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  log.debug("Leaving cookiesOf(). " + Object.keys(out).length + " cookie(s).");
  return out;
}

function sessionOf(req) {
  log.debug("Entering sessionOf().");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (!id) {
    log.debug("Leaving sessionOf(). No session cookie.");
    return null;
  }
  const session = sessions.get(id);
  if (!session) {
    log.debug("Leaving sessionOf(). The cookie names no session this server knows.");
    return null;
  }
  if (session.expires < Date.now()) {
    sessions.delete(id);
    log.debug("Leaving sessionOf(). The session had expired and was discarded.");
    return null;
  }
  log.debug("Leaving sessionOf(). Signed in as " + session.user.username + ".");
  return session;
}

// The authorization request, as the query string it arrived as. Kept whole so
// the redirect back after login is the same request over again.
function queryString(query, omit) {
  log.debug("Entering queryString().");
  const usp = new URLSearchParams();
  Object.keys(query).forEach(function (k) {
    if (omit && omit.indexOf(k) >= 0) return;
    usp.set(k, query[k]);
  });
  log.debug("Leaving queryString().");
  return usp.toString();
}

function loginPage(base, login, error) {
  log.debug("Entering loginPage(). client_id=" + (login.query.client_id || '(none)') +
            (error ? ", showing an error" : ""));
  const q = login.query;
  const scope = q.scope || '(none requested)';
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Sign in — mock authorization server</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:28px 32px;width:380px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}' +
    'p.sub{color:#666;font-size:.85em;margin:0 0 18px}label{display:block;font-size:.85em;font-weight:600;' +
    'margin:12px 0 4px}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px 10px;' +
    'border:1px solid #bbb;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:20px}' +
    'button{flex:1;padding:9px 12px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;' +
    'font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}' +
    '.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;' +
    'font-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;' +
    'font-size:.75em;color:#777;word-break:break-all}.meta div{margin:2px 0}code{font-family:ui-monospace,' +
    'SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Sign in</h1>' +
    '<p class="sub">Mock authorization server at <code>' + xmlEscape(base) + '</code></p>' +
    (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
    '<form method="post" action="/oauth2/login">' +
    '<input type="hidden" name="login_id" value="' + xmlEscape(login.id) + '">' +
    '<label for="username">Username</label>' +
    '<input type="text" id="username" name="username" autocomplete="username" autofocus' +
    ' value="' + xmlEscape(q.login_hint || '') + '">' +
    '<label for="password">Password</label>' +
    '<input type="password" id="password" name="password" autocomplete="current-password">' +
    '<div class="row"><button type="submit" id="kc-login" name="action" value="login">Sign In</button>' +
    '<button type="submit" id="kc-cancel" name="action" value="cancel" class="secondary">Cancel</button></div>' +
    '</form><div class="meta">' +
    '<div>No password is checked. The username you enter is the identity the issued tokens describe.</div>' +
    '<div>client_id: <code>' + xmlEscape(q.client_id || '') + '</code></div>' +
    '<div>scope: <code>' + xmlEscape(scope) + '</code></div>' +
    '<div>redirect_uri: <code>' + xmlEscape(q.redirect_uri || '') + '</code></div>' +
    (q.issuer_state
      ? '<div>issuer_state: <code>' + xmlEscape(q.issuer_state) + '</code>' +
        (issuerStates.has(String(q.issuer_state)) ? ' (from a Credential Offer this issuer made)' : '') +
        '</div>'
      : '') +
    '</div></div></body></html>\n';
  log.debug("Leaving loginPage().");
  return page;
}

// Build the authorization response for a signed-in user and redirect back to
// the client. Everything after authentication — which is "as normal".
function issueAuthorizationResponse(req, res, query, user, authTime) {
  log.debug("Entering issueAuthorizationResponse(). response_type=" + (query.response_type || '(none)') +
            ", user=" + user.username);
  const base = baseUrlOf(req);
  const redirectUri = String(query.redirect_uri);
  const types = String(query.response_type || '').split(/\s+/).filter(Boolean);
  const scope = String(query.scope || 'openid');
  const out = {};

  if (types.indexOf('code') >= 0) {
    const code = randomId(24);
    authzCodes.set(code, {
      client_id: String(query.client_id), redirect_uri: redirectUri, scope: scope,
      nonce: query.nonce, user: user, auth_time: authTime,
      code_challenge: query.code_challenge, code_challenge_method: query.code_challenge_method || 'plain',
      expires: Date.now() + AUTH_CODE_TTL_MS
    });
    out.code = code;
  }
  if (types.indexOf('token') >= 0) {
    out.access_token = accessToken(base, { user: user, client_id: String(query.client_id), scope: scope });
    out.token_type = 'Bearer';
    out.expires_in = ACCESS_TOKEN_TTL;
    out.scope = scope;
  }
  if (types.indexOf('id_token') >= 0) {
    out.id_token = idToken(base, {
      user: user, client_id: String(query.client_id), nonce: query.nonce, auth_time: authTime,
      access_token: out.access_token, code: out.code
    });
  }
  // Only a bare code goes in the query; anything carrying a token uses the
  // fragment, per OAuth 2.0 / OIDC.
  logArtifact('Authorization response', 'as returned to the client', out);
  redirectBack(res, base, redirectUri, query.state, out,
    types.length > 1 || types.indexOf('code') < 0);
  log.debug("Leaving issueAuthorizationResponse().");
}

function redirectBack(res, base, redirectUri, state, params, fragment) {
  log.debug("Entering redirectBack(). fragment=" + !!fragment);
  const usp = new URLSearchParams();
  Object.keys(params).forEach(function (k) { if (params[k] !== undefined) usp.set(k, params[k]); });
  if (state !== undefined) usp.set('state', state);
  usp.set('iss', base);
  const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
  res.redirect(302, redirectUri + sep + usp.toString());
  log.debug("Leaving redirectBack().");
}

app.get('/oauth2/authorize', function (req, res) {
  log.debug("Entering the authorization endpoint.");
  const base = baseUrlOf(req);
  const q = req.query || {};
  const redirectUri = String(q.redirect_uri || '');

  // Without a usable redirect_uri there is nowhere to report an error TO, so it
  // is reported here instead (OAuth 2.0 section 4.1.2.1).
  if (!redirectUri || !/^https?:\/\//i.test(redirectUri)) {
    log.debug("Leaving the authorization endpoint. There is no usable redirect_uri to report to.");
    return oauthError(res, 400, 'invalid_request', 'A valid absolute redirect_uri is required.');
  }
  const fail = function (error, description) {
    log.debug("Leaving the authorization endpoint. Reporting " + error + " to the client.");
    redirectBack(res, base, redirectUri, q.state, { error: error, error_description: description }, false);
  };
  if (!q.client_id) return fail('invalid_request', 'client_id is required.');
  const types = String(q.response_type || '').split(/\s+/).filter(Boolean);
  const known = ['code', 'token', 'id_token'];
  if (!types.length || types.some(function (t) { return known.indexOf(t) < 0; })) {
    return fail('unsupported_response_type', 'response_type "' + (q.response_type || '') + '" is not supported.');
  }

  // issuer_state (OID4VCI section 4.1.1): if this request came from a Credential
  // Offer this server issued, say so — it is what ties the authorization request
  // back to the offer, and seeing it arrive is most of its debugging value.
  if (q.issuer_state) {
    const known = issuerStates.get(String(q.issuer_state));
    if (known && known.expires >= Date.now()) {
      log.debug("The authorization request carries an issuer_state from a Credential Offer this issuer made" +
                " (credential_configuration_ids=" + (known.configurationIds || []).join(', ') + ").");
    } else {
      log.debug("The authorization request carries an issuer_state this issuer does not recognise: " +
                q.issuer_state);
    }
  }

  // Already signed in? Then this is the second pass — after the login screen,
  // or a later request on the same session — and the response goes out now.
  const session = sessionOf(req);
  const forcePrompt = String(q.prompt || '').split(/\s+/).indexOf('login') >= 0;
  if (session && !forcePrompt) {
    log.debug("Leaving the authorization endpoint. The session stands, so the response goes out now.");
    return issueAuthorizationResponse(req, res, q, session.user, session.authTime);
  }
  if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
    // OIDC: prompt=none must not show any UI.
    return fail('login_required', 'No session, and prompt=none forbids showing the login screen.');
  }

  // Otherwise: authenticate the user first. The request is stashed so the login
  // POST can send the browser back to it unchanged.
  const login = {
    id: randomId(18),
    query: JSON.parse(JSON.stringify(q)),
    expires: Date.now() + LOGIN_TTL_MS
  };
  pendingLogins.set(login.id, login);
  pendingLogins.forEach(function (v, k) { if (v.expires < Date.now()) pendingLogins.delete(k); });
  res.status(200).type('text/html').set('Cache-Control', 'no-store').send(loginPage(base, login, ''));
  log.debug("Leaving the authorization endpoint. Showing the login screen first.");
});

app.post('/oauth2/login', function (req, res) {
  log.debug("Entering the login endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const login = pendingLogins.get(String(body.login_id || ''));
  if (!login || login.expires < Date.now()) {
    pendingLogins.delete(String(body.login_id || ''));
    log.debug("Leaving the login endpoint. The form had expired.");
    return oauthError(res, 400, 'invalid_request',
      'This login form has expired. Start the authorization request again.');
  }
  const redirectUri = String(login.query.redirect_uri);

  if (String(body.action || '') === 'cancel') {
    pendingLogins.delete(login.id);
    log.debug("Leaving the login endpoint. The user cancelled.");
    return redirectBack(res, base, redirectUri, login.query.state,
      { error: 'access_denied', error_description: 'The user cancelled at the login screen.' }, false);
  }

  const username = String(body.username || '').trim();
  // The only two ways to fail: no username to put in the tokens, and the
  // reserved password the rest of this mock also refuses.
  if (!username) {
    log.debug("Leaving the login endpoint. No username was entered, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Enter a username. It does not have to exist — it is the identity the ' +
                                  'issued tokens will describe.'));
  }
  if (String(body.password || '') === 'invalid') {
    log.debug("Leaving the login endpoint. The reserved password was used, so the form is shown again.");
    return res.status(200).type('text/html').set('Cache-Control', 'no-store')
      .send(loginPage(base, login, 'Authentication failed for ' + username + '.'));
  }

  pendingLogins.delete(login.id);
  const sessionId = randomId(24);
  sessions.set(sessionId, {
    user: userFor(username), authTime: nowSec(), expires: Date.now() + SESSION_TTL_MS
  });
  res.set('Set-Cookie', SESSION_COOKIE + '=' + sessionId + '; Path=/; HttpOnly; SameSite=Lax');

  // Back to the authorization endpoint with the original request — minus
  // prompt, which has now been honoured and would otherwise prompt forever.
  res.redirect(302, base + '/oauth2/authorize?' + queryString(login.query, ['prompt']));
  log.debug("Leaving the login endpoint. " + username + " is signed in; back to the authorization endpoint.");
});

// Ends the session, so the next authorization request prompts again.
app.get('/oauth2/logout', function (req, res) {
  log.debug("Entering the logout endpoint.");
  const id = cookiesOf(req)[SESSION_COOKIE];
  if (id) sessions.delete(id);
  res.set('Set-Cookie', SESSION_COOKIE + '=; Path=/; Max-Age=0');
  const target = req.query.post_logout_redirect_uri;
  if (target && /^https?:\/\//i.test(String(target))) {
    log.debug("Leaving the logout endpoint. Redirecting to " + target + ".");
    return res.redirect(302, String(target));
  }
  res.status(200).type('text/plain').send('Signed out of the mock authorization server.\n');
  log.debug("Leaving the logout endpoint.");
});

// --- token endpoint ---------------------------------------------------------
app.post('/oauth2/token', function (req, res) {
  log.debug("Entering the token endpoint.");
  const base = baseUrlOf(req);
  const body = parseBody(req);
  const client = clientFrom(req, body);
  const grant = String(body.grant_type || '');
  res.set('Cache-Control', 'no-store');

  const respond = function (payload) {
    res.status(200).type('application/json').send(JSON.stringify(payload));
    log.debug("Leaving the token endpoint. Issued: " + Object.keys(payload).join(', '));
  };

  if (grant === 'authorization_code') {
    const record = authzCodes.get(String(body.code || ''));
    if (!record) return oauthError(res, 400, 'invalid_grant', 'Unknown or already-used authorization code.');
    authzCodes.delete(String(body.code));  // single use
    if (record.expires < Date.now()) return oauthError(res, 400, 'invalid_grant', 'The authorization code has expired.');
    if (body.redirect_uri && body.redirect_uri !== record.redirect_uri) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    }
    if (record.code_challenge) {
      const verifier = String(body.code_verifier || '');
      if (!verifier) return oauthError(res, 400, 'invalid_grant', 'PKCE was used, so code_verifier is required.');
      const computed = record.code_challenge_method === 'S256'
        ? b64u(crypto.createHash('sha256').update(verifier, 'ascii').digest())
        : verifier;
      if (computed !== record.code_challenge) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        return oauthError(res, 400, 'invalid_grant', 'The code_verifier does not match the code_challenge.');
      }
    }
    return respond(tokenSet(base, {
      user: record.user, client_id: record.client_id, scope: record.scope,
      nonce: record.nonce, auth_time: record.auth_time
    }));
  }

  if (grant === 'refresh_token') {
    let claims;
    try {
      claims = jwt.verify(String(body.refresh_token || ''), STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      log.error('the refresh token is not valid: ' + e.message);
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'The refresh token is not valid: ' + e.message);
    }
    if (revokedJtis.has(claims.jti)) return oauthError(res, 400, 'invalid_grant', 'The refresh token was revoked.');
    return respond(tokenSet(base, {
      user: userFor(claims.username), client_id: claims.client_id,
      scope: body.scope ? String(body.scope) : claims.scope
    }));
  }

  if (grant === 'client_credentials') {
    // No user is involved, so no refresh token and no ID token.
    return respond(tokenSet(base, {
      sub: client.client_id || 'unknown-client', username: client.client_id,
      client_id: client.client_id, scope: String(body.scope || ''), withRefresh: false,
      user: Object.assign(userFor(client.client_id), { sub: client.client_id || 'unknown-client' })
    }));
  }

  if (grant === 'password') {
    const username = String(body.username || '');
    if (!username || !body.password) {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_request', 'username and password are required.');
    }
    // The one credential this mock rejects, so a negative test has something to
    // fail on (the WS-Trust side of this service does the same).
    if (body.password === 'invalid') {
      log.debug("Leaving the token endpoint. The grant was refused.");
      return oauthError(res, 400, 'invalid_grant', 'Authentication failed for user ' + username + '.');
    }
    return respond(tokenSet(base, {
      user: userFor(username), client_id: client.client_id, scope: String(body.scope || 'openid')
    }));
  }

  if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    const subjectToken = String(body.subject_token || '');
    if (!subjectToken) return oauthError(res, 400, 'invalid_request', 'subject_token is required.');
    let subject = {};
    try {
      subject = jwt.verify(subjectToken, STS.certPem, { algorithms: ['RS256'] });
    } catch (e) {
      // A token from somewhere else: exchange it anyway, but say who it was for
      // as best it can be read.
      log.debug("The subject_token was not signed by this server; reading it without verifying.");
      try {
        subject = jsonFromB64u(subjectToken.split('.')[1]) || {};
      } catch (e2) {
        log.error('the subject_token could not be read at all: ' + e2.message);
        subject = {};
      }
    }
    let act;
    if (body.actor_token) {
      try {
        act = { sub: (jsonFromB64u(String(body.actor_token).split('.')[1]) || {}).sub };
      } catch (e) {
        log.error('the actor_token could not be read: ' + e.message);
        act = undefined;
      }
    }
    const exchanged = tokenSet(base, {
      sub: subject.sub || 'urn:sts-mock:exchanged',
      user: Object.assign(userFor(subject.username), subject.sub ? { sub: subject.sub } : {}),
      client_id: client.client_id, scope: String(body.scope || subject.scope || ''),
      audience: body.audience || body.resource, act: act, withRefresh: false
    });
    exchanged.issued_token_type = 'urn:ietf:params:oauth:token-type:access_token';
    return respond(exchanged);
  }

  log.debug("Leaving the token endpoint.");
  log.debug("Leaving the token endpoint. The grant type is not supported.");
  return oauthError(res, 400, 'unsupported_grant_type', 'grant_type "' + grant + '" is not supported.');
});

// --- introspection (RFC 7662) ------------------------------------------------
app.post('/oauth2/introspect', function (req, res) {
  log.debug("Entering the introspection endpoint.");
  const body = parseBody(req);
  res.set('Cache-Control', 'no-store');
  const inactive = function () {
    res.status(200).type('application/json').send(JSON.stringify({ active: false }));
    log.debug("Leaving the introspection endpoint. The token is not active.");
  };
  const token = String(body.token || '');
  if (!token) return inactive();
  let claims;
  try {
    claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
  } catch (e) {
    // Expired, forged, or simply not one of ours.
    log.debug("Introspection: the token does not verify (" + e.message + "), so it is inactive.");
    return inactive();
  }
  if (revokedJtis.has(claims.jti)) return inactive();
  res.status(200).type('application/json').send(JSON.stringify({
    active: true,
    scope: claims.scope || '',
    client_id: claims.client_id,
    username: claims.username,
    token_type: claims.typ === 'Refresh' ? 'refresh_token' : 'Bearer',
    exp: claims.exp, iat: claims.iat, nbf: claims.nbf,
    sub: claims.sub, aud: claims.aud, iss: claims.iss, jti: claims.jti
  }));
  log.debug("Leaving the introspection endpoint. The token is active.");
});

// --- revocation (RFC 7009) ---------------------------------------------------
// "The authorization server responds with HTTP 200 for both a successful
// revocation and an invalid token" — so this always succeeds. A revoked jti
// stops introspecting as active and stops refreshing.
app.post('/oauth2/revoke', function (req, res) {
  log.debug("Entering the revocation endpoint.");
  const body = parseBody(req);
  const token = String(body.token || '');
  if (token) {
    try {
      const claims = jwt.verify(token, STS.certPem, { algorithms: ['RS256'] });
      if (claims.jti) revokedJtis.add(claims.jti);
    } catch (e) {
      // RFC 7009: an invalid token is still a successful revocation.
      log.debug("Revocation: the token does not verify (" + e.message + "), so there is nothing to revoke.");
    }
  }
  res.status(200).set('Cache-Control', 'no-store').end();
  log.debug("Leaving the revocation endpoint. " + revokedJtis.size + " token(s) revoked so far.");
});

// --- dynamic client registration (RFC 7591) + management (RFC 7592) ----------
function clientRecord(base, metadata, clientId, secret, token) {
  log.debug("Entering clientRecord(). client_id=" + clientId);
  const record = Object.assign({}, metadata, {
    client_id: clientId,
    client_id_issued_at: nowSec(),
    client_secret: secret,
    client_secret_expires_at: 0,               // 0 = never
    registration_access_token: token,
    registration_client_uri: base + '/oauth2/register/' + clientId
  });
  log.debug("Leaving clientRecord().");
  return record;
}

app.post('/oauth2/register', function (req, res) {
  log.debug("Entering the client registration endpoint.");
  const base = baseUrlOf(req);
  const metadata = parseBody(req);
  if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
    return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris must be an array.');
  }
  const clientId = 'sts-mock-client-' + randomId(8);
  const record = clientRecord(base, metadata, clientId, randomId(24), randomId(24));
  registeredClients.set(clientId, record);
  res.status(201).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record, null, 2));
  log.debug("Leaving the client registration endpoint. Registered " + clientId + ".");
});

// The management calls all authenticate with the registration access token the
// registration handed out.
function withRegisteredClient(req, res, handler) {
  log.debug("Entering withRegisteredClient(). client_id=" + req.params.client_id);
  const record = registeredClients.get(req.params.client_id);
  if (!record) {
    log.debug("Leaving withRegisteredClient(). No such client.");
    return oauthError(res, 404, 'invalid_client', 'No such registered client.');
  }
  const auth = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  if (auth !== record.registration_access_token) {
    res.set('WWW-Authenticate', 'Bearer');
    log.debug("Leaving withRegisteredClient(). The registration access token did not match.");
    return oauthError(res, 401, 'invalid_token', 'The registration access token does not match.');
  }
  const result = handler(record);
  log.debug("Leaving withRegisteredClient().");
  return result;
}

app.get('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client read endpoint.");
  withRegisteredClient(req, res, function (record) {
    res.status(200).type('application/json').send(JSON.stringify(record, null, 2));
  });
  log.debug("Leaving the client read endpoint.");
});

app.put('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client update endpoint.");
  withRegisteredClient(req, res, function (record) {
    const updated = Object.assign({}, parseBody(req), {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      client_secret: record.client_secret,
      client_secret_expires_at: record.client_secret_expires_at,
      registration_access_token: record.registration_access_token,
      registration_client_uri: record.registration_client_uri
    });
    registeredClients.set(record.client_id, updated);
    res.status(200).type('application/json').send(JSON.stringify(updated, null, 2));
  });
  log.debug("Leaving the client update endpoint.");
});

app.delete('/oauth2/register/:client_id', function (req, res) {
  log.debug("Entering the client delete endpoint.");
  withRegisteredClient(req, res, function (record) {
    registeredClients.delete(record.client_id);
    res.status(204).end();
  });
  log.debug("Leaving the client delete endpoint.");
});

// --- the documents the metadata links to ------------------------------------
app.get('/docs', function (req, res) {
  log.debug("Entering the service documentation endpoint.");
  res.type('text/plain').send(
    'Mock authorization server (service_documentation).\n\n' +
    'Every endpoint in ' + baseUrlOf(req) + '/.well-known/oauth-authorization-server answers.\n' +
    'Tokens are RS256 JWTs signed with the key at ' + baseUrlOf(req) + '/oauth2/jwks.\n' +
    'No credential is ever verified: this server exists to exercise a client.\n');
  log.debug("Leaving the service documentation endpoint.");
});

app.get('/policy', function (req, res) {
  log.debug("Entering the policy document endpoint.");
  res.type('text/plain').send('Mock authorization server policy (op_policy_uri). Test data only.\n');
  log.debug("Leaving the policy document endpoint.");
});

app.get('/tos', function (req, res) {
  log.debug("Entering the terms of service endpoint.");
  res.type('text/plain').send('Mock authorization server terms of service (op_tos_uri). Test data only.\n');
  log.debug("Leaving the terms of service endpoint.");
});

app.listen(PORT, '0.0.0.0', function () {
  log.info('WS-Trust STS mock listening on :' + PORT + ' (issuer ' + ISSUER + '); POST SOAP RST to /sts');
  log.info('RFC 8414 metadata at /.well-known/oauth-authorization-server; JWKS at /oauth2/jwks');
  log.info('OID4VCI issuer metadata at /.well-known/openid-credential-issuer; ' +
           'credential endpoint at /oid4vci/credential');
  log.info('Issuer-initiated (OID4VCI H.1): the issuer web page is at /issuer; ' +
           'it builds a Credential Offer and sends the browser to the wallet.');
  log.info('Mock authorization server endpoints: /oauth2/authorize (login screen), /oauth2/login, ' +
           '/oauth2/token, /oauth2/introspect, /oauth2/revoke, /oauth2/register, /oauth2/logout');
  log.info('Every endpoint call, and every token or assertion before and after it was signed, ' +
           'is written to this log at debug level.');
});
