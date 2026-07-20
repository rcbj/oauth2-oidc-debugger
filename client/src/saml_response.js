// File: saml_response.js
// Author: Robert C. Broeckelmann Jr.
//
// SAML Response debugger page. The API ACS endpoint stashes the IdP's
// SAMLResponse and redirects here with ?id=<stash id>; this page fetches the
// stashed XML (GET /samlresponse?id=), shows the full response and the extracted
// assertion, and lists the assertion attributes (incl. NameID) in a table.
//
// As a fallback it also accepts the base64 SAMLResponse directly in the query
// (?SAMLResponse=) for manual testing.

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'saml_response', level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// Signer certificate extracted from the response-level <Signature>; handed to
// the certificate-details page via localStorage when "View" is clicked.
var responseSignerCertPem = '';

function el(id) { return document.getElementById(id); }
function setVal(id, v) { var e = el(id); if (e) e.value = (v == null ? '' : v); }
function setStatus(msg) { setVal('saml_resp_status', msg); }
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function qp(name) { return new URLSearchParams(window.location.search).get(name); }
function tags(root, localName) { return root.getElementsByTagNameNS('*', localName); }

// Minimal, dependency-free XML pretty-printer.
function formatXml(xml) {
  if (!xml) return '';
  var reg = /(>)(<)(\/*)/g;
  xml = xml.replace(reg, '$1\n$2$3');
  var pad = 0, out = '';
  xml.split('\n').forEach(function (node) {
    var indent = 0;
    if (/^<\/\w/.test(node)) { pad = Math.max(pad - 1, 0); }
    else if (/^<\w[^>]*[^\/]>.*$/.test(node) && !/<\/\w/.test(node)) { indent = 1; }
    out += new Array(pad + 1).join('  ') + node + '\n';
    pad += indent;
  });
  return out.trim();
}

function serialize(node) {
  try { return new XMLSerializer().serializeToString(node); } catch (e) { return ''; }
}

function render(responseXml) {
  setVal('saml_resp_xml', formatXml(responseXml));

  var doc = new DOMParser().parseFromString(responseXml, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) {
    setStatus('Response received, but XML is malformed.');
    return;
  }

  buildResponseDetailsTable(doc);

  var assertion = tags(doc, 'Assertion')[0];
  var assertionXml = assertion ? serialize(assertion) : '';
  setVal('saml_assertion_xml', assertionXml ? formatXml(assertionXml) : '(no <Assertion> — the response may be an error or encrypted)');

  buildAttributesTable(assertion);
  saveSubjectForLogout(assertion);
  setStatus('Response loaded.');
}

// Persist the NameID + SessionIndex so the config page's Single Logout can build
// a LogoutRequest for this session.
function saveSubjectForLogout(assertion) {
  if (!assertion || !window.localStorage) return;
  var subj = tags(assertion, 'Subject')[0];
  var nameId = subj ? tags(subj, 'NameID')[0] : null;
  if (nameId) {
    localStorage.setItem('saml_last_nameid', (nameId.textContent || '').trim());
    localStorage.setItem('saml_last_nameid_format', nameId.getAttribute('Format') || '');
  }
  var authn = tags(assertion, 'AuthnStatement')[0];
  if (authn) localStorage.setItem('saml_last_session_index', authn.getAttribute('SessionIndex') || '');
}

function row(cells) {
  return '<tr>' + cells.map(function (c) { return '<td>' + c + '</td>'; }).join('') + '</tr>';
}

function buildAttributesTable(assertion) {
  var container = el('saml_attrs_table');
  if (!assertion) { container.innerHTML = '<em>No assertion available.</em>'; return; }

  var html = '<table class="saml-table"><tr><th>Name</th><th>Value(s)</th><th>Format</th><th>FriendlyName</th></tr>';

  // Assertion metadata.
  html += row(['<span class="saml-key">Assertion ID</span>', esc(assertion.getAttribute('ID') || ''), '', '']);
  html += row(['<span class="saml-key">IssueInstant</span>', esc(assertion.getAttribute('IssueInstant') || ''), '', '']);

  // Conditions: validity window plus every restriction (Audience, etc.). Wrapped
  // so an unexpected condition shape can never blank the whole table (which would
  // drop the NameID/attribute rows built below).
  try {
    var cond = tags(assertion, 'Conditions')[0];
    if (cond) {
      if (cond.getAttribute('NotBefore')) {
        html += row(['<span class="saml-key">Conditions NotBefore</span>', esc(cond.getAttribute('NotBefore')), '', '']);
      }
      if (cond.getAttribute('NotOnOrAfter')) {
        html += row(['<span class="saml-key">Conditions NotOnOrAfter</span>', esc(cond.getAttribute('NotOnOrAfter')), '', '']);
      }
      var cc = cond.firstChild;
      while (cc) {
        if (cc.nodeType === 1) {
          if (cc.localName === 'AudienceRestriction') {
            var auds = tags(cc, 'Audience'), list = [];
            for (var ci = 0; ci < auds.length; ci++) { list.push(esc((auds[ci].textContent || '').trim())); }
            html += row(['<span class="saml-key">Condition: AudienceRestriction</span>', list.join('<br>'), '', '']);
          } else {
            html += row(['<span class="saml-key">Condition: ' + esc(cc.localName) + '</span>', esc((cc.textContent || '').trim()) || '(present)', '', '']);
          }
        }
        cc = cc.nextSibling;
      }
    }
  } catch (e) {
    log.error('buildAttributesTable conditions: ' + e.message);
  }

  // NameID (from Subject) shown first.
  var subj = tags(assertion, 'Subject')[0];
  if (subj) {
    var nameId = tags(subj, 'NameID')[0];
    if (nameId) {
      html += row([
        '<span class="saml-key">NameID</span>',
        esc((nameId.textContent || '').trim()),
        esc(nameId.getAttribute('Format') || ''),
        ''
      ]);
    }
  }

  // Attributes from every AttributeStatement.
  var attrs = tags(assertion, 'Attribute');
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    var vals = tags(a, 'AttributeValue');
    var valStrs = [];
    for (var j = 0; j < vals.length; j++) { valStrs.push(esc((vals[j].textContent || '').trim())); }
    html += row([
      esc(a.getAttribute('Name') || ''),
      valStrs.join('<br>'),
      esc(a.getAttribute('NameFormat') || ''),
      esc(a.getAttribute('FriendlyName') || '')
    ]);
  }
  html += '</table>';
  container.innerHTML = html;
}

// Two-column key/value row (value may already contain HTML).
function kv(k, v) { return '<tr><td class="saml-key">' + esc(k) + '</td><td>' + v + '</td></tr>'; }

// Text of a direct-child element by local name (avoids grabbing a nested
// element of the same name, e.g. the assertion's Issuer vs the response's).
function directChildText(parent, localName) {
  var kids = parent.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === localName) return (kids[i].textContent || '').trim();
  }
  return '';
}

// The X509Certificate from the response-level <Signature> (a direct child of
// <Response>), not the assertion's signature.
function responseSignerCert(responseEl) {
  var kids = responseEl.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1 && kids[i].localName === 'Signature') {
      var c = tags(kids[i], 'X509Certificate')[0];
      return c ? (c.textContent || '').replace(/\s+/g, '') : '';
    }
  }
  return '';
}

function buildResponseDetailsTable(doc) {
  var container = el('saml_resp_details');
  var resp = tags(doc, 'Response')[0];
  if (!resp) { container.innerHTML = '<em>No &lt;Response&gt; element found.</em>'; return; }

  var status = tags(resp, 'StatusCode')[0];
  var statusVal = status ? (status.getAttribute('Value') || '') : '';
  var statusMsg = tags(resp, 'StatusMessage')[0];
  var certB64 = responseSignerCert(resp);
  responseSignerCertPem = certB64; // saml_cert.js accepts bare base64 DER

  var certCell;
  if (certB64) {
    certCell = '<a href="/saml_cert.html?from=saml_response.html" onclick="return saml_response.viewSignerCert();">View certificate details &rarr;</a>' +
      '<div style="word-break:break-all; font-size:0.85em; margin-top:4px;">' +
      esc(certB64.substring(0, 96)) + (certB64.length > 96 ? '…' : '') + '</div>';
  } else {
    certCell = '<em>(response not signed / no certificate)</em>';
  }

  var html = '<table class="saml-table">';
  html += kv('SAML Protocol Version', esc(resp.getAttribute('Version') || ''));
  html += kv('Issue Date (IssueInstant)', esc(resp.getAttribute('IssueInstant') || ''));
  html += kv('In Response To', esc(resp.getAttribute('InResponseTo') || ''));
  html += kv('ID', esc(resp.getAttribute('ID') || ''));
  html += kv('Issuer', esc(directChildText(resp, 'Issuer')));
  html += kv('Signer Certificate', certCell);
  html += kv('SAML Status', esc(statusVal) + (statusMsg ? '<br>' + esc((statusMsg.textContent || '').trim()) : ''));
  html += '</table>';
  container.innerHTML = html;
}

function viewSignerCert() {
  if (!responseSignerCertPem) return false;
  try { if (window.localStorage) localStorage.setItem('saml_cert_view', responseSignerCertPem); } catch (e) { /* ignore */ }
  window.open('/saml_cert.html?from=saml_response.html', '_blank');
  return false;
}

// Tab switching scoped to the pane containing the clicked tab, so the two tab
// groups (SAMLResponse pane, Assertion pane) toggle independently.
function showTab(evt, tabId) {
  var target = el(tabId);
  var scope = (target && target.closest && target.closest('.saml-pane')) || document;
  var contents = scope.getElementsByClassName('saml-tabcontent');
  for (var i = 0; i < contents.length; i++) { contents[i].style.display = 'none'; }
  var links = scope.getElementsByClassName('tablinks');
  for (var k = 0; k < links.length; k++) { links[k].className = links[k].className.replace(' active', ''); }
  if (target) target.style.display = 'block';
  if (evt && evt.currentTarget) evt.currentTarget.className += ' active';
  return false;
}

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

window.onload = function () {
  var id = qp('id');
  var direct = qp('SAMLResponse');
  if (id) {
    setStatus('Loading response…');
    fetch(appconfig.apiUrl + '/samlresponse?id=' + encodeURIComponent(id))
      .then(function (r) { if (!r.ok) { throw new Error('HTTP ' + r.status); } return r.json(); })
      .then(function (j) {
        if (!j || !j.responseXml) { setStatus('No response found for that id (it may have expired).'); return; }
        render(j.responseXml);
      })
      .catch(function (e) { log.error('fetch response: ' + e.message); setStatus('Failed to load response: ' + e.message); });
  } else if (direct) {
    try { render(decodeURIComponent(escape(atob(direct)))); }
    catch (e) { setStatus('Could not decode SAMLResponse parameter: ' + e.message); }
  } else {
    setStatus('No response id in the URL. Start from the SAML Test Tools page and click "Call IdP".');
  }
};

module.exports = {
  showTab,
  viewSignerCert,
  copyField
};
