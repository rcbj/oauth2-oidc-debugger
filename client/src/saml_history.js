// File: saml_history.js
//
// The Operations History store shared by the SAML pages — the SAML counterpart
// of the Operation History pane on debugger2.html. It lives in localStorage so
// it survives the navigations a SAML round-trip is made of, and it is shared
// because a call's outcome is learned on a DIFFERENT page than the one that
// made it:
//
//   saml_request.html   records the attempt, then hands the browser to the IdP;
//   saml_response.html  sees what the IdP actually answered, and resolves it.
//
// So an entry has three possible results:
//
//   Failure  the call never left this browser (no key, no endpoint, a signing
//            or encryption error, a metadata fetch that did not land), or the
//            IdP answered with a non-Success <samlp:StatusCode>.
//   Sent     the request was built, signed, and dispatched, and no answer has
//            come back yet. NOT a success: if the IdP rejects the request with
//            an error page, or the endpoint is wrong, the entry stays "Sent" —
//            which is exactly what happened.
//   Success  the IdP answered with <samlp:StatusCode> Success.
//
// No DOM ids are baked in: render() takes the container element, so any page
// can display the log.

var STORE_KEY = 'samltools_operation_history';
var LIMIT = 1000;

var RESULT_SENT = 'Sent';
var RESULT_SUCCESS = 'Success';
var RESULT_FAILURE = 'Failure';

function hasStorage() {
  try { return !!window.localStorage; } catch (e) { return false; }
}

function read() {
  if (!hasStorage()) return [];
  try {
    var h = JSON.parse(localStorage.getItem(STORE_KEY) || '[]');
    return Object.prototype.toString.call(h) === '[object Array]' ? h : [];
  } catch (e) { return []; }
}

function write(history) {
  if (!hasStorage()) return;
  // Keep the most recent entries once the cap is reached.
  if (history.length > LIMIT) history = history.slice(history.length - LIMIT);
  try { localStorage.setItem(STORE_KEY, JSON.stringify(history)); } catch (e) { /* quota */ }
}

function newEntryId() {
  return 'op' + Date.now().toString(36) + Math.floor(Math.random() * 1e6).toString(36);
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Append an entry. `entry` carries operation/binding/version/spEntityId/
// idpEntityId/result/detail. Returns the id, so a caller can resolve it later.
function record(entry) {
  entry = entry || {};
  var history = read();
  var saved = {
    id: newEntryId(),
    timestamp: new Date().toISOString(),
    operation: entry.operation || '',
    binding: entry.binding || '',
    version: entry.version || '',
    spEntityId: entry.spEntityId || '',
    idpEntityId: entry.idpEntityId || '',
    result: entry.result || RESULT_SENT,
    detail: entry.detail || ''
  };
  history.push(saved);
  write(history);
  return saved.id;
}

function update(id, result, detail) {
  if (!id) return false;
  var history = read();
  for (var i = history.length - 1; i >= 0; i--) {
    if (history[i].id !== id) continue;
    history[i].result = result;
    if (detail) history[i].detail = detail;
    history[i].resolvedAt = new Date().toISOString();
    write(history);
    return true;
  }
  return false;
}

// Resolve the newest still-"Sent" entry — the call this answer belongs to.
// `operation` narrows it (a LogoutResponse resolves the Single Logout, not an
// AuthnRequest sent before it); pass nothing to take the newest of any kind.
function resolvePending(result, detail, operation) {
  var history = read();
  for (var i = history.length - 1; i >= 0; i--) {
    if (history[i].result !== RESULT_SENT) continue;
    if (operation && history[i].operation !== operation) continue;
    history[i].result = result;
    history[i].detail = detail || history[i].detail;
    history[i].resolvedAt = new Date().toISOString();
    write(history);
    return history[i];
  }
  return null;
}

function clear() {
  if (hasStorage()) localStorage.removeItem(STORE_KEY);
}

function resultClass(result) {
  if (result === RESULT_SUCCESS) return 'saml-ok';
  if (result === RESULT_FAILURE) return 'saml-bad';
  return 'saml-pending';
}

// Render the log newest-first into `box` (a DOM element).
function render(box) {
  if (!box) return;
  var history = read();
  if (!history.length) {
    box.innerHTML = '<p class="saml-history-empty">No IdP calls recorded yet.</p>';
    return;
  }
  var html = '<div class="saml-history-scroll"><table class="saml-table saml-history">' +
    '<thead><tr>' +
    '<th>#</th><th>Time (UTC)</th><th>Operation</th><th>Binding</th><th>Version</th>' +
    '<th>SP entityID</th><th>IdP entityID</th><th>Result</th>' +
    '</tr></thead><tbody>';
  for (var i = history.length - 1; i >= 0; i--) {
    var item = history[i] || {};
    var ts = String(item.timestamp || '');
    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td class="saml-history-time">' + escapeHtml(ts.substring(0, 10)) + '<br>' +
        escapeHtml(ts.substring(11, 19)) + 'Z</td>' +
      '<td>' + escapeHtml(item.operation) + '</td>' +
      '<td>' + escapeHtml(item.binding) + '</td>' +
      '<td>' + escapeHtml(item.version) + '</td>' +
      '<td class="saml-history-uri">' + escapeHtml(item.spEntityId) + '</td>' +
      '<td class="saml-history-uri">' + escapeHtml(item.idpEntityId) + '</td>' +
      '<td class="' + resultClass(item.result) + '">' + escapeHtml(item.result) +
        (item.detail ? ' — ' + escapeHtml(item.detail) : '') + '</td>' +
      '</tr>';
  }
  box.innerHTML = html + '</tbody></table></div>';
}

module.exports = {
  SENT: RESULT_SENT,
  SUCCESS: RESULT_SUCCESS,
  FAILURE: RESULT_FAILURE,
  STORE_KEY: STORE_KEY,
  LIMIT: LIMIT,
  read: read,
  record: record,
  update: update,
  resolvePending: resolvePending,
  clear: clear,
  render: render
};
