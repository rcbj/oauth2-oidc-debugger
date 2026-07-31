// File: connect_timeout.js
//
// ---------------------------------------------------------------------------
// A TRUE connection timeout for the api's outbound calls.
//
// axios has no such setting. Its own `timeout` bounds the whole call — the DNS
// lookup, the TCP connect, the TLS handshake, sending the request and waiting for
// the response — and `AbortSignal.timeout` is no different: it starts counting
// when the signal is created, so it too is a deadline on everything that follows.
// Neither can express "give up if the host will not TALK to us, but let a host
// that has answered take as long as it legitimately needs".
//
// That distinction is the whole point of a separate connectionTimeout. A dead or
// firewalled address should fail in a second or two, because nothing is going to
// come of it; an identity provider that has accepted the connection and is busy
// minting a token deserves the longer callTimeout. Collapsing the two means
// choosing between failing slow on dead hosts and failing fast on live ones.
//
// Node has no connect-phase timeout either, so it is built here, at the only
// place that sees the socket being opened: the agent's createConnection. A timer
// is armed when the socket is created and cleared the moment the connection is
// USABLE — 'connect' for plain HTTP, 'secureConnect' for TLS, so the handshake is
// inside the budget (an https host that completes the TCP handshake and then
// stalls mid-handshake is exactly as dead as one that never accepts). Once
// cleared, nothing here constrains the call again; from that point on axios's
// `timeout` is the only deadline, which is what makes the two settings additive
// rather than one shadowing the other.
//
// Keep-alive note: a REUSED socket never goes through createConnection, so no
// timer is armed for it. That is correct — it is already connected.
// ---------------------------------------------------------------------------
'use strict';

/**
 * Arm a connect-phase timeout on one freshly created socket.
 *
 * @param {net.Socket|tls.TLSSocket} socket - the socket createConnection returned.
 * @param {number} ms - milliseconds allowed to reach a usable connection.
 * @param {object} [logger] - bunyan-style logger; only used when the timeout fires.
 * @param {string} [target] - host:port for the message. Worth passing: a socket
 *   that never connected has no remoteAddress to report, so without it the error
 *   cannot name what it failed to reach.
 * @returns {net.Socket|tls.TLSSocket} the same socket, for chaining.
 */
function armConnectTimeout(socket, ms, logger, target) {
  // The guard ahead of this may have refused the connection outright, in which
  // case there is no socket to arm and nothing to time.
  if (!socket || typeof socket.once !== 'function') {
    return socket;
  }

  // A TLSSocket reports itself encrypted from the moment tls.connect returns, so
  // this decides which event means "connected" before either can be emitted.
  const settledEvent = socket.encrypted ? 'secureConnect' : 'connect';

  const timer = setTimeout(function () {
    const where = target || describeSocket(socket);
    const error = new Error('Connection to ' + where + ' timed out after ' + ms +
                            'ms (connectionTimeout).');
    error.code = 'ECONNECTTIMEOUT';
    error.connectTimeout = ms;
    if (logger && typeof logger.warn === 'function') {
      logger.warn('connect_timeout: no usable connection to ' + where + ' within ' +
                  ms + 'ms; destroying the socket.');
    }
    // destroy(error) is what surfaces this to the http request, and from there to
    // axios's rejection — so the caller is told the connection never opened
    // rather than being handed a bare socket hang-up.
    socket.destroy(error);
  }, ms);

  function disarm() {
    clearTimeout(timer);
  }

  socket.once(settledEvent, disarm);
  // 'error' and 'close' matter as well: without them a socket that failed for its
  // own reasons (refused, unreachable, DNS) would leave a timer pending, and the
  // later destroy() would attribute an unrelated failure to a timeout.
  socket.once('error', disarm);
  socket.once('close', disarm);

  return socket;
}

/**
 * Describe a socket for an error message, best effort.
 *
 * The remote address is not known until the socket connects — which by
 * definition it has not — so the requested host/port is used when available.
 *
 * @param {net.Socket} socket
 * @returns {string}
 */
function describeSocket(socket) {
  const host = socket._host || socket.remoteAddress ||
               (socket._parent && socket._parent.remoteAddress) || 'the remote host';
  const port = socket.remotePort || (socket._parent && socket._parent.remotePort);
  return port ? host + ':' + port : String(host);
}

/**
 * Describe what a connection was aimed at, from the options it was opened with.
 *
 * @param {object} options - what createConnection was called with.
 * @returns {string}
 */
function describeTarget(options) {
  if (!options) return '';
  const host = options.host || options.hostname;
  if (!host) return '';
  return options.port ? host + ':' + options.port : String(host);
}

/**
 * Wrap an agent so every NEW socket it opens carries the connect-phase timeout.
 *
 * Composes with anything already wrapping createConnection (the SSRF guard does),
 * because it calls whatever was there and only decorates the result. Apply this
 * OUTSIDE the guard so a refused connection is refused before a timer is armed.
 *
 * @param {http.Agent|https.Agent} agent - mutated in place.
 * @param {number} ms - milliseconds allowed to reach a usable connection.
 * @param {object} [logger] - bunyan-style logger.
 * @returns {http.Agent|https.Agent} the same agent.
 */
function withConnectTimeout(agent, ms, logger) {
  if (!agent || !Number.isFinite(ms) || ms <= 0) {
    return agent;
  }
  const inner = agent.createConnection;
  agent.createConnection = function (options, callback) {
    // `inner` may be an own property (the guard's wrapper) or inherited from the
    // Agent prototype; either way it must run with the agent as its receiver.
    const socket = inner.call(this, options, callback);
    return armConnectTimeout(socket, ms, logger, describeTarget(options));
  };
  return agent;
}

module.exports = {
  armConnectTimeout: armConnectTimeout,
  withConnectTimeout: withConnectTimeout
};
