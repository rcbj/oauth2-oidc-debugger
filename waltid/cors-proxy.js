// File: cors-proxy.js
//
// ---------------------------------------------------------------------------
// CORS in front of walt.id's issuer-api2.
//
// walt.id's services send no CORS headers — they install no CORS plugin at all,
// and walt.id's own compose stack puts a reverse proxy in front of every one of
// them for that reason. That is fine for a server-side wallet and fatal for a
// browser-based one: without `Access-Control-Allow-Origin` the browser refuses to
// hand the response to the page, so the debugger could not read the issuer's
// metadata, let alone POST a Credential Request.
//
// So the wallet talks to this, and the issuer's own `baseUrl` names it: every URL
// walt.id publishes in its metadata is built from that base, and they have to be
// URLs a browser can actually use. Nothing is rewritten here — the issuer already
// believes it lives at this address.
//
// Permissive on purpose: this fronts a throwaway test issuer on a private
// network. A real deployment would name its wallet origins.
//
//   WALTID_UPSTREAM     host:port of the issuer (default localhost:7006)
//   WALTID_PROXY_PORT   the port to serve (default 7005)
//
// No dependencies, so it runs on a stock node image with nothing installed.
// ---------------------------------------------------------------------------
var http = require("http");

var UPSTREAM = process.env.WALTID_UPSTREAM || "localhost:7006";
var PORT = parseInt(process.env.WALTID_PROXY_PORT, 10) || 7005;
var upstreamHost = UPSTREAM.split(":")[0];
var upstreamPort = parseInt(UPSTREAM.split(":")[1], 10) || 80;

// Preflighted requests are the whole reason this exists: the wallet sends
// Content-Type: application/json and an Authorization header, which makes the
// browser ask permission first.
var CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Expose-Headers": "Content-Type, Location",
  "Access-Control-Max-Age": "86400"
};

function applyCors(res) {
  Object.keys(CORS).forEach(function (name) {
    res.setHeader(name, CORS[name]);
  });
}

function log(message) {
  // One line per call, so a failing browser request can be traced to what the
  // issuer actually answered.
  console.log(new Date().toISOString() + "  " + message);
}

var server = http.createServer(function (req, res) {
  applyCors(res);

  // A preflight is answered here rather than forwarded: the issuer has no route
  // for OPTIONS and would 404 it, which the browser reads as "not allowed" and
  // then never sends the real request.
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    log("204 OPTIONS " + req.url + " (preflight answered here)");
    return;
  }

  var headers = Object.assign({}, req.headers);
  // The upstream must see a Host it accepts; it is addressed by its own name.
  headers.host = UPSTREAM;

  var upstream = http.request({
    host: upstreamHost,
    port: upstreamPort,
    method: req.method,
    path: req.url,
    headers: headers
  }, function (answer) {
    // Whatever the issuer said, plus the CORS headers already set. Its own CORS
    // headers (there are none today) would otherwise arrive twice, which a
    // browser rejects.
    Object.keys(answer.headers).forEach(function (name) {
      if (name.toLowerCase().indexOf("access-control-") === 0) return;
      res.setHeader(name, answer.headers[name]);
    });
    res.writeHead(answer.statusCode);
    answer.pipe(res);
    log(answer.statusCode + " " + req.method + " " + req.url);
  });

  upstream.on("error", function (e) {
    // The issuer is not there, or not there yet. 502 with a readable reason
    // beats a socket hangup the browser reports as a network error.
    log("502 " + req.method + " " + req.url + " — upstream " + UPSTREAM + ": " + e.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
    }
    res.end(JSON.stringify({
      error: "upstream_unavailable",
      error_description: "The walt.id issuer at " + UPSTREAM + " did not answer: " + e.message
    }));
  });

  req.pipe(upstream);
});

server.listen(PORT, "0.0.0.0", function () {
  log("CORS proxy listening on 0.0.0.0:" + PORT + ", forwarding to " + UPSTREAM + ".");
});
