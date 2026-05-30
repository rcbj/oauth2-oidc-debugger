// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
var appconfig = require(process.env.CONFIG_FILE);
const expressLogging = require('express-logging');
const logger = require('logops');
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'server', 
                                logLevel: appconfig.logLevel });

log.info('appconfig: ' + JSON.stringify(appconfig));
// Constants
const PORT = appconfig.port || 3000;
const HOST = appconfig.hostname || '0.0.0.0';

// App
const app = express();

app.use(function(req, res, next) {
  if (!req.path.endsWith('.html')) { return next(); }
  const filePath = path.join(__dirname, 'public', req.path);
  fs.readFile(filePath, 'utf8', function(err, content) {
    if (err) { return next(); }
    var processed = content.replace(/<!--#include file="([^"]+)"-->/g, function(match, file) {
      try { return fs.readFileSync(path.join(__dirname, 'public', file), 'utf8'); }
      catch(e) { log.error('SSI include failed: ' + file + ' - ' + e); return ''; }
    });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(processed);
  });
});

app.use( function(req, res, next) {
    console.log(req.originalUrl);
    next();
}, express.static('public'));
app.use(expressLogging(logger));

app.get('/callback', (req, res) => {
  var qp = req.query;
  var queryString='';
  Object.keys(qp).forEach( (key) => {
    queryString= queryString +
                 key +
                 '=' +
                 qp[key] +
                 '&';
  });
  queryString = queryString.substring(0, queryString.length - 1);
  log.info('host: ' + req.headers.host);
  log.info('queryString: ' + queryString);
  res.writeHead(302, {
    'Location': appconfig.uiUrl + '/debugger2.html' + '?' + queryString
  });
  res.end();
});

app.listen(PORT, HOST);
log.info(`Running on http://${HOST}:${PORT}`);
