// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');
var appconfig = require(process.env.CONFIG_FILE);
const expressLogging = require('express-logging');
const logger = require('logops');

console.log('appconfig: ' + JSON.stringify(appconfig));
// Constants
const PORT = appconfig.port || 3000;
const HOST = appconfig.hostname || '0.0.0.0';

// App
const app = express();

app.use(express.static('public'));
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
  console.log('host: ' + req.headers.host);
  console.log('queryString: ' + queryString);
  res.writeHead(302, {
    'Location': appconfig.uiUrl + '/debugger2.html' + '?' + queryString
  });
  res.end();
});

app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);
