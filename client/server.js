// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');

const expressLogging = require('express-logging');
const logger = require('logops');
// Constants
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

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
    'Location': process.env.BASE_URL + '/debugger2.html' + '?' + queryString
  });
  res.end();
});

app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);
