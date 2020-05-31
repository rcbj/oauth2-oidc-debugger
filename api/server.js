// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');
const expressLogging = require('express-logging');
const logger = require('logops');
const request = require('request');
const bodyParser = require('body-parser');
var cors = require('cors');

// Constants
const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '0.0.0.0';

const app = express();

app.use(bodyParser.json());
app.use(expressLogging(logger));
app.options('*', cors());
app.use(cors());

app.post('/token', (req, res) => {
  try {
    console.log('Entering app.post for /token.');
    const body = req.body;
    console.log('body: ' + JSON.stringify(body));
    var grantType= body.grant_type;  //=authorization_code
    var clientId = body.client_id;  //=5qqbus6ukft6srjgqlijvk2465
    var code = body.code; //=2a795117-43d5-4d4c-bdd6-0fc9632c0594
    var redirectUri = body.redirect_uri; //=http%3A%2F%2Flocalhost%3A3000%2Fcallback
    var scope = body.scope || ""; //=openid+email+phone+profile
    var tokenEndpoint = body.token_endpoint; //=https%3A%2F%2Fblogpost1.auth.us-west-2.amazoncognito.com%2Foauth2%2Ftoken
    var sslValidate = body.sslValidate; //=true
    var clientSecret = body.client_secret; //=tester
    var username = body.username || "";
    var password = body.password || "";
    var refreshToken = body.refresh_token || "";
    var resource = body.resource || "";
  
    console.log('grantType: ' + grantType);
    console.log('clientId: ' + clientId);
    console.log('code: ' + code);
    console.log('redirectUri: ' + redirectUri);
    console.log('scope: ' + scope);
    console.log('tokenEndpoint: ' + tokenEndpoint);
    console.log('sslValidate: ' + sslValidate);
    console.log('clientSecret: ' + clientSecret);
    console.log('username: ' + username);
    console.log('password: ' + password);
    console.log('refreshToken: ' + refreshToken);
    console.log('resource: ' + resource);
  
    var parameterObject = {};
    if(grantType == "authorization_code") {
      parameterObject = { 
  	grant_type: grantType,
  	client_id: clientId,
  	client_secret: clientSecret,
  	code: code,
  	redirect_uri: redirectUri
      };
    } else if(grantType == "client_credentials") {
       parameterObject =  {
          grant_type: grantType,
  	client_id: clientId,
  	client_secret: clientSecret
       };
    } else if(grantType == "password") {
       parameterObject = {
  	grant_type: grantType,
  	client_id: clientId,
  	client_secret: clientSecret,
  	username: username,
  	password: password
       };
    } else if(grantType == "refresh_token") {
      parameterObject = {
        grant_type: grantType,
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: refreshToken
      };
    }

    if(resource != "") {
      parameterObject.resource = resource;
    }

    if(scope != "") {
      parameterObject.scope = scope;
    }

    console.log("parameterObject: " + JSON.stringify(parameterObject));
  
    var parameterString = "";
    Object.keys(parameterObject).forEach( (key) => {
      parameterString = parameterString +
                      key +
                      "=" +
                      parameterObject[key] +
                      "&";
    });
    parameterString = parameterString.substring(0, parameterString.length - 1);
    request.post({
      headers: {'content-type' : 'application/x-www-form-urlencoded'},
      url:    tokenEndpoint,
      body: parameterString,
      strictSSL: sslValidate
    }, function(error, response, body){
      console.log('Response from OAuth2 Token Endpoint: ' + body);
      res.status(response.statusCode);
      res.json(JSON.parse(body));
    });
  } catch (e) {
    console.log('An error occurred: ' + e);
    res.status(500);
    res.json({ "error": e });
  }
});

app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);

