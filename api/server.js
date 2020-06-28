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
const cors = require('cors');

// Constants
const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '0.0.0.0';

const app = express();
const expressSwagger = require('express-swagger-generator')(app);

app.use(bodyParser.json());
app.use(expressLogging(logger));
app.options('*', cors());
app.use(cors());

/**
 * @typedef TokenRequest
 * @property {string} grant_type.required - The OAuth2 / OIDC Grant / Flow Type
 * @property {string} client_id.required - The OAuth2 client identifier
 * @property {string} code.required - The OAuth2 Authorization Code
 * @property {string} redirect_uri.required - The registered redirect (callback) URI for the OAuth2 application definition.
 * @property {string} scope.required - The requested OAuth2 scope.
 * @property {string} token_endpoint.required - The Token Endpoint URL for this OAuth2 Provider
 * @property {boolean} sslValidate.required - Validate the token endpoint SSL/TLS certificate
 * @property {string} resource - Resource parameter
 * @property {string} refresh_token - OAuth2 Refresh Token needed for Refresh Grant
 * @property {string} username - The username used with the OAuth2 Resource Owner Credential Grant
 * @property {string} password - The password used with the OAuth2 Resource Owner Credential Grant
 * @property {string} client_secret - The client secret for a confidential client
 * @property {object} customParams - List of key:value pairs
 */

/**
 * @typedef TokenResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 * @property {string} refresh_token - The OAuth2 Refresh Token
 * @property {string} expires_in.required - How long the access token is valid (seconds)
 * @property {string} token_type - The OAuth2 Access Token type
 */

/**
 * @typedef Error
 * @property {boolean} status.required
 * @property {string} code.required
 */

/**
 * Wrapper around OAuth2 Token Endpoint
 * @route POST /token
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {TokenRequest.model} req.body.required - Token Endpoint Request
 * @returns {TokenResponse.model} 200 - Token Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
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
    var customParams = body.customParams || {}; 
  
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
    Object.keys(customParams).forEach( (key) => {
      console.log(key + ':' + customParams[key]);
    }); 
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

    if (Object.keys(customParams).length > 0) {
      Object.keys(customParams).forEach( (key) => {
        parameterObject[key] = customParams[key];
      });
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

let options = {
    swaggerDefinition: {
        info: {
            description: 'IDPTools API',
            title: 'Swagger',
            version: '1.0.0',
        },
        host: 'localhost:4000',
        basePath: '/',
        produces: [
            "application/json",
        ],
        schemes: ['http', 'https'],
        securityDefinitions: {
        }
    },
    basedir: __dirname, //app absolute path
    files: ['server.js'] //Path to the API handle folder
};

expressSwagger(options)
app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);

