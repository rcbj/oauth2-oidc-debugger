// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');
const expressLogging = require('express-logging');
const bunyan = require("bunyan");
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

// Constants
const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || '0.0.0.0';
const LOG_LEVEL = process.env.LOG_LEVEL || 'debug';
const uiUrl = 'http://localhost:3000';

var log = bunyan.createLogger({ name: 'server',
                                level: LOG_LEVEL });
log.info("Log initialized. logLevel=" + log.level());

const app = express();
const expressSwagger = require('express-swagger-generator')(app);

app.use(bodyParser.json());
// app.use(expressLogging(logger));
app.options('*', cors());
app.use(cors());

/**
 * @typedef HealthcheckResponse
 * @property {string} message - Status message
 */
/**
 * System healthcheck
 * @route GET /healthcheck
 * @group System - Support operations
 * @returns {HealthcheckResponse.model} 200 - Health Check Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/healthcheck', function (req, res) {
  res.json({ message: 'Success' });
});

/**
 * System healthcheck
 * @route GET /claimdescription
 * @group Metadata - Support operations
 * @returns {HealthcheckResponse.model} 200 - Claim Description Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/claimdescription', function(req, res) {
  fetch("https://www.iana.org/assignments/jwt/jwt.xml")
  .then((response) => {
    response.text()
    .then( (text) => {
      log.debug("Retrieved: " + text);
      res
      .append('Content-Type', 'application/xml')
      .send(text)
    });
  });
});

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
 * @property {string} code_verifier - PKCE RFC code_verifier parameter
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
    log.info('Entering app.post for /token.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var grantType = body.grant_type;  //=authorization_code
    var clientId = body.client_id;  //=5qqbus6ukft6srjgqlijvk2465
    var code = body.code; //=2a795117-43d5-4d4c-bdd6-0fc9632c0594
    var redirectUri = body.redirect_uri; //=http%3A%2F%2Flocalhost%3A3000%2Fcallback
    var scope = body.scope || ""; //=openid+email+phone+profile
    var tokenEndpoint = body.token_endpoint; //=https%3A%2F%2Fblogpost1.auth.us-west-2.amazoncognito.com%2Foauth2%2Ftoken
    var sslValidate = body.sslValidate; //=true
    var clientSecret = encodeURIComponent(body.client_secret); //=tester
    var username = body.username || "";
    var password = body.password || "";
    var refreshToken = body.refresh_token || "";
    var resource = body.resource || "";
    var customParams = body.customParams || {}; 
    var code_verifier = body.code_verifier;
    var auth_style = body.auth_style;
 
    log.debug('grantType: ' + grantType);
    log.debug('clientId: ' + clientId);
    log.debug('code: ' + code);
    log.debug('redirectUri: ' + redirectUri);
    log.debug('scope: ' + scope);
    log.debug('tokenEndpoint: ' + tokenEndpoint);
    log.debug('sslValidate: ' + sslValidate);
    log.debug('clientSecret: ' + clientSecret);
    log.debug('username: ' + username);
    log.debug('password: ' + password);
    log.debug('refreshToken: ' + refreshToken);
    log.debug('resource: ' + resource);
    Object.keys(customParams).forEach( (key) => {
      log.debug(key + ':' + customParams[key]);
    });
    log.debug("code_verifier: " + code_verifier);
    log.debug("auth_style: " + auth_style);
    var parameterObject = {};
    if(grantType == "authorization_code") {
      parameterObject = { 
  	grant_type: grantType,
        client_id: clientId,
  	code: code,
  	redirect_uri: redirectUri,
      };
      if (typeof code_verifier != "undefined") {
        parameterObject.code_verifier = code_verifier
      }
      log.debug("clientSecret: " + clientSecret);
      log.debug("auth_style: " + auth_style);
      if (!!clientSecret && auth_style) {
        parameterObject.client_secret = clientSecret;
      }
    } else if(grantType == "client_credentials") {
       parameterObject =  {
         grant_type: grantType
       };
       log.debug("clientSecret: " + clientSecret);
       log.debug("auth_style: " + auth_style);
       if ((typeof clientSecret != "undefined" && clientSecret != "undefined")
          && auth_style) {
         parameterObject.client_secret = clientSecret;
       }
    } else if(grantType == "password") {
       parameterObject = {
  	grant_type: grantType,
  	username: username,
  	password: password
       };
    } else if(grantType == "refresh_token") {
      parameterObject = {
        grant_type: grantType,
        client_id: clientId,
        refresh_token: refreshToken,
      };
      log.debug("clientSecret: " + clientSecret);
      log.debug("auth_style: " + auth_style);
      if ((typeof clientSecret != "undefined" && clientSecret != "undefined")
         && auth_style) {
        parameterObject.client_secret = clientSecret;
      }
    }
    if(auth_style) {
        parameterObject.client_id = clientId;
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
    log.debug("parameterObject: " + JSON.stringify(parameterObject));
  
    var parameterString = "";
    Object.keys(parameterObject).forEach( (key) => {
      parameterString = parameterString +
                      key +
                      "=" +
                      parameterObject[key] +
                      "&";
    });

    var headers = {
      'content-type' : 'application/x-www-form-urlencoded'
    };
    if ( typeof code_verifier != "undefined" ||
         (grantType == "refresh_token" &&
          !clientSecret)) {
      headers.origin = uiUrl;
    } 
    if (!auth_style) {
      // Put client_id + client_secret in Authorization header
      headers.authorization = 'Basic ' + Buffer.from(clientId + ":" + clientSecret).toString('base64');
    }
    parameterString = parameterString.substring(0, parameterString.length - 1);
    log.debug("Making call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: headers,
      data: parameterString,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint: ' + JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Token Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        if (!!error.response) {
          res.status(error.response.status);
          res.json(error.response.data);
        } else {
          res.status(500);
          res.json(error.message);
        }
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
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
log.info(`Running on http://${HOST}:${PORT}`);
