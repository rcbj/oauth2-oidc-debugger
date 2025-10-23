// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

var appconfig = require(process.env.CONFIG_FILE);
const express = require('express');
const expressLogging = require('express-logging');
const bunyan = require("bunyan");
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const { convertToOAuth2Format  } = require('./data.js');

// Constants
const PORT = appconfig.port || 4000;
const HOST = appconfig.host || '0.0.0.0';
const LOG_LEVEL = appconfig.logLevel || 'debug';
const uiUrl = appconfig.uiUrl || 'http://localhost:3000';

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
    const parameterString = convertToOAuth2Format(body);
    var headers = {
      'content-type' : 'application/x-www-form-urlencoded'
    };
    const grantType = body.grant_type;
    const clientSecret = encodeURIComponent(body.client_secret);
    const code_verifier = body.code_verifier;
    if ( typeof code_verifier != "undefined" ||
         (grantType == "refresh_token" &&
          !clientSecret)) {
      headers.origin = uiUrl;
    }
    const auth_style = body.auth_style;
    var clientId = body.client_id;
    if (!auth_style) {
      // Put client_id + client_secret in Authorization header
      headers.authorization = 'Basic ' + Buffer.from(clientId + ":" + clientSecret).toString('base64');
    }
    var tokenEndpoint = body.token_endpoint;
    var sslValidate = body.sslValidate; 
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
