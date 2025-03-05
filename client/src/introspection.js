// File: introspection.js
// Author: Robert C. Broeckelmann Jr.
// Date: 07/11/2020
// Notes:
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
var log = bunyan.createLogger({ name: 'introspection',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
const jwt = require('jsonwebtoken');
var introspection_endpoint = "";
var introspection_token = "";
var introspection_token_type_hint = "";
var client_id = "";
var client_secret = "";

function getParameterByName(name, url)
{
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

function callIntrospectionEndpoint()
{
  log.debug("Entering callIntrospectionEndpoint().");

  client_id = document.getElementById("client_id").value;
  client_secret = document.getElementById("client_secret").value;

  var introspectionEndpointCall = $.ajax({
    type: "POST",
    url: introspection_endpoint,
    crossDomain: true,
    headers: {
      "Authorization": "Basic " + btoa(client_id + ":" + client_secret),
      "Content-Type": "application/x-www-form-urlencoded"
    },
    data: {
      token: introspection_token,
      token_type_hint: introspection_token_type_hint
    },
    success: function(data, textStatus, request) {
      log.debug('Entering ajax success function for Access Token call.');
      log.debug('Introspection textStatus: ' + JSON.stringify(textStatus));
      log.debug('Introspection Endpoint Response: ' + JSON.stringify(data));
      log.debug('Introspection request: ' + JSON.stringify(request));
      log.debug('Introspection Response Content-Type: ' + introspectionEndpointCall.getResponseHeader("Content-Type"));
      log.debug('Introspection Headers: ' + JSON.stringify(introspectionEndpointCall.getAllResponseHeaders()));
      var responseContentType = introspectionEndpointCall.getResponseHeader("Content-Type");
      if (responseContentType.includes('application/json')) {
        log.debug('plaintext response detected, no signature, no encryption');
        log.debug('Introspection Endpoint Response: ' + JSON.stringify(data, null, 2));
        document.getElementById("introspection_output").value = JSON.stringify(data,null,2);
      } else {
        log.error('Unknown response format.');
      }
    },
    error: function (request, status, error) {
      log.debug("request: " + JSON.stringify(request));
      log.debug("status: " + JSON.stringify(status));
      log.debug("error: " + JSON.stringify(error));
      // recalculateTokenErrorDescription(request);
    }
  });
  writeValuesToLocalStorage();
  log.debug("Entering callIntrospectionEndpoint().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    introspection_endpoint = localStorage.getItem("introspection_endpoint");

    const type = getParameterByName('type');
    if (type == 'access') {
      introspection_token = localStorage.getItem("token_access_token");
      introspection_token_type_hint = "access_token";
    } else if (type == 'refresh') {
      introspection_token = localStorage.getItem("token_refresh_token");
      introspection_token_type_hint = "refresh_token";
    } else if (type == 'refresh_access') {
      introspection_token = localStorage.getItem("refresh_access_token");
      introspection_token_type_hint = "access_token";
    } else if (type == 'refresh_refresh') {
      introspection_token = localStorage.getItem("refresh_refresh_token");
      introspection_token_type_hint = "refresh_token";
    } else {
      log.error('Unknown token type encountered.');
    }
  }
  // Set configuration fields
  document.getElementById("introspection_endpoint").value = introspection_endpoint;
  document.getElementById("introspection_token").value = introspection_token;
  document.getElementById("introspection_token_type_hint").value = introspection_token_type_hint;
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("introspection_endpoint", introspection_endpoint);
    localStorage.setItem("introspection_client_id", client_id)
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function onClickToggleConfigurationParameters() {
  log.debug("Entering onClickToggleConfigurationParameters().");
  if(document.getElementById("config_fieldset").style.display == 'block') {
    document.getElementById('config_fieldset').style.display = 'none'
  } else {
    document.getElementById('config_fieldset').style.display = 'block'
  }
  log.debug("Leaving onClickToggleConfigurationParameters().");
}

window.onload = function() 
{
  log.debug("Entering window.onload() function.");
  loadValuesFromLocalStorage();
  log.debug("Leaving window.onload() function.");
}

module.exports = {
  callIntrospectionEndpoint,
  onClickToggleConfigurationParameters
};