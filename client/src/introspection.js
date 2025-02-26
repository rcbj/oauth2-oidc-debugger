// File: userinfo.js
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
var initialized = false
var introspection_endpoint = "";
var userinfo_scope = "";
var userinfo_method = "";
var userinfo_claims = "";
var token_access_token = "";
var query_string = "";

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

window.onload = function() 
{
  log.debug("Entering window.onload() function.");
  initLocalStorage();
  loadValuesFromLocalStorage();
  resetErrorDisplays();
  log.debug("Leaving window.onload() function.");
}

function recalculateUserInfoURL()
{
  log.debug("Entering recalculateUserInfoURL() function.");
  if(userinfo_scope) {
    query_string = 'scope=' + userinfo_scope;
  }
  if(userinfo_claims) {
    query_string += '&claims=' + userinfo_claims;
  }
  log.debug("Leaving recalcualteUserInfoURL().");
}

function callUserInfoEndpoint()
{
  log.debug("Entering callUserInfoEndpoint().");
  var userinfoEndpointCall = $.ajax({
    type: userinfo_method,
    crossdomain: true,
    url: userinfo_endpoint + "?" + query_string,
    headers: {
      Authorization: 'Bearer ' + token_access_token
    },
    success: function(data, textStatus, request) {
      log.debug('Entering ajax success function for Access Token call.');
      log.debug('UserInfo textStatus: ' + JSON.stringify(textStatus));
      log.debug('UserInfo Endpoint Response: ' + JSON.stringify(data));
      log.debug('UserInfo request: ' + JSON.stringify(request));
      log.debug('UserInfo Response Content-Type: ' + userinfoEndpointCall.getResponseHeader("Content-Type"));
      log.debug('UserInfo Headers: ' + JSON.stringify(userinfoEndpointCall.getAllResponseHeaders()));
      var responseContentType = userinfoEndpointCall.getResponseHeader("Content-Type");
      if (responseContentType.includes('application/json')) {
        log.debug('plaintext response detected, no signature, no encryption');
        log.debug('UserInfo Endpoint Response: ' + JSON.stringify(data, null, 2));
        document.getElementById("userinfo_output").value = JSON.stringify(data,null,2);
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
  log.debug("Entering callUserInfoEndpoint().");
}

$(".userinfo_endpoint").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
});

$(".userinfo_method").keypress(function() {
  log.debug("Entering keypress()."); 
  localStorage.setItem("userinfo_method", userinfo_method);
});

$(".userinfo_scope").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_scope", userinfo_scope);
  recalculateUserInfoURL();
});

$(".userinfo_claims").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_claims", userinfo_claims);
  recalculateUserInfoURL(); 
});

$(".token_access_token").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("token_access_token", token_access_token);
});

function resetUI(value)
{
  log.debug("Entering resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
    localStorage.setItem("userinfo_method", userinfo_method);
    localStorage.setItem("userinfo_scope", userinfo_scope);
    localStorage.setItem("userinfo_claims", userinfo_claims);
    localStorage.setItem("token_access_token", token_access_token);
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function initLocalStorage()
{
  log.debug("Entering initLocalStorage().");
  if(localStorage && !initialized) {
    localStorage.setItem("userinfo_method", "GET");
    localStorage.setItem("userinfo_scope", "profile email address phone");
    var default_claims = {
     "userinfo":
      {
       "given_name": {"essential": true},
       "nickname": null,
       "email": {"essential": true},
       "email_verified": {"essential": true},
       "picture": null,
       "http://example.info/claims/groups": null
      },
     "id_token":
      {
       "auth_time": {"essential": true},
       "acr": {"values": ["urn:mace:incommon:iap:silver"] }
      }
    };
    localStorage.setItem("userinfo_claims", JSON.stringify(default_claims, null, 2));
    initialized = true;
  }
  log.debug("Leaving initLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    userinfo_endpoint = localStorage.getItem("oidc_userinfo_endpoint");
    userinfo_method = localStorage.getItem("userinfo_method");
    userinfo_scope = localStorage.getItem("userinfo_scope");
    userinfo_claims = localStorage.getItem("userinfo_claims");
    token_access_token = localStorage.getItem("token_access_token");
  }
  // Set configuration fields
  document.getElementById("userinfo_endpoint").value = userinfo_endpoint;
  document.getElementById("userinfo_method").value = userinfo_method;
  document.getElementById("userinfo_scope").value = userinfo_scope;
  document.getElementById("userinfo_claims").value = userinfo_claims;
  document.getElementById("token_access_token").value = token_access_token;
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
  log.debug("Leaving regenerateState().");
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

module.exports = {
  getParameterByName,
  callUserInfoEndpoint,
  onClickToggleConfigurationParameters
};
