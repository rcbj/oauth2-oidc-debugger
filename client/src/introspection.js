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

window.onload = function() 
{
  log.debug("Entering window.onload() function.");
  initLocalStorage();
  loadValuesFromLocalStorage();
  resetErrorDisplays();
  log.debug("Leaving window.onload() function.");
}

function callIntrospectionEndpoint()
{
  log.debug("Entering callIntrospectionEndpoint().");
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
  log.debug("Entering callIntrospectionEndpoint().");
}

$(".introspection_endpoint").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("introspection_endpoint", introspection_endpoint);
});

$(".introspection_token").keypress(function() {
  log.debug("Entering keypress()."); 
  localStorage.setItem("introspection_token", introspection_token);
});

$(".introspection_token_type_hint").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("introspection_token_type_hint", introspection_token_type_hint);
});

$(".client_id").keypress(function() {
  log.debug("Entering keypress().");

  const type = getParameterByName('type');
  if (type == 'access' || type == 'refresh') {
    localStorage.setItem("token_client_id", client_id);
  } else if (type == 'refresh_access' || type == 'refresh_refresh') {
    localStorage.setItem("refresh_client_id", client_id);
  } else {
    log.error('Unknown token type encountered.');
  }
});

$(".client_secret").keypress(function() {
  log.debug("Entering keypress().");

  const type = getParameterByName('type');
  if (type == 'access' || type == 'refresh') {
    localStorage.setItem("token_client_secret", client_secret);
  } else if (type == 'refresh_access' || type == 'refresh_refresh') {
    localStorage.setItem("refresh_client_secret", client_secret);
  } else {
    log.error('Unknown token type encountered.');
  }
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
    localStorage.setItem("introspection_endpoint", introspection_endpoint);
    localStorage.setItem("introspection_token", introspection_token);
    localStorage.setItem("introspection_token_type_hint", introspection_token_type_hint);
    
    const type = getParameterByName('type');
    if (type == 'access' || type == 'refresh') {
      localStorage.setItem("token_client_id", client_id);
      localStorage.setItem("token_client_secret", client_secret);
    } else if (type == 'refresh_access' || type == 'refresh_refresh') {
      localStorage.setItem("refresh_client_id", client_id);
      localStorage.setItem("refresh_client_secret", client_secret);
    } else {
      log.error('Unknown token type encountered.');
    }
    
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function initLocalStorage()
{
  log.debug("Entering initLocalStorage().");
  if(localStorage && !initialized) {
    localStorage.setItem("introspection_token_type_hint", "");
    initialized = true;
  }
  log.debug("Leaving initLocalStorage().");
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
      client_id = localStorage.getItem("token_client_id");
      client_secret = localStorage.getItem("token_client_secret");
    } else if (type == 'refresh') {
      introspection_token = localStorage.getItem("token_refresh_token");
      introspection_token_type_hint = "refresh_token";
      client_id = localStorage.getItem("token_client_id");
      client_secret = localStorage.getItem("token_client_secret");
    } else if (type == 'refresh_access') {
      introspection_token = localStorage.getItem("refresh_access_token");
      introspection_token_type_hint = "access_token";
      client_id = localStorage.getItem("refresh_client_id");
      client_secret = localStorage.getItem("refresh_client_secret");
    } else if (type == 'refresh_refresh') {
      introspection_token = localStorage.getItem("refresh_refresh_token");
      introspection_token_type_hint = "refresh_token";
      client_id = localStorage.getItem("refresh_client_id");
      client_secret = localStorage.getItem("refresh_client_secret");
    } else {
      log.error('Unknown token type encountered.');
    }

    
  }
  // Set configuration fields
  document.getElementById("introspection_endpoint").value = introspection_endpoint;
  document.getElementById("introspection_token").value = introspection_token;
  document.getElementById("introspection_token_type_hint").value = introspection_token_type_hint;
  document.getElementById("client_id").value = client_id;
  document.getElementById("client_secret").value = client_secret;
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
  callIntrospectionEndpoint,
  onClickToggleConfigurationParameters
};
