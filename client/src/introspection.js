// File: introspection.js
// Author: Robert C. Broeckelmann Jr.
// Date: 07/11/2020
// Notes:
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
var log = bunyan.createLogger({name: 'introspection', level: appconfig.logLevel});
log.info("Log initialized. logLevel=" + log.level());

function getParameterByName(name, url) {
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

function callIntrospectionEndpoint() {
  log.debug("Entering callIntrospectionEndpoint().");

  var introspection_endpoint = document.getElementById("introspection_endpoint").value;
  var introspection_token = document.getElementById("introspection_token").value;
  var introspection_token_type_hint = document.getElementById("introspection_token_type_hint").value;
  var introspection_authentication_type = document.getElementById("introspection_authentication_type").value;
  var introspection_client_id = document.getElementById("introspection_client_id").value;
  var introspection_client_secret = document.getElementById("introspection_client_secret").value;
  var introspection_bearer_token = document.getElementById("introspection_bearer_token").value;

  var introspectionEndpointCall = $.ajax({
    type: "POST",
    url: introspection_endpoint,
    crossDomain: true,
    headers: {
      "Authorization": introspection_authentication_type == "basic_auth" ? 
        "Basic " + btoa(introspection_client_id + ":" + introspection_client_secret) : 
        "Bearer " + introspection_bearer_token,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    data: {
      token: introspection_token,
      token_type_hint: introspection_token_type_hint != "" ? introspection_token_type_hint : undefined
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
    }
  });

  writeValuesToLocalStorage();
  log.debug("Entering callIntrospectionEndpoint().");
}

function loadValuesFromLocalStorage() {
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    document.getElementById("introspection_endpoint").value = localStorage.getItem("introspection_endpoint");

    const type = getParameterByName('type');
    if (type == 'access') {
      document.getElementById("introspection_token").value = localStorage.getItem("token_access_token");
      document.getElementById("introspection_token_type_hint").value = "access_token";
    } else if (type == 'refresh') {
      document.getElementById("introspection_token").value = localStorage.getItem("token_refresh_token");
      document.getElementById("introspection_token_type_hint").value = "refresh_token";
    } else if (type == 'refresh_access') {
      document.getElementById("introspection_token").value = localStorage.getItem("refresh_access_token");
      document.getElementById("introspection_token_type_hint").value = "access_token";
    } else if (type == 'refresh_refresh') {
      document.getElementById("introspection_token").value = localStorage.getItem("refresh_refresh_token");
      document.getElementById("introspection_token_type_hint").value = "refresh_token";
    } else {
      log.error('Unknown token type encountered.');
    }
  }

  document.getElementById("introspection_client_id").value = localStorage.getItem("introspection_client_id");
  document.getElementById("introspection_bearer_token").value = localStorage.getItem("introspection_bearer_token");
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function writeValuesToLocalStorage() {
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("introspection_endpoint", document.getElementById("introspection_endpoint").value);
    localStorage.setItem("introspection_client_id", document.getElementById("introspection_client_id").value);
    localStorage.setItem("introspection_bearer_token", document.getElementById("introspection_bearer_token").value);
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

$(document).on("change", "#introspection_authentication_type", function() {
  if (this.value == "basic_auth") {
    $("#introspection_client_id").closest('tr').show();
    $("#introspection_client_secret").closest('tr').show();
    $("#introspection_bearer_token").closest('tr').hide();
  } else if (this.value == "bearer_token") {
    $("#introspection_client_id").closest('tr').hide();
    $("#introspection_client_secret").closest('tr').hide();
    $("#introspection_bearer_token").closest('tr').show();
  } else {
    log.error('Unknown authentication type encountered.');
  }
});

window.onload = function() {
  log.debug("Entering window.onload() function.");
  loadValuesFromLocalStorage();
  $("#introspection_authentication_type").trigger("change");
  log.debug("Leaving window.onload() function.");
}

module.exports = {
  callIntrospectionEndpoint,
  onClickToggleConfigurationParameters
};