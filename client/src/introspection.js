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

var useFrontEnd = false;

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

  var headers = {
        "Authorization": introspection_authentication_type == "basic_auth" ?
          "Basic " + btoa(introspection_client_id + ":" + introspection_client_secret) :
          "Bearer " + introspection_bearer_token,
        "Content-Type": "application/json"
  };
  var body = {
    token: introspection_token,
    token_type_hint: introspection_token_type_hint != "" ? introspection_token_type_hint : undefined,
  }
  var url_ = "";
  if(useFrontEnd) {
    url_ = appconfig.apiUrl + "/introspection";
    body["introspectionEndpoint"] = introspection_endpoint;
  } else {
    url_ = introspection_endpoint;
  }
  log.debug("Method: POST");
  log.debug("URL: " + url_);
  log.debug("crossDomainn: true");
  log.debug("body: " + JSON.stringify(body));
  log.debug("Headers: " + JSON.stringify(headers));
  $.ajax({
    type: "POST",
    url: url_,
    crossDomain: true,
    headers: headers,
    data: JSON.stringify(body),
    success: introspectionSuccess,
    error: introspectionError
  });
  writeValuesToLocalStorage();
  log.debug("Entering callIntrospectionEndpoint().");
}

function introspectionError(request, status, error) {
  log.debug("request: " + JSON.stringify(request));
  log.debug("status: " + JSON.stringify(status));
  log.debug("error: " + JSON.stringify(error));
  try {
    var errorReport = {
      "request": request,
      "status": status,
      "error": error
    };
    $("#introspection_output").val(JSON.stringify(errorReport));
  } catch (e) {
    log.error("Error occurred while generating error report: " + e.stack);
    $("#introspection_output").val("Error occurred while generating error report: " + e.stack);
  }
}

function introspectionSuccess(data, textStatus, jqXHR) {
  log.debug('Entering ajax success function for Introspection Endpoint call.');
  log.debug('Introspection textStatus: ' + JSON.stringify(textStatus));
  log.debug('Introspection Endpoint Response: ' + JSON.stringify(data));
  log.debug('Introspection request: ' + JSON.stringify(jqXHR));
  log.debug('Introspection Response Content-Type: ' + jqXHR.getResponseHeader("Content-Type"));
  log.debug('Introspection Headers: ' + JSON.stringify(jqXHR.getAllResponseHeaders()));
  var responseContentType = jqXHR.getResponseHeader("Content-Type");
  if (responseContentType.includes('application/json')) {
    log.debug('plaintext response detected, no signature, no encryption');
    log.debug('Introspection Endpoint Response: ' + JSON.stringify(data, null, 2));
    $("#introspection_output").val(JSON.stringify(data,null,2));
  } else {
    log.error('Unknown response format.');
  }
  log.debug("Leaving ajax success function for Introspection Endpoint call.");
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
  $("#introspection_initiateFromFrontEnd").prop("checked", getLSBooleanItem("introspection_initiateFromFrontEnd"));
  $("#introspection_initiateFromBackEnd").prop("checked", getLSBooleanItem("introspection_initiateFromBackEnd"));
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function writeValuesToLocalStorage() {
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("introspection_endpoint", document.getElementById("introspection_endpoint").value);
    localStorage.setItem("introspection_client_id", document.getElementById("introspection_client_id").value);
    localStorage.setItem("introspection_bearer_token", document.getElementById("introspection_bearer_token").value);
    localStorage.setItem("introspection_initiateFromFrontEnd", $("#introspection_initiateFromFrontEnd").is(":checked"));
    localStorage.setItem("introspection_initiateFromBackEnd", $("#introspection_initiateFromBackEnd").is(":checked"));
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

function setInitiateFromEnd() {
  log.debug("Entering setInitiateFromEnd().");
  var frontEndInitiated = $("#introspection_initiateFromFrontEnd").is(":checked");
  var backEndInitiated = $("#introspection_initiateFromBackEnd").is(":checked");
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("frontEndInitiated: " + frontEndInitiated);
  log.debug("backEndInitiated: " + backEndInitiated);
  log.debug("Leaving setInitiateFromEnd().");
}

function getLSBooleanItem(key)
{
  return localStorage.getItem(key) === 'true';
}

module.exports = {
  callIntrospectionEndpoint,
  onClickToggleConfigurationParameters,
  setInitiateFromEnd
};
