// File: userinfo.js
// Author: Robert C. Broeckelmann Jr.
// Date: 07/11/2020
// Notes:
//
const jwt = require('jsonwebtoken');
var initialized = false
var userinfo_endpoint = "";
var userinfo_scope = "";
var userinfo_method = "";
var userinfo_claims = "";
var token_access_token = "";
var query_string = "";

function getParameterByName(name, url)
{
  console.log("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.href;
  }
  name = name.replace(/[\[\]]/g, "\\$&");
  var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
      results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return "";
  console.log("Entering getParameterByName().");
  return decodeURIComponent(results[2].replace(/\+/g, " "));
}

window.onload = function() 
{
  console.log("Entering window.onload() function.");
  initLocalStorage();
  loadValuesFromLocalStorage();
  resetErrorDisplays();
}

function recalculateUserInfoURL()
{
  if(userinfo_scope) {
    query_string = 'scope=' + userinfo_scope;
  }
  if(userinfo_claims) {
    query_string += '&claims=' + userinfo_claims;
  }
}

function callUserInfoEndpoint()
{
  var userinfoEndpointCall = $.ajax({
    type: userinfo_method,
    crossdomain: true,
    url: userinfo_endpoint + "?" + query_string,
    headers: {
      Authorization: 'Bearer ' + token_access_token
    },
    success: function(data, textStatus, request) {
      console.log('Entering ajax success function for Access Token call.');
      console.log('UserInfo textStatus: ' + JSON.stringify(textStatus));
      console.log('UserInfo Endpoint Response: ' + JSON.stringify(data));
      console.log('UserInfo request: ' + JSON.stringify(request));
      console.log('UserInfo Response Content-Type: ' + userinfoEndpointCall.getResponseHeader("Content-Type"));
      console.log('UserInfo Headers: ' + JSON.stringify(userinfoEndpointCall.getAllResponseHeaders()));
      var responseContentType = userinfoEndpointCall.getResponseHeader("Content-Type");
      if (responseContentType.includes('application/json')) {
        console.log('plaintext response detected, no signature, no encryption');
        console.log('UserInfo Endpoint Response: ' + JSON.stringify(data, null, 2));
        document.getElementById("userinfo_output").value = JSON.stringify(data,null,2);
      } else {
        console.log('Unknown response format.');
      }
    },
    error: function (request, status, error) {
      console.log("request: " + JSON.stringify(request));
      console.log("status: " + JSON.stringify(status));
      console.log("error: " + JSON.stringify(error));
      // recalculateTokenErrorDescription(request);
    }
  });
}

$(".userinfo_endpoint").keypress(function() {
  console.log("Entering keypress().");
  localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
});

$(".userinfo_method").keypress(function() {
  console.log("Entering keypress()."); 
  localStorage.setItem("userinfo_method", userinfo_method);
});

$(".userinfo_scope").keypress(function() {
  console.log("Entering keypress().");
  localStorage.setItem("userinfo_scope", userinfo_scope);
  recalculateUserInfoURL();
});

$(".userinfo_claims").keypress(function() {
  console.log("Entering keypress().");
  localStorage.setItem("userinfo_claims", userinfo_claims);
  recalculateUserInfoURL(); 
});

$(".token_access_token").keypress(function() {
  console.log("Entering keypress().");
  localStorage.setItem("token_access_token", token_access_token);
});

function resetUI(value)
{
}

function resetErrorDisplays()
{
  console.log("Entering resetErrorDisplays().");
  console.log("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  console.log("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
    localStorage.setItem("userinfo_method", userinfo_method);
    localStorage.setItem("userinfo_scope", userinfo_scope);
    localStorage.setItem("userinfo_claims", userinfo_claims);
    localStorage.setItem("token_access_token", token_access_token);
  }
  console.log("Leaving writeValuesToLocalStorage().");
}

function initLocalStorage()
{
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
}

function loadValuesFromLocalStorage()
{
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
}

function regenerateState() {
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
}

function onClickToggleConfigurationParameters() {
    if(document.getElementById("config_fieldset").style.display == 'block') {
       document.getElementById('config_fieldset').style.display = 'none'
    } else {
      document.getElementById('config_fieldset').style.display = 'block'
    }
}


module.exports = {
  getParameterByName,
  callUserInfoEndpoint,
  onClickToggleConfigurationParameters
};
