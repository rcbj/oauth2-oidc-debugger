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

function OnSubmitTokenEndpointForm()
{
  console.log("Entering OnSubmitTokenEndpointForm().");
  //document.token_step.action = document.getElementById("token_endpoint").value;
  document.token_step.action = "/token";
  console.log("Leaving OnSubmitTokenEndpointForm().");
  return true;
}

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
  var queryString= '';
  if(userinfo_scope) {
    queryString = 'scope=' + userinfo_scope;
  }
  if(userinfo_claims) {
    queryString = 'claims=' + userinfo_claims;
  }
  var userinfoEndpointCall = $.ajax({
    type: userinfo_method,
    crossdomain: true,
    url: userinfo_endpoint + "?" + queryString,
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
        console.log('UserInfo Endpoint Response: ' + JSON.stringify(data));
      } else if (responseContentType.includes('application/json')) {
        console.log('signed or encrypted response detected as JWT');
        console.log('jwt: ' + jwt);
        const decodedJWT = decodeJWT(jwt);
        console.log('decoded jwt: ' + JSON.stringify(decodedJWT));
        document.getElementById('jwt_header').value = JSON.stringify(decodedJWT.header, null, 2);
        document.getElementById('jwt_payload').value = JSON.stringify(decodedJWT.payload, null, 2);
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

function resetUI(value)
{
}

function resetErrorDisplays()
{
  console.log("Entering resetErrorDisplays().");
//  $("#display_refresh_error_class").html("");
  console.log("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  console.log("Entering writeValuesToLocalStorage().");
  if (localStorage) {
  }
  console.log("Leaving writeValuesToLocalStorage().");
}

function initLocalStorage()
{
  if(localStorage && !initialized) {
    localStorage.setItem("userinfo_method", "GET");
    localStorage.setItem("userinfo_scope", "openid profile email");
    localStorage.setItem("userinfo_claims", "tester");
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
}

function regenerateState() {
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
}

function OnSubmitUserInfoEndpointForm() {
  return false;
}

module.exports = {
OnSubmitTokenEndpointForm,
getParameterByName,
OnSubmitUserInfoEndpointForm
};
