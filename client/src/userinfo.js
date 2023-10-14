// File: userinfo.js
// Author: Robert C. Broeckelmann Jr.
// Date: 07/11/2020
// Notes:
//
const jwt = require('jsonwebtoken');

var displayOpenIDConnectArtifacts = false;
var appconfig = require(process.env.CONFIG_FILE);

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, {complete: true});
}

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

$(document).ready(function() {
  console.log("Entering ready function().");

  $(".btn_userinfo_endpoint").click(function() {
      console.log("Entering UserInfo Call function.");
      var formData = {
      };
      writeValuesToLocalStorage();
      resetErrorDisplays();
      var userinfoScope = document.getElementById("userinfo_scope").value
      var queryString= '';
      if(userinfoScope) {
        queryString = 'scope=' + userinfoScope;
      }
      var userinfoClaims = document.getElementById("userinfo_claims").value;
      if(userinfoClaims) {
        queryString = 'claims=' + userinfoClaims;
      }
      var tmp1 = (document.getElementById("userinfo_method").value == 'GET')? '?' + queryString: '';
      console.log('RCBJ0001: ' + document.getElementById("userinfo_userinfo_endpoint").value + tmp1);
  var userinfoEndpointCall = $.ajax({
    type: document.getElementById("userinfo_method").value,
    crossdomain: true,
    url: document.getElementById("userinfo_userinfo_endpoint").value + tmp1,
    data: document.getElementById("userinfo_method").value == 'POST'? queryString: '',
    headers: {
      Authorization: 'Bearer ' + localStorage.getItem('token_access_token')
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
  return false;
    });

});

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
    localStorage.setItem('userinfo_method', document.getElementById("userinfo_method").value);
    localStorage.setItem('userinfo_userinfo_endpoint', document.getElementById("userinfo_userinfo_endpoint").value);
  }
  console.log("Leaving writeValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  if(localStorage) {
    document.getElementById("userinfo_userinfo_endpoint").value = localStorage.getItem("oidc_userinfo_endpoint");
  }
}

window.onload = function() {
  console.log("Entering onload function.");

  if (!appconfig) {
    console.log('Failed to load appconfig.');
  }
 
//  document.getElementById("customTokenParametersCheck-yes").addEventListener("onClick", recalculateTokenRequestDescription());
//  document.getElementById("customTokenParametersCheck-no").addEventListener("onClick", recalculateTokenRequestDescription());

  loadValuesFromLocalStorage();
//  recalculateAuthorizationErrorDescription();
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
