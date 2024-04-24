// File: introspection.js
// Author: Robert C. Broeckelmann Jr., Jim Van Fleet
// Date: 04/24/2024
// Notes:
//
const jwt = require('jsonwebtoken');
var initialized = false
var introspection_endpoint = "";
var token_access_token = "";
var token_refresh_token = "";

function getParameterByName(name, url)
{
  console.log("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  return urlParams.get(name);
}

window.onload = function() 
{
  console.log("Entering window.onload() function.");
  loadValuesFromLocalStorage();
  resetErrorDisplays();
}


function callIntrospectionEndpoint()
{
  var introspectEndpointCall = $.ajax({
    type: "POST",
    crossdomain: true,
    url: introspection_endpoint + "?" + query_string,
    headers: {
      Authorization: 'Bearer ' + token_access_token
    },
    success: function(data, textStatus, request) {
      console.log('Entering ajax success function for Access Token call.');
      console.log('Introspection textStatus: ' + JSON.stringify(textStatus));
      console.log('Introspection Endpoint Response: ' + JSON.stringify(data));
      console.log('Introspection request: ' + JSON.stringify(request));
      console.log('Introspection Response Content-Type: ' + introspectEndpointCall.getResponseHeader("Content-Type"));
      console.log('UserInfo Headers: ' + JSON.stringify(introspectEndpointCall.getAllResponseHeaders()));
      var responseContentType = introspectEndpointCall.getResponseHeader("Content-Type");
      if (responseContentType.includes('application/json')) {
        console.log('plaintext response detected, no signature, no encryption');
        console.log('Introspection Endpoint Response: ' + JSON.stringify(data, null, 2));
        document.getElementById("introspection_output").value = JSON.stringify(data,null,2);
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

function resetUI(value)
{
}

function resetErrorDisplays()
{
  console.log("Entering resetErrorDisplays().");
  console.log("Leaving resetErrorDisplays().");
}

function loadValuesFromLocalStorage()
{
  if(localStorage) {
    token_access_token = localStorage.getItem("token_access_token");
    token_refresh_token = localStorage.getItem("token_refresh_token");
  }
  // Set configuration fields
  document.getElementById("token_access_token").value = token_access_token;
  document.getElementById("token_refresh_token").value = token_refresh_token;
}


function onClickToggleFieldset(name) {
  if(document.getElementById(name).style.display == 'block') {
      document.getElementById(name).style.display = 'none'
  } else {
    document.getElementById(name).style.display = 'block'
  }
}


module.exports = {
  getParameterByName,
  callIntrospectionEndpoint,
  onClickToggleFieldset 
};
