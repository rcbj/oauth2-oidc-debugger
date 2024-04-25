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

window.onload = function() 
{
  console.log("Entering window.onload() function.");
  useAccessToken();
  resetErrorDisplays();
}


function callIntrospectionEndpoint()
{
  console.log("Introspect link clicked.");
  token_access_token = document.getElementById("introspection_access_token").value;
  var nameValuePairs = {};

  $('#introspection_fieldset input.q').each(function() {
    var className = $(this).attr('name');
    var value = $(this).val();
    if (value!=""){ 
      nameValuePairs[className] = value;; 
    }
  });
  console.log(nameValuePairs); // Log the name-value pairs

  var introspectEndpointCall = $.ajax({
    type: "POST",
    crossdomain: true,
    url: introspection_endpoint,
    data: nameValuePairs,
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

$(document).ready(function() {
  console.log("Entering ready function().");


  $("#access_token_introspection_button").click(function() {
    useAccessToken();
  });
  $("#refresh_token_introspection_button").click(function() {
    useRefreshToken();
  });
  document.getElementById("introspection_token_type_hint").value  = 'access_token';
  
});

function useAccessToken(){
  if(localStorage) {
    token_access_token = localStorage.getItem("token_access_token");
  }
  // Set configuration fields
  document.getElementById("introspection_token_type_hint").value  = 'access_token';
  document.getElementById("introspection_token").value = token_access_token;
  document.getElementById("introspection_access_token").value = token_access_token;
}

function useRefreshToken(){
  if(localStorage) {
    token_refresh_token = localStorage.getItem("token_refresh_token");
  }
  // Set configuration fields
  document.getElementById("introspection_token_type_hint").value  = 'refresh_token';
  document.getElementById("introspection_token").value = token_refresh_token;
}


module.exports = {
  callIntrospectionEndpoint,
  useRefreshToken,
  useAccessToken 
};
