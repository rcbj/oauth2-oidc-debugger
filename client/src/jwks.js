// File: jwks.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/28/2020
//Notes:
//
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
const pemfile = require('pem-file');
const { Certificate } = require('@fidm/x509');
const pkcs8 = require('@peculiar/asn1-pkcs8');

window.onload = function() {
  console.log("Entering onload function.");
  loadValuesFromLocalStorage();
}

function loadValuesFromLocalStorage()
{
  console.log("Entering loadValuesFromLocalStorage().");
  document.getElementById("jwks_endpoint").value = localStorage.getItem("jwks_endpoint");
}

function OnSubmitJWKSEndpointForm() {
  console.log("Entering OnSubmitJWKSEndpointForm().");
}

function OnSubmitJWKSEndpointForm()
{
  console.log("Entering OnSubmitJWKSEndpointForm().");
//  writeValuesToLocalStorage();
  var jwksEndpoint = document.getElementById("jwks_endpoint").value;
  console.log('URL: ' + jwksEndpoint);
  if (isUrl(jwksEndpoint)) {
    console.log('valid URL: ' + jwksEndpoint);
    $.ajax({ type: 'GET',
             crossOrigin: true,
             url: jwksEndpoint,
             success: function(result) {
               console.log("JWKS Endpoint Result: " + JSON.stringify(result));
               jwksInfo = result;
               parseJWKSInfo(result);
               buildJWKSInfoTable(result);
             },
             error: function (request, status, error) {
               console.log("request: " + JSON.stringify(request));
               console.log("status: " + JSON.stringify(status));
               console.log("error: " + JSON.stringify(error));
             }
           });
    console.log("Leaving OnSubmitJWKSEndpointForm()");
    return false;
  } else {
    console.log('Not a valid URL.');
    console.log("Leaving OnSubmitJWKSEndpointForm()");
    return false;
  }
}

function isUrl(url) {
  console.log('Entering isUrl().');
  try {
    return Boolean(new URL(url));
  } catch(e) {
    console.log('An error occurred: ' + e.stack);
    return false;
  }
}

function parseJWKSInfo(discoveryInfo) {
  console.log("Entering parseJWKSInfo().");
}

function buildJWKSInfoTable(discoveryInfo) {
  console.log("Entering buildJWKSInfoTable().");
  var discovery_info_table_html = "";
   var i = 0;
   for( i = 0; i < discoveryInfo.keys.length; i++) {
     console.log('iteration: ' + i);
     discovery_info_table_html = discovery_info_table_html +
                                 "<fieldset><legend>Signer Certificate #" + i + "</legend>";
     discovery_info_table_html = discovery_info_table_html +
                                    "<fieldset><legend>JWKS Format</legend>" +
                                    "<table border='2' style='border:2px;'>" +
                                    "<tr>" +
                                      "<th>Attribute</th>" +
                                      '<th style="max-width: 50px; word-wrap: break-word;">Value</th>' +
                                    "</tr>";
     Object.keys(discoveryInfo.keys[i]).forEach( (key) => {
       if ( key == 'n') {
         discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + key + "</td>" +
                                   '<td><textarea id="jwks-' + i + '" name="jwks-' + i + '" rows="10" cols="70" readonly="true">' + discoveryInfo.keys[i][key] + "</textarea></td>" +
                                 "</tr>";
       } else {
        discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + key + "</td>" +
                                   "<td>" + discoveryInfo.keys[i][key] + "</td>" +
                                 "</tr>";
       }
     });

     discovery_info_table_html = discovery_info_table_html +
                                "</table></fieldset>";

     var pem = jwkToPem(discoveryInfo.keys[i]);
     console.log('cert: ' + pem);
     discovery_info_table_html = discovery_info_table_html +
                                 "<fieldset><legend>PEM Format</legend>" +
                                 '<textarea id="x509-' + i + '" name="x509-' + i + '" rows="10" cols="70" readonly="true">' + pem + '</textarea>' +
                                 "</fieldset>";

//     console.log('decoded: ' + pemfile.decode(pem).toString());    
//     const cert = Certificate.fromPEM(pem);
    discovery_info_table_html = discovery_info_table_html +
                                "</fieldset>";

     
  }
  console.log('certData: ' + discovery_info_table_html);
  $("#jwks_info_table").html(discovery_info_table_html);
}

function onSubmitPopulateFormsWithDiscoveryInformation() {
  console.log('Entering OnSubmitPopulateFormsWithDiscoveryInformation().');
  var authorizationEndpoint = discoveryInfo["authorization_endpoint"];
  var idTokenSigningAlgValuesSupported = discoveryInfo["id_token_signing_alg_values_supported"];
  var issuer = discoveryInfo["issuer"];
  var jwksUri = discoveryInfo["jwks_uri"];
  var responseTypesSupported = discoveryInfo["response_types_supported"];
  var scopesSupported = discoveryInfo["scopes_supported"].toString().replace(/,/g, " ");
  var subjectTypesSupported = discoveryInfo["subject_types_supported"];
  var tokenEndpoint = discoveryInfo["token_endpoint"];
  var tokenEndpointAuthMethodsSupported = discoveryInfo["token_endpoint_auth_methods_supported"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];

  document.getElementById("authorization_endpoint").value = authorizationEndpoint;
  document.getElementById("token_endpoint").value = tokenEndpoint;
  document.getElementById("token_scope").value = scopesSupported;
  document.getElementById("scope").value = scopesSupported;
  document.getElementById("oidc_userinfo_endpoint").value = userInfoEndpoint;
  document.getElementById("jwks_endpoint").value = jwksUri;
  if (localStorage) {
      console.log('Adding to local storage.');
      localStorage.setItem("authorization_endpoint", authorizationEndpoint );
      localStorage.setItem("token_endpoint", tokenEndpoint );
      localStorage.setItem("scope", scopesSupported);
      localStorage.setItem("token_scope", scopesSupported );
      localStorage.setItem("jwks_endpoint", jwksUri);
  }
  console.log('Leaving OnSubmitPopulateFormsWithDiscoveryInformation().');
  return true;
}
// document.getElementById("step0").style.display = "none";

// Reset all forms and clear local storage
function onSubmitClearAllForms() {
  if (localStorage) {
  }
  $("#jwks_info_table").html("");
}

module.exports = {
 loadValuesFromLocalStorage,
 OnSubmitJWKSEndpointForm,
 onSubmitClearAllForms,
 OnSubmitJWKSEndpointForm,
 isUrl,
 parseJWKSInfo,
 buildJWKSInfoTable,
 onSubmitPopulateFormsWithDiscoveryInformation,
};
