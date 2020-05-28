
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

function onSubmitClearAllForms() {

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
  var discovery_info_table_html = "<table border='2' style='border:2px;'>" +
                                    "<tr>" +
                                      "<td><strong>Attribute</strong></td>" +
                                      "<td><strong>Value</strong></td>" +
                                    "</tr>";
   var i = 0;
   for( i = 0; i < discoveryInfo.keys.length; i++) {
     console.log('iteration: ' + i);
     discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + "Signer Certificate" + i + "</td><td></td>" +
                                 "</tr>";
     Object.keys(discoveryInfo.keys[i]).forEach( (key) => {
       discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + key + "</td>" +
                                   "<td>" + discoveryInfo.keys[i][key] + "</td>" +
                                 "</tr>";
     });
  }

   discovery_info_table_html = discovery_info_table_html +
                              "</table>";

//   var discovery_info_meta_data_html = '<table>' +
//                                       '<form>' +
//                                         '<td>' +
//                                          '<input class="btn_oidc_populate_meta_data" type="button" value="Populate Meta Data" onclick="return onSubmitPopulateFormsWithDiscoveryInformation();"/>' +
//                                        '</td>' +
//                                       '</form>' +
//                                       '</table>';
//  $("#discovery_info_meta_data_populate").html(discovery_info_meta_data_html);
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
      localStorage.setItem("authorization_endpoint", "");
      localStorage.setItem("token_endpoint", "");
      localStorage.setItem("client_id", "");
      localStorage.setItem("scope", "");
      localStorage.setItem("resource", "");
      localStorage.setItem("redirect_uri", "");
      localStorage.setItem("token_client_id", "");
      localStorage.setItem("token_client_secret", "");
      localStorage.setItem("token_redirect_uri", "");
      localStorage.setItem("token_username", "");
      localStorage.setItem("token_scope", "");
      localStorage.setItem("authorization_grant_type", "");
      localStorage.setItem("token_resource", "");
      localStorage.setItem("yesCheckToken", true);
      localStorage.setItem("noCheckToken", false);
      localStorage.setItem("yesCheckOIDCArtifacts", true);
      localStorage.setItem("noCheckOIDCArtifacts", false);
      localStorage.setItem("refresh_client_id", "");
      localStorage.setItem("refresh_client_secret", "");
      localStorage.setItem("refresh_scope", "");
      localStorage.setItem("useRefreshToken_yes", true);
      localStorage.setItem("useRefreshToken_no", false);
      localStorage.setItem("oidc_userinfo_endpoint", "");
//      localStorage.setItem("oidc_discovery_endpoint", "");
      localStorage.setItem("jwks_endpoint", "");
  }
  document.getElementById("authorization_endpoint").value = "";
  document.getElementById("token_endpoint").value = "";
  document.getElementById("token_client_id").value = "";
  document.getElementById("token_client_secret").value = "";
  document.getElementById("token_redirect_uri").value = "";
  document.getElementById("token_username").value = "";
  document.getElementById("token_scope").value = "";
  document.getElementById("authorization_grant_type").value = "";
  document.getElementById("token_resource").value = "";
  document.getElementById("yesCheckToken").checked = true;
  document.getElementById("noCheckToken").checked = false;
  document.getElementById("yesCheckOIDCArtifacts").checked = true;
  document.getElementById("noCheckOIDCArtifacts").checked = false;
  document.getElementById("refresh_client_id").value = "";
  document.getElementById("refresh_client_secret").value = "";
  document.getElementById("refresh_scope").value = "";
  document.getElementById("useRefreshToken-yes").checked = true;
  document.getElementById("useRefreshToken-no").checked = false;
//  document.getElementById("oidc_discovery_endpoint").value = "";
  document.getElementById("client_id").value = "";
  document.getElementById("scope").value = "";
  document.getElementById("resource").value = "";
  document.getElementById("redirect_uri").value = "";
  document.getElementById("oidc_userinfo_endpoint").value = "";
  document.getElementById("jwks_endpoint").value = "";

  $("#discovery_info_table").html("");
}

function regenerateState() {
  document.getElementById("state").value = generateUUID();
}

function regenerateNonce() {
  document.getElementById("nonce_field").value = generateUUID();
}
