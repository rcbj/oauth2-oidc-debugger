// File: debugger.js
// Author: Robert C. Broeckelmann Jr.
// Date: 06/15/2017
// Notes:
//
// This file provides the interactive functionality needed for the first debugger screen which
// has the authorization endpoint, general configuration, and OIDC Discovery Endpoint pantes.
//
// This file is run through browserify and the output copied into the public/js directory.
//
var displayOpenIDConnectArtifacts = false;
var useRefreshTokenTester = false;
var displayStep0 = true;
var displayStep1 = true;
var displayStep2 = true;
var displayStep3 = true;
var displayStep4 = true;
var displayStep5 = true;
var discoveryInfo = {};

function OnSubmitForm()
{
  console.log("Entering OnSubmitForm().");
//  document.auth_step.action = document.getElementById("authorization_endpoint").value;
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  console.log("Leaving OnSubmitForm().");
  return true;
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
  var sel = $("#authorization_grant_type");
  sel.change(function() {
    console.log("Entering selection changed function().");
    var value = $(this).val();
    resetUI(value);
    recalculateAuthorizationRequestDescription();
    recalculateTokenRequestDescription();
    recalculateRefreshRequestDescription();
    console.log("Leaving selection changed function().");
  });
  var value = $("#authorization_grant_type").value;
  resetUI(value);
  recalculateAuthorizationRequestDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();

  $(".btn1").click(function() {
      console.log("Entering token Submit button clicked function.");
      // validate and process form here
      var token_endpoint = document.getElementById("token_endpoint").value;
      var client_id = document.getElementById("token_client_id").value;
      var client_secret = document.getElementById("token_client_secret").value;
      var code = document.getElementById("code").value;
      var grant_type = document.getElementById("token_grant_type").value;
      var redirect_uri = document.getElementById("token_redirect_uri").value;
      var username = document.getElementById("token_username").value;
      var password = document.getElementById("token_password").value;
      var scope = document.getElementById("token_scope").value;
      var sslValidate = "";
      if( document.getElementById("SSLValidate-yes").checked)
      {
        sslValidate = document.getElementById("SSLValidate-yes").value;
      } else if (document.getElementById("SSLValidate-no").checked) {
	sslValidate = document.getElementById("SSLValidate-no").value;
      } else {
        sslValidate = "true";
      }
      var formData = {};
      if(grant_type == "authorization_code")
      {
        formData = {
          grant_type: grant_type,
          client_id: client_id,
          code: code,
          redirect_uri: redirect_uri,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate
        };
      } else if( grant_type == "password") {
        formData = {
          grant_type: grant_type,
          client_id: client_id,
          username: username,
          password: password,
          code: code,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate
        };
      } else if( grant_type == "client_credentials") {
        formData = {
          grant_type: grant_type,
          client_id: client_id,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate
        };
      }
      var yesCheck = document.getElementById("yesCheckToken").checked;
      if(yesCheck) //add resource value to OAuth query string
      {
        var resource = document.getElementById("token_resource").value;
        if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
        {
          formData.resource = resource
        }
      }
      if(client_secret != "")
      {
        formData.client_secret = client_secret
      }
      writeValuesToLocalStorage();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      resetErrorDisplays();
  $.ajax({
    type: "POST",
    url: "/token",
    data: formData,
    success: function(data, textStatus, request) {
      var token_endpoint_result_html = "";
      console.log("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      if(displayOpenIDConnectArtifacts == true)
      {
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" + 
				      "<table>" +
				        "<tr>" +
                                          "<td>access_token</td>" + 
                                          "<td><textarea rows=10 cols=100>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>refresh_token</td>" +
                                          "<td><textarea rows=10 cols=100>" + 
                                            data.refresh_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>id_token</td>" +
                                          "<td><textarea rows=10 cols=100>" + 
                                             data.id_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
      } else {
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" +
                                      "<table>" +
                                        "<tr>" +
                                          "<td>access_token</td>" +
                                          "<td><textarea rows=10 cols=100>" +
                                            data.access_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>refresh_token</td>" +
                                          "<td><textarea rows=10 cols=100>" +
                                            data.refresh_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
      }
      $("#token_endpoint_result").html(token_endpoint_result_html);
      document.getElementById("refresh_refresh_token").value = data.refresh_token;
    },
    error: function (request, status, error) {
      console.log("request: " + JSON.stringify(request));
      console.log("status: " + JSON.stringify(status));
      console.log("error: " + JSON.stringify(error));
      recalculateTokenErrorDescription(request);
    }
  });
  return false;
    });

$(".refresh_btn").click(function() {
      console.log("Entering refresh Submit button clicked function.");
      // validate and process form here
      var token_endpoint = document.getElementById("token_endpoint").value;
      var client_id = document.getElementById("refresh_client_id").value;
      var client_secret = document.getElementById("refresh_client_secret").value;
      var refresh_token = document.getElementById("refresh_refresh_token").value;
      var grant_type = document.getElementById("refresh_grant_type").value;
      var scope = document.getElementById("refresh_scope").value;
      var sslValidate = "";
      if( document.getElementById("SSLValidate-yes").checked)
      {
        sslValidate = document.getElementById("SSLValidate-yes").value;
      } else if (document.getElementById("SSLValidate-no").checked) {
	sslValidate = document.getElementById("SSLValidate-no").value;
      } else {
        sslValidate = "true";
      }
      var formData = {
        grant_type: grant_type,
        client_id: client_id,
        refresh_token: refresh_token,
        scope: scope,
        token_endpoint: token_endpoint,
        sslValidate: sslValidate
      };
      if(client_secret != "")
      {
        formData.client_secret = client_secret
      }
      writeValuesToLocalStorage();
      recalculateRefreshRequestDescription();
      resetErrorDisplays();
  $.ajax({
    type: "POST",
    url: "/token",
    data: formData,
    success: function(data, textStatus, request) {
      var refresh_endpoint_result_html = "";
      console.log("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      var iteration = 1;
      if( document.getElementById("refresh-token-results-iteration-count") != null)
      {
        iteration = parseInt(document.getElementById("refresh-token-results-iteration-count").value) + 1;
      }
      if(displayOpenIDConnectArtifacts == true)
      {
         refresh_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results for Refresh Token Call:</legend>" + 
				      "<table>" +
				        "<tr>" +
                                          "<td>access_token</td>" + 
                                          "<td><textarea rows=10 cols=100>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>refresh_token</td>" +
                                          "<td><textarea rows=10 cols=100>" + 
                                            data.refresh_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>id_token</td>" +
                                          "<td><textarea rows=10 cols=100>" + 
                                             data.id_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
					  "<td>iteration</td>" +
					  "<td><input type=\"text\" value=\"" + iteration + "\" id=\"refresh-token-results-iteration-count\" name=\"refresh-token-results-iteration-count\"></td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
      } else {
         refresh_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results for Refresh Token Call:</legend>" +
                                      "<table>" +
                                        "<tr>" +
                                          "<td>access_token</td>" +
                                          "<td><textarea rows=10 cols=100>" +
                                            data.access_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>refresh_token</td>" +
                                          "<td><textarea rows=10 cols=100>" +
                                            data.refresh_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          "<td>iteration</td>" +
                                          "<td><input type=\"text\" value=\"" + iteration + "\" id=\"refresh-token-results-iteration-count\" name=\"refresh-token-results-iteration-count\"></td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
      }
      $("#refresh_endpoint_result").html(refresh_endpoint_result_html);
      document.getElementById("refresh_refresh_token").value = data.refresh_token;
      recalculateRefreshRequestDescription();
    },
    error: function (request, status, error) {
      console.log("request: " + JSON.stringify(request));
      console.log("status: " + JSON.stringify(status));
      console.log("error: " + JSON.stringify(error));
      recalculateRefreshErrorDescription(request);
    }
  });
  return false;
    });
    console.log("Leaving token submit button clicked function.");

});

function resetUI(value)
{
    console.log("Entering resetUI().");
    if( value == "implicit_grant" )
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse'; 
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      $("#nonce").show();
      document.getElementById("response_type").value = "token";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      document.getElementById("token_grant_type").value = "";
      document.getElementById("h2_title_1").innerHTML = "Request Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").hide();
    }
    if( value == "client_credential")
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").hide();
      $("#step3").show();
      $("#nonce").hide();
      document.getElementById("response_type").value = "";
      document.getElementById("token_grant_type").value = "client_credentials";
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
//      document.getElementById("h2_title_2").innerHTML = "Obtain Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
    }
    if( value == "resource_owner")
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = '';
      document.getElementById("authzPasswordRow").style.visibility = '';
      $("#step2").hide();
      $("#step3").show();
      $("#nonce").hide();
      document.getElementById("response_type").value = "";
      document.getElementById("token_grant_type").value = "password";
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
//      document.getElementById("h2_title_2").innerHTML = "Obtain Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
    }
    if( value == "authorization_grant")
    {
      $("#code").show();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      $("#nonce").hide();
      document.getElementById("response_type").value = "code";
//      document.getElementById("token_grant_type").value = "authorization_code";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
//      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
    }
    if ( value == "oidc_implicit_flow")
    {
      $("#code").hide();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      $("#nonce").show();
      document.getElementById("response_type").value = "id_token token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
//      document.getElementById("token_grant_type").value = "";
      document.getElementById("h2_title_1").innerHTML = "Request Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").hide();
      displayOpenIDConnectArtifacts = true;
    }
    if ( value == "oidc_implicit_flow_id_token")
    {
      $("#code").hide();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      $("#nonce").show();
      document.getElementById("response_type").value = "id_token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
//      document.getElementById("token_grant_type").value = "";
      document.getElementById("h2_title_1").innerHTML = "Request Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").hide();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_authorization_code_flow")
    {
      $("#code").show();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code";
//      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
//      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token")
    {
      $("#code").show();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code id_token";
//      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
//      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      document.getElementById("code").value = "";
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_token")
    {
      $("#code").show();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code token";
//      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
//      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token_token")
    {
      $("#code").show();
//      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
//      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code id_token token";
//      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
//      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
    }
    resetErrorDisplays();
    console.log("Leaving resetUI().");
}

function resetErrorDisplays()
{
  console.log("Entering resetErrorDisplays().");
  $("#display_authz_error_class").html("");
  $("#display_token_error_class").html("");
  $("#display_refresh_error_class").html("");
  console.log("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  console.log("Entering writeValuesToLocalStorage().");
  if (localStorage) {
      localStorage.setItem("authorization_grant_type", document.getElementById("authorization_grant_type").value);
      localStorage.setItem("yesCheckOIDCArtifacts", document.getElementById("yesCheckOIDCArtifacts").checked);
      localStorage.setItem("noCheckOIDCArtifacts", document.getElementById("noCheckOIDCArtifacts").checked);
      localStorage.setItem("useRefreshToken_yes", document.getElementById("useRefreshToken-yes").checked);
      localStorage.setItem("client_id", document.getElementById("client_id").value);
      localStorage.setItem("redirect_uri", document.getElementById("redirect_uri").value);
      localStorage.setItem("scope", document.getElementById("scope").value);
      localStorage.setItem("useRefreshToken_no", document.getElementById("useRefreshToken-no").checked);
      localStorage.setItem("oidc_discovery_endpoint", document.getElementById("oidc_discovery_endpoint").value);
      localStorage.setItem("oidc_userinfo_endpoint", document.getElementById("oidc_userinfo_endpoint").value);
      localStorage.setItem("jwks_endpoint", document.getElementById("jwks_endpoint").value);
      localStorage.setItem("authzcustomParametersCheck-yes", document.getElementById("authzcustomParametersCheck-yes").checked);
      localStorage.setItem("authzcustomParametersCheck-no", document.getElementById("authzcustomParametersCheck-no").checked);
      localStorage.setItem("authzNumberCustomParameters", document.getElementById("authzNumberCustomParameters").value);
      if (document.getElementById("authzcustomParametersCheck-yes").checked) {
        var i = 0;
        var authzNumberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);
        for(i = 0; i < authzNumberCustomParameters; i++)
        {
          console.log("Writing customParameterName-" + i + " as " + document.getElementById("customParameterName-" + i).value + "\n");
          localStorage.setItem("customParameterName-" + i, document.getElementById("customParameterName-" + i).value);
          console.log("Writing customParameterValue-" + i + " as " + document.getElementById("customParameterValue-" + i).value + "\n");
          localStorage.setItem("customParameterValue-" + i, document.getElementById("customParameterValue-" + i).value);
        }
      }
  }
  console.log("Leaving writeValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  console.log("Entering loadValuesFromLocalStorage().");
  var authzGrantType = localStorage.getItem("authorization_grant_type");
  console.log("authzGrantType=" + authzGrantType);
  if (authzGrantType == "" || typeof(authzGrantType) == "undefined" || authzGrantType == "null")
  {
    document.getElementById("authorization_grant_type").value = "authorization_grant"
    resetUI("authorization_grant");
  } else {
    document.getElementById("authorization_grant_type").value = authzGrantType;
    resetUI(authzGrantType);
  }
  document.getElementById("authorization_endpoint").value = localStorage.getItem("authorization_endpoint");
  document.getElementById("token_endpoint").value = localStorage.getItem("token_endpoint");
  document.getElementById("redirect_uri").value = localStorage.getItem("redirect_uri");
  document.getElementById("client_id").value = localStorage.getItem("client_id");
  document.getElementById("scope").value = localStorage.getItem("scope");
  document.getElementById("resource").value = localStorage.getItem("resource");
  document.getElementById("yesCheck").checked = localStorage.getItem("yesCheck")? localStorage.getItem("yesCheck") : false;
  document.getElementById("noCheck").checked = localStorage.getItem("noCheck")? localStorage.getItem("noCheck") : true;
  document.getElementById("yesCheckOIDCArtifacts").checked = localStorage.getItem("yesCheckOIDCArtifacts");
  document.getElementById("noCheckOIDCArtifacts").checked = localStorage.getItem("noCheckOIDCArtifacts");
  document.getElementById("useRefreshToken-yes").checked = localStorage.getItem("useRefreshToken_yes");
  document.getElementById("useRefreshToken-no").checked = localStorage.getItem("useRefreshToken_no");
  document.getElementById("oidc_discovery_endpoint").value = localStorage.getItem("oidc_discovery_endpoint");
  document.getElementById("oidc_userinfo_endpoint").value = localStorage.getItem("oidc_userinfo_endpoint");
  document.getElementById("jwks_endpoint").value = localStorage.getItem("jwks_endpoint");
  document.getElementById("authzcustomParametersCheck-yes").checked = localStorage.getItem("authzcustomParametersCheck-yes")? localStorage.getItem("authzcustomParametersCheck-yes") : false;
  document.getElementById("authzcustomParametersCheck-no").checked = localStorage.getItem("authzcustomParametersCheck-no")? localStorage.getItem("authzcustomParametersCheck-no") : true;
  document.getElementById("authzNumberCustomParameters").value = localStorage.getItem("authzNumberCustomParameters")? localStorage.getItem("authzNumberCustomParameters") : 1;

  if (document.getElementById("authzcustomParametersCheck-yes").checked) {
    generateCustomParametersListUI();
    var i = 0;
    var authzNumberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);  
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      console.log("Reading customParameterName-" + i + " as " + localStorage.getItem("customParameterName-" + i + "\n"));
      document.getElementById("customParameterName-" + i).value = localStorage.getItem("customParameterName-" + i);
      console.log("Reading customParameterValue-" + i + " as " + localStorage.getItem("customParameterValue-" + i + "\n"));
      document.getElementById("customParameterValue-" + i).value = localStorage.getItem("customParameterValue-" + i);
    }
  }

  var agt = document.getElementById("authorization_grant_type").value;

  var pathname = window.location.pathname;
  console.log("agt=" + agt);
  console.log("pathname=" + pathname);
  if (  (agt ==  "authorization_grant" || 
         agt == "oidc_hybrid_code_id_token" || 
         agt == "oidc_hybrid_code_token" || 
         agt == "oidc_hybrid_code_id_token_token" ) &&
	pathname == "/callback")
  {
    console.log("Checking for code.  agt=" + agt + ", pathname=" + pathname);
    console.log("fragement: " + parseFragment());
    code = parseFragment()["code"];
    if(code == null || code == "null" || code == "" || typeof code == "undefined")
    {
      code = "NO_CODE_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    console.log("code=" + code);
    if(document.getElementById("code").value == "")
    {
      console.log("code not yet set in next form. Doing so now.");
      document.getElementById("code").value = code;
    }
  }
  if ( 	(agt == "implicit_grant" || 
         agt == "oidc_implicit_flow" ) &&
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
  {
    var access_token = getParameterByName("access_token",window.location.href);
    console.log("access_token=" + access_token);
    if(access_token == null || 
       access_token == "null" || 
       access_token == "" || 
       typeof access_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      console.log("fragement: " + parseFragment());
      access_token = parseFragment()["access_token"];
      if(access_token == null || access_token == "null" || access_token == "" || typeof access_token == "undefined")
      {
        access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    console.log("access_token=" + access_token);
    var authorization_endpoint_result_html = "<fieldset>" +
                                             "<legend>Authorization Endpoint Results:</legend>" +
                                             "<table>" + 
                                               "<tr>" +
                                                 "<td>access_token</td>" +
                                                 "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" 
                                                   + access_token + 
                                                   "</textarea>" +
                                                 "</td>" +
                                               "</tr>" + 
                                             "</table>" +
                                             "</fieldset>";
    $("#authorization_endpoint_result").html(authorization_endpoint_result_html);
  }
  if (  agt == "oidc_hybrid_code_id_token_token" &&
        pathname == "/callback") //retrieve access code and id_token that is returned from authorization endpoint.
  {
    console.log("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" || 
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    console.log("access_token=" + access_token);
    console.log("fragement: " + parseFragment());
    id_token = parseFragment()["id_token"];
    if(	id_token == null ||
	id_token == "null" ||
	id_token == "" ||
	typeof id_token == "undefined")
    {
      id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    var authz_endpoint_results_html = "";
    if(displayOpenIDConnectArtifacts == true)
    {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint Results:</legend>" +
				    "<table>" +
				      "<tr>" +
				        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td>"
				      "</tr>" + 
				      "<tr>" +
				        "<td>id_token</td>" + 
				        "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + id_token + "</textarea></td>" +
				      "</tr>" +
				    "</table>" +
                                    "</fieldset>";
    } else {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint Results:</legend>" +
                                    "<table>" +
                                      "<tr>" +
                                        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td>"
                                      "</tr>" +
                                    "</table>" +
                                    "</fieldset>";
    }
    $("#authorization_endpoint_result").html(authz_endpoint_results_html);
  }

  if (  agt == "oidc_hybrid_code_token" &&
        pathname == "/callback") //retrieve access code that is returned from authorization endpoint.
  {
    console.log("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" ||
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    console.log("access_token=" + access_token);
    $("#authorization_endpoint_result").html("<fieldset><legend>Authorization Endpoint Results:</legend><table><tr><td>access_token</td><td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td></tr></table></fieldset>");
  }
  if ( 	(agt == "oidc_implicit_flow" || agt == "oidc_implicit_flow_id_token" ||  agt == "oidc_hybrid_code_id_token") && 
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
  {
    var id_token = getParameterByName("id_token",window.location.href);
    console.log("id_token=" + access_token);
    if(id_token == null || id_token == "null" || id_token == "" || typeof id_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      console.log("fragement: " + parseFragment());
      id_token = parseFragment()["id_token"];
      if(id_token == null || id_token == "null" || id_token == "" || typeof id_token == "undefined")
      {
        id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    console.log("id_token=" + id_token);
    $("#authorization_endpoint_id_token_result").html("<fieldset><legend>Authorization Endpoint Results</legend><table><tr><td>id_token</td><td><textarea id=\"implicit_flow_id_token\" rows=5 cols=100>" + id_token + "</textarea></td></tr></table></fieldset>");
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = document.getElementById("authorization_grant_type").value;
  if(	pathname == "/callback" && 
	(authzGrantType == "authorization_grant" || authzGrantType == "implicit_grant" || authzGrantType == "oidc_hybrid_code_id_token") &&
	(error != null && error != "null" && typeof error != "undefined" && error != ""))
  {
    $("#display_authz_error_class").html("<fieldset><legend>Authorization Endpoint Error</legend><form action=\"\" name=\"display_authz_error_form\" id=\"display_authz_error_form\"><table><tr><td><label name=\"display_authz_error_form_label1\" value=\"\" id=\"display_authz_error_form_label1\">Error</label></td><td><textarea rows=\"10\" cols=\"100\" id=\"display_authz_error_form_textarea1\"></td></tr></table></textarea></form></fieldset>");
  }
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
  document.getElementById("nonce_field").value = generateUUID();
  localStorage.setItem('nonce_field', document.getElementById("nonce_field").value);
  recalculateAuthorizationRequestDescription();
  console.log("Leaving loadValuesFromLocalStorage().");
}

function recalculateAuthorizationRequestDescription()
{
  console.log("Entering recalculateAuthorizationRequestDescription().");
  console.log("update request field");
  var ta1 = document.getElementById("display_authz_request_form_textarea1");
  console.log("ta1=" + ta1);
  var yesCheck = document.getElementById("yesCheck").checked;
  console.log("yesCheck=" + yesCheck);
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = document.getElementById("resource").value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  console.log("resourceComponent=" + resourceComponent);
  var customParametersComponent = "";
  var authzcustomParametersCheck = document.getElementById("authzcustomParametersCheck-yes").checked;
  console.log("authzcustomParametersCheck: " + authzcustomParametersCheck + ", type=" + typeof(authzcustomParametersCheck));
  if(authzcustomParametersCheck) {
    const numberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);
    console.log('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++) 
    {
       customParametersComponent = customParametersComponent +
                                   document.getElementById("customParameterName-" + i).value +
                                   '=' + document.getElementById("customParameterValue-" + i).value + "&" + "\n";
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    console.log('customParametersComponent=' + customParametersComponent);
  }
  if (ta1 != null)
  {
    var grant_type = document.getElementById("response_type").value;
    console.log("grant_type=" + grant_type);
    if( grant_type == "code" ||
	grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      document.getElementById("display_authz_request_form_textarea1").value = "GET " + document.getElementById("authorization_endpoint").value + "?" + "\n" +
                                                                      "state=" + document.getElementById("state").value + "&" + "\n" +
  								      "response_type=" + document.getElementById("response_type").value + "&" + "\n" +
  								      "client_id=" + document.getElementById("client_id").value + "&" + "\n" +
                						      "redirect_uri=" + document.getElementById("redirect_uri").value + "&" +"\n" +
								      "scope=" + document.getElementById("scope").value;
       if ( resourceComponent.length > 0) {
         document.getElementById("display_authz_request_form_textarea1").value += "&\n" + resourceComponent + "\n";
       }
       if (customParametersComponent.length > 0) {
         document.getElementById("display_authz_request_form_textarea1").value += "&\n" +  customParametersComponent + "\n";
       }
    } else if (	grant_type == "token" || 
		grant_type == "id_token token" || 
		grant_type == "id_token") {
      document.getElementById("display_authz_request_form_textarea1").value = "GET " + document.getElementById("authorization_endpoint").value + "?" + "\n" +
                                                                      "state=" + document.getElementById("state").value + "&" + "\n" +
                                                                      "nonce=" + document.getElementById("nonce_field").value + "&" + "\n" +
                                                                      "response_type=" + document.getElementById("response_type").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("client_id").value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById("redirect_uri").value + "&" +"\n" +
                                                                      "scope=" + document.getElementById("scope").value;
      if ( resourceComponent.length > 0) {
        document.getElementById("display_authz_request_form_textarea1").value += "&" + resourceComponent + "\n";
      }
      if (customParametersComponent.length > 0) {
        document.getElementById("display_authz_request_form_textarea1").value += "&" +  customParametersComponent + "\n";
      }
    } else {
      document.getElementById("display_authz_request_form_textarea1").value = "UNKNOWN_GRANT_TYPE";
    }
  }
  console.log('display_authz_request_form_textarea1=' + document.getElementById("display_authz_request_form_textarea1").value);
  console.log("Leaving recalculateAuthorizationRequestDescription().");
}

function triggerAuthZEndpointCall()
{
  console.log("Entering triggerAuthZEndpointCall().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  window.location.href = document.getElementById("display_authz_request_form_textarea1").value.substring(4, document.getElementById("display_authz_request_form_textarea1").value.length).replace("\n","");
  console.log("Leaving triggerAuthZEndpointCall().");
}

function recalculateTokenRequestDescription()
{
  console.log("Entering recalculateTokenRequestDescription().");
  console.log("update request field");
  var ta1 = document.getElementById("display_token_request_form_textarea1");
//  var yesCheck = document.getElementById("yesCheckToken").checked;
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
//    var resource = document.getElementById("token_resource").value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }

  if (ta1 != null)
  {
    var grant_type = document.getElementById("token_grant_type").value;
    if( grant_type == "authorization_code")
    {
      document.getElementById("display_token_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
								      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("token_grant_type").value + "&" + "\n" +
                                                                      "code=" + document.getElementById("code").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("token_client_id").value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById("token_redirect_uri").value + "&" +"\n" +
                                                                      "scope=" + document.getElementById("token_scope").value + "\n" + 
                                                           	      resourceComponent + "\n";
    } else if (grant_type == "client_credentials") {
      document.getElementById("display_token_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                     "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("token_grant_type").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("token_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("token_client_secret").value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById("token_redirect_uri").value + "&" +"\n" +
                                                                      "scope=" + document.getElementById("token_scope").value + "\n" +
                                                                      resourceComponent + "\n";
    } else if (grant_type == "password") {
      document.getElementById("display_token_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("token_grant_type").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("token_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("token_client_secret").value + "&" + "\n" +
                                                                      "username=" + document.getElementById("token_username").value + "&" + "\n" +
                                                                      "password=" + document.getElementById("token_password").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("token_scope").value + "\n" +
                                                                      resourceComponent +"\n";
    }
  }
  console.log("Leaving recalculateTokenRequestDescription().");
}

function recalculateRefreshRequestDescription()
{
  console.log("Entering recalculateRefreshRequestDescription().");
  console.log("update request field");
  var ta1 = document.getElementById("display_refresh_request_form_textarea1");
//  var yesCheck = document.getElementById("yesCheckToken").checked;
  var resourceComponent = "";
//  if(yesCheck) //add resource value to OAuth query string
//  {
//    var resource = document.getElementById("token_resource").value;
//    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
//    {
//      resourceComponent =  "&resource=" + resource;
//    }
//  }

  if (ta1 != null)
  {
    var grant_type = document.getElementById("refresh_grant_type").value;
    if( grant_type == "refresh_token")
    {
      var client_secret = document.getElementById("refresh_client_secret").value;
      if( client_secret != "" &&
          client_secret != null &&
          client_secret != "null")
      {
        document.getElementById("display_refresh_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("refresh_grant_type").value + "&" + "\n" +
                                                                      "refresh_token=" + document.getElementById("refresh_refresh_token").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("refresh_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("refresh_client_secret").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("refresh_scope").value + "\n";
      } else {
        document.getElementById("display_refresh_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("refresh_grant_type").value + "&" + "\n" +
                                                                      "refresh_token=" + document.getElementById("refresh_refresh_token").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("refresh_client_id").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("refresh_scope").value + "\n";
      }
    }
  }
  console.log("Leaving recalculateRefreshRequestDescription().");
}

window.onload = function() {
  console.log("Entering onload function.");
  $("#password-form-group1").hide();
  $("#password-form-group2").hide();

  document.getElementById("authorization_endpoint").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("state").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("nonce_field").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("response_type").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("client_id").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("redirect_uri").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("scope").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("resource").addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById("yesCheck").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("noCheck").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("yesCheckOIDCArtifacts").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("noCheckOIDCArtifacts").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("authzcustomParametersCheck-yes").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("authzcustomParametersCheck-no").addEventListener("onClick", recalculateAuthorizationRequestDescription());

  // Set initial values in case this is the first time the page was hit
  onSubmitClearAllForms(); 

  if (localStorage) {
    // Add an event listener for form submissions
    document.getElementById("auth_step").addEventListener("submit", function() {
      console.log("Entering auth_step submit event listner function.");
      localStorage.setItem("client_id", document.getElementById("client_id").value);
      localStorage.setItem("scope", document.getElementById("scope").value);
      localStorage.setItem("authorization_endpoint", document.getElementById("authorization_endpoint").value);
      localStorage.setItem("token_endpoint", document.getElementById("token_endpoint").value);
      localStorage.setItem("redirect_uri", document.getElementById("redirect_uri").value);
      localStorage.setItem("authorization_grant_type", document.getElementById("authorization_grant_type").value);
      localStorage.setItem("resource", document.getElementById("resource").value);
      localStorage.setItem("yesCheck", document.getElementById("yesCheck").checked);
      localStorage.setItem("noCheck", document.getElementById("noCheck").checked);
      localStorage.setItem("yesCheckOIDCArtifacts", document.getElementById("yesCheckOIDCArtifacts").checked);
      localStorage.setItem("noCheckOIDCArtifacts", document.getElementById("noCheckOIDCArtifacts").checked);
      localStorage.setItem("authzcustomParametersCheck-yes", document.getElementById("authzcustomParametersCheck-yes").checked);
      localStorage.setItem("authzcustomParametersCheck-no", document.getElementById("authzcustomParametersCheck-no").checked);

      console.log("Leaving auth_step submit event listener function.");
    });
  }
  loadValuesFromLocalStorage();
  generateCustomParametersListUI
  recalculateAuthorizationRequestDescription();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();
  var yesChecked = document.getElementById("yesCheck").checked;
  if(yesChecked)
  {
    document.getElementById("authzResourceRow").style.visibility = '';
  } else {
    document.getElementById("authzResourceRow").style.visibility = 'collapse';
  }
  if( document.getElementById("useRefreshToken-yes").checked)
  {
    useRefreshTokenTester = document.getElementById("useRefreshToken-yes").value;
  } else if (document.getElementById("useRefreshToken-no").checked) {
    useRefreshTokenTester = document.getElementById("useRefreshToken-no").value;
  } else {
    useRefreshTokenTester = true;
  }
  var authzcustomParametersCheck = document.getElementById("authzcustomParametersCheck-yes").checked;
  if(authzcustomParametersCheck)
  {
    document.getElementById("authzCustomParametersRow").style.visibility = '';
  } else {
    document.getElementById("authzCustomParametersRow").style.visibility = 'collapse';
  }
  displayAuthzCustomParametersCheck();
  console.log("Leaving onload().");
}

function generateUUID () { // Public Domain/MIT
    console.log("Entering generateUUID().");
    var d = new Date().getTime();
    if (typeof performance !== "undefined" && typeof performance.now === "function"){
        d += performance.now(); //use high-precision timer if available
    }
    console.log("Leaving generateUUID().");
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function displayResourceCheck()
{
  console.log("Entering displayResourceCheck().");
  var yesCheck = document.getElementById("yesCheck").checked;
  var noCheck = document.getElementById("noCheck").checked;
  console.log("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if(yesCheck) {
    document.getElementById("authzResourceRow").style.visibility = '';
  } else if(noCheck) {
    document.getElementById("authzResourceRow").style.visibility = "collapse"
  }
  recalculateAuthorizationRequestDescription();
  console.log("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  console.log("Entering displayTokenResourceCheck().");
  var yesCheck = document.getElementById("yesCheckToken").checked;
  var noCheck = document.getElementById("noCheckToken").checked;
  if( yesCheck) {
    document.getElementById("authzTokenResourceRow").style.visibility = '';
  } if(noCheck) {
    document.getElementById("authzTokenResourceRow").style.visibility = 'collapse';
  }
  recalculateTokenRequestDescription();
  console.log("Leaving displayTokenResourceCheck().");
}

$(function() {
$("#auth_step").submit(function () {
    console.log("Entering auth_step submit function.");
    var resource = document.getElementById("resource").value;
    var yesCheck = document.getElementById("yesCheck").checked;
    console.log("yesCheck=" + yesCheck);
    console.log("resource=" + resource);
    if(yesCheck == false)
    {
      document.getElementById("resource").disabled = "disabled"; 
      document.getElementById("yesCheck").disabled = "disabled";
      document.getElementById("noCheck").disabled = "disabled";
    } else {
      document.getElementById("resource").removeAttribute("disabled");
      document.getElementById("yesCheck").removeAttribute("disabled");
      document.getElementById("noCheck").removeAttribute("disabled");
    }
    $(this)
      .find("input[name]")
      .filter(function () {
          return !this.value;
      })
      .prop("name", "");
});
    console.log("Leaving auth_step submit function.");
});

function recalculateAuthorizationErrorDescription()
{
  console.log("Entering recalculateAuthorizationErrorDescription().");
  console.log("update error field");
  var ta1 = document.getElementById("display_authz_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = document.getElementById("response_type").value;
    if( grant_type == "code" ||
        grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      var pathname = window.location.pathname;
      console.log("pathname=" + pathname);
      if (pathname == "/callback")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state", window.location.href);
        document.getElementById("display_authz_error_form_textarea1").value = "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n";
      }
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //document.getElementById("display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      console.log("pathname=" + pathname);
      if (pathname == "/callback")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        document.getElementById("display_authz_error_form_textarea1").value = "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n";
      }
    }
  }
  console.log("Leaving recalculateAuthorizationErrorDescription().");
}

function recalculateTokenErrorDescription(data)
{
  console.log("Entering recalculateTokenErrorDescription().");
//  $("#display_token_error_class").show();
  var display_token_error_class_html = "<fieldset>" +
                                       "<legend>Token Endpoint Error</legend>" +
                                         "<form action=\"\" name=\"display_token_error_form\" id=\"display_token_error_form\">" +
                                           "<table>" +
                                             "<tr>" +
                                               "<td><label name=\"display_token_error_form_label1\" value=\"\" id=\"display_token_error_form_label1\">Error</label></td>" +
                                               "<td><textarea rows=\"10\" cols=\"100\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class").html(display_token_error_class_html);
  console.log("update error field");
  var ta1 = document.getElementById("display_token_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = document.getElementById("token_grant_type").value;
    if( grant_type == "authorization_code")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      document.getElementById("display_token_error_form_textarea1").value = "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n";
    } else if (grant_type == "client_credentials") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      document.getElementById("display_token_error_form_textarea1").value = "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n";
    } else if (grant_type == "password") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      document.getElementById("display_token_error_form_textarea1").value = "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n";
    }
  }
  console.log("Leaving recalculateTokenErrorDescription().");
}

function recalculateRefreshErrorDescription(data)
{
  console.log("Entering recalculateRefreshErrorDescription().");
//  $("#display_token_error_class").show();
  var display_refresh_error_class = "<fieldset>" +
                                    "<legend>Token Endpoint (For Refresh) Error</legend>" +
                                       "<form action=\"\" name=\"display_refresh_error_form\" id=\"display_refresh_error_form\">" +
                                         "<table>" +
                                           "<tr>" +
                                             "<td><label name=\"display_refresh_error_form_label1\" value=\"\" id=\"display_refresh_error_form_label1\">Error</label></td>" +
                                             "<td><textarea rows=\"10\" cols=\"100\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(display_refresh_error_class);
  console.log("update error field");
  var ta1 = document.getElementById("display_refresh_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = document.getElementById("refresh_grant_type").value;
    if( grant_type == "refresh_token")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      document.getElementById("display_refresh_error_form_textarea1").value = "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n";
    }
  }
  console.log("Leaving recalculateRefreshErrorDescription().");
}

function parseFragment()
{
  console.log("hash=" + window.location.hash);
  var hash = window.location.hash.substr(1);

  var result = hash.split("&").reduce(function (result, item) {
      var parts = item.split("=");
      result[parts[0]] = parts[1];
      return result;
  }, {});
  return result;
}

function displayOIDCArtifacts()
{
  console.log("Entering displayOIDCArtifacts().");
  var yesCheck = document.getElementById("yesCheckOIDCArtifacts").checked;
  var noCheck = document.getElementById("noCheckOIDCArtifacts").checked;
  console.log("yesCheckOIDCArtifacts=" + yesCheck, "noCheckOIDCArtifacts=" + noCheck);
  if(yesCheck) {
    displayOpenIDConnectArtifacts = true;
    
  } else if(noCheck) {
    displayOpenIDConnectArtifacts = false;
  }
  console.log("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  console.log("Leaving displayOIDCArtifacts().");
}

function useRefreshTokens()
{
  console.log("Entering useRefreshToken().");
  var yesCheck = document.getElementById("useRefreshToken-yes").checked;
  var noCheck = document.getElementById("useRefreshToken-no").checked;
  console.log("useRefreshToken-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if(yesCheck) {
    useRefreshTokenTester = true;
    $("#step4").show();
  } else if(noCheck) {
    useRefreshTokenTester = false;
    $("#step4").hide();
  }
  console.log("useRefreshTokenTester=" + useRefreshTokenTester);
  console.log("Leaving useRefreshTokens().");
}

$("#tipText").hover(
   function(e){
       $("#tooltip").show();
   },
   function(e){
       $("#tooltip").hide();
  });

function OnSubmitOIDCDiscoveryEndpointForm()
{
  console.log("Entering OnSubmitOIDCDiscoveryEndpointForm().");
  writeValuesToLocalStorage();
  var oidcDiscoveryEndpoint = document.getElementById("oidc_discovery_endpoint").value;
  console.log('URL: ' + oidcDiscoveryEndpoint);
  if (isUrl(oidcDiscoveryEndpoint)) {
    console.log('valid URL: ' + oidcDiscoveryEndpoint);
    $.ajax({ type: 'GET',
             crossOrigin: true,
             url: oidcDiscoveryEndpoint,
             success: function(result) {
               console.log("OIDC Discovery Endpoint Result: " + JSON.stringify(result));
               discoveryInfo = result;
               parseDiscoveryInfo(result);
               buildDiscoveryInfoTable(result);
             },
             error: function (request, status, error) {
               console.log("request: " + JSON.stringify(request));
               console.log("status: " + JSON.stringify(status));
               console.log("error: " + JSON.stringify(error));
             }
           });
    console.log("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
    return false;
  } else {
    console.log('Not a valid URL.');
    console.log("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
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

function parseDiscoveryInfo(discoveryInfo) {
  console.log("Entering parseDiscoveryInfo().");
  var authorizationEndpoint = discoveryInfo["authorization_endpoint"];
  var idTokenSigningAlgValuesSupported = discoveryInfo["id_token_signing_alg_values_supported"];
  var issuer = discoveryInfo["issuer"];
  var jwksUri = discoveryInfo["jwks_uri"];
  var responseTypesSupported = discoveryInfo["response_types_supported"];
  var scopesSupported = discoveryInfo["scopes_supported"];
  var subjectTypesSupported = discoveryInfo["subject_types_supported"];
  var tokenEndpoint = discoveryInfo["token_endpoint"];
  var tokenEndpointAuthMethodsSupported = discoveryInfo["token_endpoint_auth_methods_supported"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];
  console.log("authorizationEndpoint: " + authorizationEndpoint);
  console.log("idTokenSigningAlgValuesSupported: " + JSON.stringify(idTokenSigningAlgValuesSupported));
  console.log("issuer: " + issuer);
  console.log("jwksUri: " + jwksUri);
  console.log("responseTypesSupported: " + JSON.stringify(responseTypesSupported));
  console.log("scopesSupported: " + JSON.stringify(scopesSupported));
  console.log("subjectTypesSupported: " + JSON.stringify(subjectTypesSupported));
  console.log("tokenEndpoint: " + tokenEndpoint);
  console.log("tokenEndpointAuthMethodsSupported: " + JSON.stringify(tokenEndpointAuthMethodsSupported));
  console.log("userInfoEndpoint: " + userInfoEndpoint);
  console.log("Leaving parseDiscoveryInfo()."); 
}

function buildDiscoveryInfoTable(discoveryInfo) {
  console.log("Entering buildDiscoveryInfoTable().");
  var discovery_info_table_html = "<table border='2' style='border:2px;'>" +
                                    "<tr>" +
                                      "<td><strong>Attribute</strong></td>" +
                                      "<td><strong>Value</strong></td>" +
                                    "</tr>";
   Object.keys(discoveryInfo).forEach( (key) => {
     discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + key + "</td>" +
                                   "<td>" + discoveryInfo[key] + "</td>" +
                                 "</tr>";
   });

   discovery_info_table_html = discovery_info_table_html +
                              "</table>";

   var discovery_info_meta_data_html = '<table>' +
                                       '<form>' +
                                         '<td>' +
                                           '<input class="btn_oidc_populate_meta_data" type="button" value="Populate Meta Data" onclick="return debug.onSubmitPopulateFormsWithDiscoveryInformation();"/>' +
                                         '</td>' +
                                       '</form>' +
                                       '</table>';
  $("#discovery_info_meta_data_populate").html(discovery_info_meta_data_html);
  $("#discovery_info_table").html(discovery_info_table_html);
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
//  document.getElementById("token_scope").value = scopesSupported;
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
  if (document.getElementById("authorization_endpoint")) {
    document.getElementById("authorization_endpoint").value = "";
  }
  if ( document.getElementById("token_endpoint")) {
     document.getElementById("token_endpoint").value = "";
  }
  if (document.getElementById("authorization_grant_type")) {
    document.getElementById("authorization_grant_type").value = "oidc_authorization_code_flow";
  }
  if (document.getElementById("token_resource")) {
    document.getElementById("token_resource").value = "";
  }
  if (document.getElementById("yesCheck")) {
    document.getElementById("yesCheck").checked = false;
  }
  if (document.getElementById("noCheck")) {
    document.getElementById("noCheck").checked = true;
  }
  if (document.getElementById("yesCheckOIDCArtifacts")) {
    document.getElementById("yesCheckOIDCArtifacts").checked = true;
  }
  if (document.getElementById("noCheckOIDCArtifacts")) {
    document.getElementById("noCheckOIDCArtifacts").checked = false;
  }
  if (document.getElementById("refresh_client_id")) {
    document.getElementById("refresh_client_id").value = "";
  }
  if (document.getElementById("refresh_client_secret")) {
    document.getElementById("refresh_client_secret").value = "";
  }
  if (document.getElementById("refresh_scope")) {
    document.getElementById("refresh_scope").value = "";
  }
  if (document.getElementById("useRefreshToken-yes")) {
    document.getElementById("useRefreshToken-yes").checked = true;
  }
  if (document.getElementById("useRefreshToken-no")) {
    document.getElementById("useRefreshToken-no").checked = false;
  }
  if (document.getElementById("authzcustomParametersCheck-yes")) {
    document.getElementById("authzcustomParametersCheck-yes").checked = true;
  }
  if (document.getElementById("authzcustomParametersCheck-no")) {
    document.getElementById("authzcustomParametersCheck-no").checked = false;
  }
  if (document.getElementById("oidc_discovery_endpoint")) {
    document.getElementById("oidc_discovery_endpoint").value = "";
  }
  if (document.getElementById("client_id")) {
    document.getElementById("client_id").value = "";
  }
  if (document.getElementById("scope")) {
    document.getElementById("scope").value = "";
  }
  if (document.getElementById("resource")) {
    document.getElementById("resource").value = "";
  }
  if (document.getElementById("redirect_uri")) {
    document.getElementById("redirect_uri").value = "";
  }
  if (document.getElementById("oidc_userinfo_endpoint")) {
    document.getElementById("oidc_userinfo_endpoint").value = "";
  }
  if (document.getElementById("jwks_endpoint")) {
    document.getElementById("jwks_endpoint").value = "";
  }

  $("#discovery_info_table").html("");
}

function regenerateState() {
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
}

function regenerateNonce() {
  document.getElementById("nonce_field").value = generateUUID();
  localStorage.setItem('nonce_field', document.getElementById("nonce_field").value);
}

function displayAuthzCustomParametersCheck()
{
  console.log("Entering displayAuthzCustomParametersCheck().");
  var yesCheck = document.getElementById("authzcustomParametersCheck-yes").checked;
  var noCheck = document.getElementById("authzcustomParametersCheck-no").checked;
  console.log("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" + noCheck);
  if(yesCheck) {
    document.getElementById("authzCustomParametersRow").style.visibility = '';
    document.getElementById("authzcustomParametersCheck-no").checked = false;
    document.getElementById("authzcustomParametersCheck-yes").checked = true;
  } else if(noCheck) {
    document.getElementById("authzCustomParametersRow").style.visibility = "collapse"
    document.getElementById("authzcustomParametersCheck-yes").checked = false;
    document.getElementById("authzcustomParametersCheck-no").checked = true;
    $("#authz_custom_parameter_list").html("");
  }
  if (yesCheck) {
    generateCustomParametersListUI();
  }
  recalculateAuthorizationRequestDescription();
  console.log("Leaving displayAuthzCustomParametersCheck()");
}

function generateCustomParametersListUI()
{
  var customParametersListHTML = "" +
    "<legend>Custom Parameters" +
    "</legend>" +
    "<table>" +
      "<tr>" +
        "<th>&nbsp;</th>" +
        "<th>Name</th>" +
        "<th>Value</th>" +
      "</tr>";
      var i = 0;
      var j = parseInt(document.getElementById("authzNumberCustomParameters").value);
      if (j > 10) {
        j = 10; // no more than ten
      }
      for( var i = 0; i < j; i++)
      {
        customParametersListHTML = customParametersListHTML +
        "<tr>" +
          "<td>Custom Parameter #" + i + "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customParameterName-' + i + '" name="' + 'customParameterName-' + i + '" type="text" maxlength="32" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customParameterValue-' + i + '" name="' + 'customParameterValue-' + i + '" type="text" maxlength="32" size="32" />' +
          "</td>" +
        "</tr>";
      }
      customParametersListHTML = customParametersListHTML +
        "</table>";
      $("#authz_custom_parameter_list").html(customParametersListHTML); 
  if (document.getElementById("authzcustomParametersCheck-yes").checked) {
    var i = 0;
    var authzNumberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
//     localStorage.setItem("customParameterName-" + i, document.getElementById("customParameterName-" + i).value);
//      localStorage.setItem("customParameterValue-" + i, document.getElementById("customParameterValue-" + i).value);
      document.getElementById("customParameterName-" + i).value = localStorage.getItem("customParameterName-" + i);
      document.getElementById("customParameterValue-" + i).value = localStorage.getItem("customParameterValue-" + i);
    }
  }
  recalculateAuthorizationRequestDescription();

}

function onClickShowAuthzFieldSet(id) {
  console.log('Entering onClickShowAuthzFieldSet(). id=' + id + ', style.display=' + document.getElementById(id).style.display);
  if(id == 'authz_fieldset') {
    if(document.getElementById(id).style.display == 'block') {
       console.log('Hide ' + id + '.');
       document.getElementById(id).style.display = 'none'
       document.getElementById('authz_expand_button').value='Expand';
       document.getElementById('config_fieldset').style.display = 'block'
       document.getElementById('config_expand_button').value='Collapse';
       document.getElementById('oidc_fieldset').style.display = 'block'
       document.getElementById('oidc_expand_button').value='Collapse';
    } else {
      console.log('Show ' + id + '.');
      document.getElementById(id).style.display = 'block';
      document.getElementById('authz_expand_button').value='Collapse';
      document.getElementById('config_fieldset').style.display = 'none'
      document.getElementById('config_expand_button').value='Expand';
      document.getElementById('oidc_fieldset').style.display = 'none';
      document.getElementById('oidc_expand_button').value='Expand';
    }
  } else {
    if(document.getElementById(id).style.display == 'block') {
      console.log('Hide ' + id + '.');
      document.getElementById(id).style.display = 'none'
    } else {
      console.log('Show ' + id + '.');
      document.getElementById(id).style.display = 'block';
    }
  }
  console.log('Leaving onClickShowAuthzFieldSet().');
  return false;
}

function onClickShowConfigFieldSet(id) {
  console.log('Entering onClickShowConfigFieldSet(). id=' + id + ', style.display=' + document.getElementById(id).style.display);
  if(document.getElementById(id).style.display == 'block') {
     document.getElementById('config_expand_button').value='Expand';
  } else {
    document.getElementById('config_expand_button').value='Hide';
  }
  if(document.getElementById(id).style.display == 'block') {
    console.log('Hide ' + id + '.');
    document.getElementById(id).style.display = 'none'
  } else {
    console.log('Show ' + id + '.');
    document.getElementById(id).style.display = 'block';
  }
  console.log('Leaving onClickShowConfigFieldSet().');
  return false;
}

function onClickClearLocalStorage()
{
  if (localStorage) {
    localStorage.clear(); 
  }
  onSubmitClearAllForms();
  return false;
}

module.exports = {
  OnSubmitForm,
  OnSubmitTokenEndpointForm,
  getParameterByName,
  resetUI,
  resetErrorDisplays,
  writeValuesToLocalStorage,
  loadValuesFromLocalStorage,
  recalculateAuthorizationRequestDescription,
  recalculateTokenRequestDescription,
  recalculateRefreshRequestDescription,
  generateUUID,
  displayResourceCheck,
  displayTokenResourceCheck,
  recalculateAuthorizationErrorDescription,
  recalculateTokenErrorDescription,
  recalculateRefreshErrorDescription,
  parseFragment,
  displayOIDCArtifacts,
  useRefreshTokens,
  OnSubmitOIDCDiscoveryEndpointForm,
  isUrl,
  parseDiscoveryInfo,
  buildDiscoveryInfoTable,
  onSubmitPopulateFormsWithDiscoveryInformation,
  onSubmitClearAllForms,
  regenerateState,
  regenerateNonce,
  displayAuthzCustomParametersCheck,
  generateCustomParametersListUI,
  triggerAuthZEndpointCall,
  onClickShowAuthzFieldSet,
  onClickShowConfigFieldSet,
  onClickClearLocalStorage
};
