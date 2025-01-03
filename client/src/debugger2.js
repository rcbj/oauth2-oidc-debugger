// File: debugger2_js.js
// Author: Robert C. Broeckelmann Jr.
// Date: 06/15/2017
//
const appconfig = require(process.env.CONFIG_FILE);
const bunyan = require("bunyan");
const DOMPurify = require("dompurify");
const $ = require("jquery");
const log = bunyan.createLogger({ name: 'debugger2',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
var displayOpenIDConnectArtifacts = false;
var useRefreshTokenTester = false;
var displayStep0 = true;
var displayStep1 = true;
var displayStep2 = true;
var displayStep3 = true;
var displayStep4 = true;
var displayStep5 = true;
var discoveryInfo = {};
var currentRefreshToken = '';
var usePKCE = false;

function OnSubmitTokenEndpointForm()
{
  log.debug("Entering OnSubmitTokenEndpointForm().");
  document.token_step.action = "/token";
  log.debug("Leaving OnSubmitTokenEndpointForm().");
  return true;
}

function getParameterByName(name, url)
{
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  return urlParams.get(name);
}

$(document).ready(function() {
  log.debug("Entering ready function().");
  // Call original onload function
  onload();
  var sel = $("#authorization_grant_type");
  sel.change(function() {
    log.debug("Entering selection changed function().");
    var value = $(this).val();
    localStorage.setItem("authorization_grant_type", value);
    if (value != "client_credential") {
      writeValuesToLocalStorage(); 
      window.location.href = "/debugger.html";
    }
    resetUI(value);
    recalculateTokenRequestDescription();
    recalculateRefreshRequestDescription();
    log.debug("Leaving selection changed function().");
  });
  var value = $("#authorization_grant_type").value;
  resetUI(value);
  recalculateRefreshRequestDescription();

  $("#logout_btn").click(function() {
    log.debug("Logout link clicked.");
    var nameValuePairs = {};

    $('#logout_fieldset input.q').each(function() {
      var className = $(this).attr('name');
      var value = $(this).val();
      if (value!=""){ 
        nameValuePairs[className] = value;; 
      }
    });
    log.debug(nameValuePairs); // Log the name-value pairs
    var queryString = $.param(nameValuePairs);

    log.debug(queryString); // Log the query string
    var logoutUrl = DOMPurify.sanitize($("#logout_end_session_endpoint").val()) + "?" + DOMPurify.sanitize(queryString);

    clearLocalStorage();
    window.location.href = logoutUrl;

    return false;
  });

  $(".btn1").click(function() {
      log.debug("Entering token Submit button clicked function.");
      // validate and process form here
      var token_endpoint = $("#token_endpoint").val();
      var client_id = $("#token_client_id").val();
      var client_secret = $("#token_client_secret").val();
      var code = $("#code").val();
      var grant_type = $("#token_grant_type").val();
      var redirect_uri = $("#token_redirect_uri").val();
      var username = $("#token_username").val();
      var password = $("#token_password").val();
      var scope = $("#token_scope").val();
      var sslValidate = "";
      var code_verifier = $("#token_pkce_code_verifier").val();
      if($("#SSLValidate-yes").prop("checked"))
      {
        sslValidate = $("#SSLValidate-yes").val();
      } else if ($("#SSLValidate-no").prop("checked")) {
	sslValidate = $("#SSLValidate-no").val();
      } else {
        sslValidate = "true";
      }
      var auth_style = getLSBooleanItem("token_post_auth_style");
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
          sslValidate: sslValidate,
          auth_style: auth_style
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
          sslValidate: sslValidate,
          auth_style: auth_style
        };
      }
      log.debug("formData=" + JSON.stringify(formData));
      var yesCheck = $("#yesResourceCheckToken").prop("checked");
      if(yesCheck) //add resource value to OAuth query string
      {
        var resource = $("#token_resource").val();
        if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
        {
          formData.resource = resource
        }
      }
      if(typeof client_secret != "undefined")
      {
        formData.client_secret = client_secret
      }
      var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").prop("checked");
      log.debug("customTokenParametersCheck: " + tokencustomParametersCheck + ", type=" + typeof(tokencustomParametersCheck));
      if(tokencustomParametersCheck) {
        formData.customParams = {};
        const numberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
        log.debug('numberCustomParameters=' + numberCustomParameters);
        var i = 0;
        for(i = 0; i < numberCustomParameters; i++)
        {
           formData.customParams[$("#customTokenParameterName-" + i).val()] =
                                  $("#customTokenParameterValue-" + i).val();
        }
      }
      if(usePKCE) {
        formData.code_verifier = code_verifier;
      }
      writeValuesToLocalStorage();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      resetErrorDisplays();
  $.ajax({
    type: "POST",
    crossdomain: true,
    url: appconfig.apiUrl + "/token",
    data: JSON.stringify(formData),
    contentType: "application/json; charset=utf-8",
    success: function(data, textStatus, request) {
      log.debug('Entering ajax success function for Access Token call.');
      var token_endpoint_result_html = "";
      if (data.refresh_token && data.refresh_token != 'undefined') {
        currentRefreshToken = data.refresh_token;
      }
      if (data.id_token && data.id_token != 'undefined'){
        $("#logout_id_token_hint").val(data.id_token);
      }
      log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      if(displayOpenIDConnectArtifacts == true)
      {
         // Display OAuth2/OIDC Artifacts
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" + 
				      "<table>" +
				        "<tr>" +
                                          '<td><a href="/token_detail.html?type=access">Access Token</a></td>' + 
                                          "<td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
        if(currentRefreshToken) {
           token_endpoint_result_html +=  "<tr>" +
                                          '<td><a href="/token_detail.html?type=refresh">Refresh Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" + 
                                            currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html +=  "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=id">ID Token</a><p>' +
                                          '<P style="font-size:50%;">Get <a href="/userinfo.html">UserInfo Data</a></P></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_id_token id=token_id_token>" + 
                                             data.id_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
         localStorage.setItem("token_access_token", data.access_token);
         localStorage.setItem("token_refresh_token", data.refresh_token);
         localStorage.setItem("token_id_token", data.id_token);
      } else {
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td><a href="/token_detail.html?type=access">Access Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" +
                                            data.access_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(currentRefreshToken) {
           token_endpoint_result_html += "<tr>" +
                                          '<td><a href="/token_detail.html?type=access">Refresh Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" +
                                           currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html += "</table>" +
                                      "</fieldset>";
         localStorage.setItem("token_access_token", data.access_token);
         localStorage.setItem("token_refresh_token", data.refresh_token);
      }
      $("#token_endpoint_result").html(DOMPurify.sanitize(token_endpoint_result_html));
      $("#refresh_refresh_token").val(currentRefreshToken);
      $("#refresh_client_id").val(localStorage.getItem("client_id"));
      $("#refresh_scope").val(localStorage.getItem("scope"));
      $("#refresh_client_secret").val(localStorage.getItem("client_secret"));
      $("#token_fieldset").hide();
      $("#token_expand_button").val("Expand");
      useRefreshTokens();
      if(currentRefreshToken) {
        $("#logout_id_token_hint").val(data.id_token);
      } else {
        $("#logout_fieldset").hide();
        $("#logout_expand_button").val("Expand");
        $("#refresh_fieldset").hide();
        $("#refresh_expand_button").val("Expand");
      }
      recalculateRefreshRequestDescription();
    },
    error: function (request, status, error) {
      log.error("An error occurred calling the token endpoint.");
      log.error("request: " + JSON.stringify(request));
      log.error("status: " + JSON.stringify(status));
      log.error("error: " + JSON.stringify(error));
      recalculateTokenErrorDescription(request);
    }
  });
  return false;
    });

$(".refresh_btn").click(function() {
      log.debug("Entering refresh Submit button clicked function.");
      // validate and process form here
      var token_endpoint = document.getElementById("token_endpoint").value;
      var client_id = document.getElementById("refresh_client_id").value;
      var client_secret = document.getElementById("refresh_client_secret").value;
      if (client_secret == "undefined") {
        client_secret = "";
      }
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
      var auth_style = getLSBooleanItem("refresh_post_auth_style");
      var formData = {
        grant_type: grant_type,
        client_id: client_id,
        refresh_token: refresh_token,
        scope: scope,
        token_endpoint: token_endpoint,
        sslValidate: sslValidate,
        auth_style: auth_style
      };
      if(typeof client_secret != "undefined")
      {
        formData.client_secret = client_secret
      }
      writeValuesToLocalStorage();
      recalculateRefreshRequestDescription();
      resetErrorDisplays();
  $.ajax({
    type: "POST",
    crossdomain: true,
    url: appconfig.apiUrl + "/token",
    data: JSON.stringify(formData),
    contentType: "application/json; charset=utf-8",
    success: function(data, textStatus, request) {
      log.debug('Entering ajax success function for Refresh Token call.');
      var refresh_endpoint_result_html = "";
      log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      var iteration = 1;
      if( document.getElementById("refresh-token-results-iteration-count") != null)
      {
        iteration = parseInt(document.getElementById("refresh-token-results-iteration-count").value) + 1;
      }
      log.debug('data.refresh_token=' + data.refresh_token);
      if(data.refresh_token && data.refresh_token != 'undefined') {
        log.debug('Setting new Refresh Token.');
        currentRefreshToken = data.refresh_token;
      }
      if(displayOpenIDConnectArtifacts == true)
      {
         refresh_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results for Refresh Token Call:</legend>" + 
				      "<table>" +
				        "<tr>" +
                                          '<td><a href="/token_detail.html?type=refresh_access">Access Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=refresh_access_token id=refresh_access_token>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          '<td><a href="/token_detail.html?type=refresh_refesh">Refresh Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=refresh_refresh_token id=refresh_refresh_token>" + 
                                            currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=refresh_id">ID Token</a></P>' +
                                          '<P style="font-size:50%;">Get <a href="/userinfo.html">UserInfo Data</a></P></td>' +
                                          "<td><textarea rows=10 cols=60 name=refresh_id_token id=refresh_id_token>" + 
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
                                          '<td><a href="/token_detail.html?type=refresh_access">Access Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=refresh_access_token id=refresh_access_token>" +
                                            data.access_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          '<td><a href="/token_detail.html?type=refresh_id">ID Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=refresh_id_token id=refresh_id_token>" +
                                            currentRefreshToken +
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
      $("#refresh_endpoint_result").html(DOMPurify.sanitize(refresh_endpoint_result_html));
      // Update refresh token field in the refresh token grant pane
      $("refresh_refresh_token").val(currentRefreshToken);
      // Store new tokens in local storage
      localStorage.setItem("refresh_access_token", data.access_token );
      localStorage.setItem("refresh_refresh_token", currentRefreshToken );
      localStorage.setItem("refresh_id_token", data.id_token );
      // Update token in logout pane.
      if(currentRefreshToken) {
        $("#logout_id_token_hint").val(data.id_token);
      } else {
        $("#logout_fieldset").hide();
      }
      recalculateRefreshRequestDescription();
    },
    error: function (request, status, error) {
      log.error("An error occurred making a token refresh call to token endpoint.");
      log.error("request: " + JSON.stringify(request));
      log.error("status: " + JSON.stringify(status));
      log.error("error: " + JSON.stringify(error));
      recalculateRefreshErrorDescription(request);
    }
  });
  return false;
    });
    log.debug("Leaving token submit button clicked function.");

});

function resetUI(value)
{
    log.debug("Entering resetUI().");
    document.getElementById("logout_post_redirect_uri").value = 'http://localhost:3000/logout.html';
    if( value == "implicit_grant" )
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse'; 
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      document.getElementById("response_type").value = "token";
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
      document.getElementById("token_grant_type").value = "client_credentials";
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_2").innerHTML = "Obtain Access Token";
      $("#token_endpoint_result").html("");
      $("#display_token_request").show();
      document.getElementById("usePKCE-yes").checked = false;
      document.getElementById("usePKCE-no").checked = true;
      usePKCERFC();
    }
    if( value == "resource_owner")
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = '';
      document.getElementById("authzPasswordRow").style.visibility = '';
      $("#step2").hide();
      $("#step3").show();
      document.getElementById("response_type").value = "";
      document.getElementById("token_grant_type").value = "password";
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_2").innerHTML = "Obtain Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
    }
    if( value == "authorization_grant")
    {
      $("#code").show();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      document.getElementById("token_grant_type").value = "authorization_code";
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
    }
    if ( value == "oidc_implicit_flow")
    {
      $("#code").hide();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      document.getElementById("response_type").value = "id_token token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationErrorDescription();
      document.getElementById("token_grant_type").value = "";
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
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").hide();
      document.getElementById("response_type").value = "id_token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationErrorDescription();
      document.getElementById("token_grant_type").value = "";
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
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      document.getElementById("token_grant_type").value = "authorization_code";
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
      useRefreshTokens();
    }
    if( value == "oidc_hybrid_code_id_token")
    {
      $("#code").show();
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      document.getElementById("response_type").value = "code id_token";
      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("token_scope").value = "openid profile";
      document.getElementById("refresh_scope").value = "openid profile";
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      //document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
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
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      document.getElementById("response_type").value = "code token";
      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("token_scope").value = "openid profile";
      document.getElementById("refresh_scope").value = "openid profile";
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
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
      document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      $("#step2").show();
      $("#step3").show();
      document.getElementById("response_type").value = "code id_token token";
      document.getElementById("token_grant_type").value = "authorization_code";
      document.getElementById("token_scope").value = "openid profile";
      document.getElementById("refresh_scope").value = "openid profile";
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      document.getElementById("h2_title_2").innerHTML = "Exchange Authorization Code for Access Token";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
    }
    resetErrorDisplays();
    document.getElementById("yesResourceCheckToken").checked = false;
    document.getElementById("noResourceCheckToken").checked = true;
    document.getElementById("customTokenParametersCheck-yes").checked = false;
    document.getElementById("customTokenParametersCheck-no").checked = true;
    document.getElementById("token_postAuthStyleCheckToken").checked = true;
    document.getElementById("token_headerAuthStyleCheckToken").checked = false;
    document.getElementById("refresh_postAuthStyleCheckToken").checked = true;
    document.getElementById("refresh_headerAuthStyleCheckToken").checked = false;

    // Clear all token values.
    localStorage.setItem("token_access_token", "");
    localStorage.setItem("token_id_token", "");
    localStorage.setItem("token_refresh_token", "");
    localStorage.setItem("refresh_access_token", "");
    localStorage.setItem("refresh_id_token", "");
    localStorage.setItem("refresh_refresh_token", "");
    
    log.debug("Leaving resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  $("#display_authz_error_class").html("");
  $("#display_token_error_class").html("");
  $("#display_refresh_error_class").html("");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
      localStorage.setItem("token_client_id", document.getElementById("token_client_id").value);
      localStorage.setItem("token_client_secret", document.getElementById("token_client_secret").value);
      localStorage.setItem("token_redirect_uri", document.getElementById("token_redirect_uri").value);
      localStorage.setItem("token_username", document.getElementById("token_username").value);
      localStorage.setItem("token_scope", document.getElementById("token_scope").value);
      localStorage.setItem("authorization_grant_type", document.getElementById("authorization_grant_type").value);
      localStorage.setItem("token_resource", document.getElementById("token_resource").value);
      localStorage.setItem("yesResourceCheckToken", document.getElementById("yesResourceCheckToken").checked);
      localStorage.setItem("noResourceCheckToken", document.getElementById("noResourceCheckToken").checked);
      localStorage.setItem("yesCheckOIDCArtifacts", document.getElementById("yesCheckOIDCArtifacts").checked);
      localStorage.setItem("noCheckOIDCArtifacts", document.getElementById("noCheckOIDCArtifacts").checked);
      localStorage.setItem("yesCheck", document.getElementById("SSLValidate-yes").checked);
      localStorage.setItem("noCheck", document.getElementById("SSLValidate-no").checked);
      localStorage.setItem("refresh_client_id", document.getElementById("refresh_client_id").value);
      localStorage.setItem("refresh_client_secret", document.getElementById("refresh_client_secret").value);
      localStorage.setItem("refresh_scope", document.getElementById("refresh_scope").value);
      localStorage.setItem("refresh_refresh_token", document.getElementById("refresh_refresh_token").value);
      localStorage.setItem("useRefreshToken_yes", document.getElementById("useRefreshToken-yes").checked);
      localStorage.setItem("useRefreshToken_no", document.getElementById("useRefreshToken-no").checked);
      localStorage.setItem("oidc_userinfo_endpoint", document.getElementById("oidc_userinfo_endpoint").value);
      localStorage.setItem("jwks_endpoint", document.getElementById("jwks_endpoint").value);
      localStorage.setItem("end_session_endpoint", document.getElementById("logout_end_session_endpoint").value);
      localStorage.setItem("logout_client_id", document.getElementById("logout_client_id").value);
      localStorage.setItem("customTokenParametersCheck-yes", document.getElementById("customTokenParametersCheck-yes").checked);
      localStorage.setItem("customTokenParametersCheck-no", document.getElementById("customTokenParametersCheck-no").checked);
      localStorage.setItem("tokenNumberCustomParameters", document.getElementById("tokenNumberCustomParameters").value);
      if (document.getElementById("token_postAuthStyleCheckToken").checked ||
         document.getElementById("refresh_postAuthStyleCheckToken").checked) {
        console.log("RCBJ0100");
        localStorage.setItem("token_post_auth_style", true);
      } else {
        console.log("RCBJ0101");
        localStorage.setItem("token_post_auth_style", false);
      }
      if (document.getElementById("customTokenParametersCheck-yes").checked) {
        var i = 0;
        var tokenNumberCustomParameters = parseInt(document.getElementById("tokenNumberCustomParameters").value);
        for(i = 0; i < tokenNumberCustomParameters; i++)
        {
          log.debug("Writing customTokenParameterName-" + i + " as " + document.getElementById("customTokenParameterName-" + i).value + "\n");
          localStorage.setItem("customTokenParameterName-" + i, document.getElementById("customTokenParameterName-" + i).value);
          log.debug("Writing customTokenParameterValue-" + i + " as " + document.getElementById("customTokenParameterValue-" + i).value + "\n");
          localStorage.setItem("customTokenParameterValue-" + i, document.getElementById("customTokenParameterValue-" + i).value);
        }
      }
      localStorage.setItem("PKCE_code_challenge",document.getElementById("token_pkce_code_challenge").value);
      localStorage.setItem("PKCE_code_challenge_method", document.getElementById("token_pkce_code_method").value);
      localStorage.setItem("PKCE_code_verifier", document.getElementById("token_pkce_code_verifier").value );
      localStorage.setItem("usePKCE_yes", document.getElementById("usePKCE-yes").value);
      localStorage.setItem("usePKCE_no", document.getElementById("usePKCE-no").value);
  }

  log.debug("Leaving writeValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  var authzGrantType = localStorage.getItem("authorization_grant_type");
  log.debug("authzGrantType=" + authzGrantType);
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
  document.getElementById("token_client_id").value = localStorage.getItem("client_id");
  document.getElementById("token_client_secret").value = localStorage.getItem("client_secret");
  document.getElementById("token_redirect_uri").value = localStorage.getItem("redirect_uri");
  document.getElementById("token_scope").value = localStorage.getItem("token_scope");
  document.getElementById("token_username").value = localStorage.getItem("token_username");
  document.getElementById("token_resource").value = localStorage.getItem("token_resource");
  document.getElementById("SSLValidate-yes").checked = getLSBooleanItem("yesCheck");
  document.getElementById("SSLValidate-no").checked = getLSBooleanItem("noCheck");
  document.getElementById("yesResourceCheckToken").checked = getLSBooleanItem("yesResourceCheckToken");
  document.getElementById("noResourceCheckToken").checked = getLSBooleanItem("noResourceCheckToken");
  document.getElementById("yesCheckOIDCArtifacts").checked = getLSBooleanItem("yesCheckOIDCArtifacts");
  document.getElementById("noCheckOIDCArtifacts").checked = getLSBooleanItem("noCheckOIDCArtifacts");
  document.getElementById("usePKCE-yes").checked = getLSBooleanItem("usePKCE_yes");
  document.getElementById("usePKCE-no").checked = getLSBooleanItem("usePKCE_no");
  document.getElementById("refresh_refresh_token").value = localStorage.getItem("refresh_refresh_token");
  document.getElementById("refresh_client_id").value = localStorage.getItem("refresh_client_id");
  document.getElementById("refresh_scope").value = localStorage.getItem("refresh_scope");
  document.getElementById("refresh_client_secret").value = localStorage.getItem("refresh_client_secret");
  document.getElementById("useRefreshToken-yes").checked = getLSBooleanItem("useRefreshToken_yes");
  document.getElementById("useRefreshToken-no").checked = getLSBooleanItem("useRefreshToken_no");
  document.getElementById("oidc_userinfo_endpoint").value = localStorage.getItem("oidc_userinfo_endpoint");
  document.getElementById("jwks_endpoint").value = localStorage.getItem("jwks_endpoint");
  document.getElementById("logout_end_session_endpoint").value = localStorage.getItem("end_session_endpoint");
  document.getElementById("logout_client_id").value = localStorage.getItem("client_id");
  document.getElementById("customTokenParametersCheck-yes").checked = getLSBooleanItem("customTokenParametersCheck-yes");
  document.getElementById("customTokenParametersCheck-no").checked = getLSBooleanItem("customTokenParametersCheck-no");
  document.getElementById("tokenNumberCustomParameters").value = localStorage.getItem("tokenNumberCustomParameters")? localStorage.getItem("tokenNumberCustomParameters"): 1;
  if (getLSBooleanItem("token_post_auth_style")) {
    console.log("RCBJ0102");
    document.getElementById("token_postAuthStyleCheckToken").checked = true
    document.getElementById("token_headerAuthStyleCheckToken").checked = false;
  } else {
    console.log("RCBJ0103");
    document.getElementById("refresh_postAuthStyleCheckToken").checked = false;
    document.getElementById("refresh_headerAuthStyleCheckToken").checked = true;
  }

  currentRefreshToken = localStorage.getItem("refresh_refresh_token");
  if (document.getElementById("customTokenParametersCheck-yes").checked) {
    generateCustomParametersListUI();
    var i = 0;
    var tokenNumberCustomParameters = parseInt(document.getElementById("tokenNumberCustomParameters").value);
    for(i = 0; i < tokenNumberCustomParameters; i++)
    {
      log.debug("Reading customTokenParameterName-" + i + " as " + localStorage.getItem("customTokenParameterName-" + i + "\n"));
      document.getElementById("customTokenParameterName-" + i).value = localStorage.getItem("customTokenParameterName-" + i);
      log.debug("Reading customTokenParameterValue-" + i + " as " + localStorage.getItem("customTokenParameterValue-" + i + "\n"));
      document.getElementById("customTokenParameterValue-" + i).value = localStorage.getItem("customTokenParameterValue-" + i);
    }
  }

  if (document.getElementById("usePKCE-yes").checked) {
    document.getElementById("token_pkce_code_challenge").value = localStorage.getItem("PKCE_code_challenge");
    document.getElementById("token_pkce_code_verifier").value = localStorage.getItem("PKCE_code_verifier");
    document.getElementById("token_pkce_code_method").value =  localStorage.getItem("PKCE_code_challenge_method");
    usePKCERFC();
  }

  var agt = document.getElementById("authorization_grant_type").value;
  var pathname = window.location.pathname;
  log.debug("agt=" + agt);
  log.debug("pathname=" + pathname);
  if (  (agt ==  "authorization_grant" || 
         agt == "oidc_hybrid_code_id_token" || 
         agt == "oidc_hybrid_code_token" || 
         agt == "oidc_hybrid_code_id_token_token" ) &&
	pathname == "/debugger2.html")
  {
    log.debug("Checking for code.  agt=" + agt + ", pathname=" + pathname);
    log.debug("fragement: " + parseFragment());
    code = parseFragment()["code"];
    if(code == null || code == "null" || code == "" || typeof code == "undefined")
    {
      code = "NO_CODE_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("code=" + code);
    if(document.getElementById("code").value == "")
    {
      log.debug("code not yet set in next form. Doing so now.");
      document.getElementById("code").value = code;
    }
  }
  if ( 	(agt == "implicit_grant" || 
         agt == "oidc_implicit_flow" ) &&
	pathname == "/debugger2.html") //retrieve access_token for implicit_grant for callback redirect response
  {
    var access_token = getParameterByName("access_token",window.location.href);
    log.debug("access_token=" + access_token);
    if(access_token == null || 
       access_token == "null" || 
       access_token == "" || 
       typeof access_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("fragement: " + parseFragment());
      access_token = parseFragment()["access_token"];
      if(access_token == null || access_token == "null" || access_token == "" || typeof access_token == "undefined")
      {
        access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    log.debug("access_token=" + access_token);
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
    $("#authorization_endpoint_result").html(DOMPurify.sanitize(authorization_endpoint_result_html));
  }
  if (  agt == "oidc_hybrid_code_id_token_token" &&
        pathname == "/debugger2.html") //retrieve access code and id_token that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" || 
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("access_token=" + access_token);
    log.debug("fragement: " + parseFragment());
    id_token = parseFragment()["id_token"];
    if(	id_token == null ||
	id_token == "null" ||
	id_token == "" ||
	typeof id_token == "undefined")
    {
      id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    $("#logout_id_token_hint").val(id_token);
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
    $("#authorization_endpoint_result").html(DOMPurify.sanitize(authz_endpoint_results_html));
  }

  if (  agt == "oidc_hybrid_code_token" &&
        pathname == "/debugger2.html") //retrieve access code that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" ||
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("access_token=" + access_token);
    $("#authorization_endpoint_result").html(DOMPurify.sanitize("<fieldset><legend>Authorization Endpoint Results:</legend><table><tr><td>access_token</td><td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td></tr></table></fieldset>"));
  }
  if ( 	(agt == "oidc_implicit_flow" || agt == "oidc_implicit_flow_id_token" ||  agt == "oidc_hybrid_code_id_token") && 
	pathname == "/debugger2.html") //retrieve access_token for implicit_grant for callback redirect response
  {
    var id_token = getParameterByName("id_token",window.location.href);
    log.debug("id_token=" + access_token);
    if(id_token == null || id_token == "null" || id_token == "" || typeof id_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("fragement: " + parseFragment());
      id_token = parseFragment()["id_token"];
      if(id_token == null || id_token == "null" || id_token == "" || typeof id_token == "undefined")
      {
        id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    log.debug("id_token=" + id_token);
    $("#logout_id_token_hint").val(id_token);
    $("#authorization_endpoint_id_token_result").html(DOMPurify.sanitize("<fieldset><legend>Authorization Endpoint Results</legend><table><tr><td>id_token</td><td><textarea id=\"implicit_flow_id_token\" rows=5 cols=100>" + DOMPurify.sanitize(id_token) + "</textarea></td></tr></table></fieldset>"));
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = document.getElementById("authorization_grant_type").value;
  if(	pathname == "/debugger2.html" && 
	(authzGrantType == "authorization_grant" || authzGrantType == "implicit_grant" || authzGrantType == "oidc_hybrid_code_id_token") &&
	(error != null && error != "null" && typeof error != "undefined" && error != ""))
  {
    $("#display_authz_error_class").html(DOMPurify.sanitize("<fieldset><legend>Authorization Endpoint Error</legend><form action=\"\" name=\"display_authz_error_form\" id=\"display_authz_error_form\"><table><tr><td><label name=\"display_authz_error_form_label1\" value=\"\" id=\"display_authz_error_form_label1\">Error</label></td><td><textarea rows=\"10\" cols=\"100\" id=\"display_authz_error_form_textarea1\"></td></tr></table></textarea></form></fieldset>"));
  }
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function recalculateTokenRequestDescription()
{
  log.debug("Entering recalculateTokenRequestDescription().");
  log.debug("update request field");
  var ta1 = document.getElementById("display_token_request_form_textarea1");
  var yesCheck = document.getElementById("yesResourceCheckToken").checked;
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = document.getElementById("token_resource").value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  var customParametersComponent = "";
  var tokencustomParametersCheck = document.getElementById("customTokenParametersCheck-yes").checked;
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck + ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) {
    const numberCustomParameters = parseInt(document.getElementById("tokenNumberCustomParameters").value);
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++)
    {
       customParametersComponent = customParametersComponent +
                                   document.getElementById("customTokenParameterName-" + i).value +
                                   '=' + document.getElementById("customTokenParameterValue-" + i).value + "&" + "\n";
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
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
                                                                      "scope=" + document.getElementById("token_scope").value;
      if(usePKCE) {
        document.getElementById("display_token_request_form_textarea1").value += "&\n" + "code_verifier=" + document.getElementById("token_pkce_code_verifier").value;
      }
    } else if (grant_type == "client_credential") {
      document.getElementById("display_token_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                     "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("token_grant_type").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("token_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("token_client_secret").value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById("token_redirect_uri").value + "&" +"\n" +
                                                                      "scope=" + document.getElementById("token_scope").value;
    } else if (grant_type == "password") {
      document.getElementById("display_token_request_form_textarea1").value = "POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("token_grant_type").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("token_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("token_client_secret").value + "&" + "\n" +
                                                                      "username=" + document.getElementById("token_username").value + "&" + "\n" +
                                                                      "password=" + document.getElementById("token_password").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("token_scope").value;
    }
    if ( resourceComponent.length > 0) {
       document.getElementById("display_token_request_form_textarea1").value += "&\n" + resourceComponent + "\n";
     }
     if (customParametersComponent.length > 0) {
       document.getElementById("display_token_request_form_textarea1").value += "&\n" +  customParametersComponent + "\n";
     }
  }
  log.debug("Leaving recalculateTokenRequestDescription().");
}

function recalculateRefreshRequestDescription()
{
  log.debug("Entering recalculateRefreshRequestDescription().");
  log.debug("update request field");
  var ta1 = document.getElementById("display_refresh_request_form_textarea1");
  var resourceComponent = "";

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
        document.getElementById("display_refresh_request_form_textarea1").value = DOMPurify.sanitize("POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("refresh_grant_type").value + "&" + "\n" +
                                                                      "refresh_token=" + document.getElementById("refresh_refresh_token").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("refresh_client_id").value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById("refresh_client_secret").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("refresh_scope").value + "\n");
      } else {
        document.getElementById("display_refresh_request_form_textarea1").value = DOMPurify.sanitize("POST " + document.getElementById("token_endpoint").value + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + document.getElementById("refresh_grant_type").value + "&" + "\n" +
                                                                      "refresh_token=" + document.getElementById("refresh_refresh_token").value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById("refresh_client_id").value + "&" + "\n" +
                                                                      "scope=" + document.getElementById("refresh_scope").value + "\n");
      }
    }
  }
  log.debug("Leaving recalculateRefreshRequestDescription().");
}

function onload() {
  log.debug("Entering onload function.");

  if (!appconfig) {
    log.debug('Failed to load appconfig.');
  }
 
  $("#password-form-group1").hide();
  $("#password-form-group2").hide();

  // Check if state matches
  log.debug('Checking on state.');
  var state = getParameterByName('state');
  if (typeof(state) != "undefined" && state != "null" && state != null && state != undefined) {
    log.debug('Found state: ' + state)
    var storedState = localStorage.getItem('state');
    if ( state == storedState) {
      log.debug('State matches stored state.');
      var stateReportHTML = '<h1>State Report</h1>' +
                            '<P>' + 'State matches: state=' + state + '</P>';
      $("#state-status").html(DOMPurify.sanitize(stateReportHTML));
    } else {
      log.debug('State does not match: state=' + state + ', storedState=' + storedState);
      var stateReportHTML = '<h1>State Report</h1>' +
                            '<P>State does not match: state=' + state + ', storedState=' + storedState + '</P>';
      $("#state-status").html(DOMPurify.sanitize(stateReportHTML));
    }
  }
  // an error was returned from the authorization endpoint
  var errorDescriptionParam = getParameterByName('error_description');
  var errorParam = getParameterByName('error');
  log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' + errorParam);
  if (errorDescriptionParam || errorParam) {
    $('#step0').hide();
    $('#step3').hide();
    $('#step4').hide();
    var authzErrorReportHTML = '<h1>Authorization Endpoint Error Report</h1>' +
                               '<P>' + 'Error: ' + errorParam + '</P>' +
                               '<P>' + 'Error Description: ' +  errorDescriptionParam + '</P>';
    $('#authz-error-report').html(DOMPurify.sanitize(authzErrorReportHTML));
    log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' + errorParam); 
    return;
  }

  resetUI();
  initFields();
  generateCustomParametersListUI();
  document.getElementById("code").value = getParameterByName('code');
  document.getElementById("customTokenParametersCheck-yes").addEventListener("onClick", recalculateTokenRequestDescription());
  document.getElementById("customTokenParametersCheck-no").addEventListener("onClick", recalculateTokenRequestDescription());

  loadValuesFromLocalStorage();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();

  var yesCheckedToken = document.getElementById("yesResourceCheckToken").checked
  if(yesCheckedToken)
  {
    document.getElementById("authzTokenResourceRow").style.visibility = '';
  } else {
    document.getElementById("authzTokenResourceRow").style.visibility = 'collapse';
  }
  if( document.getElementById("useRefreshToken-yes").checked)
  {
    useRefreshTokenTester = document.getElementById("useRefreshToken-yes").value;
  } else if (document.getElementById("useRefreshToken-no").checked) {
    useRefreshTokenTester = document.getElementById("useRefreshToken-no").value;
  } else {
    useRefreshTokenTester = true;
  }
  if(useRefreshTokenTester == true)
  {
    $("#step4").show();
  } else {
    $("#step4").hide();
  }
  var tokencustomParametersCheck = document.getElementById("customTokenParametersCheck-yes").checked;
  if(tokencustomParametersCheck)
  {
    document.getElementById("tokenCustomParametersRow").style.visibility = '';
  } else {
    document.getElementById("tokenCustomParametersRow").style.visibility = 'collapse';
  }

  var authzGrantType = localStorage.getItem("authorization_grant_type");
  if (authzGrantType == "client_credential") {
    usePKCE = false;
    document.getElementById("usePKCE-yes").checked = false;
    document.getElementById("usePKCE-no").checked = true;
    usePKCERFC();
  }

  displayTokenCustomParametersCheck();

  if(getParameterByName("redirectFromTokenDetail") == "true") {
    log.debug('Detected redirect back from token detail page.');
    $("#step3").hide();
    recreateTokenDisplay();
  }
  log.debug("Leaving onload().");
}

function generateUUID () { // Public Domain/MIT
    log.debug("Entering generateUUID().");
    var d = new Date().getTime();
    if (typeof performance !== "undefined" && typeof performance.now === "function"){
        d += performance.now(); //use high-precision timer if available
    }
    log.debug("Leaving generateUUID().");
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function displayResourceCheck()
{
  log.debug("Entering displayResourceCheck().");
  var yesCheck = document.getElementById("yesCheck").checked;
  var noCheck = document.getElementById("noCheck").checked;
  log.debug("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if(yesCheck) {
    document.getElementById("authzResourceRow").style.visibility = '';
  } else if(noCheck) {
    document.getElementById("authzResourceRow").style.visibility = "collapse"
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  log.debug("Entering displayTokenResourceCheck().");
  var yesCheck = document.getElementById("yesResourceCheckToken").checked;
  var noCheck = document.getElementById("noResourceCheckToken").checked;
  if( yesCheck) {
    document.getElementById("authzTokenResourceRow").style.visibility = '';
  } if(noCheck) {
    document.getElementById("authzTokenResourceRow").style.visibility = 'collapse';
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayTokenResourceCheck().");
}

$(function() {
$("#auth_step").submit(function () {
    log.debug("Entering auth_step submit function.");
    var resource = document.getElementById("resource").value;
    var yesCheck = document.getElementById("yesCheck").checked;
    log.debug("yesCheck=" + yesCheck);
    log.debug("resource=" + resource);
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
    log.debug("Leaving auth_step submit function.");
});

function recalculateAuthorizationErrorDescription()
{
  log.debug("Entering recalculateAuthorizationErrorDescription().");
  log.debug("update error field");
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
      log.debug("pathname=" + pathname);
      if (pathname == "/debugger2.html")
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
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //document.getElementById("display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/debugger2.html")
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
  log.debug("Leaving recalculateAuthorizationErrorDescription().");
}

function recalculateTokenErrorDescription(data)
{
  log.debug("Entering recalculateTokenErrorDescription().");
  var display_token_error_class_html = "<fieldset>" +
                                       "<legend>Token Endpoint Error</legend>" +
                                         "<form action=\"\" name=\"display_token_error_form\" id=\"display_token_error_form\">" +
                                           "<table>" +
                                             "<tr>" +
                                               "<td><label name=\"display_token_error_form_label1\" value=\"\" id=\"display_token_error_form_label1\">Error</label></td>" +
                                               "<td><textarea rows=\"10\" cols=\"60\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class").html(DOMPurify.sanitize(display_token_error_class_html));
  log.debug("update error field");
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
  log.debug("Leaving recalculateTokenErrorDescription().");
}

function recalculateRefreshErrorDescription(data)
{
  log.debug("Entering recalculateRefreshErrorDescription().");
  var display_refresh_error_class = "<fieldset>" +
                                    "<legend>Token Endpoint (For Refresh) Error</legend>" +
                                       "<form action=\"\" name=\"display_refresh_error_form\" id=\"display_refresh_error_form\">" +
                                         "<table>" +
                                           "<tr>" +
                                             "<td><label name=\"display_refresh_error_form_label1\" value=\"\" id=\"display_refresh_error_form_label1\">Error</label></td>" +
                                             "<td><textarea rows=\"10\" cols=\"60\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(DOMPurify.sanitize(display_refresh_error_class));
  log.debug("update error field");
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
  log.debug("Leaving recalculateRefreshErrorDescription().");
}

function parseFragment()
{
  log.debug("hash=" + window.location.hash);
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
  log.debug("Entering displayOIDCArtifacts().");
  var yesCheck = document.getElementById("yesCheckOIDCArtifacts").checked;
  var noCheck = document.getElementById("noCheckOIDCArtifacts").checked;
  log.debug("yesCheckOIDCArtifacts=" + yesCheck, "noCheckOIDCArtifacts=" + noCheck);
  if(yesCheck) {
    displayOpenIDConnectArtifacts = true;
    
  } else if(noCheck) {
    displayOpenIDConnectArtifacts = false;
  }
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  log.debug("Leaving displayOIDCArtifacts().");
}

function useRefreshTokens()
{
  log.debug("Entering useRefreshToken().");
  var yesCheck = document.getElementById("useRefreshToken-yes").checked;
  var noCheck = document.getElementById("useRefreshToken-no").checked;
  log.debug("useRefreshToken-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if(yesCheck) {
    useRefreshTokenTester = true;
    $("#step4").show();
  } else if(noCheck) {
    useRefreshTokenTester = false;
    $("#step4").hide();
  }
  log.debug("useRefreshTokenTester=" + useRefreshTokenTester);
  log.debug("Leaving useRefreshTokens().");
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
  log.debug("Entering OnSubmitOIDCDiscoveryEndpointForm().");
  writeValuesToLocalStorage();
  var oidcDiscoveryEndpoint = document.getElementById("oidc_discovery_endpoint").value;
  log.debug('URL: ' + oidcDiscoveryEndpoint);
  if (isUrl(oidcDiscoveryEndpoint)) {
    log.debug('valid URL: ' + oidcDiscoveryEndpoint);
    $.ajax({ type: 'GET',
             crossOrigin: true,
             url: oidcDiscoveryEndpoint,
             success: function(result) {
               log.debug("OIDC Discovery Endpoint Result: " + JSON.stringify(result));
               discoveryInfo = result;
               parseDiscoveryInfo(result);
               buildDiscoveryInfoTable(result);
             },
             error: function (request, status, error) {
               log.debug("request: " + JSON.stringify(request));
               log.debug("status: " + JSON.stringify(status));
               log.debug("error: " + JSON.stringify(error));
             }
           });
    log.debug("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
    return false;
  } else {
    log.debug('Not a valid URL.');
    log.debug("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
    return false;
  }
}

function isUrl(url) {
  log.debug('Entering isUrl().');
  try {
    return Boolean(new URL(url));
  } catch(e) {
    log.debug('An error occurred: ' + e.stack);
    return false;
  }
}

function parseDiscoveryInfo(discoveryInfo) {
  log.debug("Entering parseDiscoveryInfo().");
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
  log.debug("authorizationEndpoint: " + authorizationEndpoint);
  log.debug("idTokenSigningAlgValuesSupported: " + JSON.stringify(idTokenSigningAlgValuesSupported));
  log.debug("issuer: " + issuer);
  log.debug("jwksUri: " + jwksUri);
  log.debug("responseTypesSupported: " + JSON.stringify(responseTypesSupported));
  log.debug("scopesSupported: " + JSON.stringify(scopesSupported));
  log.debug("subjectTypesSupported: " + JSON.stringify(subjectTypesSupported));
  log.debug("tokenEndpoint: " + tokenEndpoint);
  log.debug("tokenEndpointAuthMethodsSupported: " + JSON.stringify(tokenEndpointAuthMethodsSupported));
  log.debug("userInfoEndpoint: " + userInfoEndpoint);
  log.debug("Leaving parseDiscoveryInfo()."); 
}

function buildDiscoveryInfoTable(discoveryInfo) {
  log.debug("Entering buildDiscoveryInfoTable().");
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
                                           '<input class="btn_oidc_populate_meta_data" type="button" value="Populate Meta Data" onclick="return onSubmitPopulateFormsWithDiscoveryInformation();"/>' +
                                         '</td>' +
                                       '</form>' +
                                       '</table>';
  $("#discovery_info_meta_data_populate").html(DOMPurify.sanitize(discovery_info_meta_data_html));
  $("#discovery_info_table").html(DOMPurify.sanitize(discovery_info_table_html));
}

function onSubmitPopulateFormsWithDiscoveryInformation() {
  log.debug('Entering OnSubmitPopulateFormsWithDiscoveryInformation().');
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
  var endSessionEndpoint = discoveryInfo["end_session_endpoint"];

  document.getElementById("authorization_endpoint").value = authorizationEndpoint;
  document.getElementById("token_endpoint").value = tokenEndpoint;
  document.getElementById("token_scope").value = scopesSupported;
  document.getElementById("scope").value = scopesSupported;
  document.getElementById("oidc_userinfo_endpoint").value = userInfoEndpoint;
  document.getElementById("jwks_endpoint").value = jwksUri;
  if (localStorage) {
      log.debug('Adding to local storage.');
      localStorage.setItem("authorization_endpoint", authorizationEndpoint );
      localStorage.setItem("token_endpoint", tokenEndpoint );
      localStorage.setItem("scope", scopesSupported);
      localStorage.setItem("token_scope", scopesSupported );
      localStorage.setItem("jwks_endpoint", jwksUri);
      localStorage.setItem("end_session_endpoint", endSessionEndpoint);
  }
  log.debug('Leaving OnSubmitPopulateFormsWithDiscoveryInformation().');
  return true;
}

function clearLocalStorage() {
  if (localStorage) {
    localStorage.setItem("token_client_secret", "");
    localStorage.setItem("refresh_client_secret", "");
  }
}

function regenerateState() {
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
}

function regenerateNonce() {
  document.getElementById("nonce_field").value = generateUUID();
  localStorage.setItem('nonce_field', document.getElementById("nonce_field").value);
}

function recreateTokenDisplay()
{
      var token_endpoint_result_html = "";
      log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      if(displayOpenIDConnectArtifacts == true)
      {
         // Display OAuth2/OIDC Artifacts
         var refreshToken = localStorage.getItem("token_refresh_token");
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" + 
				      "<table>" +
				        "<tr>" +
                                          '<td><a href="/token_detail.html?type=access">Access Token</a></td>' + 
                                          "<td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" + 
                                            localStorage.getItem("token_access_token") + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(typeof refreshToken != "undefined" && refreshToken != "undefined") {
           token_endpoint_result_html += "<tr>" +
                                          '<td><a href="/token_detail.html?type=refresh">Refresh Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" + 
                                            refreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html += "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=id">ID Token</a></P>' +
                                          '<P style="font-size:50%;">Get <a href="/userinfo.html">UserInfo Data</a></P></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_id_token id=token_id_token>" + 
                                             localStorage.getItem("token_id_token") +
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
                                          '<td><a href="/token_detail.html?type=access">Access Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" +
                                            localStorage.getItem("token_access_token") +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(typeof refreshToken != "undefined" && refreshToken != "undefined") {
           token_endpoint_result_html += "<tr>" +
                                          '<td><a href="/token_detail.html?type=access">Refresh Token</a></td>' +
                                          "<td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" +
                                            refreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
        }
        token_endpoint_result_html += "</table>" +
                                      "</fieldset>";
      }
      $("#token_endpoint_result").html(DOMPurify.sanitize(token_endpoint_result_html));
}

function displayTokenCustomParametersCheck()
{
  log.debug("Entering displayTokenCustomParametersCheck().");
  var yesCheck = document.getElementById("customTokenParametersCheck-yes").checked;
  var noCheck = document.getElementById("customTokenParametersCheck-no").checked;
  log.debug("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" + noCheck);
  if(yesCheck) {
    document.getElementById("tokenCustomParametersRow").style.visibility = '';
    document.getElementById("customTokenParametersCheck-no").checked = false;
    document.getElementById("customTokenParametersCheck-yes").checked = true;
  } else if(noCheck) {
    document.getElementById("tokenCustomParametersRow").style.visibility = "collapse"
    document.getElementById("customTokenParametersCheck-yes").checked = false;
    document.getElementById("customTokenParametersCheck-no").checked = true;
    $("#token_custom_parameter_list").html("");
  }
  if (yesCheck) {
    generateCustomParametersListUI();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayTokenCustomParametersCheck()");
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
      var j = parseInt(document.getElementById("tokenNumberCustomParameters").value);
      if (j > 10) {
        j = 10; // no more than ten
      }
      for( var i = 0; i < j; i++)
      {
        customParametersListHTML = customParametersListHTML +
        "<tr>" +
          "<td>Custom Parameter #" + i + "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customTokenParameterName-' + i + '" name="' + 'customTokenParameterName-' + i + '" type="text" maxlength="64" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customTokenParameterValue-' + i + '" name="' + 'customTokenParameterValue-' + i + '" type="text" maxlength="128" size="64" />' +
          "</td>" +
        "</tr>";
      }
      customParametersListHTML = customParametersListHTML +
        "</table>";
      $("#token_custom_parameter_list").html(DOMPurify.sanitize(customParametersListHTML));
  if (document.getElementById("customTokenParametersCheck-yes").checked) {
    var i = 0;
    var authzNumberCustomParameters = parseInt(document.getElementById("tokenNumberCustomParameters").value);
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      document.getElementById("customTokenParameterName-" + i).value = localStorage.getItem("customTokenParameterName-" + i);
      document.getElementById("customTokenParameterValue-" + i).value = localStorage.getItem("customTokenParameterValue-" + i);
    }
  }
  recalculateTokenRequestDescription();
}

function onClickShowFieldSet(expand_button_id, field_set_id) {
  log.debug('Entering onClickShowConfigFieldSet(). expand_button_id='
    + expand_button_id + ', field_set_id=' + field_set_id
    + ', fieldset.style.display=' + document.getElementById(field_set_id).style.display
    + ', expand_button.value=' + document.getElementById(expand_button_id).value);
  if(document.getElementById(field_set_id).style.display == 'block') {
    log.debug('Hide ' + field_set_id + '.');
    document.getElementById(field_set_id).style.display = 'none'
    document.getElementById(expand_button_id).value='Expand';
  } else {
    log.debug('Show ' + field_set_id + '.');
    document.getElementById(field_set_id).style.display = 'block';
    document.getElementById(expand_button_id).value='Hide';
  }
  document.getElementById("step0_expand_form").addEventListener("click", function(event) {
    event.preventDefault();
  });
  log.debug('Leaving onClickShowConfigFieldSet().');
  return false;
}

function initFields() {
  log.debug("Entering initFields().");
  var token_initialize = getLSBooleanItem("token_initialize");
  if(!token_initialize) {
    if (document.getElementById("yesResourceCheckToken")) {
        document.getElementById("yesResourceCheckToken").checked = false;
        localStorage.setItem("yesResourceCheckToken", false);
    }
    if (document.getElementById("noResourceCheckToken")) {
        document.getElementById("noResourceCheckToken").checked = true;
        localStorage.setItem("noResourceCheckToken", true);
    }
    if (document.getElementById("customTokenParametersCheck-yes")) {
        document.getElementById("customTokenParametersCheck-yes").checked = false;
        localStorage.setItem("customTokenParametersCheck-yes", false);
    }
    if (document.getElementById("customTokenParametersCheck-no")) {
        document.getElementById("customTokenParametersCheck-no").checked = true;
        localStorage.setItem("customTokenParametersCheck-no", true);
    }
    if (document.getElementById("token_postAuthStyleCheckToken")) {
        console.log("RCBJ0104");
        document.getElementById("token_postAuthStyleCheckToken").checked = true;
    }
    if (document.getElementById("token_headerAuthStyleCheckToken")) {
        console.log("RCBJ0105");
        document.getElementById("token_headerAuthStyleCheckToken").checked = false;
    }
    if (document.getElementById("refresh_postAuthStyleCheckToken")) {
        console.log("RCBJ0106");
        document.getElementById("refresh_postAuthStyleCheckToken").checked = true;
    }
    if (document.getElementById("refresh_headerAuthStyleCheckToken")) {
        console.log("RCBJ0107");
        document.getElementById("refresh_headerAuthStyleCheckToken").checked = false;
    }
    localStorage.setItem("refresh_post_auth_style", true);
    localStorage.setItem("token_initialize", true);
    token_initialize = true;
  }
  log.debug("Leaving initFields().");
}

function usePKCERFC()
{
  log.debug("Entering usePKCERFC().");
  var yesCheck = document.getElementById("usePKCE-yes").checked;
  var noCheck = document.getElementById("usePKCE-no").checked;
  log.debug("usePKCE-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if (yesCheck) {
    usePKCE = true;
  } else {
    usePKCE = false;
  }
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    document.getElementById("token_pkce_code_challenge_row").style.visibility = '';
    document.getElementById("token_pkce_code_verifier_row").style.visibility = '';
    document.getElementById("token_pkce_code_method_row").style.visibility = '';
  } else {
    log.debug("Hide PKCE Data fields.");
    document.getElementById("token_pkce_code_challenge_row").style.visibility = 'collapse';
    document.getElementById("token_pkce_code_verifier_row").style.visibility = 'collapse';
    document.getElementById("token_pkce_code_method_row").style.visibility = 'collapse';
  }

  recalculateTokenRequestDescription();
  log.debug("Leaving usePKCERFC().");
}

function getLSBooleanItem(key)
{
  return localStorage.getItem(key) === 'true';
}

function setPostAuthStyleCheckToken() {
  log.debug("Entering setPostAuthStyleCheckToken().");
  document.getElementById("token_postAuthStyleCheckToken").checked=true;
  document.getElementById("token_headerAuthStyleCheckToken").checked=false;
  localStorage.setItem("token_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleCheckToken().");
  return false;
}

function setHeaderAuthStyleCheckToken() {
  log.debug("Entering setHeaderAuthStyleCheckToken().");
  document.getElementById("token_postAuthStyleCheckToken").checked=false;
  document.getElementById("token_headerAuthStyleCheckToken").checked=true;
  localStorage.setItem("token_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleCheckToken().");
  return false;
}

function setPostAuthStyleRefreshToken() {
  log.debug("Entering setPostAuthStyleRefreshToken().");
  document.getElementById("refresh_postAuthStyleCheckToken").checked=true;
  document.getElementById("refresh_headerAuthStyleCheckToken").checked=false;
  localStorage.setItem("refresh_post_auth_style", true);
  return false;
}

function setHeaderAuthStyleRefreshToken() {
  log.debug("Entering setHeaderAuthStyleRefreshToken().");
  document.getElementById("refresh_postAuthStyleCheckToken").checked=false;
  document.getElementById("refresh_headerAuthStyleCheckToken").checked=true;
  localStorage.setItem("refresh_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleRefreshToken().");
  return false;
}

module.exports = {
  OnSubmitTokenEndpointForm,
  getParameterByName,
  resetUI,
  resetErrorDisplays,
  writeValuesToLocalStorage,
  loadValuesFromLocalStorage,
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
  regenerateState,
  regenerateNonce,
  recreateTokenDisplay,
  displayTokenCustomParametersCheck,
  generateCustomParametersListUI,
  onClickShowFieldSet,
  usePKCERFC,
  setPostAuthStyleCheckToken,
  setHeaderAuthStyleCheckToken,
  setPostAuthStyleRefreshToken,
  setHeaderAuthStyleRefreshToken
};
