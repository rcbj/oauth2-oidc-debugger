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
var displayOpenIDConnectArtifacts = true;
var useRefreshTokenTester = true;
var discoveryInfo = {};
var currentRefreshToken = '';
var usePKCE = true;

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
  var value = $("#authorization_grant_type").val();
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
      if($("#SSLValidate-yes").is(":checked"))
      {
        sslValidate = $("#SSLValidate-yes").val();
      } else if ($("#SSLValidate-no").is(":checked")) {
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
      var yesCheck = $("#yesResourceCheckToken").is(":checked");
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
      var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
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
                                          '<td><P><a href="/token_detail.html?type=access">Access Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=access">Introspect Token</a></P>' + 
                                          "</td><td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
        if(currentRefreshToken) {
           token_endpoint_result_html +=  "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=refresh">Refresh Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=refresh">Introspect Token</a></P>' +
                                          "</td><td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" + 
                                            currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html +=  "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=id">ID Token</a></P>' +
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
      var token_endpoint = $("#token_endpoint").val();
      var client_id = $("#refresh_client_id").val();
      var client_secret = $("#refresh_client_secret").val();
      if (client_secret == "undefined") {
        client_secret = "";
      }
      var refresh_token = $("#refresh_refresh_token").val();
      var grant_type = $("#refresh_grant_type").val();
      var scope = $("#refresh_scope").val();
      var sslValidate = "";
      if( $("#SSLValidate-yes").is(":checked"))
      {
        sslValidate = $("#SSLValidate-yes").val();
      } else if ($("#SSLValidate-no").is(":checked")) {
	sslValidate = $("#SSLValidate-no").val();
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
      if(!!$("#refresh-token-results-iteration-count").val())
      {
        iteration = parseInt($("#refresh-token-results-iteration-count").val()) + 1;
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
                                          '<td><P><a href="/token_detail.html?type=refresh_access">Access Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_access">Introspect Token</a></P>' +
                                          "</td><td><textarea rows=10 cols=60 name=refresh_access_token id=refresh_access_token>" + 
                                            data.access_token + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>" +
                                        "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=refresh_refresh">Refresh Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_refresh">Introspect Token</a></P>' +
                                          "</td><td><textarea rows=10 cols=60 name=refresh_refresh_token id=refresh_refresh_token>" + 
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
    $("#logout_post_redirect_uri").val('http://localhost:3000/logout.html');
    if( value == "client_credential")
    {
      $("#code").hide();
      $("#authzUsernameRow").hide();
      $("#authzPasswordRow").hide();
      $("#step2").hide();
      $("#step3").show();
      $("#token_grant_type").val("client_credentials");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#h2_title_2").innerHTML = "Obtain Access Token";
      $("#token_endpoint_result").html("");
      $("#display_token_request").show();
      $("#usePKCE-yes").prop("checked", false);
      $("#usePKCE-no").prop("checked", true);
      usePKCERFC();
      $("#step5").hide();
      $("#useRefreshToken-yes").prop("checked", false);
      $("#useRefreshToken-no").prop("checked", true);
      displayOpenIDConnectArtifacts = false;
      useRefreshTokenTester = false;
    }
    if( value == "resource_owner")
    {
      $("#code").hide();
      $("#authzUsernameRow").show();
      $("#authzPasswordRow").show();
      $("#step2").hide();
      $("#step3").show();
      $("#response_type").val("");
      $("#token_grant_type").val("password");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#h2_title_2").html("Obtain Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
    }
    resetErrorDisplays();
    $("#yesResourceCheckToken").prop("checked", false);
    $("#noResourceCheckToken").prop("checked", true);
    $("#customTokenParametersCheck-yes").prop("checked", false);
    $("#customTokenParametersCheck-no").prop("checked", true);
    $("#token_postAuthStyleCheckToken").prop("checked", true);
    $("#token_headerAuthStyleCheckToken").prop("checked", false);
    $("#refresh_postAuthStyleCheckToken").prop("checked", true);
    $("#refresh_headerAuthStyleCheckToken").prop("checked", false);

    recalculateTokenRequestDescription();
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
      localStorage.setItem("token_client_id", $("#token_client_id").val());
      localStorage.setItem("token_client_secret", $("#token_client_secret").val());
      localStorage.setItem("token_redirect_uri", $("#token_redirect_uri").val());
      localStorage.setItem("token_username", $("#token_username").val());
      localStorage.setItem("token_scope", $("#token_scope").val());
      localStorage.setItem("authorization_grant_type", $("#authorization_grant_type").val());
      localStorage.setItem("token_resource", $("#token_resource").val());
      localStorage.setItem("yesResourceCheckToken", $("#yesResourceCheckToken").is(":checked"));
      localStorage.setItem("noResourceCheckToken", $("#noResourceCheckToken").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts", $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts", $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("yesCheck", $("#SSLValidate-yes").is(":checked"));
      localStorage.setItem("noCheck", $("#SSLValidate-no").is(":checked"));
      localStorage.setItem("refresh_client_id", $("#refresh_client_id").val());
      localStorage.setItem("refresh_client_secret", $("#refresh_client_secret").val());
      localStorage.setItem("refresh_scope", $("#refresh_scope").val());
      localStorage.setItem("refresh_refresh_token", $("#refresh_refresh_token").val());
      localStorage.setItem("useRefreshToken_yes", $("#useRefreshToken-yes").is(":checked"));
      localStorage.setItem("useRefreshToken_no", $("#useRefreshToken-no").is(":checked"));
      localStorage.setItem("oidc_userinfo_endpoint", $("#oidc_userinfo_endpoint").val());
      localStorage.setItem("jwks_endpoint", $("#jwks_endpoint").val());
      localStorage.setItem("end_session_endpoint", $("#logout_end_session_endpoint").val());
      localStorage.setItem("logout_client_id", $("#logout_client_id").val());
      localStorage.setItem("customTokenParametersCheck-yes", $("#customTokenParametersCheck-yes").is(":checked"));
      localStorage.setItem("customTokenParametersCheck-no", $("#customTokenParametersCheck-no").is(":checked"));
      localStorage.setItem("tokenNumberCustomParameters", $("#tokenNumberCustomParameters").val());
      if ($("#token_postAuthStyleCheckToken").is(":checked") ||
         $("#refresh_postAuthStyleCheckToken").is(":checked")) {
        localStorage.setItem("token_post_auth_style", true);
      } else {
        localStorage.setItem("token_post_auth_style", false);
      }
      if ($("#customTokenParametersCheck-yes").is(":checked")) {
        var i = 0;
        var tokenNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
        for(i = 0; i < tokenNumberCustomParameters; i++)
        {
          log.debug("Writing customTokenParameterName-" + i + " as " + $("#customTokenParameterName-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterName-" + i, $("#customTokenParameterName-" + i).val());
          log.debug("Writing customTokenParameterValue-" + i + " as " + $("#customTokenParameterValue-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterValue-" + i, $("#customTokenParameterValue-" + i).val());
        }
      }
      localStorage.setItem("PKCE_code_challenge",$("#token_pkce_code_challenge").val());
      localStorage.setItem("PKCE_code_challenge_method", $("#token_pkce_code_method").val());
      localStorage.setItem("PKCE_code_verifier", $("#token_pkce_code_verifier").val() );
      localStorage.setItem("usePKCE_yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("usePKCE_no", $("#usePKCE-no").is(":checked"));
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
    $("#authorization_grant_type").val("authorization_grant");
    resetUI("authorization_grant");
  } else {
    $("#authorization_grant_type").val(authzGrantType);
    resetUI(authzGrantType);
  }
  $("#authorization_endpoint").val(localStorage.getItem("authorization_endpoint"));
  $("#token_endpoint").val(localStorage.getItem("token_endpoint"));

  if (localStorage.getItem("introspection_endpoint")) {
    $("#introspection_endpoint").val(localStorage.getItem("introspection_endpoint"));
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }
  $("#token_client_id").val(localStorage.getItem("client_id"));
  $("#token_client_secret").val(localStorage.getItem("client_secret"));
  $("#token_redirect_uri").val(localStorage.getItem("redirect_uri"));
  $("#token_scope").val(localStorage.getItem("token_scope"));
  $("#token_username").val(localStorage.getItem("token_username"));
  $("#token_resource").val(localStorage.getItem("token_resource"));
  $("#SSLValidate-yes").prop("checked", getLSBooleanItem("yesCheck"));
  $("#SSLValidate-no").prop("checked", getLSBooleanItem("noCheck"));
  $("#yesResourceCheckToken").prop("checked", getLSBooleanItem("yesResourceCheckToken"));
  $("#noResourceCheckToken").prop("checked", getLSBooleanItem("noResourceCheckToken"));
  $("#yesCheckOIDCArtifacts").prop("checked", getLSBooleanItem("yesCheckOIDCArtifacts"));
  $("#noCheckOIDCArtifacts").prop("checked", getLSBooleanItem("noCheckOIDCArtifacts"));
  $("#usePKCE-yes").prop("checked", getLSBooleanItem("usePKCE_yes"));
  $("#usePKCE-no").prop("checked", getLSBooleanItem("usePKCE_no"));
  $("#refresh_refresh_token").val(localStorage.getItem("refresh_refresh_token"));
  $("#refresh_client_id").val(localStorage.getItem("refresh_client_id"));
  $("#refresh_scope").val(localStorage.getItem("refresh_scope"));
  $("#refresh_client_secret").val(localStorage.getItem("refresh_client_secret"));
  $("#useRefreshToken-yes").prop("checked", getLSBooleanItem("useRefreshToken_yes"));
  $("#useRefreshToken-no").prop("checked", getLSBooleanItem("useRefreshToken_no"));
  $("#oidc_userinfo_endpoint").val(localStorage.getItem("oidc_userinfo_endpoint"));
  $("#jwks_endpoint").val(localStorage.getItem("jwks_endpoint"));
  $("#logout_end_session_endpoint").val(localStorage.getItem("end_session_endpoint"));
  $("#logout_client_id").val(localStorage.getItem("client_id"));
  $("#customTokenParametersCheck-yes").prop("checked", getLSBooleanItem("customTokenParametersCheck-yes"));
  $("#customTokenParametersCheck-no").prop("checked", getLSBooleanItem("customTokenParametersCheck-no"));
  $("#tokenNumberCustomParameters").val(localStorage.getItem("tokenNumberCustomParameters")? localStorage.getItem("tokenNumberCustomParameters"): 1);
  if (getLSBooleanItem("token_post_auth_style")) {
    $("#token_postAuthStyleCheckToken").prop("checked", true);
    $("#token_headerAuthStyleCheckToken").prop("checked", false);
  } else {
    $("#refresh_postAuthStyleCheckToken").prop("checked", false);
    $("#refresh_headerAuthStyleCheckToken").prop("checked", true);
  }

  currentRefreshToken = localStorage.getItem("refresh_refresh_token");
  if ($("#customTokenParametersCheck-yes").is(":checked")) {
    generateCustomParametersListUI();
    var i = 0;
    var tokenNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < tokenNumberCustomParameters; i++)
    {
      log.debug("Reading customTokenParameterName-" + i + " as " + localStorage.getItem("customTokenParameterName-" + i + "\n"));
      $("#customTokenParameterName-" + i).val(localStorage.getItem("customTokenParameterName-" + i));
      log.debug("Reading customTokenParameterValue-" + i + " as " + localStorage.getItem("customTokenParameterValue-" + i + "\n"));
      $("#customTokenParameterValue-" + i).val(localStorage.getItem("customTokenParameterValue-" + i));
    }
  }

  if ($("#usePKCE-yes").is(":checked")) {
    $("#token_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
    $("#token_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
    $("#token_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));
  }
  usePKCERFC();

  var agt = $("#authorization_grant_type").val();
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
    if($("#code").val() == "")
    {
      log.debug("code not yet set in next form. Doing so now.");
      $("#code").val(code);
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
    $("#authorization_endpoint_result").html(DOMPurify.sanitize("<fieldset>" +
                                                                "  <legend>Authorization Endpoint Results:</legend>" +
                                                                "  <table>" +
                                                                "    <tr>" +
                                                                "      <td>access_token</td>" +
                                                                "      <td>" +
                                                                "        <textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea>" +
                                                                "      </td>" +
                                                                "    </tr>" +
                                                                "  </table>" +
                                                                "</fieldset>"));
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
    $("#authorization_endpoint_id_token_result").html(DOMPurify.sanitize("<fieldset>" +
                                                                         "  <legend>Authorization Endpoint Results</legend>" +
                                                                         "  <table>" +
                                                                         "    <tr>" +
                                                                         "      <td>id_token</td>" +
                                                                         "      <td>" +
                                                                         "        <textarea id='implicit_flow_id_token' rows=5 cols=100>" + DOMPurify.sanitize(id_token) + "</textarea>" +
                                                                         "      </td>" +
                                                                         "    </tr>" +
                                                                         "  </table>" +
                                                                         "</fieldset>"));
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = $("#authorization_grant_type").val();
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
  var ta1 = $("#display_token_request_form_textarea1");
  var yesCheck = $("#yesResourceCheckToken").is(":checked");
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = $("#token_resource").val();
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  var customParametersComponent = "";
  var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck + ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) {
    const numberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++)
    {
       customParametersComponent = customParametersComponent +
                                   $("#customTokenParameterName-" + i).val() +
                                   '=' + $("#customTokenParameterValue-" + i).val() + "&" + "\n";
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (ta1 != null)
  {
    var grant_type = $("#token_grant_type").val();
    if(grant_type == "authorization_code")
    {
      $("#display_token_request_form_textarea1").val(                 "POST " + $("#token_endpoint").val() + "\n" +
								      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "code=" + $("#code").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val());
      if(usePKCE) {
        $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() +"&\n" + "code_verifier=" + $("#token_pkce_code_verifier").val());
      }
    } else if (grant_type == "client_credentials") {
      $("#display_token_request_form_textarea1").val(		      "POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val());
    } else if (grant_type == "password") {
      $("#display_token_request_form_textarea1").val(                 "POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "username=" + $("#token_username").val() + "&" + "\n" +
                                                                      "password=" + $("#token_password").val() + "&" + "\n" +
                                                                      "scope=" + $("#token_scope").val());
    }
    if ( resourceComponent.length > 0) {
       $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() + "&\n" + resourceComponent + "\n");
     }
     if (customParametersComponent.length > 0) {
       $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() + "&\n" +  customParametersComponent + "\n");
     }
  }
  log.debug("Leaving recalculateTokenRequestDescription().");
}

function recalculateRefreshRequestDescription()
{
  log.debug("Entering recalculateRefreshRequestDescription().");
  log.debug("update request field");
  var ta1 = $("#display_refresh_request_form_textarea1");
  var resourceComponent = "";

  if (ta1 != null)
  {
    var grant_type = $("#refresh_grant_type").val();
    if( grant_type == "refresh_token")
    {
      var client_secret = $("#refresh_client_secret").val();
      if( client_secret != "" &&
          client_secret != null &&
          client_secret != "null")
      {
        $("#display_refresh_request_form_textarea1").val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#refresh_grant_type").val() + "&" + "\n" +
                                                                      "refresh_token=" + $("#refresh_refresh_token").val() + "&" + "\n" +
                                                                      "client_id=" + $("#refresh_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#refresh_client_secret").val() + "&" + "\n" +
                                                                      "scope=" + $("#refresh_scope").val() + "\n"));
      } else {
        $("#display_refresh_request_form_textarea1").val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#refresh_grant_type").val() + "&" + "\n" +
                                                                      "refresh_token=" + $("#refresh_refresh_token").val() + "&" + "\n" +
                                                                      "client_id=" + $("#refresh_client_id").val() + "&" + "\n" +
                                                                      "scope=" + $("#refresh_scope").val() + "\n"));
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
  $("#code").val(getParameterByName('code'));
  $("#customTokenParametersCheck-yes").on("click", recalculateTokenRequestDescription);
  $("#customTokenParametersCheck-no").on("click", recalculateTokenRequestDescription);

  loadValuesFromLocalStorage();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();

  var yesCheckedToken = $("#yesResourceCheckToken").is(":checked");
  if(yesCheckedToken)
  {
    $("#authzTokenResourceRow").show();
  } else {
    $("#authzTokenResourceRow").hide();
  }
  if( $("#useRefreshToken-yes").is(":checked"))
  {
    useRefreshTokenTester = $("#useRefreshToken-yes").val();
  } else if ($("#useRefreshToken-no").is(":checked")) {
    useRefreshTokenTester = $("#useRefreshToken-no").val();
  } else {
    useRefreshTokenTester = true;
  }
  if(useRefreshTokenTester == true)
  {
    $("#step4").show();
  } else {
    $("#step4").hide();
  }
  var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
  if(tokencustomParametersCheck)
  {
    $("#tokenCustomParametersRow").show();
  } else {
    $("#tokenCustomParametersRow").hide();
  }

  var authzGrantType = localStorage.getItem("authorization_grant_type");
  if (authzGrantType == "client_credential") {
    usePKCE = false;
    $("#usePKCE-yes").prop("checked", false);
    $("#usePKCE-no").prop("checked", true);
    usePKCERFC();
  }

  displayTokenCustomParametersCheck();

  if(getParameterByName("redirectFromTokenDetail") == "true") {
    log.debug('Detected redirect back from token detail page.');
    $("#step3").hide();
    recreateTokenDisplay();
    $("#logout_id_token_hint").val(localStorage.getItem("token_id_token"));
  } else {
    // Clear all token values.
    localStorage.setItem("token_access_token", "");
    localStorage.setItem("token_id_token", "");
    localStorage.setItem("token_refresh_token", "");
    localStorage.setItem("refresh_access_token", "");
    localStorage.setItem("refresh_id_token", "");
    localStorage.setItem("refresh_refresh_token", "");
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
  var yesCheck = $("#yesCheck").is(":checked");
  var noCheck = $("#noCheck").is(":checked");
  log.debug("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if(yesCheck) {
    $("#authzResourceRow").show();
  } else if(noCheck) {
    $("#authzResourceRow").hide();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  log.debug("Entering displayTokenResourceCheck().");
  var yesCheck = $("#yesResourceCheckToken").is(":checked");
  var noCheck = $("#noResourceCheckToken").is(":checked");
  if( yesCheck) {
    $("#authzTokenResourceRow").show();
  } if(noCheck) {
    $("#authzTokenResourceRow").hide();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayTokenResourceCheck().");
}

$(function() {
$("#auth_step").submit(function () {
    log.debug("Entering auth_step submit function.");
    var resource = $("#resource").val();
    var yesCheck = $("#yesCheck").is(":checked");
    log.debug("yesCheck=" + yesCheck);
    log.debug("resource=" + resource);
    if(yesCheck == false)
    {
      $("#resource").prop("disabled", true); 
      $("#yesCheck").prop("disabled", true);
      $("#noCheck").prop("disabled", true);
    } else {
      $("#resource").prop("disabled", false);
      $("#yesCheck").prop("disabled", false);
      $("#noCheck").prop("disabled", false);
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
  var ta1 = $("#display_authz_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#response_type").val();
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
        $("#display_authz_error_form_textarea1").val(                         "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
      }
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //$("#display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/debugger2.html")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1").val(                         "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
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
  var ta1 = $("#display_token_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#token_grant_type").val();
    if( grant_type == "authorization_code")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1").val(                             "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n");
    } else if (grant_type == "client_credentials") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1").val(                         "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n");
    } else if (grant_type == "password") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1").val(                         "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n");
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
  var ta1 = $("#display_refresh_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#refresh_grant_type").val();
    if( grant_type == "refresh_token")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = JSON.parse(responseText);
      $("#display_refresh_error_form_textarea1").val(                           "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n");
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
  var yesCheck = $("#yesCheckOIDCArtifacts").is(":checked");
  var noCheck = $("#noCheckOIDCArtifacts").is("checked");
  log.debug("yesCheckOIDCArtifacts=" + yesCheck + ", noCheckOIDCArtifacts=" + noCheck + ", typeof=" + typeof(yesCheck));
  if(yesCheck) {
    displayOpenIDConnectArtifacts = true;
  } else if(noCheck) {
    displayOpenIDConnectArtifacts = false;
  } else {
    displayOpenIDConnectArtifacts = true;
  }
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  log.debug("Leaving displayOIDCArtifacts().");
}

function useRefreshTokens()
{
  log.debug("Entering useRefreshToken().");
  var yesCheck = $("#useRefreshToken-yes").is(":checked");
  var noCheck = $("#useRefreshToken-no").is(":checked");
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

function isUrl(url) {
  log.debug('Entering isUrl().');
  try {
    return Boolean(new URL(url));
  } catch(e) {
    log.debug('An error occurred: ' + e.stack);
    return false;
  }
}

function clearLocalStorage() {
  if (localStorage) {
    localStorage.setItem("token_client_secret", "");
    localStorage.setItem("refresh_client_secret", "");
  }
}

function regenerateState() {
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
}

function regenerateNonce() {
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
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
                                          '<td><P><a href="/token_detail.html?type=access">Access Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=access">Introspect Token</a></P>' + 
                                          "</td><td><textarea rows=10 cols=60 name=token_access_token id=token_access_token>" + 
                                            localStorage.getItem("token_access_token") + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(typeof refreshToken != "undefined" && refreshToken != "undefined") {
           token_endpoint_result_html += "<tr>" +
                                          '<td><P><a href="/token_detail.html?type=refresh">Refresh Token</a></P>' +
                                          '<P style="font-size:50%;"><a href="/introspection.html?type=refresh">Introspect Token</a></P>' +
                                          "</td><td><textarea rows=10 cols=60 name=token_refresh_token id=token_refresh_token>" + 
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
  var yesCheck = $("#customTokenParametersCheck-yes").is(":checked");
  var noCheck = $("#customTokenParametersCheck-no").is(":checked");
  log.debug("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" + noCheck);
  if(yesCheck) {
    $("#tokenCustomParametersRow").show();
    $("#customTokenParametersCheck-no").prop("checked", false);
    $("#customTokenParametersCheck-yes").prop("checked", true);
  } else if(noCheck) {
    $("#tokenCustomParametersRow").hide();
    $("#customTokenParametersCheck-yes").prop("checked", false);
    $("#customTokenParametersCheck-no").prop("checked", true);
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
      var j = parseInt($("#tokenNumberCustomParameters").val());
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
  if ($("#customTokenParametersCheck-yes").is(":checked")) {
    var i = 0;
    var authzNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      $("#customTokenParameterName-" + i).val(localStorage.getItem("customTokenParameterName-" + i));
      $("#customTokenParameterValue-" + i).val(localStorage.getItem("customTokenParameterValue-" + i));
      $("#customTokenParameterName-" + i).on("keypress", recalculateTokenRequestDescription);
      $("#customTokenParameterValue-" + i).on("keypress", recalculateTokenRequestDescription);

    }
  }
  recalculateTokenRequestDescription();
}

function onClickShowFieldSet(expand_button_id, field_set_id) {
  log.debug('Entering onClickShowConfigFieldSet(). expand_button_id='
    + expand_button_id + ', field_set_id=' + field_set_id
    + ', fieldset.style.display=' + $("#" + field_set_id).css("display")
    + ', expand_button.value=' + $("#" + expand_button_id).val());
  if($("#" + field_set_id).css("display") == 'block') {
    log.debug('Hide ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "none");
    $("#" + expand_button_id).val("Expand");
  } else {
    log.debug('Show ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "block");
    $("#" + expand_button_id).val("Hide");
  }
  $("#step0_expand_form").on("click", function(event) {
    event.preventDefault();
  });
  log.debug('Leaving onClickShowConfigFieldSet().');
  return false;
}

function initFields() {
  log.debug("Entering initFields().");
  var token_initialize = getLSBooleanItem("token_initialize");
  if(!token_initialize) {
    if ($("#yesResourceCheckToken")) {
        $("#yesResourceCheckToken").prop("checked", false);
        localStorage.setItem("yesResourceCheckToken", false);
    }
    if ($("#noResourceCheckToken")) {
        $("#noResourceCheckToken").prop("checked", true);
        localStorage.setItem("noResourceCheckToken", true);
    }
    if ($("#customTokenParametersCheck-yes")) {
        $("#customTokenParametersCheck-yes").prop("checked", false);
        localStorage.setItem("customTokenParametersCheck-yes", false);
    }
    if ($("#customTokenParametersCheck-no")) {
        $("#customTokenParametersCheck-no").prop("checked", true);
        localStorage.setItem("customTokenParametersCheck-no", true);
    }
    if ($("#token_postAuthStyleCheckToken")) {
        $("#token_postAuthStyleCheckToken").prop("checked", true);
    }
    if ($("#token_headerAuthStyleCheckToken")) {
        $("#token_headerAuthStyleCheckToken").prop("checked", false);
    }
    if ($("#refresh_postAuthStyleCheckToken")) {
        $("#refresh_postAuthStyleCheckToken").prop("checked", true);
    }
    if ($("#refresh_headerAuthStyleCheckToken")) {
        $("#refresh_headerAuthStyleCheckToken").prop("checked", false);
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
  if ($("#usePKCE-yes").is(":checked")) {
    usePKCE = true;
  } else {
    usePKCE = false;
  }
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    $("#token_pkce_code_challenge_row").show();
    $("#token_pkce_code_verifier_row").show();
    $("#token_pkce_code_method_row").show();
  } else {
    log.debug("Hide PKCE Data fields.");
    $("#token_pkce_code_challenge_row").hide();
    $("#token_pkce_code_verifier_row").hide();
    $("#token_pkce_code_method_row").hide();
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
  $("#token_postAuthStyleCheckToken").prop("checked", true);
  $("#token_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("token_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleCheckToken().");
  return false;
}

function setHeaderAuthStyleCheckToken() {
  log.debug("Entering setHeaderAuthStyleCheckToken().");
  $("#token_postAuthStyleCheckToken").prop("checked", false);
  $("#token_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("token_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleCheckToken().");
  return false;
}

function setPostAuthStyleRefreshToken() {
  log.debug("Entering setPostAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", true);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("refresh_post_auth_style", true);
  return false;
}

function setHeaderAuthStyleRefreshToken() {
  log.debug("Entering setHeaderAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", false);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", true);
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
  isUrl,
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
