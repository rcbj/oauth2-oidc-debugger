// File: debugger.js
// Author: Robert C. Broeckelmann Jr.
// Date: 06/15/2017
// Notes:
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var DOMPurify = require("dompurify");
var $ = require("jquery");
console.log("logLevel: " + appconfig.logLevel);
var log = bunyan.createLogger({ name: 'debugger',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
var displayOpenIDConnectArtifacts = true;
var useRefreshTokenTester = true;
var usePKCE = true;
var displayStep0 = true;
var displayStep1 = true;
var displayStep2 = true;
var displayStep3 = true;
var displayStep4 = true;
var displayStep5 = true;
var discoveryInfo = {};
var initialized = false;

function OnSubmitForm()
{
  log.debug("Entering OnSubmitForm().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving OnSubmitForm().");
  return true;
}

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
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

$(document).ready(function() {
  log.debug("Entering ready function.");
  // Eliminating use of window.onload function.
  onload();
  $("#authorization_grant_type").change(function() {
    log.debug("Entering selection changed function().");
    var value = $(this).val();
    resetUI(value);
    recalculateAuthorizationRequestDescription();
    if(value == "client_credential") {
      writeValuesToLocalStorage();
      window.location.href = "/debugger2.html";
    }
    log.debug("Leaving selection changed function().");
  });
  var value = $("#authorization_grant_type").val();
  resetUI(value);
  if( value == "client_credential") {
    writeValuesToLocalStorage();
    window.location.href = "/debugger2.html";
  }
  recalculateAuthorizationRequestDescription();
  initializeUIPostDebuggerInitialization();
  log.debug("Leaving ready function.");
});

function initializeUIPostDebuggerInitialization()
{
  log.debug("Entering initializeUIPostDebuggerInitialization().");
  var debuggerInitialized = false;
  if (localStorage) {
    debuggerInitialized = getLSBooleanItem("debugger_initialized");
  }
  log.debug("debugger_initialized: " + debuggerInitialized);
  if (debuggerInitialized) {
    log.debug("The debugger configuration has been initialized through Discovery.");
    document.getElementById("oidc_fieldset").style.display = "none";
    document.getElementById("oidc_expand_button").value = "Expand";
    document.getElementById("config_fieldset").style.display = "none";
    document.getElementById("config_expand_button").value = "Expand";
    document.getElementById("authz_fieldset").style.display = "block";
    document.getElementById("authz_expand_button").value = "Collapse";
  }
  log.debug("Leaving initializeUIPostDebuggerInitialization().");
}

function resetUI(value)
{
    log.debug("Entering resetUI().");
    if( value == "implicit_grant" )
    {
      $("#code").hide();
      if(document.getElementById("authzUsernameRow")) {
        document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      }
      if(document.getElementById("authzPasswordRow")) {
        document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      }
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
      if(document.getElementById("authzUsernameRow")) {
        document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      }
      if(document.getElementById("authzPasswordRow")) {
        document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      }
      $("#step2").hide();
      $("#nonce").hide();
      document.getElementById("response_type").value = "";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      writeValuesToLocalStorage();     
      usePKCE = false;
//      window.location.href = "/debugger2.html";
    }
    if( value == "resource_owner")
    {
      $("#code").hide();
      if(document.getElementById("authzUsernameRow")) {
        document.getElementById("authzUsernameRow").style.visibility = '';
      }
      if(document.getElementById("authzPasswordRow")) {
        document.getElementById("authzPasswordRow").style.visibility = '';
      }
      $("#step2").hide();
      $("#step3").show();
      $("#nonce").hide();
      document.getElementById("response_type").value = "";
      document.getElementById("token_grant_type").value = "password";
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
    }
    if( value == "authorization_grant")
    {
      $("#code").show();
      $("#step2").show();
      $("#step3").show();
      $("#nonce").hide();
      document.getElementById("response_type").value = "code";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
    }
    if ( value == "oidc_implicit_flow")
    {
      $("#code").hide();
      if(document.getElementById("authzUsernameRow")) {
        document.getElementById("authzUsernameRow").style.visibility = 'collapse';
      }
      if(document.getElementById("authzPasswordRow")) {
        document.getElementById("authzPasswordRow").style.visibility = 'collapse';
      }
      $("#step2").show();
      $("#step3").hide();
      $("#nonce").show();
      document.getElementById("response_type").value = "id_token token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
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
      $("#step2").show();
      $("#step3").hide();
      $("#nonce").show();
      document.getElementById("response_type").value = "id_token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
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
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
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
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code id_token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      if(document.getElementById("code")){
        document.getElementById("code").value = "";
      };
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
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
      $("#step2").show();
      $("#step3").show();
      $("#nonce").show();
      document.getElementById("response_type").value = "code id_token token";
      document.getElementById("scope").value = "openid profile";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      document.getElementById("h2_title_1").innerHTML = "Request Authorization Code";
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = true;
    }
    resetErrorDisplays();
    log.debug("Leaving resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  $("#display_authz_error_class").html("");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
      localStorage.setItem("authorization_grant_type", document.getElementById("authorization_grant_type").value);
      localStorage.setItem("yesCheck", document.getElementById("SSLValidate-yes").checked);
      localStorage.setItem("noCheck", document.getElementById("SSLValidate-no").checked);
      localStorage.setItem("yesResourceCheck", document.getElementById("yesResourceCheck").checked);
      localStorage.setItem("noResourceCheck", document.getElementById("noResourceCheck").checked);
      localStorage.setItem("yesCheckOIDCArtifacts", document.getElementById("yesCheckOIDCArtifacts").checked);
      localStorage.setItem("noCheckOIDCArtifacts", document.getElementById("noCheckOIDCArtifacts").checked);
      localStorage.setItem("useRefreshToken_yes", document.getElementById("useRefreshToken-yes").checked);
      localStorage.setItem("usePKCE_yes", document.getElementById("usePKCE-yes").checked);
      localStorage.setItem("client_id", document.getElementById("client_id").value);
      localStorage.setItem("redirect_uri", document.getElementById("redirect_uri").value);
      localStorage.setItem("scope", document.getElementById("scope").value);
      localStorage.setItem("useRefreshToken_no", document.getElementById("useRefreshToken-no").checked);
      localStorage.setItem("usePKCE_no", document.getElementById("usePKCE-no").checked);
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
          if(document.getElementById("customParameterName-" + i)){
            log.debug("Writing customParameterName-" + i + " as " + document.getElementById("customParameterName-" + i).value + "\n");
            localStorage.setItem("customParameterName-" + i, document.getElementById("customParameterName-" + i).value);
            log.debug("Writing customParameterValue-" + i + " as " + document.getElementById("customParameterValue-" + i).value + "\n");
            localStorage.setItem("customParameterValue-" + i, document.getElementById("customParameterValue-" + i).value);
          };
        }
      }
      setPKCEValues();
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function initValuesToLocalStorage()
{
  log.debug("Entering initValuesToLocalStorage().");
  var initialized = getLSBooleanItem("initialized");
  if (localStorage && !initialized) {
      localStorage.setItem("authorization_grant_type", "oidc_authorization_code_flow");
      localStorage.setItem("authorization_endpoint", "https://localhost/oauth2/authorization");
      localStorage.setItem("token_endpoint","https://localhost/oauth2/token");
      localStorage.setItem("yesResourceCheck", false);
      localStorage.setItem("noResourceCheck", true);
      localStorage.setItem("yesCheck", true);
      localStorage.setItem("noCheck", false);
      localStorage.setItem("yesCheckOIDCArtifacts", true);
      localStorage.setItem("noCheckOIDCArtifacts", false);
      localStorage.setItem("useRefreshToken_yes", true);
      localStorage.setItem("usePKCE_yes", true);
      localStorage.setItem("client_id", "abcxyz");
      localStorage.setItem("redirect_uri", "http://localhost:3000/callback");
      localStorage.setItem("scope", "openid profile");
      localStorage.setItem("useRefreshToken_no", false);
      localStorage.setItem("usePKCE_no", false);
      localStorage.setItem("oidc_discovery_endpoint", "https://localhost/oidc/.well-known");
      localStorage.setItem("oidc_userinfo_endpoint", "https://localhost/oidc/userinfo");
      localStorage.setItem("jwks_endpoint", "https://localhost/oidc/.well-known/jwks");
      localStorage.setItem("authzcustomParametersCheck-yes", false);
      localStorage.setItem("authzcustomParametersCheck-no", true);
      localStorage.setItem("authzNumberCustomParameters", 1);
      if (document.getElementById("authzcustomParametersCheck-yes").checked) {
        var i = 0;
        var authzNumberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);
        for(i = 0; i < authzNumberCustomParameters; i++)
        {
          log.debug("Writing customParameterName-" + i + " as " + "xyz" + "\n");
          localStorage.setItem("customParameterName-" + i, "xyz");
          log.debug("Writing customParameterValue-" + i + " as " + "xyz" + "\n");
          localStorage.setItem("customParameterValue-" + i, "xyz");
        }
      }
      setPKCEValues();
      localStorage.setItem("initialized", "true");
      initialized = true;
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  var authzGrantType = localStorage.getItem("authorization_grant_type");
  log.debug("authzGrantType=" + authzGrantType);
  if ( authzGrantType == "" || 
       typeof(authzGrantType) == "undefined" || 
       authzGrantType == "null" ||
       authzGrantType == "undefined")
  {
    $("#authorization_grant_type").val("oidc_authorization_code_flow");
    resetUI("authorization_grant");
  } else {
    $("#authorization_grant_type").val(authzGrantType);
    resetUI(authzGrantType);
  }
  console.log("RCBJ0001");
  $("#authorization_endpoint").val(localStorage.getItem("authorization_endpoint"));
  $("#token_endpoint").val(localStorage.getItem("token_endpoint"));
  $("#redirect_uri").val(localStorage.getItem("redirect_uri"));
  $("#client_id").val(localStorage.getItem("client_id"));
  $("#scope").val(localStorage.getItem("scope"));
  $("#resource").val(localStorage.getItem("resource"));
  $("#SSLValidate-yes").prop("checked", getLSBooleanItem("yesCheck"));
  $("#SSLValidate-no").prop("checked", getLSBooleanItem("noCheck"));
  $("#yesResourceCheck").prop("checked", getLSBooleanItem("yesResourceCheck"));
  $("#noResourceCheck").prop("checked", getLSBooleanItem("noResourceCheck"));
  $("#yesCheckOIDCArtifacts").prop("checked", getLSBooleanItem("yesCheckOIDCArtifacts"));
  $("#noCheckOIDCArtifacts").prop("checked", getLSBooleanItem("noCheckOIDCArtifacts"));
  $("#useRefreshToken-yes").prop("checked", getLSBooleanItem("useRefreshToken_yes"));
  $("#useRefreshToken-no").prop("checked", getLSBooleanItem("useRefreshToken_no"));
  $("#usePKCE-yes").prop("checked", getLSBooleanItem("usePKCE_yes"));
  $("#usePKCE-no").prop("checked", getLSBooleanItem("usePKCE_no"));
  $("#oidc_discovery_endpoint").val(localStorage.getItem("oidc_discovery_endpoint"));
  $("#oidc_userinfo_endpoint").val(localStorage.getItem("oidc_userinfo_endpoint"));
  $("#jwks_endpoint").val(localStorage.getItem("jwks_endpoint"));
  $("#authzcustomParametersCheck-yes").prop("checked", getLSBooleanItem("authzcustomParametersCheck-yes"));
  $("#authzcustomParametersCheck-no").prop("checked", getLSBooleanItem("authzcustomParametersCheck-no"));
  $("#authzNumberCustomParameters").val(localStorage.getItem("authzNumberCustomParameters")? localStorage.getItem("authzNumberCustomParameters") : 1);

  $("#authz_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
  $("#authz_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
  $("#authz_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));

  recalculateAuthorizationRequestDescription();

  if ($("#authzcustomParametersCheck-yes").is(":checked")) {
    generateCustomParametersListUI();
    var i = 0;
    var authzNumberCustomParameters = parseInt($("#authzNumberCustomParameters").val());  
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      log.debug("Reading customParameterName-" + i + " as " + localStorage.getItem("customParameterName-" + i + "\n"));
      $("#customParameterName-" + i).val(localStorage.getItem("customParameterName-" + i));
      log.debug("Reading customParameterValue-" + i + " as " + localStorage.getItem("customParameterValue-" + i + "\n"));
      $("#customParameterValue-" + i).val(localStorage.getItem("customParameterValue-" + i));
    }
  }
  setPKCEValues();
  console.log("RCBJ0002");
  var agt = $("#authorization_grant_type").val();

  var pathname = window.location.pathname;
  log.debug("agt=" + agt);
  log.debug("pathname=" + pathname);
  if (  (agt ==  "authorization_grant" || 
         agt == "oidc_hybrid_code_id_token" || 
         agt == "oidc_hybrid_code_token" || 
         agt == "oidc_hybrid_code_id_token_token" ) &&
	pathname == "/callback")
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
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
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
        pathname == "/callback") //retrieve access code and id_token that is returned from authorization endpoint.
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
        pathname == "/callback") //retrieve access code that is returned from authorization endpoint.
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
    $("#authorization_endpoint_result").html(DOMPurify.sanitize("<fieldset>"
    + "<legend>Authorization Endpoint Results:</legend>"
    + "<table>"
    +   "<tr>"
    +     "<td>access_token</td>"
    +     "<td>"
    +       "<textarea id='implicit_grant_access_token' rows=5 cols=100>"
    +         access_token
    +       "</textarea>"
    +     "</td>"
    +   "</tr>"
    + "</table>"
    + "</fieldset>"));
  }
  if ( 	(agt == "oidc_implicit_flow" || agt == "oidc_implicit_flow_id_token" ||  agt == "oidc_hybrid_code_id_token") && 
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
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
    $("#authorization_endpoint_id_token_result").html(DOMPurify.sanitize("<fieldset>"
      +  "<legend>Authorization Endpoint Results</legend>"
      +  "<table>"
      +      "<tr>"
      +        "<td>id_token</td>"
      +        "<td>" 
      +          "<textarea id='implicit_flow_id_token' rows=5 cols=100>"
      +            id_token
      +          "</textarea>"
      +        "</td>"
      +      "</tr>"
      +    "</table>"
      +  "</fieldset>"));
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = $("#authorization_grant_type").val();
  if(	pathname == "/callback" && 
	(authzGrantType == "authorization_grant" || authzGrantType == "implicit_grant" || authzGrantType == "oidc_hybrid_code_id_token") &&
	(error != null && error != "null" && typeof error != "undefined" && error != ""))
  {
    $("#display_authz_error_class").html(DOMPurify.sanitize("<fieldset>"
       + "<legend>Authorization Endpoint Error</legend><form action=''"
       + "name='display_authz_error_form'" 
       + "id='display_authz_error_form'>"
       + "<table>"
       +   "<tr>"
       +     "<td>"
       +       "<label name='display_authz_error_form_label1'"
       +         " value='' id='display_authz_error_form_label1'>Error</label>"
       +     "</td>"
       +     "<td>"
       +       "<textarea rows='10' cols='100'"
       +         " id='display_authz_error_form_textarea1'>"
       +     "</td>"
       +   "</tr>"
       + "</table>"
       + "</textarea></form></fieldset>"));
  }
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function recalculateAuthorizationRequestDescription()
{
  log.debug("Entering recalculateAuthorizationRequestDescription().");
  log.debug("update request field");
  var ta1 = document.getElementById("display_authz_request_form_textarea1");
  log.debug("ta1=" + ta1);
  var yesCheck = document.getElementById("yesResourceCheck").checked;
  log.debug("yesCheck=" + yesCheck);
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = document.getElementById("resource").value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  log.debug("resourceComponent=" + resourceComponent);
  var customParametersComponent = "";
  var authzcustomParametersCheck = document.getElementById("authzcustomParametersCheck-yes").checked;
  log.debug("authzcustomParametersCheck: " + authzcustomParametersCheck + ", type=" + typeof(authzcustomParametersCheck));
  if(authzcustomParametersCheck) {
    const numberCustomParameters = parseInt(document.getElementById("authzNumberCustomParameters").value);
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++) 
    {
         try {
           customParametersComponent = customParametersComponent +
                                       document.getElementById("customParameterName-" + i).value +
                                       '=' + document.getElementById("customParameterValue-" + i).value + "&" + "\n";
         } catch (e) {
           log.error("Unable to read custom parameter. Skipping.");
         }
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (ta1 != null)
  {
    var grant_type = document.getElementById("response_type").value;
    log.debug("grant_type=" + grant_type);
    if( grant_type == "code" ||
	grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      document.getElementById("display_authz_request_form_textarea1").value = "GET " + document.getElementById("authorization_endpoint").value + "?" + "\n" +
                                                                      "state=" + document.getElementById("state").value + "&" + "\n" +
                                                                      "nonce=" + document.getElementById("nonce_field").value + "&" + "\n" +
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
       if (usePKCE) {
         document.getElementById("display_authz_request_form_textarea1").value += "&\n" + "code_challenge=" + document.getElementById("authz_pkce_code_challenge").value  + "&\n" +
                                                                                          "code_challenge_method=" + document.getElementById("authz_pkce_code_method").value
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
  log.debug('display_authz_request_form_textarea1=' + document.getElementById("display_authz_request_form_textarea1").value);
  log.debug("Leaving recalculateAuthorizationRequestDescription().");
}

function triggerAuthZEndpointCall()
{
  log.debug("Entering triggerAuthZEndpointCall().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  window.location.href = DOMPurify.sanitize(document.getElementById("display_authz_request_form_textarea1").value.substring(4, 
    document.getElementById("display_authz_request_form_textarea1").value.length
  ).replace("\n",""));
  log.debug("Leaving triggerAuthZEndpointCall().");
}

function recalculateTokenRequestDescription()
{
  log.debug("Entering recalculateTokenRequestDescription().");
  log.debug("update request field");
  var ta1 = document.getElementById("display_token_request_form_textarea1");
  var yesCheck = false;
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
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
  log.debug("Leaving recalculateRefreshRequestDescription().");
}

function onload() {
  log.debug("Entering onload function.");
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
  document.getElementById("yesResourceCheck").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("noResourceCheck").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("yesCheckOIDCArtifacts").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("noCheckOIDCArtifacts").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("authzcustomParametersCheck-yes").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("authzcustomParametersCheck-no").addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById("usePKCE-yes").addEventListener("onClick", usePKCERFC());
  document.getElementById("usePKCE-no").addEventListener("onClick", usePKCERFC());

  // Set initial values in case this is the first time the page was hit
  onSubmitClearAllForms(); 
  initValuesToLocalStorage();

  if (localStorage) {
    // Add an event listener for form submissions
    document.getElementById("auth_step").addEventListener("submit", function() {
      log.debug("Entering auth_step submit event listner function.");
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
      localStorage.setItem("usePKCE-yes", document.getElementById("usePKCE-yes").checked );
      localStorage.setItem("usePKCE-no", document.getElementById("usePKCE-no").checked );
      log.debug("Leaving auth_step submit event listener function.");
    });
  }
  loadValuesFromLocalStorage();
  generateCustomParametersListUI
  recalculateAuthorizationRequestDescription();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();
  var yesChecked = document.getElementById("yesResourceCheck").checked;
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
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    document.getElementById("authz_pkce_code_challenge_row").style.visibility = '';
    document.getElementById("authz_pkce_code_verifier_row").style.visibility = '';
    document.getElementById("authz_pkce_code_method_row").style.visibility = '';
  } else {
    log.debug("Hide PKCE Data fields.");
    document.getElementById("authz_pkce_code_challenge_row").style.visibility = 'collapse';
    document.getElementById("authz_pkce_code_verifier_row").style.visibility = 'collapse';
    document.getElementById("authz_pkce_code_method_row").style.visibility = 'collapse';
  }

  if (usePKCE) {
    document.getElementById("authz_pkce_code_challenge").value = localStorage.getItem("PKCE_code_challenge");
    document.getElementById("authz_pkce_code_verifier").value = localStorage.getItem("PKCE_code_verifier");
    document.getElementById("authz_pkce_code_method").value =  localStorage.getItem("PKCE_code_challenge_method");
  }
  recalculateAuthorizationRequestDescription();

  var type = document.getElementById("response_type").value;
  if(type == "client_credential") {
    window.location.href = "/debugger2.html";
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
  var yesCheck = document.getElementById("yesResourceCheck").checked;
  var noCheck = document.getElementById("noResourceCheck").checked;
  log.debug("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if(yesCheck) {
    document.getElementById("authzResourceRow").style.visibility = '';
  } else if(noCheck) {
    document.getElementById("authzResourceRow").style.visibility = "collapse"
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  log.debug("Entering displayTokenResourceCheck().");
  var yesCheck = document.getElementById("yesCheckToken").checked;
  var noCheck = document.getElementById("noCheckToken").checked;
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
    log.debug("Registered auth_step submit function.");
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
      log.debug("pathname=" + pathname);
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
                                               "<td><textarea rows=\"10\" cols=\"100\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class").html(display_token_error_class_html);
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
                                             "<td><textarea rows=\"10\" cols=\"100\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(display_refresh_error_class);
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
  log.debug("Entering parseFragment().");
  log.debug("hash=" + window.location.hash);
  var hash = window.location.hash.substr(1);

  var result = hash.split("&").reduce(function (result, item) {
      var parts = item.split("=");
      result[parts[0]] = parts[1];
      return result;
  }, {});
  log.debug("Leaving parseFragment().");
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
    document.getElementById("authz_pkce_code_challenge_row").style.visibility = '';
    document.getElementById("authz_pkce_code_verifier_row").style.visibility = '';
    document.getElementById("authz_pkce_code_method_row").style.visibility = '';
    document.getElementById("authz_pkce_code_challenge").value = localStorage.getItem("PKCE_code_challenge");
    document.getElementById("authz_pkce_code_verifier").value = localStorage.getItem("PKCE_code_verifier");
    document.getElementById("authz_pkce_code_method").value =  localStorage.getItem("PKCE_code_challenge_method");
  } else {
    log.debug("Hide PKCE Data fields.");
    document.getElementById("authz_pkce_code_challenge_row").style.visibility = 'collapse';
    document.getElementById("authz_pkce_code_verifier_row").style.visibility = 'collapse';
    document.getElementById("authz_pkce_code_method_row").style.visibility = 'collapse';
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving usePKCERFC().");
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
  var endSessionEndpoint = discoveryInfo["end_session_endpoint"];
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
  log.debug("endSessionEndpoint: " + endSessionEndpoint);
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
                                           '<input class="btn_oidc_populate_meta_data" type="button" value="Populate Meta Data" onclick="return debug.onSubmitPopulateFormsWithDiscoveryInformation();"/>' +
                                         '</td>' +
                                       '</form>' +
                                       '</table>';
  $("#discovery_info_meta_data_populate").html(discovery_info_meta_data_html);
  $("#discovery_info_table").html(discovery_info_table_html);
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
      localStorage.setItem("debugger_initialized", true);
  }
  log.debug('Leaving OnSubmitPopulateFormsWithDiscoveryInformation().');
  return true;
}

// Reset all forms and clear local storage
function onSubmitClearAllForms() {
  log.debug("Entering onSubmitClearAllForms().");
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
  if (document.getElementById("SSLValidate-yes")) {
    document.getElementById("SSLValidate-yes").checked = true;
  }
  if (document.getElementById("SSLValidate-no")) {
    document.getElementById("SSLValidate-no").checked = false;
  }
  if (document.getElementById("yesCheckOIDCArtifacts")) {
    document.getElementById("yesCheckOIDCArtifacts").checked = true;
  }
  if (document.getElementById("noCheckOIDCArtifacts")) {
    document.getElementById("noCheckOIDCArtifacts").checked = false;
  }
  if (document.getElementById("useRefreshToken-yes")) {
    document.getElementById("useRefreshToken-yes").checked = true;
  }
  if (document.getElementById("useRefreshToken-no")) {
    document.getElementById("useRefreshToken-no").checked = false;
  }
  if (document.getElementById("usePKCE-yes")) {
    document.getElementById("usePKCE-yes").checked = true;
  }
  if (document.getElementById("usePKCE-no")) {
    document.getElementById("usePKCE-no").checked = false;
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
  log.debug("Leaving onSubmitClearAllForms().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
  log.debug("Leaving regenerateState().");
}

function regenerateNonce() {
  log.debug("Entering regenerateNonce().");
  document.getElementById("nonce_field").value = generateUUID();
  localStorage.setItem('nonce_field', document.getElementById("nonce_field").value);
  log.debug("Leaving regenerateNonce().");
}

function displayAuthzCustomParametersCheck()
{
  log.debug("Entering displayAuthzCustomParametersCheck().");
  var yesCheck = document.getElementById("authzcustomParametersCheck-yes").checked;
  var noCheck = document.getElementById("authzcustomParametersCheck-no").checked;
  log.debug("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" + noCheck);
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
  log.debug("Leaving displayAuthzCustomParametersCheck()");
}

function generateCustomParametersListUI()
{
  log.debug("Entering generateCustomParametersListUI().");
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
            '<input class="stored" id="' + 'customParameterName-' + i + '" name="' + 'customParameterName-' + i + '" type="text" maxlength="64" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customParameterValue-' + i + '" name="' + 'customParameterValue-' + i + '" type="text" maxlength="128" size="64" />' +
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
      document.getElementById("customParameterName-" + i).value = localStorage.getItem("customParameterName-" + i);
      document.getElementById("customParameterValue-" + i).value = localStorage.getItem("customParameterValue-" + i);
    }
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving generateCustomParametersListUI().");
}

function onClickShowAuthzFieldSet(id) {
  log.debug('Entering onClickShowAuthzFieldSet(). id=' + id + ', style.display=' + document.getElementById(id).style.display);
  if(id == 'authz_fieldset') {
    if(document.getElementById(id).style.display == 'block') {
       log.debug('Hide ' + id + '.');
       document.getElementById(id).style.display = 'none'
       document.getElementById('authz_expand_button').value='Expand';
       document.getElementById('config_fieldset').style.display = 'block'
       document.getElementById('config_expand_button').value='Collapse';
       document.getElementById('oidc_fieldset').style.display = 'block'
       document.getElementById('oidc_expand_button').value='Collapse';
    } else {
      log.debug('Show ' + id + '.');
      document.getElementById(id).style.display = 'block';
      document.getElementById('authz_expand_button').value='Collapse';
      document.getElementById('config_fieldset').style.display = 'none'
      document.getElementById('config_expand_button').value='Expand';
      document.getElementById('oidc_fieldset').style.display = 'none';
      document.getElementById('oidc_expand_button').value='Expand';
    }
  } else {
    if(document.getElementById(id).style.display == 'block') {
      log.debug('Hide ' + id + '.');
      document.getElementById(id).style.display = 'none'
      document.getElementById("oidc_expand_button").value='Expand';
    } else {
      log.debug('Show ' + id + '.');
      document.getElementById(id).style.display = 'block';
      document.getElementById("oidc_expand_button").value='Hide';
    }
  }
  log.debug('Leaving onClickShowAuthzFieldSet().');
  return false;
}

function onClickShowConfigFieldSet(id) {
  log.debug('Entering onClickShowConfigFieldSet(). id=' + id + ', style.display=' + document.getElementById(id).style.display);
  if(document.getElementById(id).style.display == 'block') {
     document.getElementById('config_expand_button').value='Expand';
  } else {
    document.getElementById('config_expand_button').value='Hide';
  }
  if(document.getElementById(id).style.display == 'block') {
    log.debug('Hide ' + id + '.');
    document.getElementById(id).style.display = 'none'
  } else {
    log.debug('Show ' + id + '.');
    document.getElementById(id).style.display = 'block';
  }
  log.debug('Leaving onClickShowConfigFieldSet().');
  return false;
}

function onClickClearLocalStorage()
{
  log.debug("Entering onClickClearLocalStorage().");
  if (localStorage) {
    localStorage.clear(); 
  }
  onSubmitClearAllForms();
  log.debug("Leaving onClickClearLocalStorage().");
  return false;
}

function generateCodeChallenge(codeVerifier) {
  log.debug("Entering generateCodeChallenge().");
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256');
  log.debug("Leaving generateCodeChallenge().");
  return hash.update(codeVerifier).digest("base64").replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

//function generatePKCECodeVerifier()
function setPKCEValues()
{
  log.debug("Entering setPKCEValues().");
  var code_verifier = Buffer.from(generateUUID() + generateUUID(),'binary').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  log.debug("code_verifier: " + code_verifier);
  var code_challenge = generateCodeChallenge(code_verifier);
  log.debug("code_challenge: " + code_challenge);
  localStorage.setItem("PKCE_code_challenge", code_challenge);
  localStorage.setItem("PKCE_code_challenge_method", "S256");
  localStorage.setItem("PKCE_code_verifier", code_verifier );
  document.getElementById("authz_pkce_code_challenge").value = localStorage.getItem("PKCE_code_challenge");
  document.getElementById("authz_pkce_code_verifier").value = localStorage.getItem("PKCE_code_verifier");
  document.getElementById("authz_pkce_code_method").value =  localStorage.getItem("PKCE_code_challenge_method");
  recalculateAuthorizationRequestDescription();
  log.debug("leaving setPKCEValues().");
  return code_challenge
}

function getLSBooleanItem(key)
{
  return localStorage.getItem(key) === 'true';
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
  onClickClearLocalStorage,
  usePKCERFC
};
