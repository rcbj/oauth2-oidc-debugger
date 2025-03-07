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
    $("#oidc_fieldset").hide();
    $("#oidc_expand_button").val("Expand");
    $("#config_fieldset").hide();
    $("#config_expand_button").val("Expand");
    $("#authz_fieldset").show();
    $("#authz_expand_button").val("Collapse");
  }
  log.debug("Leaving initializeUIPostDebuggerInitialization().");
}

function resetUI(value)
{
    log.debug("Entering resetUI().");
    if( value == "implicit_grant" )
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("token");
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#token_grant_type").val("");
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").hide();
    }
    if( value == "authorization_grant")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").hide();
      $("#response_type").val("code");
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#display_authz_request_class").show();
    }
    if ( value == "oidc_implicit_flow")
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("id_token token");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if ( value == "oidc_implicit_flow_id_token")
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("id_token");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_authorization_code_flow")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("code");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("code id_token");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      if($("#code")){
        $("#code").val("");
      };
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("code token");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("response_type").val("code id_token token");
      if($("scope").val() == "") {
        $("scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
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
      localStorage.setItem("authorization_grant_type", $("#authorization_grant_type").val());
      localStorage.setItem("yesCheck", $("#SSLValidate-yes").is(":checked"));
      localStorage.setItem("noCheck", $("#SSLValidate-no").is(":checked"));
      localStorage.setItem("yesResourceCheck", $("#yesResourceCheck").is(":checked"));
      localStorage.setItem("noResourceCheck", $("#noResourceCheck").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts", $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts", $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("useRefreshToken_yes", $("#useRefreshToken-yes").is(":checked"));
      localStorage.setItem("usePKCE_yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("client_id", $("#client_id").val());
      localStorage.setItem("redirect_uri", $("#redirect_uri").val());
      localStorage.setItem("scope", $("#scope").val());
      localStorage.setItem("useRefreshToken_no", $("#useRefreshToken-no").is(":checked"));
      localStorage.setItem("usePKCE_no", $("#usePKCE-no").is(":checked"));
      localStorage.setItem("oidc_discovery_endpoint", $("#oidc_discovery_endpoint").val());
      localStorage.setItem("oidc_userinfo_endpoint", $("#oidc_userinfo_endpoint").val());
      localStorage.setItem("jwks_endpoint", $("#jwks_endpoint").val());
      localStorage.setItem("authzcustomParametersCheck-yes", $("#authzcustomParametersCheck-yes").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-no", $("#authzcustomParametersCheck-no").is(":checked"));
      localStorage.setItem("authzNumberCustomParameters", $("#authzNumberCustomParameters").val());
      if ( $("#authzcustomParametersCheck-yes").is(":checked")) {
        var i = 0;
        var authzNumberCustomParameters = parseInt($("#authzNumberCustomParameters").val());
        for(i = 0; i < authzNumberCustomParameters; i++)
        {
          if($("#customParameterName-" + i)){
            log.debug("Writing customParameterName-" + i + " as " + $("#customParameterName-" + i).val() + "\n");
            localStorage.setItem("customParameterName-" + i, $("#customParameterName-" + i).val());
            log.debug("Writing customParameterValue-" + i + " as " + $("#customParameterValue-" + i).val() + "\n");
            localStorage.setItem("customParameterValue-" + i, $("#customParameterValue-" + i).val());
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
      localStorage.setItem("introspection_endpoint","https://localhost/oauth2/token/introspect");
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
      if ($("#authzcustomParametersCheck-yes").is(":checked")) {
        var i = 0;
        var authzNumberCustomParameters = parseInt($("#authzNumberCustomParameters").val());
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
  $("#authorization_endpoint").val(localStorage.getItem("authorization_endpoint"));
  $("#token_endpoint").val(localStorage.getItem("token_endpoint"));

  if (localStorage.getItem("introspection_endpoint")) {
    $("#introspection_endpoint").val(localStorage.getItem("introspection_endpoint"));
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }

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
  var ta1 =$("#display_authz_request_form_textarea1");
  log.debug("ta1=" + JSON.stringify(ta1));
  var yesCheck = $("#yesResourceCheck").is(":checked");
  log.debug("yesCheck=" + yesCheck);
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = $("#resource").val();
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  log.debug("resourceComponent=" + resourceComponent);
  var customParametersComponent = "";
  var authzcustomParametersCheck = $("#authzcustomParametersCheck-yes").is(":checked");
  log.debug("authzcustomParametersCheck: " + authzcustomParametersCheck + ", type=" + typeof(authzcustomParametersCheck));
  if(authzcustomParametersCheck) {
    const numberCustomParameters = parseInt($("#authzNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++) 
    {
         try {
           customParametersComponent = customParametersComponent +
                                       $("#customParameterName-" + i).val() +
                                       '=' + $("#customParameterValue-" + i).val() + "&" + "\n";
         } catch (e) {
           log.error("Unable to read custom parameter. Skipping.");
         }
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (ta1 != null)
  {
    var grant_type = $("#response_type").val();
    log.debug("grant_type=" + grant_type);
    if( grant_type == "code" ||
	grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      $("#display_authz_request_form_textarea1").val(                  "GET " + $("#authorization_endpoint").val() + "?" + "\n" +
                                                                      "state=" + $("#state").val() + "&" + "\n" +
                                                                      "nonce=" + $("#nonce_field").val() + "&" + "\n" +
                                                                      "response_type=" + $("#response_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#scope").val());
       if ( resourceComponent.length > 0) {
         $("#display_authz_request_form_textarea1").val( $("#display_authz_request_form_textarea1").val() + "&\n" + resourceComponent + "\n");
       }
       if (customParametersComponent.length > 0) {
         $("#display_authz_request_form_textarea1").val( $("#display_authz_request_form_textarea1").val() + "&\n" +  customParametersComponent + "\n");
       }
       if (usePKCE) {
         $("#display_authz_request_form_textarea1").val( $("#display_authz_request_form_textarea1").val() + "&\n" + "code_challenge=" + $("#authz_pkce_code_challenge").val()  + "&\n" +
                                                                                          "code_challenge_method=" + $("#authz_pkce_code_method").val());
       }
    } else if (	grant_type == "token" || 
		grant_type == "id_token token" || 
		grant_type == "id_token") {
      $("#display_authz_request_form_textarea1").val( 		      "GET " + $("#authorization_endpoint").val() + "?" + "\n" +
                                                                      "state=" + $("#state").val() + "&" + "\n" +
                                                                      "nonce=" + $("#nonce_field").val() + "&" + "\n" +
                                                                      "response_type=" + $("#response_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#scope").val());
      if ( resourceComponent.length > 0) {
        $("#display_authz_request_form_textarea1").val( $("#display_authz_request_form_textarea1").val() + "&" + resourceComponent + "\n");
      }
      if (customParametersComponent.length > 0) {
        $("#display_authz_request_form_textarea1").val( $("#display_authz_request_form_textarea1").val() + "&" +  customParametersComponent + "\n");
      }
    } else {
      $("#display_authz_request_form_textarea1").val("UNKNOWN_GRANT_TYPE");
    }
  }
  log.debug('display_authz_request_form_textarea1=' + $("#display_authz_request_form_textarea1").val());
  log.debug("Leaving recalculateAuthorizationRequestDescription().");
}

function triggerAuthZEndpointCall()
{
  log.debug("Entering triggerAuthZEndpointCall().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  window.location.href = DOMPurify.sanitize($("#display_authz_request_form_textarea1").val().substring(4, 
    $("#display_authz_request_form_textarea1").val().length
  ).replace("\n",""));
  log.debug("Leaving triggerAuthZEndpointCall().");
}

function onload() {
  log.debug("Entering onload function.");
  $("#password-form-group1").hide();
  $("#password-form-group2").hide();

  $("#authorization_endpoint").on("keypress", recalculateAuthorizationRequestDescription);
  $("#state").on("keypress", recalculateAuthorizationRequestDescription);
  $("#nonce_field").on("keypress", recalculateAuthorizationRequestDescription);
  $("#response_type").on("keypress", recalculateAuthorizationRequestDescription);
  $("#client_id").on("keypress", recalculateAuthorizationRequestDescription);
  $("#redirect_uri").on("keypress", recalculateAuthorizationRequestDescription);
  $("#scope").on("keypress", recalculateAuthorizationRequestDescription);
  $("#resource").on("keypress", recalculateAuthorizationRequestDescription);
  $("#yesResourceCheck").on("click", recalculateAuthorizationRequestDescription);
  $("#noResourceCheck").on("click", recalculateAuthorizationRequestDescription);
  $("#yesCheckOIDCArtifacts").on("click", recalculateAuthorizationRequestDescription);
  $("#noCheckOIDCArtifacts").on("click", recalculateAuthorizationRequestDescription);
  $("#authzcustomParametersCheck-yes").on("click", recalculateAuthorizationRequestDescription);
  $("#authzcustomParametersCheck-no").on("click", recalculateAuthorizationRequestDescription);
  $("#usePKCE-yes").on("click", usePKCERFC);
  $("#usePKCE-no").on("click", usePKCERFC);

  // Set initial values in case this is the first time the page was hit
  onSubmitClearAllForms(); 
  initValuesToLocalStorage();

  if (localStorage) {
    // Add an event listener for form submissions
    $("#auth_step").on("submit", function() {
      log.debug("Entering auth_step submit event listner function.");
      localStorage.setItem("client_id", $("#client_id").val());
      localStorage.setItem("scope", $("#scope").val());
      localStorage.setItem("authorization_endpoint", $("#authorization_endpoint").val());
      localStorage.setItem("token_endpoint", $("#token_endpoint").val());

      if ($("#introspection_endpoint").val()) {
        localStorage.setItem("introspection_endpoint", $("#introspection_endpoint").val());
      } else {
        localStorage.setItem("introspection_endpoint", "")
      }

      localStorage.setItem("redirect_uri", $("#redirect_uri").val());
      localStorage.setItem("authorization_grant_type", $("#authorization_grant_type").val());
      localStorage.setItem("resource", $("#resource").val());
      localStorage.setItem("yesCheck", $("#yesCheck").is(":checked"));
      localStorage.setItem("noCheck", $("#noCheck").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts", $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts", $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-yes", $("#authzcustomParametersCheck-yes").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-no", $("#authzcustomParametersCheck-no").is(":checked"));
      localStorage.setItem("usePKCE-yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("usePKCE-no", $("#usePKCE-no").is(":checked"));
      log.debug("Leaving auth_step submit event listener function.");
    });
  }
  loadValuesFromLocalStorage();
  generateCustomParametersListUI
  recalculateAuthorizationRequestDescription();
  recalculateAuthorizationErrorDescription();
  if($("#yesResourceCheck").is(":checked"))
  {
    $("#authzResourceRow").show();
  } else {
    $("#authzResourceRow").hide();
  }
  if($("#useRefreshToken-yes").is(":checked"))
  {
    useRefreshTokenTester = $("#useRefreshToken-yes").val();
  } else if ($("#useRefreshToken-no").is(":checked")) {
    useRefreshTokenTester = $("#useRefreshToken-no").val();
  } else {
    useRefreshTokenTester = true;
  }
  var authzcustomParametersCheck = $("#authzcustomParametersCheck-yes").is(":checked");
  if(authzcustomParametersCheck)
  {
    $("#authzCustomParametersRow").show();
  } else {
    $("#authzCustomParametersRow").hide();
  }
  displayAuthzCustomParametersCheck();
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").show();
    $("#authz_pkce_code_verifier_row").show();
    $("#authz_pkce_code_method_row").show();
  } else {
    log.debug("Hide PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").hide();
    $("#authz_pkce_code_verifier_row").hide();
    $("#authz_pkce_code_method_row").hide();
  }

  if (usePKCE) {
    $("#authz_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
    $("#authz_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
    $("#authz_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));
  }
  recalculateAuthorizationRequestDescription();

  var type = $("#response_type").val();
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
  if($("#yesResourceCheck").is(":checked")) {
    log.debug("Showing authzResourceRow.");
    $("#authzResourceRow").show();
  } else if($("#noResourceCheck").is(":checked")) {
    log.debug("Hiding authzResourceRow.");
    $("#authzResourceRow").hide();
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving displayResourceCheck().");
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
    log.debug("Registered auth_step submit function.");
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
      if (pathname == "/callback")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state", window.location.href);
        $("#display_authz_error_form_textarea1").val(                          "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
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
        $("#display_authz_error_form_textarea1").val(                          "error: " + error + "\n" +
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
                                               "<td><textarea rows=\"10\" cols=\"100\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class").html(display_token_error_class_html);
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
                                             "<td><textarea rows=\"10\" cols=\"100\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(display_refresh_error_class);
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
  var yesCheck = $("#yesCheckOIDCArtifacts").is(":checked");
  var noCheck = $("#noCheckOIDCArtifacts").is(":checked");
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

function usePKCERFC()
{
  log.debug("Entering usePKCERFC().");
  var yesCheck = $("#usePKCE-yes").is(":checked");
  var noCheck = $("#usePKCE-no").is(":checked");
  log.debug("usePKCE-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if (yesCheck) {
    usePKCE = true;
  } else {
    usePKCE = false;
  }
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").show();
    $("#authz_pkce_code_verifier_row").show();
    $("#authz_pkce_code_method_row").show();
    $("#authz_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
    $("#authz_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
    $("#authz_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));
  } else {
    log.debug("Hide PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").hide();
    $("#authz_pkce_code_verifier_row").hide();
    $("#authz_pkce_code_method_row").hide();
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
  var oidcDiscoveryEndpoint = $("#oidc_discovery_endpoint").val();
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
  var introspectionEndpoint = discoveryInfo["introspection_endpoint"];
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
  log.debug("introspectionEndpoint: " + introspectionEndpoint);
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
  var introspectionEndpoint = discoveryInfo["introspection_endpoint"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];
  var endSessionEndpoint = discoveryInfo["end_session_endpoint"];

  $("#authorization_endpoint").val(authorizationEndpoint);
  $("#token_endpoint").val(tokenEndpoint);

  if (introspectionEndpoint) {
    $("#introspection_endpoint").val(introspectionEndpoint);
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }

  $("#scope").val(scopesSupported);
  $("#oidc_userinfo_endpoint").val(userInfoEndpoint);
  $("#jwks_endpoint").val(jwksUri);
  if (localStorage) {
      log.debug('Adding to local storage.');
      localStorage.setItem("authorization_endpoint", authorizationEndpoint );
      localStorage.setItem("token_endpoint", tokenEndpoint );

      if (introspectionEndpoint) {
        localStorage.setItem("introspection_endpoint", introspectionEndpoint );
      } else {
        localStorage.setItem("introspection_endpoint", "" );
      }

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
  if ($("#authorization_endpoint")) {
    $("#authorization_endpoint").val("");
  }
  if ( $("#token_endpoint")) {
     $("#token_endpoint").val("");
  }
  if ( $("#introspection_endpoint")) {
    $("#introspection_endpoint").val("");
  }
  if ( $("#authorization_grant_type")) {
    $("#authorization_grant_type").val("oidc_authorization_code_flow");
  }
  if ( $("#token_resource")) {
    $("#token_resource").val("");
  }
  if ( $("#SSLValidate-yes")) {
    $("#SSLValidate-yes").prop("checked", true);
  }
  if ( $("#SSLValidate-no")) {
    $("#SSLValidate-no").prop("checked", false);
  }
  if ( $("#yesCheckOIDCArtifacts")) {
    $("#yesCheckOIDCArtifacts").prop("checked", true);
  }
  if ( $("#noCheckOIDCArtifacts")) {
    $("#noCheckOIDCArtifacts").prop("checked", false);
  }
  if ( $("#useRefreshToken-yes")) {
    $("#useRefreshToken-yes").prop("checked", true);
  }
  if ( $("#useRefreshToken-no")) {
    $("#useRefreshToken-no").prop("checked", false);
  }
  if ( $("#usePKCE-yes")) {
    $("#usePKCE-yes").prop("checked", true);
  }
  if ( $("#usePKCE-no")) {
    $("#usePKCE-no").prop("checked", false);
  }

  if ( $("#refresh_client_id")) {
    $("#refresh_client_id").val("");
  }
  if ( $("#refresh_client_secret")) {
    $("#refresh_client_secret").val("");
  }
  if ( $("#refresh_scope")) {
    $("#refresh_scope").val("");
  }
  if ( $("#useRefreshToken-yes")) {
    $("#useRefreshToken-yes").prop("checked", true);
  }
  if ( $("#useRefreshToken-no")) {
    $("#useRefreshToken-no").prop("checked", false);
  }
  if ( $("#authzcustomParametersCheck-yes")) {
    $("#authzcustomParametersCheck-yes").prop("checked", true);
  }
  if ( $("#authzcustomParametersCheck-no")) {
    $("#authzcustomParametersCheck-no").prop("checked", false);
  }
  if ( $("#oidc_discovery_endpoint")) {
    $("#oidc_discovery_endpoint").val("");
  }
  if ( $("#client_id")) {
    $("#client_id").val("");
  }
  if ( $("#scope")) {
    $("#scope").val("");
  }
  if ( $("#resource")) {
    $("#resource").val("");
  }
  if ( $("#redirect_uri")) {
    $("#redirect_uri").val("");
  }
  if ( $("#oidc_userinfo_endpoint")) {
    $("#oidc_userinfo_endpoint").val("");
  }
  if ( $("#jwks_endpoint")) {
    $("#jwks_endpoint").val("");
  }
  if ( $("#discovery_info_table") ) {
    $("#discovery_info_table").html("");
  }
  log.debug("Leaving onSubmitClearAllForms().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
  log.debug("Leaving regenerateState().");
}

function regenerateNonce() {
  log.debug("Entering regenerateNonce().");
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
  log.debug("Leaving regenerateNonce().");
}

function displayAuthzCustomParametersCheck()
{
  log.debug("Entering displayAuthzCustomParametersCheck().");
  if($("#authzcustomParametersCheck-yes").is(":checked")) {
    $("#authzCustomParametersRow").show();
    $("#authzcustomParametersCheck-no").prop("checked", false);
    $("#authzcustomParametersCheck-yes").prop("checked", true);
    generateCustomParametersListUI();
  } else if($("#authzcustomParametersCheck-no").is(":checked")) {
    $("#authzCustomParametersRow").hide();
    $("#authzcustomParametersCheck-yes").prop("checked", false);
    $("#authzcustomParametersCheck-no").prop("checked", true);
    $("#authz_custom_parameter_list").html("");
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
      var j = parseInt($("#authzNumberCustomParameters").val());
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
  if ( $("#authzcustomParametersCheck-yes").is(":checked")) {
    var i = 0;
    var authzNumberCustomParameters = parseInt($("#authzNumberCustomParameters").val());
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      $("#customParameterName-" + i).val(localStorage.getItem("customParameterName-" + i));
      $("#customParameterValue-" + i).val(localStorage.getItem("customParameterValue-" + i));
      $("#customParameterName-" + i).on("keypress", recalculateAuthorizationRequestDescription);
      $("#customParameterValue-" + i).on("keypress", recalculateAuthorizationRequestDescription);
    }
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving generateCustomParametersListUI().");
}

function onClickShowAuthzFieldSet(id) {
  log.debug("Entering onClickShowAuthzFieldSet(). id=" + id + ". display=" + $("#" + id).css("display"));
  if(id == "authz_fieldset") {
    if($("#" + id).css("display") == 'block') {
       log.debug('Hide ' + id + '.');
       $("#" + id).hide();
       $('#authz_expand_button').val("Expand");
       $('#config_fieldset').show();
       $('#config_expand_button').val("Collapse");
       $('#oidc_fieldset').show();
       $('#oidc_expand_button').val("Collapse");
    } else {
      log.debug('Show ' + id + '.');
      $("#" + id).show();
      $("#authz_expand_button").val("Collapse");
      $('#config_fieldset').hide();
      $("#config_expand_button").val("Expand");
      $('#oidc_fieldset').hide();
      $('#oidc_expand_button').val("Expand");
    }
  } else {
    if($("#" + id).css("display") == 'block') {
      log.debug('Hide ' + id + '.');
      $("#" + id).hide();
      $("#oidc_expand_button").val("Expand");
    } else {
      log.debug('Show ' + id + '.');
      $("#" + id).show();
      $("#oidc_expand_button").val("Hide");
    }
  }
  log.debug('Leaving onClickShowAuthzFieldSet().');
  return false;
}

function onClickShowGenericFieldSet(id) {
  log.debug('Entering onClickShowConfigFieldSet(). id=' 
            + id + ', style.display='
            + $("#" + id).css("display"));
  var jid = "#" + id;
  if($(jid).css("display") == 'block') {
    $(jid).val("Expand");
    $(jid).hide();
  } else {
    $(jid).val('Hide');
    $(jid).show();
  }
  log.debug('Leaving onClickShowGenericFieldSet().');
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
  $("#authz_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
  $("#authz_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
  $("#authz_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));
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
  generateUUID,
  displayResourceCheck,
  recalculateAuthorizationErrorDescription,
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
  onClickShowGenericFieldSet,
  onClickClearLocalStorage,
  usePKCERFC
};
