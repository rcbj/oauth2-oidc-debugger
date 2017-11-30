function OnSubmitForm()
{
  console.log("Entering OnSubmitForm().");
  document.auth_step.action = document.getElementById('authorization_endpoint').value;
  recalculateAuthorizationRequestDescription();
  console.log("Leaving OnSubmitForm().");
  return true;
}

function OnSubmitTokenEndpointForm()
{
  console.log("Entering OnSubmitTokenEndpointForm().");
  //document.token_step.action = document.getElementById('token_endpoint').value;
  document.token_step.action = "/token";
  console.log("Leaving OnSubmitTokenEndpointForm().");
  return true;
}

function getParameterByName(name, url)
{
    console.log("Entering getParameterByName().");
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    console.log("Entering getParameterByName().");
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}

$(document).ready(function()
{ 
    console.log("Entering ready function().");
    var sel = $('#authorization_grant_type');
    sel.change(function(){
    console.log("Entering selection changed function().");
    var value = $(this).val();
    resetUI(value);
    recalculateAuthorizationRequestDescription();
    recalculateTokenRequestDescription();
    console.log("Leaving selection changed function().");
  });
  var value = $('#authorization_grant_type').value;
  resetUI(value);
  recalculateAuthorizationRequestDescription();
  recalculateTokenRequestDescription();
  console.log("Leaving ready function().");
});

function resetUI(value)
{
    console.log("Entering resetUI().");
    if( value == "implicit_grant" )
    {
      $('#code').hide();
      $('#password-form-group1').hide();
      $('#password-form-group2').hide();
      $('#step2').show();
      $('#step3').hide();
      $('#nonce').show();
      document.getElementById('response_type').value = "token";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      document.getElementById('token_grant_type').value = "";
      document.getElementById('h2_title_1').innerHTML = "Request Access Token";
      $('#authorization_endpoint_result').html("");
      $('#token_endpoint_result').html("");
      $('#display_authz_request_class').show();
      $('#display_token_request').hide();
    }
    if( value == "client_credential")
    {
      $('#code').hide();
      $('#password-form-group1').hide();
      $('#password-form-group2').hide();
      $('#step2').hide();
      $('#step3').show();
      $('#nonce').hide();
      document.getElementById('response_type').value = "";
      document.getElementById('token_grant_type').value = "client_credentials";
      recalculateTokenRequestDescription();
      document.getElementById('h2_title_2').innerHTML = "Obtain Access Token";
      $('#authorization_endpoint_result').html("");
      $('#token_endpoint_result').html("");
      $('#display_authz_request_class').hide();
      $('#display_token_request').show();
    }
    if( value == "resource_owner")
    {
      $('#code').hide();
      $('#password-form-group1').show();
      $('#password-form-group2').show();
      $('#step2').hide();
      $('#step3').show();
      $('#nonce').hide();
      document.getElementById('response_type').value = "";
      document.getElementById('token_grant_type').value = "password";
      recalculateTokenRequestDescription();
      document.getElementById('h2_title_2').innerHTML = "Obtain Access Token";
      $('#authorization_endpoint_result').html("");
      $('#token_endpoint_result').html("");
      $('#display_authz_request_class').hide();
      $('#display_token_request').show();
    }
    if( value == "authorization_grant")
    {
      $('#code').show();
      $('#password-form-group1').hide();
      $('#password-form-group2').hide();
      $('#step2').show();
      $('#step3').show();
      $('#nonce').hide();
      document.getElementById('response_type').value = "code";
      document.getElementById('token_grant_type').value = "authorization_code";
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      recalculateTokenRequestDescription();
      document.getElementById('h2_title_1').innerHTML = "Request Authorization Code";
      document.getElementById('h2_title_2').innerHTML = "Exchange Authorization Code for Access Token";
      $('#authorization_endpoint_result').html("");
      $('#token_endpoint_result').html("");
      $('#display_authz_request_class').show();
      $('#display_token_request').show();
    }
    $('#display_authz_error_class').html("");
    $('#display_token_error_class').html("");
    console.log("Leaving resetUI().");
}

function writeValuesToLocalStorage()
{
  console.log("Entering writeValuesToLocalStorage().");
  if (localStorage) {
      localStorage.setItem('token_client_id', document.getElementById('token_client_id').value);
      localStorage.setItem('token_client_secret', document.getElementById('token_client_secret').value);
      localStorage.setItem('token_redirect_uri', document.getElementById('token_redirect_uri').value);
      localStorage.setItem('token_username', document.getElementById('token_username').value);
      localStorage.setItem('token_scope', document.getElementById('token_scope').value);
      localStorage.setItem('authorization_grant_type', document.getElementById('authorization_grant_type').value);
      localStorage.setItem('token_resource', document.getElementById('token_resource').value);
      localStorage.setItem('yesCheckToken', document.getElementById('yesCheckToken').checked);
      localStorage.setItem('noCheckToken', document.getElementById('noCheckToken').checked);
  }
  console.log("Leaving writeValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  console.log("Entering loadValuesFromLocalStorage().");
  var authzGrantType = localStorage.getItem('authorization_grant_type');
  console.log("authzGrantType=" + authzGrantType);
  if (authzGrantType == "" || typeof(authzGrantType) == "undefined" || authzGrantType == "null")
  {
    document.getElementById('authorization_grant_type').value = "authorization_grant"
    resetUI("authorization_grant");
  } else {
    document.getElementById('authorization_grant_type').value = authzGrantType;
    resetUI(authzGrantType);
  }
  document.getElementById('authorization_endpoint').value = localStorage.getItem('authorization_endpoint');
  document.getElementById('token_endpoint').value = localStorage.getItem('token_endpoint');
  document.getElementById('redirect_uri').value = localStorage.getItem('redirect_uri');
  document.getElementById('client_id').value = localStorage.getItem('client_id');
  document.getElementById('scope').value = localStorage.getItem('scope');
  document.getElementById('resource').value = localStorage.getItem('resource');
  document.getElementById('token_client_id').value = localStorage.getItem('token_client_id');
  document.getElementById('token_client_secret').value = localStorage.getItem('token_client_secret');
  document.getElementById('token_redirect_uri').value = localStorage.getItem('token_redirect_uri');
  document.getElementById('token_scope').value = localStorage.getItem('token_scope');
  document.getElementById('token_username').value = localStorage.getItem('token_username');
  document.getElementById('token_resource').value = localStorage.getItem('token_resource');
  document.getElementById('yesCheck').checked = localStorage.getItem('yesCheck');
  document.getElementById('noCheck').checked = localStorage.getItem('noCheck');
  document.getElementById('yesCheckToken').checked = localStorage.getItem('yesCheckToken');
  document.getElementById('noCheckToken').checked = localStorage.getItem('noCheckToken');


  var agt = document.getElementById("authorization_grant_type").value;
  var pathname = window.location.pathname;
  console.log("agt=" + agt);
  console.log("pathname=" + pathname);
  if ( agt == "implicit_grant" && pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
  {
    var access_token = getParameterByName("access_token",window.location.href);
    console.log("access_token=" + access_token);
    if(access_token == null || access_token == "null" || access_token == "" || typeof access_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      console.log("fragement: " + parseFragment());
      access_token = parseFragment()['access_token'];
      if(access_token == null || access_token == "null" || access_token == "" || typeof access_token == "undefined")
      {
        access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    console.log("access_token=" + access_token);
    $('#authorization_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea></td></tr></table>");
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = document.getElementById('authorization_grant_type').value;
  if(	pathname == "/callback" && 
	(authzGrantType == "authorization_grant" || authzGrantType == "implicit_grant") &&
	(error != null && error != "null" && typeof error != "undefined" && error != ""))
	
  {
    $('#display_authz_error_class').html("<form action=\"\" name=\"display_authz_error_form\" id=\"display_authz_error_form\"><label name=\"display_authz_error_form_label1\" value=\"\" id=\"display_authz_error_form_label1\">Error</label><textarea rows=\"10\" cols=\"100\" id=\"display_authz_error_form_textarea1\"></textarea></form>");
  }
  document.getElementById("state").value = generateUUID();
  document.getElementById("nonce_field").value = generateUUID();
  console.log("Leaving loadValuesFromLocalStorage().");
}

function recalculateAuthorizationRequestDescription()
{
  console.log("Entering recalculateAuthorizationRequestDescription().");
  console.log("update request field");
  var ta1 = document.getElementById('display_authz_request_form_textarea1');
  var yesCheck = document.getElementById('yesCheck').checked;
  console.log("yesCheck=" + yesCheck);
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = document.getElementById('resource').value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  '&resource=' + resource;
    }
  }
  if (ta1 != null)
  {
    var grant_type = document.getElementById('response_type').value;
    if( grant_type == "code")
    {
      document.getElementById('display_authz_request_form_textarea1').value = "GET " + document.getElementById('authorization_endpoint').value + "?" + "\n" +
                                                                      "state=" + document.getElementById('state').value + "&" + "\n" +
  								      "response_type=" + document.getElementById('response_type').value + "&" + "\n" +
  								      "client_id=" + document.getElementById('client_id').value + "&" + "\n" +
                						      "redirect_uri=" + document.getElementById('redirect_uri').value + "&" +"\n" +
								      "scope=" + document.getElementById('scope').value + "\n" +
                                                                      resourceComponent + "\n";
    } else if (grant_type == "token") {
      document.getElementById('display_authz_request_form_textarea1').value = "GET " + document.getElementById('authorization_endpoint').value + "?" + "\n" +
                                                                      "state=" + document.getElementById('state').value + "&" + "\n" +
                                                                      "nonce=" + document.getElementById('nonce_field').value + "&" + "\n" +
                                                                      "response_type=" + document.getElementById('response_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('client_id').value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById('redirect_uri').value + "&" +"\n" +
                                                                      "scope=" + document.getElementById('scope').value + "\n" +
                                                                      resourceComponent + "\n";
    }
  }
  console.log("Leaving recalculateAuthorizationRequestDescription().");
}

function recalculateTokenRequestDescription()
{
  console.log("Entering recalculateTokenRequestDescription().");
  console.log("update request field");
  var ta1 = document.getElementById('display_token_request_form_textarea1');
  var yesCheck = document.getElementById('yesCheckToken').checked;
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = document.getElementById('token_resource').value;
    if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
    {
      resourceComponent =  '&resource=' + resource;
    }
  }

  if (ta1 != null)
  {
    var grant_type = document.getElementById('token_grant_type').value;
    if( grant_type == "authorization_code")
    {
      console.log("RCBJ0040");
      document.getElementById('display_token_request_form_textarea1').value = "POST " + document.getElementById('token_endpoint').value + "?" + "\n" +
                                                                      "grant_type=" + document.getElementById('token_grant_type').value + "&" + "\n" +
                                                                      "code=" + document.getElementById('code').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('token_client_id').value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById('token_redirect_uri').value + "&" +"\n" +
                                                                      "scope=" + document.getElementById('token_scope').value + "\n" + 
                                                           	      resourceComponent + "\n";
    } else if (grant_type == "client_credentials") {
      console.log("RCBJ0041");
      document.getElementById('display_token_request_form_textarea1').value = "POST " + document.getElementById('token_endpoint').value + "?" + "\n" +
                                                                      "grant_type=" + document.getElementById('token_grant_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('token_client_id').value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById('token_client_secret').value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById('token_redirect_uri').value + "&" +"\n" +
                                                                      "scope=" + document.getElementById('token_scope').value + "\n" +
                                                                      resourceComponent + "\n";
    } else if (grant_type == "password") {
      console.log("RCBJ0042");
      document.getElementById('display_token_request_form_textarea1').value = "POST " + document.getElementById('token_endpoint').value + "?" + "\n" +
                                                                      "grant_type=" + document.getElementById('token_grant_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('token_client_id').value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById('token_client_secret').value + "&" + "\n" +
                                                                      "username=" + document.getElementById('token_username').value + "&" + "\n" +
                                                                      "password=" + document.getElementById('token_password').value + "&" + "\n" +
                                                                      "scope=" + document.getElementById('token_scope').value + "\n" +
                                                                      resourceComponent +"\n";
    }
  }
  console.log("Leaving recalculateTokenRequestDescription().");
}

window.onload = function() {
  console.log("Entering onload function.");
  $('#password-form-group1').hide();
  $('#password-form-group2').hide();

  document.getElementById('authorization_endpoint').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('state').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('nonce_field').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('response_type').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('client_id').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('redirect_uri').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('scope').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('resource').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('yesCheck').addEventListener("onClick", recalculateAuthorizationRequestDescription());
  document.getElementById('noCheck').addEventListener("onClick", recalculateAuthorizationRequestDescription());

  if (localStorage) {
    // Add an event listener for form submissions
    document.getElementById('auth_step').addEventListener('submit', function() {
      console.log("Entering auth_step submit event listner function.");
      localStorage.setItem('client_id', document.getElementById('client_id').value);
      localStorage.setItem('scope', document.getElementById('scope').value);
      localStorage.setItem('authorization_endpoint', document.getElementById('authorization_endpoint').value);
      localStorage.setItem('token_endpoint', document.getElementById('token_endpoint').value);
      localStorage.setItem('redirect_uri', document.getElementById('redirect_uri').value);
      localStorage.setItem('authorization_grant_type', document.getElementById('authorization_grant_type').value);
      localStorage.setItem('resource', document.getElementById('resource').value);
      localStorage.setItem('yesCheck', document.getElementById('yesCheck').checked);
      localStorage.setItem('noCheck', document.getElementById('noCheck').checked);
      console.log("Leaving auth_step submit event listener function.");
    });
  }
  loadValuesFromLocalStorage();
//  resetUI();
  recalculateAuthorizationRequestDescription();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  var yesChecked = document.getElementById('yesCheck').checked;
  if(yesChecked)
  {
    $('#resourceIfYes').slideDown(); 
  } else {
    $('#resourceIfYes').slideUp();
  }
  var yesCheckedToken = document.getElementById('yesCheckToken').checked
  if(yesCheckedToken)
  {
    $('#resourceTokenIfYes').slideDown();
  } else {
    $('#resourceTokenIfYes').slideUp();
  }
  console.log("Leaving recalculateTokenRequestDescription().");
}

//  $(function() {
//    $(".btn2").click(function() {
//      // validate and process form here
//      var client_id = document.getElementById('client_id').value;
//      var code = document.getElementById('code').value;
//      var response_type = document.getElementById('response_type').value;
//      var redirect_uri = document.getElementById('redirect_uri').value;
//      var scope = document.getElementById('scope').value;
//      var state  = document.getElementById('state').value;
//      var nonce = document.getElementById('nonce').value;
//      var dataString = "";
//      if(response_type == "code")
//      {
//
//        dataString = 'response_type=' + response_type + '&client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=' + scope + '&state=' + state;
//      }  else if( response_type == "token") {
//        dataString = 'response_type=' + response_type + '&client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=' + scope + '&state=' + state + '&nonce=' + nonce;
//      }
//      console.log("RCBJ0070: ");
//  $.ajax({
//    type: "GET",
//    url: document.getElementById('authorization_endpoint').value + "?" + dataString,
//    success: function(data, textStatus, request) {
//      console.log("RCBJ0060: " + JSON.stringify(data));
//      writeValuesToLocalStorage();
//      recalculateTokenRequestDescription();
////      var access_token = getParameterByName("access_token",window.location.href);
//      $('#authorization_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea></td></tr></table>");
//    }
//  });
//  return false;
//
//    });
//  });

function generateUUID () { // Public Domain/MIT
    console.log("Entering generateUUID().");
    var d = new Date().getTime();
    if (typeof performance !== 'undefined' && typeof performance.now === 'function'){
        d += performance.now(); //use high-precision timer if available
    }
    console.log("Leaving generateUUID().");
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function displayResourceCheck()
{
  console.log("Entering displayResourceCheck().");
  var yesCheck = document.getElementById('yesCheck').checked;
  var noCheck = document.getElementById('noCheck').checked;
  console.log("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if( yesCheck) {
    document.getElementById('resourceIfYes').style.visibility = 'visible';
    document.getElementById('resourceIfYes').style.display = 'block';
    $('#resourceIfYes').slideDown();
  } else if(noCheck) {
    document.getElementById('resourceIfYes').style.visibility = 'hidden';
    document.getElementById('resourceIfYes').style.display = 'none';
    $('#resourceIfYes').slideUp();
  }
  recalculateAuthorizationRequestDescription();
  console.log("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  console.log("Entering displayTokenResourceCheck().");
  var yesCheck = document.getElementById('yesCheckToken').checked;
  var noCheck = document.getElementById('noCheckToken').checked;
  if( yesCheck) {
    document.getElementById('resourceTokenIfYes').style.visibility = 'visible';
    document.getElementById('resourceTokenIfYes').style.display = 'block';
    $('#resourceTokenIfYes').slideDown();
  } if(noCheck) {
    document.getElementById('resourceTokenIfYes').style.visibility = 'hidden';
    document.getElementById('resourceTokenIfYes').style.display = 'none';
    $('#resourceTokenIfYes').slideUp();
  }
  recalculateTokenRequestDescription();
  console.log("Leaving displayTokenResourceCheck().");
}

$(function() {
$('#auth_step').submit(function () {
    console.log("Entering auth_step submit function.");
    console.log("RCBJ0010");
    var resource = document.getElementById('resource').value;
    var yesCheck = document.getElementById('yesCheck').checked;
    console.log("yesCheck=" + yesCheck);
    console.log("resource=" + resource);
//    if ( resource == "" || 
//         (resource == null || typeof resource == "undefined" || resource == "null") ||
    if(yesCheck == false)
    {
      console.log("RCBJ0100");
      document.getElementById('resource').disabled = "disabled"; 
      document.getElementById('yesCheck').disabled = "disabled";
      document.getElementById('noCheck').disabled = "disabled";
    } else {
      console.log("RCBJ0101");
      document.getElementById('resource').removeAttribute("disabled");
      document.getElementById('yesCheck').removeAttribute("disabled");
      document.getElementById('noCheck').removeAttribute("disabled");
    }
    console.log("RCBJ0011");
    $(this)
      .find('input[name]')
      .filter(function () {
          return !this.value;
      })
      .prop('name', '');
});
    console.log("Leaving auth_step submit function.");
});

function recalculateAuthorizationErrorDescription()
{
  console.log("Entering recalculateAuthorizationErrorDescription().");
  console.log("update error field");
  var ta1 = document.getElementById('display_authz_error_form_textarea1');
  if (ta1 != null)
  {
    var grant_type = document.getElementById('response_type').value;
    if( grant_type == "code")
    {
      var pathname = window.location.pathname;
      console.log("pathname=" + pathname);
      if (pathname == "/callback")
      {
        console.log("RCBJ0050");
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
//        $('#authorization_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea></td></tr></table>");
        document.getElementById('display_authz_error_form_textarea1').value = "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n";
      }
    } else if (grant_type == "token") {
      //document.getElementById('display_authz_request_form_textarea1').value = "";
      var pathname = window.location.pathname;
      console.log("pathname=" + pathname);
      if (pathname == "/callback")
      {
        console.log("RCBJ0050");
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
//        $('#authorization_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea></td></tr></table>");
        document.getElementById('display_authz_error_form_textarea1').value = "error: " + error + "\n" +
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
//  $('#display_token_error_class').show();
  $('#display_token_error_class').html("<form action=\"\" name=\"display_token_error_form\" id=\"display_token_error_form\"><label name=\"display_token_error_form_label1\" value=\"\" id=\"display_token_error_form_label1\">Error</label><textarea rows=\"10\" cols=\"100\" id=\"display_token_error_form_textarea1\"></textarea></form>");
  console.log("update error field");
  var ta1 = document.getElementById('display_token_error_form_textarea1');
  if (ta1 != null)
  {
    var grant_type = document.getElementById('token_grant_type').value;
    if( grant_type == "authorization_code")
    {
          var status = data.status;
          var statusText = data.statusText;
          var readyState = data.readyState;
          var responseText = data.responseText;
          var responseObject = JSON.parse(responseText);
          document.getElementById('display_token_error_form_textarea1').value = "status: " + status + "\n" +
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
          document.getElementById('display_token_error_form_textarea1').value = "status: " + status + "\n" +
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
          document.getElementById('display_token_error_form_textarea1').value = "status: " + status + "\n" +
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

function useTokenRedirectSubmission()
{
  console.log("Entering useTokenRedirectSubmission().");
  console.log("Leaving useTokenRedirectSubmission().");
}

function useTokenAJAXSubmission()
{
  console.log("Entering useTokenAJAXSubmission().");
  $(function() {
    $(".btn1").click(function() {
      console.log("Entering token Submit button clicked function.");
      // validate and process form here
      var token_endpoint = document.getElementById('token_endpoint').value;
      var client_id = document.getElementById('token_client_id').value;
      var client_secret = document.getElementById('token_client_secret').value;
      var code = document.getElementById('code').value;
      var grant_type = document.getElementById('token_grant_type').value;
      var redirect_uri = document.getElementById('token_redirect_uri').value;
      var username = document.getElementById('token_username').value;
      var password = document.getElementById('token_password').value;
      var scope = document.getElementById('token_scope').value;
      var dataString = "";
      if(grant_type == "authorization_code")
      {
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + '&code=' + code + '&redirect_uri=' + redirect_uri + "&scope=" + scope + '&token_endpoint=' + token_endpoint;
      } else if( grant_type == "password") {
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + '&username=' + username + '&password=' + password + "&scope=" + scope + '&token_endpoint=' + token_endpoint;
      } else if( grant_type == "client_credentials") {
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + "&scope=" + scope + '&token_endpoint=' + token_endpoint;
      }
      var yesCheck = document.getElementById('yesCheckToken').checked;
      if(yesCheck) //add resource value to OAuth query string
      {
        var resource = document.getElementById('token_resource').value;
        if (resource != "" && typeof resource != "undefined" && resource != null && resource != "null")
        {
          dataString = dataString + '&resource=' + resource;
        }
      }
      writeValuesToLocalStorage();
      recalculateTokenRequestDescription();
  $.ajax({
    type: "POST",
    url: "/token",
    data: dataString,
    success: function(data, textStatus, request) {
      $('#token_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea rows=10 cols=100>" + data.access_token + "</textarea></td></tr><tr><td>refresh_token</td><td><textarea rows=10 cols=100>" + data.refresh_token + "</textarea></td></tr><tr><td>id_token</td><td><textarea rows=10 cols=100>" + data.id_token + "</textarea></td></tr></table>");
    },
    error: function (request, status, error) {
      console.log("request: " + JSON.stringify(request));
      console.log("status: " + JSON.stringify(status));
      console.log("error: " + JSON.stringify(error));
//      if(error != null && error != "null" && typeof error != "undefined" && error != "")
//      {
//        $('#display_authz_error_class').html("<form action=\"\" name=\"display_authz_error_form\" id=\"display_authz_error_form\"><label name=\"display_authz_error_form_label1\" value=\"\" id=\"display_authz_error_form_label1\">Error</label><textarea rows=\"10\" cols=\"100\" id=\"display_authz_error_form_textarea1\"></textarea></form>");
//      }
      recalculateTokenErrorDescription(request);
    }
  });
  return false;

    });
    console.log("Leaving token submit button clicked function.");
 });
}

function parseFragment()
{
  console.log("hash=" + window.location.hash);
  var hash = window.location.hash.substr(1);

  var result = hash.split('&').reduce(function (result, item) {
      var parts = item.split('=');
      result[parts[0]] = parts[1];
      return result;
  }, {});
  return result;
}
