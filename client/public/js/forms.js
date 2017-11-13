function OnSubmitForm()
{
  document.auth_step.action = document.getElementById('authorization_endpoint').value;
  recalculateAuthorizationRequestDescription();
  return true;
}

function OnSubmitTokenEndpointForm()
{
  document.token_step.action = document.getElementById('token_endpoint').value;
  return true;
}

function getParameterByName(name, url) {
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}

$(document).ready(function(){ 
    var sel = $('#authorization_grant_type');
    sel.change(function(){
    var value = $(this).val();
    resetUI(value);
    recalculateAuthorizationRequestDescription();
    recalculateTokenRequestDescription();
  });
  var value = $('#authorization_grant_type').value;
  resetUI(value);
  recalculateAuthorizationRequestDescription();
  recalculateTokenRequestDescription();
});

function resetUI(value)
{
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
      recalculateTokenRequestDescription();
      document.getElementById('h2_title_1').innerHTML = "Request Authorization Code";
      document.getElementById('h2_title_2').innerHTML = "Exchange Authorization Code for Access Token";
      $('#authorization_endpoint_result').html("");
      $('#token_endpoint_result').html("");
      $('#display_authz_request_class').show();
      $('#display_token_request').show();
    }
}

function writeValuesToLocalStorage()
{
  if (localStorage) {
      localStorage.setItem('token_client_id', document.getElementById('token_client_id').value);
      localStorage.setItem('token_client_secret', document.getElementById('token_client_secret').value);
      localStorage.setItem('token_redirect_uri', document.getElementById('token_redirect_uri').value);
      localStorage.setItem('token_username', document.getElementById('token_username').value);
      localStorage.setItem('token_scope', document.getElementById('token_scope').value);
      localStorage.setItem('authorization_grant_type', document.getElementById('authorization_grant_type').value);
  }
}

function loadValuesFromLocalStorage()
{
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
  document.getElementById('token_client_id').value = localStorage.getItem('token_client_id');
  document.getElementById('token_client_secret').value = localStorage.getItem('token_client_secret');
  document.getElementById('token_redirect_uri').value = localStorage.getItem('token_redirect_uri');
  document.getElementById('token_scope').value = localStorage.getItem('token_scope');
  document.getElementById('token_username').value = localStorage.getItem('token_username');
  var agt = document.getElementById("authorization_grant_type").value;
  var pathname = window.location.pathname;
  console.log("agt=" + agt);
  console.log("pathname=" + pathname);
  if ( agt == "implicit_grant" && pathname == "/callback")
  {
    console.log("RCBJ0030");
    var access_token = getParameterByName("access_token",window.location.href);
    $('#authorization_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea id='implicit_grant_access_token' rows=5 cols=100>" + access_token + "</textarea></td></tr></table>");
  }
  document.getElementById("state").value = generateUUID();
  document.getElementById("nonce_field").value = generateUUID();
}

function recalculateAuthorizationRequestDescription()
{
  console.log("update request field");
  var ta1 = document.getElementById('display_authz_request_form_textarea1');
  console.log("RCBJ0050: " + ta1);
  if (ta1 != null)
  {
    var grant_type = document.getElementById('response_type').value;
    if( grant_type == "code")
    {
      console.log("RCBJ0020");
      document.getElementById('display_authz_request_form_textarea1').value = "GET " + document.getElementById('authorization_endpoint').value + "?" + "\n" +
                                                                      "state=" + document.getElementById('state').value + "&" + "\n" +
  								      "response_type=" + document.getElementById('response_type').value + "&" + "\n" +
  								      "client_id=" + document.getElementById('client_id').value + "&" + "\n" +
                						      "redirect_uri=" + document.getElementById('redirect_uri').value + "&" +"\n" +
								      "scope=" + document.getElementById('scope').value + "\n";
    } else if (grant_type == "token") {
      console.log("RCBJ0021");
      document.getElementById('display_authz_request_form_textarea1').value = "GET " + document.getElementById('authorization_endpoint').value + "?" + "\n" +
                                                                      "state=" + document.getElementById('state').value + "&" + "\n" +
                                                                      "nonce=" + document.getElementById('nonce_field').value + "&" + "\n" +
                                                                      "response_type=" + document.getElementById('response_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('client_id').value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById('redirect_uri').value + "&" +"\n" +
                                                                      "scope=" + document.getElementById('scope').value + "\n";
    }
  }
}

function recalculateTokenRequestDescription()
{
  console.log("update request field");
  var ta1 = document.getElementById('display_token_request_form_textarea1');
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
                                                                      "scope=" + document.getElementById('token_scope').value + "\n";
    } else if (grant_type == "client_credentials") {
      console.log("RCBJ0041");
      document.getElementById('display_token_request_form_textarea1').value = "POST " + document.getElementById('token_endpoint').value + "?" + "\n" +
                                                                      "grant_type=" + document.getElementById('token_grant_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('token_client_id').value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById('token_client_secret').value + "&" + "\n" +
                                                                      "redirect_uri=" + document.getElementById('token_redirect_uri').value + "&" +"\n" +
                                                                      "scope=" + document.getElementById('token_scope').value + "\n";
    } else if (grant_type == "password") {
      console.log("RCBJ0042");
      document.getElementById('display_token_request_form_textarea1').value = "POST " + document.getElementById('token_endpoint').value + "?" + "\n" +
                                                                      "grant_type=" + document.getElementById('token_grant_type').value + "&" + "\n" +
                                                                      "client_id=" + document.getElementById('token_client_id').value + "&" + "\n" +
                                                                      "client_secret=" + document.getElementById('token_client_secret').value + "&" + "\n" +
                                                                      "username=" + document.getElementById('token_username').value + "&" + "\n" +
                                                                      "password=" + document.getElementById('token_password').value + "&" + "\n" +
                                                                      "scope=" + document.getElementById('token_scope').value + "\n"
    } 


  }
}

window.onload = function() {

  $('#password-form-group1').hide();
  $('#password-form-group2').hide();

  document.getElementById('authorization_endpoint').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('state').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('nonce_field').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('response_type').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('client_id').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('redirect_uri').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());
  document.getElementById('scope').addEventListener("onkeypress", recalculateAuthorizationRequestDescription());

  if (localStorage) {
    // Add an event listener for form submissions
    document.getElementById('auth_step').addEventListener('submit', function() {
      localStorage.setItem('client_id', document.getElementById('client_id').value);
      localStorage.setItem('scope', document.getElementById('scope').value);
      localStorage.setItem('authorization_endpoint', document.getElementById('authorization_endpoint').value);
      localStorage.setItem('token_endpoint', document.getElementById('token_endpoint').value);
      localStorage.setItem('redirect_uri', document.getElementById('redirect_uri').value);
      localStorage.setItem('authorization_grant_type', document.getElementById('authorization_grant_type').value);
    });
  }
  loadValuesFromLocalStorage();
//  resetUI();
  recalculateAuthorizationRequestDescription();
  recalculateTokenRequestDescription();
  
}

  $(function() {
    $(".btn1").click(function() {
      // validate and process form here
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
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + '&code=' + code + '&redirect_uri=' + redirect_uri + "&scope=" + scope;
      } else if( grant_type == "password") {
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + '&username=' + username + '&password=' + password + "&scope=" + scope;
      } else if( grant_type == "client_credentials") {
        dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + "&scope=" + scope;
      }
  $.ajax({
    type: "POST",
    url: document.getElementById('token_endpoint').value,
    data: dataString,
    success: function(data, textStatus, request) {
      $('#token_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea rows=10 cols=100>" + data.access_token + "</textarea></td></tr><tr><td>refresh_token</td><td><textarea rows=10 cols=100>" + data.refresh_token + "</textarea></td></tr><tr><td>id_token</td><td><textarea rows=10 cols=100>" + data.id_token + "</textarea></td></tr></table>");
      writeValuesToLocalStorage();
      recalculateTokenRequestDescription();
//    $('#token_endpoint_result').scrollView();
    }
  });
  return false;

    });
  });

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
    var d = new Date().getTime();
    if (typeof performance !== 'undefined' && typeof performance.now === 'function'){
        d += performance.now(); //use high-precision timer if available
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}


