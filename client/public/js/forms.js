function OnSubmitForm()
{
  document.auth_step.action = document.getElementById('authorization_endpoint').value;
  return true;
}

function OnSubmitTokenEndpointForm()
{
  document.token_step.action = document.getElementById('token_endpoint').value;
  return true;
}

window.onload = function() {

  $('#password-form-group1').hide();
  $('#password-form-group2').hide();

  if (localStorage) {
    // Add an event listener for form submissions
    document.getElementById('auth_step').addEventListener('submit', function() {
 //     alert("RCBJ0005: " + document.getElementById('token_redirect_uri').value);
      localStorage.setItem('client_id', document.getElementById('client_id').value);
      localStorage.setItem('scope', document.getElementById('scope').value);
     localStorage.setItem('authorization_endpoint', document.getElementById('authorization_endpoint').value);
     localStorage.setItem('token_endpoint', document.getElementById('token_endpoint').value);
    });
    document.getElementById('token_step').addEventListener('submit', function() {
//      window.alert("RCBJ0005: " + document.getElementById('token_redirect_uri').value);
      localStorage.setItem('token_client_id', document.getElementById('token_client_id').value);
      localStorage.setItem('token_client_secret', document.getElementById('token_client_secret').value);
      localStorage.setItem('token_redirect_uri', document.getElementById('token_redirect_uri').value);
      localStorage.setItem('token_username', document.getElementById('token_username').value);
    });
  }

  // Retrieve the users name.
  document.getElementById('authorization_endpoint').value = localStorage.getItem('authorization_endpoint');
  document.getElementById('token_endpoint').value = localStorage.getItem('token_endpoint');
  document.getElementById('client_id').value = localStorage.getItem('client_id');
  document.getElementById('scope').value = localStorage.getItem('scope');
  document.getElementById('token_client_id').value = localStorage.getItem('token_client_id');
  document.getElementById('token_client_secret').value = localStorage.getItem('token_client_secret');
  document.getElementById('token_redirect_uri').value = localStorage.getItem('token_redirect_uri');
  document.getElementById('token_username').value = localStorage.getItem('token_username');
}

  $(function() {
    $(".btn1").click(function() {
      // validate and process form here
      var client_id = document.getElementById('token_client_id').value;
      var client_secret = document.getElementById('token_client_secret').value;
      var code = document.getElementById('code').value;
      var grant_type = document.getElementById('token_grant_type').value;
      var redirect_uri = document.getElementById('token_redirect_uri').value;
      var dataString = 'grant_type=' + grant_type + '&client_id='+ client_id + '&client_secret=' + client_secret + '&code=' + code + '&redirect_uri=' + redirect_uri;
  $.ajax({
    type: "POST",
    url: document.getElementById('token_endpoint').value,
    data: dataString,
    success: function(data, textStatus, request) {
      $('#token_endpoint_result').html("<H2>Results:</H2><table><tr><td>access_token</td><td><textarea rows=5 cols=100>" + data.access_token + "</textarea></td></tr><tr><td>refresh_token</td><td><textarea rows=5 cols=100>" + data.refresh_token + "</textarea></td></tr><tr><td>id_token</td><td><textarea rows=5 cols=100>" + data.id_token + "</textarea></td></tr></table>");
    $('#token_endpoint_result').scrollView();
    }
  });
  return false;

    });
  });

$(document).ready(function(){ // ran when the document is fully loaded
  // retrieve the jQuery wrapped dom object identified by the selector '#mySel'
  var sel = $('#authorization_grant_type');
  // assign a change listener to it
  sel.change(function(){ //inside the listener
    // retrieve the value of the object firing the event (referenced by this)
    var value = $(this).val();
    // print it in the logs
    console.log(value); // crashes in IE, if console not open
    // make the text of all label elements be the value 
    if( value == "implicit_grant" )
    {
      $('#step3').hide();
    }
    if( value == "client_credential" || value == "resource_owner")
    { 
      $('#step2').hide();
    }
    if( value == "resource_owner")
    {
      $('#password-form-group1').show();
      $('#password-form-group2').show();
    }
  }); // close the change listener

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
}); // close the ready listener 
