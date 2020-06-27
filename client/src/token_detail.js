// File: token_detail.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/28/2020
// Notes:
//
const jwt = require('jsonwebtoken');

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, {complete: true});
}

window.onload = function() {
  console.log("Entering onload function.");
  const type = getParameterByName('type');
  var jwt = "";
  if (type == 'access') {
    jwt = localStorage.getItem("token_access_token");
  } else if (type == 'refresh') {
    jwt = localStorage.getItem("token_refresh_token");
  } else if (type == 'id') {
    jwt = localStorage.getItem("token_id_token");
  } else if (type == 'refresh_access') {
    jwt = localStorage.getItem("refresh_access_token");
  } else if (type == 'refresh_refresh') {
    jwt = localStorage("refresh_refresh_token");
  } else if (type == 'refresh_id') {
    jwt = localStorage.getItem('refresh_id_token');
  } else {
    console.log('Unknown token type encountered.');
  }
  console.log('jwt: ' + jwt);
  const decodedJWT = decodeJWT(jwt);
  console.log('decoded jwt: ' + JSON.stringify(decodedJWT));
  document.getElementById('jwt_header').value = JSON.stringify(decodedJWT.header, null, 2);
  document.getElementById('jwt_payload').value = JSON.stringify(decodedJWT.payload, null, 2);
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

module.exports = {
 decodeJWT
};


