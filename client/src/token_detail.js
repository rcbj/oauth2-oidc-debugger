// File: token_detail.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/28/2020
// Notes:
//
// Node modules are needed to be able to read the JWT tokens.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
const { DOMParser } = require('xmldom');
var log = bunyan.createLogger({ name: 'token_detail',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
const jwt = require('jsonwebtoken');

claimDescriptionDictionary = {};

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

function decodeJWT(jwt_) {
  return jwt.decode(jwt_, {complete: true});
}

async function verifyJWT() {
  var type = getParameterByName('type');
  var jwt_verification_type = document.getElementById("jwt_verification_type").value;
  var jwt_verification_key = document.getElementById("jwt_verification_key").value;
  var jwt_ = "";
  if (type == 'access') {
    jwt_ = localStorage.getItem("token_access_token");
  } else if (type == 'refresh') {
    jwt_ = localStorage.getItem("token_refresh_token");
  } else if (type == 'id') {
    jwt_ = localStorage.getItem("token_id_token");
  } else if (type == 'refresh_access') {
    jwt_ = localStorage.getItem("refresh_access_token");
  } else if (type == 'refresh_refresh') {
    jwt_ = localStorage("refresh_refresh_token");
  } else if (type == 'refresh_id') {
    jwt_ = localStorage.getItem('refresh_id_token');
  } else {
    log.error('Unknown token type encountered.');
  }

  try {
    const [headerB64, payloadB64, signatureB64] = jwt_.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) throw new Error('Invalid JWT format.');

    const header = JSON.parse(atobUrl(headerB64));
    var isValid = false;
    if (jwt_verification_type === 'hmac') {
      isValid = await verifyHMAC(jwt_, jwt_verification_key, header.alg);
    } else if (jwt_verification_type === 'x509') {
      isValid = await verifyX509(jwt_, jwt_verification_key, header.alg);
    } else if (jwt_verification_type === 'jwks') {
      isValid = await verifyJWKS(jwt_, JSON.parse(jwt_verification_key));
    } else if (jwt_verification_type === 'jwks_url') {
      const response = await fetch(jwt_verification_key);
      if (!response.ok) throw new Error('Failed to fetch JWKS.');
      isValid = await verifyJWKS(jwt_, await response.json());
    } else {
      throw new Error('Unsupported verification method.');
    }
  } catch (err) {
    log.error("Error while verifying JWT: " + err.message);
  }

  document.getElementById('jwt_verification_output').value = "Signature Verified: " + isValid;
}

function atobUrl(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '==='.slice(0, (4 - input.length % 4) % 4);
  return atob(input + pad);
}

function base64UrlToUint8Array(base64UrlString) {
  const binary = atobUrl(base64UrlString);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function pemToArrayBuffer(pem) {
  const binary = atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const buffer = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  
  return buffer.buffer;
}

async function verifyHMAC(jwt_, secret, alg = 'HS256') {
  const encoder = new TextEncoder();
  const algo = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' }[alg];
  if (!algo) throw new Error('Unsupported HMAC algorithm: ' + alg);

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  return await crypto.subtle.verify('HMAC', key, signature, data);
}

async function verifyX509(jwt_, pem, alg = 'RS256') {
  const encoder = new TextEncoder();
  const algo = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' }[alg];
  if (!algo) throw new Error('Unsupported RSA algorithm: ' + alg);

  const key = await crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
}

async function verifyJWKS(jwt_, jwks) {
  const header = JSON.parse(atobUrl(jwt_.split('.')[0]));
  if (!header.kid) throw new Error('No "kid" found in JWT header.');

  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Matching "kid" not found in JWKS.');
  if (jwk.kty !== 'RSA') throw new Error('Only RSA keys are supported.');

  const encoder = new TextEncoder();
  const algo = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' }[header.alg];
  if (!algo) throw new Error('Unsupported algorithm: ' + header.alg);

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e },
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: algo } },
    false,
    ['verify']
  );
  const data = encoder.encode(jwt_.split('.').slice(0, 2).join('.'));
  const signature = base64UrlToUint8Array(jwt_.split('.')[2]);

  return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
}

$(document).on("change", "#jwt_verification_type", function() {
  if (this.value == "jwks_url") {
    document.getElementById('jwt_verification_key').value = localStorage.getItem("jwks_endpoint");
  }
});

window.onload = function() {
  log.debug("Entering onload function.");
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
    jwt = localStorage.getItem("refresh_refresh_token");
  } else if (type == 'refresh_id') {
    jwt = localStorage.getItem('refresh_id_token');
  } else {
    log.error('Unknown token type encountered.');
  }
  // Retrieve IANA JWT claim assignments
  fetch(appconfig.apiUrl + "/claimdescription")
  .then((response) => response.text())
  .then((body_text) => {
    console.log(body_text);
    parser = new DOMParser();
    xmlDoc = parser.parseFromString(body_text, "application/xml");
    records = xmlDoc.getElementsByTagName("record");
    for (i = 0; i < records.length; i++)
    {
      claim = records[i].getElementsByTagName("value")[0].textContent;
      description = records[i].getElementsByTagName("description")[0].textContent;
  //    console.log(claim + ":" + description);
      claimDescriptionDictionary[claim] = description;
    }
  }).then( () => {
    Object.keys(claimDescriptionDictionary).forEach( (key) => {
      log.debug("Claims Description Map Entry: " + key + ":" + claimDescriptionDictionary[key]);
      log.debug('jwt: ' + jwt);
      const decodedJWT = decodeJWT(jwt);
      log.debug('decoded jwt: ' + JSON.stringify(decodedJWT));
      // Populate JSON tab.  
      $('#jwt_header').val(JSON.stringify(decodedJWT.header, null, 2));
      $('#jwt_payload').val(JSON.stringify(decodedJWT.payload, null, 2));
      // Populate Key-Pair tab
      keyPairJWTHeader = '<table border="1">'
                       +   '<tr>'
                       +     '<td><b>Claim</b></td><td><b>Value</b></td><td><b>Description</b></td>'
                       +   '</tr>'
      Object.keys(decodedJWT.header).forEach(key => {
        if ( typeof decodedJWT.header[key] === "object" )
        {
          keyPairJWTHeader += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + JSON.stringify(decodedJWT.header[key]) + '</td>';
          if (!!claimDescriptionDictionary[key]) {
            keyPairJWTHeader += '<td>' + claimDescriptionDictionary[key] + '</td>';
          }
          keyPairJWTHeader += '</tr>';
        } else {
          keyPairJWTHeader += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + decodedJWT.header[key] + '</td>';
          if (!!claimDescriptionDictionary[key]) {
            keyPairJWTHeader += '<td>' + claimDescriptionDictionary[key] + '</td>';
          }
          keyPairJWTHeader += '</tr>';
        }
      });
      keyPairJWTHeader += '</table>';
      $('#key_pair_jwt_header').html(keyPairJWTHeader);
      keyPairJWTPayload = '<table border="1">'
                       +   '<tr>'
                       +     '<td><b>Claim</b></td><td><b>Value</b></td><td><b>Description</b></td>'
                       +   '</tr>'
      Object.keys(decodedJWT.payload).forEach(key => {
        if (typeof decodedJWT.payload[key] === "object" )
        {
          keyPairJWTPayload += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + JSON.stringify(decodedJWT.payload[key]) + '</td>';
          if (!!claimDescriptionDictionary[key]) {
            keyPairJWTPayload += '<td>' + claimDescriptionDictionary[key] + '</td>';
          }
          keyPairJWTPayload += '</tr>';
        } else {
          keyPairJWTPayload += '<tr>'
                            + '<td>' + key + '</td>'
                            + '<td>' + decodedJWT.payload[key] + '</td>';
          if (!!claimDescriptionDictionary[key]) {
            keyPairJWTPayload += '<td>' + claimDescriptionDictionary[key] + '</td>';
          }
          keyPairJWTPayload += '</tr>';
        }
      });
      keyPairJWTPayload += '</table>';
      $('#key_pair_jwt_payload').html(keyPairJWTPayload);
    });
  })
  .catch( (error) => {
    log.error("An error was encountered: " + error.stack);
  });
}

function populateTable(evt, tabName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(tabName).style.display = "block";
  evt.currentTarget.className += " active";
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
 decodeJWT,
 verifyJWT,
 populateTable,
 clickLink
};
