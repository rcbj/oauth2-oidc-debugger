#!/bin/bash
set -x

check_return_code()
{
  rc=$1
  if [  $rc -ne 0 ];
  then
    echo "Non-zero return code. Exiting."
    exit 1
  fi
}

configureKeycloak()
{
  echo "Entering configureKeycloak()."
  # Configure Keycloak
  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" |\
    jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
  then
    echo "Failed to obtain access token." 
      exit 1
  fi
  
  curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"realm": "debugger-testing", "enabled": true}'
  check_return_code $?
  
  for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC IMPLICIT OIDC_AUTHORIZATION_CODE_CONFIDENTIAL OIDC_AUTHORIZATION_CODE_PUBLIC
  do
    FLOW_NAME=$(echo ${FLOW_VARIABLE} | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl \
      -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli" \
      -d "username=keycloak" \
      -d "password=keycloak" \
      -d "grant_type=password" \
      | jq -r '.access_token')
    if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
    then
      echo "KEYCLOAK_ACCESS_TOKEN is blank."
      exit 1
    fi
    curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "name": "'${FLOW_NAME}'-scope",
            "protocol": "openid-connect",
            "attributes": {
              "display.on.consent.screen": "false",
              "include.in.token.scope": "true"
            }
         }'
    check_return_code $?
    case "${FLOW_VARIABLE}" in
        CLIENT_CREDENTIALS)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                 "clientId": "'${FLOW_NAME}'",
                 "protocol": "openid-connect",
                 "publicClient": false,
                 "serviceAccountsEnabled": true,
                 "authorizationServicesEnabled": false,
                 "standardFlowEnabled": false,
                 "directAccessGrantsEnabled": false,
                 "clientAuthenticatorType": "client-secret"
               }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'", 
                   "protocol": "openid-connect", 
                   "publicClient": false, 
                   "serviceAccountsEnabled": false, 
                   "authorizationServicesEnabled": false, 
                   "standardFlowEnabled": true, 
                   "directAccessGrantsEnabled": false, 
                   "clientAuthenticatorType": "client-secret", 
                   "frontchannelLogout": true, 
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                   "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}'"], 
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'", 
                "protocol": "openid-connect", 
                "publicClient": true, 
                "serviceAccountsEnabled": false, 
                "authorizationServicesEnabled": false, 
                "standardFlowEnabled": true, 
                "directAccessGrantsEnabled": false, 
                "clientAuthenticatorType": null, 
                "frontchannelLogout": true, 
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}'"], 
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            ;;
        IMPLICIT)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "implicitFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;

    esac

    CLIENT_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].id')
    CLIENT_CLIENTID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].clientId')
    CLIENT_SECRET=$(curl  \
      -X GET \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
     | jq -r '.[0].secret')
    SCOPE_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .id')
    SCOPE_NAME=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .name')
    curl \
     -X PUT \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients/${CLIENT_ID}/optional-client-scopes/${SCOPE_ID}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}"
    check_return_code $?
    USER_ID=$(curl \
      -X POST \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{ 
            "username": "'${FLOW_NAME}'",
            "firstName": "'${FLOW_NAME}'", 
            "lastName": "'${FLOW_NAME}'", 
            "email": "'${FLOW_NAME}'@iyasec.io", 
            "enabled": true, "emailVerified": true
          }' \
      -i \
      | grep Location \
      | rev \
      | cut -d '/' -f 1 \
      | rev \
      | tr -d ' \n\r')
    if [ -z "${CLIENT_ID}" ] || \
       [ -z "${CLIENT_CLIENTID}" ] || \
       [ -z "${CLIENT_SECRET}" ] || \
       [ -z "${SCOPE_ID}" ] || \
       [ -z "${SCOPE_NAME} ] || \
       [ -z "${USER_ID} ];
    then
      echo "Required variable is blank."
      exit 1
    fi 
    curl \
      -X PUT \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users/${USER_ID}/reset-password" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "type": "password",
            "value": "'${FLOW_NAME}'",
            "temporary": false
          }'
    check_return_code $?

    declare -g ${FLOW_VARIABLE}_AUDIENCE="${KEYCLOAK_BASE_URL}/realms/debugger-testing"
    declare -g ${FLOW_VARIABLE}_DISCOVERY_ENDPOINT="${KEYCLOAK_BASE_URL}/realms/debugger-testing/.well-known/openid-configuration"
    declare -g ${FLOW_VARIABLE}_CLIENT_ID="${CLIENT_CLIENTID}"
    declare -g ${FLOW_VARIABLE}_CLIENT_SECRET="${CLIENT_SECRET}"
    declare -g ${FLOW_VARIABLE}_SCOPE="${SCOPE_NAME}"
    declare -g ${FLOW_VARIABLE}_USER="${USER_ID}"

    VAR_NAME1=${FLOW_VARIABLE}_DISCOVERY_ENDPOINT
    VAR_NAME2=${FLOW_VARIABLE}_CLIENT_ID
    VAR_NAME3=${FLOW_VARIABLE}_CLIENT_SECRET
    VAR_NAME4=${FLOW_VARIABLE}_SCOPE
    VAR_NAME5=${FLOW_VARIABLE}_USER
    VAR_NAME6=${FLOW_VARIABLE}_AUDIENCE

    echo "${VAR_NAME1}=${!VAR_NAME1}"
    echo "${VAR_NAME2}=${!VAR_NAME2}"
    echo "${VAR_NAME3}=${!VAR_NAME3}"
    echo "${VAR_NAME4}=${!VAR_NAME4}"
    echo "${VAR_NAME5}=${!VAR_NAME5}"
    echo "${VAR_NAME6}=${!VAR_NAME6}"
  done
  echo "Leaving configureKeycloak()."
}

runTests()
{
  echo "Entering runTests()."
  # Test client credentials flow
  AUDIENCE=${CLIENT_CREDENTIALS_AUDIENCE} \
  DISCOVERY_ENDPOINT=${CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT} \
  CLIENT_ID=${CLIENT_CREDENTIALS_CLIENT_ID} \
  CLIENT_SECRET=${CLIENT_CREDENTIALS_CLIENT_SECRET} \
  SCOPE=${CLIENT_CREDENTIALS_SCOPE} \
  node ${NODEJS_BASE_DIR}/oauth2_client_credentials.js --url "${DEBUGGER_BASE_URL}"
  check_return_code $?

  # Test authorization code Grant
  echo "Test Authorization Code Grant"
  for PKCE_ENABLED in true false
  do
    echo "AUDIENCE=${AUTHORIZATION_CODE_CONFIDENTIAL_AUDIENCE}"
    echo "DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID}"
    echo "CLIENT_SECRET=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET}"
    echo "SCOPE=${AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE}"
    echo "USER=${AUTHORIZATION_CODE_CONFIDENTIAL_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

#    # Confidential client
#    AUDIENCE=${AUTHORIZATION_CODE_CONFIDENTIAL_AUDIENCE} \
#    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT} \
#    CLIENT_ID=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID} \
#    CLIENT_SECRET=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET} \
#    SCOPE=${AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE} \
#    USER=${AUTHORIZATION_CODE_CONFIDENTIAL_USER} \
#    PKCE_ENABLED=${PKCE_ENABLED} \
#    node ${NODEJS_BASE_DIR}/oauth2_authorization_code.js --url "${DEBUGGER_BASE_URL}"
#    check_return_code $?

    echo "AUDIENCE=${AUTHORIZATION_CODE_PUBLIC_AUDIENCE}"
    echo "DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${AUTHORIZATION_CODE_PUBLIC_CLIENT_ID}"
    echo "CLIENT_SECRET=${AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET}"
    echo "SCOPE=${AUTHORIZATION_CODE_PUBLIC_SCOPE}"
    echo "USER=${AUTHORIZATION_CODE_PUBLIC_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

    # Public client
    AUDIENCE=${AUTHORIZATION_CODE_PUBLIC_AUDIENCE} \
    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${AUTHORIZATION_CODE_PUBLIC_CLIENT_ID} \
    CLIENT_SECRET=${AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET} \
    SCOPE=${AUTHORIZATION_CODE_PUBLIC_SCOPE} \
    USER=${AUTHORIZATION_CODE_PUBLIC_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node ${NODEJS_BASE_DIR}/oauth2_authorization_code.js --url "${DEBUGGER_BASE_URL}"
    check_return_code $?
  done

  # OAuth2 Implicit Grant
  AUDIENCE=${IMPLICIT_AUDIENCE} \
  DISCOVERY_ENDPOINT=${IMPLICIT_DISCOVERY_ENDPOINT} \
  CLIENT_ID=${IMPLICIT_CLIENT_ID} \
  SCOPE=${IMPLICIT_SCOPE} \
  USER=${IMPLICIT_USER} \
  node ${NODEJS_BASE_DIR}/oauth2_implicit.js --url "${DEBUGGER_BASE_URL}"
  check_return_code $?

  # Test OIDC Authorization Code Flow
  echo "Test OIDC AUthorization Code Flow."
  for PKCE_ENABLED in true false
  do
    echo "AUDIENCE=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_AUDIENCE}"
    echo "DISCOVERY_ENDPOINT=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID}"
    echo "CLIENT_SECRET=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET}"
    echo "SCOPE=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE}"
    echo "USER=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

#    # Confidential client
#    AUDIENCE=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_AUDIENCE} \
#    DISCOVERY_ENDPOINT=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT} \
#    CLIENT_ID=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID} \
#    CLIENT_SECRET=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET} \
#    SCOPE="openid profile email offline_access ${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE}" \
#    USER=${OIDC_AUTHORIZATION_CODE_CONFIDENTIAL_USER} \
#    PKCE_ENABLED=${PKCE_ENABLED} \
#    node ${NODEJS_BASE_DIR}/oidc_authorization_code.js --url "${DEBUGGER_BASE_URL}"
#    check_return_code $?

    echo "AUDIENCE=${OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE}"
    echo "DISCOVERY_ENDPOINT=${OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID}"
    echo "CLIENT_SECRET=${OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET}"
    echo "SCOPE={OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE}"
    echo "USER=${OIDC_AUTHORIZATION_CODE_PUBLIC_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

    # Public client
    AUDIENCE=${OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE} \
    DISCOVERY_ENDPOINT=${OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID} \
    CLIENT_SECRET=${OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET} \
    SCOPE="openid profile email offline_access ${OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE}" \
    USER=${OIDC_AUTHORIZATION_CODE_PUBLIC_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node ${NODEJS_BASE_DIR}/oidc_authorization_code.js --url "${DEBUGGER_BASE_URL}"
    check_return_code $?
  done

  echo "Leaving runTests()."
}
