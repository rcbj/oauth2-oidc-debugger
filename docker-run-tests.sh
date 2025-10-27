#!/bin/bash
set -x

init()
{
  DEBUGGER_BASE_URL=http://client:3000
  CONFIG_FILE=./env/local.js
}

check_return_code()
{
  rc=$1
  if [  $rc -ne 0 ];
  then
    echo "Non-zero return code. Exiting."
    exit 1
  fi
}

init
KEYCLOAK_ACCESS_TOKEN=$(curl \
  -X POST "http://keycloak:8080/realms/master/protocol/openid-connect/token" \
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

curl -X POST "http://keycloak:8080/admin/realms" \
  -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"realm": "debugger-testing", "enabled": true}'
check_return_code $?

for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC
do
    FLOW_NAME=$(echo ${FLOW_VARIABLE} | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl \
      -X POST "http://keycloak:8080/realms/master/protocol/openid-connect/token" \
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
    curl -X POST "http://keycloak:8080/admin/realms/debugger-testing/client-scopes" \
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
            curl -X POST "http://keycloak:8080/admin/realms/debugger-testing/clients" \
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
            curl -X POST "http://keycloak:8080/admin/realms/debugger-testing/clients" \
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
                   "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}/*'"], 
                   "attributes": {
                      "frontchannel.logout.url": 
                      "'${DEBUGGER_BASE_URL}/logout'"
                   }
                }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "http://keycloak:8080/admin/realms/debugger-testing/clients" \
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
                "webOrigins": ["/*", "'${DEBUGGER_BASE_URL}/*'"], 
                "attributes": {
                  "frontchannel.logout.url": 
                  "'${DEBUGGER_BASE_URL}/logout'"
                }
             }'
            check_return_code $?
            ;;
    esac

    CLIENT_ID=$(curl \
      -X GET \
      "http://keycloak:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].id')
    CLIENT_CLIENTID=$(curl \
      -X GET \
      "http://keycloak:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].clientId')
    CLIENT_SECRET=$(curl  \
      -X GET \
     "http://keycloak:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
     | jq -r '.[0].secret')
    SCOPE_ID=$(curl \
      -X GET \
      "http://keycloak:8080/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .id')
    SCOPE_NAME=$(curl \
      -X GET \
      "http://keycloak:8080/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .name')
    curl \
     -X PUT \
     "http://keycloak:8080/admin/realms/debugger-testing/clients/${CLIENT_ID}/optional-client-scopes/${SCOPE_ID}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}"
    check_return_code $?
    USER_ID=$(curl \
      -X POST \
      "http://keycloak:8080/admin/realms/debugger-testing/users" \
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
      "http://keycloak:8080/admin/realms/debugger-testing/users/${USER_ID}/reset-password" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "type": "password",
            "value": "'${FLOW_NAME}'",
            "temporary": false
          }'
    check_return_code $?

    declare ${FLOW_VARIABLE}_DISCOVERY_ENDPOINT="http://keycloak:8080/realms/debugger-testing/.well-known/openid-configuration"
    declare ${FLOW_VARIABLE}_CLIENT_ID="${CLIENT_CLIENTID}"
    declare ${FLOW_VARIABLE}_CLIENT_SECRET="${CLIENT_SECRET}"
    declare ${FLOW_VARIABLE}_SCOPE="${SCOPE_NAME}"
    declare ${FLOW_VARIABLE}_USER="${USER_ID}"
done

# Test client credentials flow
DISCOVERY_ENDPOINT=${CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT} \
CLIENT_ID=${CLIENT_CREDENTIALS_CLIENT_ID} \
CLIENT_SECRET=${CLIENT_CREDENTIALS_CLIENT_SECRET} \
SCOPE=${CLIENT_CREDENTIALS_SCOPE} \
node oauth2_client_credentials.js --url "${DEBUGGER_BASE_URL}"
check_return_code $?

# Test authorization code flow
for PKCE_ENABLED in true false
do
    echo "DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID}"
    echo "CLIENT_SECRET=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET}"
    echo "SCOPE=${AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE}"
    echo "USER=${AUTHORIZATION_CODE_CONFIDENTIAL_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

    # Confidential client
    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID} \
    CLIENT_SECRET=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET} \
    SCOPE=${AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE} \
    USER=${AUTHORIZATION_CODE_CONFIDENTIAL_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node oauth2_authorization_code.js --url "${DEBUGGER_BASE_URL}"
    check_return_code $?

    echo "DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT}"
    echo "CLIENT_ID=${AUTHORIZATION_CODE_PUBLIC_CLIENT_ID}"
    echo "CLIENT_SECRET=${AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET}"
    echo "SCOPE=${AUTHORIZATION_CODE_PUBLIC_SCOPE}"
    echo "USER=${AUTHORIZATION_CODE_PUBLIC_USER}"
    echo "PKCE_ENABLED=${PKCE_ENABLED}"

    # Public client
    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${AUTHORIZATION_CODE_PUBLIC_CLIENT_ID} \
    CLIENT_SECRET=${AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET} \
    SCOPE=${AUTHORIZATION_CODE_PUBLIC_SCOPE} \
    USER=${AUTHORIZATION_CODE_PUBLIC_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node oauth2_authorization_code.js --url "${DEBUGGER_BASE_URL}"
    check_return_code $?
done
