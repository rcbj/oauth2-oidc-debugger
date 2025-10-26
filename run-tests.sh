#!/bin/bash
. $NVM_DIR/nvm.sh

# Install testing dependencies

# Start Docker containers
CONFIG_FILE=./env/local.js docker-compose -f docker-compose-with-keycloak.yml build
CONFIG_FILE=./env/local.js docker-compose -f docker-compose-with-keycloak.yml up -d

sleep 30

# Configure Keycloak
KEYCLOAK_ACCESS_TOKEN=$(curl -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" -d "grant_type=password" | jq -r '.access_token')
curl -X POST "http://localhost:8080/admin/realms" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"realm": "debugger-testing", "enabled": true}'

for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC
do
    FLOW_NAME=$(echo ${FLOW_VARIABLE} | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" -d "grant_type=password" | jq -r '.access_token')
    curl -X POST "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"name": "'${FLOW_NAME}'-scope", "protocol": "openid-connect", "attributes": {"display.on.consent.screen": "false", "include.in.token.scope": "true"}}'
    case "${FLOW_VARIABLE}" in
        CLIENT_CREDENTIALS)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"clientId": "'${FLOW_NAME}'", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "clientAuthenticatorType": "client-secret"}'
            ;;
        AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"clientId": "'${FLOW_NAME}'", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": false, "authorizationServicesEnabled": false, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "clientAuthenticatorType": "client-secret", "frontchannelLogout": true, "redirectUris": ["http://localhost:3000/callback"], "webOrigins": ["/*", "http://localhost:3000/*"], "attributes": {"frontchannel.logout.url": "http://localhost:3000/logout"}}'
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"clientId": "'${FLOW_NAME}'", "protocol": "openid-connect", "publicClient": true, "serviceAccountsEnabled": false, "authorizationServicesEnabled": false, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "clientAuthenticatorType": null, "frontchannelLogout": true, "redirectUris": ["http://localhost:3000/callback"], "webOrigins": ["/*", "http://localhost:3000/*"], "attributes": {"frontchannel.logout.url": "http://localhost:3000/logout"}}'
            ;;
    esac

    CLIENT_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" | jq -r '.[0].id')
    CLIENT_CLIENTID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" | jq -r '.[0].clientId')
    CLIENT_SECRET=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" | jq -r '.[0].secret')
    SCOPE_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .id')
    SCOPE_NAME=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .name')
    curl -X PUT "http://localhost:8080/admin/realms/debugger-testing/clients/${CLIENT_ID}/optional-client-scopes/${SCOPE_ID}" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}"
    USER_ID=$(curl -X POST "http://localhost:8080/admin/realms/debugger-testing/users" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"username": "'${FLOW_NAME}'", "firstName": "'${FLOW_NAME}'", "lastName": "'${FLOW_NAME}'", "email": "'${FLOW_NAME}'@iyasec.io", "enabled": true, "emailVerified": true}' -i | grep Location | rev | cut -d '/' -f 1 | rev | tr -d ' \n\r')
    curl -X PUT "http://localhost:8080/admin/realms/debugger-testing/users/${USER_ID}/reset-password" -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" -H "Content-Type: application/json" -d '{"type": "password", "value": "'${FLOW_NAME}'", "temporary": false}'

    declare ${FLOW_VARIABLE}_DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration"
    declare ${FLOW_VARIABLE}_CLIENT_ID="${CLIENT_CLIENTID}"
    declare ${FLOW_VARIABLE}_CLIENT_SECRET="${CLIENT_SECRET}"
    declare ${FLOW_VARIABLE}_SCOPE="${SCOPE_NAME}"
    declare ${FLOW_VARIABLE}_USER="${USER_ID}"
done

node --version
exit 0
# Test client credentials flow
DISCOVERY_ENDPOINT=${CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT} \
CLIENT_ID=${CLIENT_CREDENTIALS_CLIENT_ID} \
CLIENT_SECRET=${CLIENT_CREDENTIALS_CLIENT_SECRET} \
SCOPE=${CLIENT_CREDENTIALS_SCOPE} \
node tests/oauth2_client_credentials.js

# Test authorization code flow
for PKCE_ENABLED in true false
do
    # Confidential client
    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_CONFIDENTIAL_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID} \
    CLIENT_SECRET=${AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET} \
    SCOPE=${AUTHORIZATION_CODE_CONFIDENTIAL_SCOPE} \
    USER=${AUTHORIZATION_CODE_CONFIDENTIAL_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node tests/oauth2_authorization_code.js

    # Public client
    DISCOVERY_ENDPOINT=${AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT} \
    CLIENT_ID=${AUTHORIZATION_CODE_PUBLIC_CLIENT_ID} \
    CLIENT_SECRET=${AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET} \
    SCOPE=${AUTHORIZATION_CODE_PUBLIC_SCOPE} \
    USER=${AUTHORIZATION_CODE_PUBLIC_USER} \
    PKCE_ENABLED=${PKCE_ENABLED} \
    node tests/oauth2_authorization_code.js
done
