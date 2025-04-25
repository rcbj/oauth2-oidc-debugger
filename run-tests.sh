#!/bin/bash

# Install testing dependencies
npm install --prefix tests

# Start Docker containers
CONFIG_FILE=./env/local.js docker compose -f docker-compose-with-keycloak.yml up -d --build
sleep 30

# Configure Keycloak
KEYCLOAK_ACCESS_TOKEN=$(curl -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" -d "grant_type=password" | jq -r '.access_token')
curl -X POST "http://localhost:8080/admin/realms" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"realm": "debugger-testing", "enabled": true}'

for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_PRIVATE AUTHORIZATION_CODE_PUBLIC
do
    FLOW_NAME=$(echo $FLOW_VARIABLE | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" -d "grant_type=password" | jq -r '.access_token')
    curl -X POST "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"name": "'$FLOW_NAME'-scope", "protocol": "openid-connect", "attributes": {"display.on.consent.screen": "false", "include.in.token.scope": "true"}}'
    case "$FLOW_VARIABLE" in
        CLIENT_CREDENTIALS)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"clientId": "'$FLOW_NAME'", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "clientAuthenticatorType": "client-secret"}'
            ;;
        AUTHORIZATION_CODE_PRIVATE)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"clientId": "'$FLOW_NAME'", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": false, "authorizationServicesEnabled": false, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "clientAuthenticatorType": "client-secret", "frontchannelLogout": true, "redirectUris": ["http://localhost:3000/callback"], "webOrigins": ["/*", "http://localhost:3000/*"], "attributes": {"frontchannel.logout.url": "http://localhost:3000/logout"}}'
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"clientId": "'$FLOW_NAME'", "protocol": "openid-connect", "publicClient": true, "serviceAccountsEnabled": false, "authorizationServicesEnabled": false, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "clientAuthenticatorType": null, "frontchannelLogout": true, "redirectUris": ["http://localhost:3000/callback"], "webOrigins": ["/*", "http://localhost:3000/*"], "attributes": {"frontchannel.logout.url": "http://localhost:3000/logout"}}'
            ;;
    esac

    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_CLIENT_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=$FLOW_NAME" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].id')
    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_CLIENT_CLIENTID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=$FLOW_NAME" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].clientId')
    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_CLIENT_SECRET=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=$FLOW_NAME" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].secret')
    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_SCOPE_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[] | select(.name=="'$FLOW_NAME'-scope") | .id')
    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_SCOPE_NAME=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[] | select(.name=="'$FLOW_NAME'-scope") | .name')
    curl -X PUT "http://localhost:8080/admin/realms/debugger-testing/clients/$(TMP=$(echo KEYCLOAK_${FLOW_VARIABLE}_CLIENT_ID); echo ${!TMP})/optional-client-scopes/$(TMP=$(echo KEYCLOAK_${FLOW_VARIABLE}_SCOPE_ID); echo ${!TMP})" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN"
    declare KEYCLOAK_$(echo $FLOW_VARIABLE)_USER_ID=$(curl -X POST "http://localhost:8080/admin/realms/debugger-testing/users" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"username": "'$FLOW_NAME'", "firstName": "'$FLOW_NAME'", "lastName": "'$FLOW_NAME'", "email": "'$FLOW_NAME'@iyasec.io", "enabled": true, "emailVerified": true}' -i | grep Location | rev | cut -d '/' -f 1 | rev | tr -d ' \n\r')
    curl -X PUT "http://localhost:8080/admin/realms/debugger-testing/users/$(TMP=$(echo KEYCLOAK_${FLOW_VARIABLE}_USER_ID); echo ${!TMP})/reset-password" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"type": "password", "value": "'$FLOW_NAME'", "temporary": false}'
done

# Test client credentials flow
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_SECRET \
SCOPE=$KEYCLOAK_CLIENT_CREDENTIALS_SCOPE_NAME \
node tests/oauth2_client_credentials.js

# Test authorization code flow
## Private client with PKCE
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_CLIENT_SECRET \
SCOPE=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_SCOPE_NAME \
PKCE_ENABLED=true \
node tests/oauth2_authorization_code.js

## Private client without PKCE
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_CLIENT_SECRET \
SCOPE=$KEYCLOAK_AUTHORIZATION_CODE_PRIVATE_SCOPE_NAME \
PKCE_ENABLED=false \
node tests/oauth2_authorization_code.js

## Public client with PKCE
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET \
SCOPE=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_SCOPE_NAME \
PKCE_ENABLED=true \
node tests/oauth2_authorization_code.js

## Public client without PKCE
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET \
SCOPE=$KEYCLOAK_AUTHORIZATION_CODE_PUBLIC_SCOPE_NAME \
PKCE_ENABLED=false \
node tests/oauth2_authorization_code.js