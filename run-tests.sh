#!/bin/bash

# Start Docker containers
CONFIG_FILE=./env/local.js docker compose -f docker-compose-with-keycloak.yml up -d --build
sleep 30

# Configure client credentials flow
KEYCLOAK_ACCESS_TOKEN=$(curl -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" -H "Content-Type: application/x-www-form-urlencoded" -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" -d "grant_type=password" | jq -r '.access_token')
curl -X POST "http://localhost:8080/admin/realms" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"realm": "debugger-testing", "enabled": true}'
curl -X POST "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"name": "client-credentials-scope", "protocol": "openid-connect", "attributes": {"display.on.consent.screen": "false", "include.in.token.scope": "true"}}'
curl -X POST "http://localhost:8080/admin/realms/debugger-testing/clients" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" -H "Content-Type: application/json" -d '{"clientId": "client-credentials", "protocol": "openid-connect", "publicClient": false, "serviceAccountsEnabled": true, "authorizationServicesEnabled": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "clientAuthenticatorType": "client-secret"}'
KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=client-credentials" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].id')
KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_CLIENTID=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=client-credentials" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].clientId')
KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_SECRET=$(curl "http://localhost:8080/admin/realms/debugger-testing/clients?clientId=client-credentials" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[0].secret')
KEYCLOAK_CLIENT_CREDENTIALS_SCOPE_ID=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[] | select(.name=="client-credentials-scope") | .id')
KEYCLOAK_CLIENT_CREDENTIALS_SCOPE_NAME=$(curl "http://localhost:8080/admin/realms/debugger-testing/client-scopes" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN" | jq -r '.[] | select(.name=="client-credentials-scope") | .name')
curl -X PUT "http://localhost:8080/admin/realms/debugger-testing/clients/$KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_ID/optional-client-scopes/$KEYCLOAK_CLIENT_CREDENTIALS_SCOPE_ID" -H "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN"

# Install dependencies
cd tests && npm install

# Test client credentials flow
DISCOVERY_ENDPOINT="http://localhost:8080/realms/debugger-testing/.well-known/openid-configuration" \
CLIENT_ID=$KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_CLIENTID \
CLIENT_SECRET=$KEYCLOAK_CLIENT_CREDENTIALS_CLIENT_SECRET \
SCOPE=$KEYCLOAK_CLIENT_CREDENTIALS_SCOPE_NAME \
node oauth2_client_credentials.js