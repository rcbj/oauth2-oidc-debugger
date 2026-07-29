#!/bin/bash
set -x
#
# This script runs tests locally.
#
# Options:
#   --saml-dev   Build + start Keycloak and the debugger (api + client) and
#                provision Keycloak with SAML AuthnRequest signature validation
#                DISABLED, then leave the stack running WITHOUT running the tests
#                (for manual SAML testing with a browser-generated SP key).
#   -h|--help    Show usage.
#
SKIP_TESTS=0
SAML_SIG_VALIDATION=true

usage()
{
  cat <<USAGE
Usage: $(basename "$0") [--saml-dev] [-h|--help]

  (default)    Build + start the stack, provision Keycloak (SAML AuthnRequest
               signature validation ENABLED), and run the full test suite.

  --saml-dev   Build + start Keycloak and the debugger (api + client), provision
               Keycloak with SAML AuthnRequest signature validation DISABLED, and
               leave the stack running WITHOUT running the tests.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --saml-dev) SKIP_TESTS=1; SAML_SIG_VALIDATION=false ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done
export SAML_SIG_VALIDATION

init()
{
  DEBUGGER_BASE_URL=http://localhost:3000
  KEYCLOAK_BASE_URL=http://localhost:8080
  KEYCLOAK_LOCALHOST_BASE_URL=http://localhost:8080
  # SAML: must match the client bundle's baked env (client/src/env/local.js).
  API_BASE_URL=http://localhost:4000
  SAML_SP_ENTITY_ID=http://localhost:3000/saml/sp
  # WS-Trust STS (mock) on the host (local-tests.yml, host networking). Must match
  # the client bundle's baked wstrustStsUrlDefault (local.js).
  WSTRUST_STS_URL=http://localhost:8081/sts
  export WSTRUST_STS_URL
  # walt.id's issuer-api2 (local-tests.yml, host networking) — the real
  # OpenID4VCI issuer the interoperability job runs against.
  WALTID_ISSUER_URL=http://localhost:7005
  export WALTID_ISSUER_URL
  # walt.id's verifier, behind its own CORS proxy on 7003. Locating it here is what
  # switches the presentation interoperability job on; unset it and that job is
  # skipped rather than failed, the same way the issuer's is.
  WALTID_VERIFIER_URL=http://localhost:7003
  export WALTID_VERIFIER_URL
  # WS-Federation IdP side-car (Keycloak 8.0.1 + wsfed, local-tests.yml, host net,
  # WildFly port-offset 2 -> 8082). Browser-facing and admin-facing URLs are the
  # same on host networking. configureKeycloakWsfed provisions it and exports the
  # WSFED_* vars the WS-Fed test consumes.
  KEYCLOAK_WSFED_BASE_URL=http://localhost:8082
  KEYCLOAK_WSFED_LOCALHOST_BASE_URL=http://localhost:8082
  export KEYCLOAK_WSFED_BASE_URL KEYCLOAK_WSFED_LOCALHOST_BASE_URL
  CONFIG_FILE=./env/local.js
  CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
  COMMON_SH=${CURRENT_DIR}/common/common.sh
  if [ -r "${COMMON_SH}" ];
  then
    . ${COMMON_SH}
  else
    echo "Cannot find ${COMMON_SH}."
    exit 1
  fi
  common_setup
  check_return_code $?
  # A fresh SP key pair for this run: exported for the tests (which sign and
  # decrypt with it) and for configureKeycloak (which registers the certificate
  # on the SAML client). Nothing is written to the repository.
  generateSpKeyPair
  check_return_code $?
  # walt.id's issuer, and the identity provider it authenticates End-Users at.
  # These are the addresses the BROWSER uses: every URL walt.id publishes in its
  # metadata is built from WALTID_BASE_URL, and the authorize redirect goes to
  # the browser too. renderWaltidConfig writes them into the container's
  # configuration, and configureKeycloak registers the callback under the same
  # base.
  WALTID_BASE_URL=http://localhost:7005
  # The verifier's public address, which its urlPrefix names: under host
  # networking that is plain localhost.
  WALTID_VERIFIER_BASE_URL=http://localhost:7003
  WALTID_VERIFIER_CLIENT_ID=verifier2
  WALTID_KEYCLOAK_AUTHORIZE_URL=http://localhost:8080/realms/debugger-testing/protocol/openid-connect/auth
  WALTID_KEYCLOAK_TOKEN_URL=http://localhost:8080/realms/debugger-testing/protocol/openid-connect/token
  WALTID_KEYCLOAK_CLIENT_ID=waltid-issuer
  WALTID_KEYCLOAK_CLIENT_SECRET=waltid-issuer-test-secret
  export WALTID_BASE_URL WALTID_KEYCLOAK_AUTHORIZE_URL WALTID_KEYCLOAK_TOKEN_URL
  export WALTID_KEYCLOAK_CLIENT_ID WALTID_KEYCLOAK_CLIENT_SECRET
  export WALTID_VERIFIER_BASE_URL WALTID_VERIFIER_CLIENT_ID
  # The walt.id issuer's configuration is rendered before compose starts: the
  # container mounts the result, so the key exists on disk for this run only.
  generateWaltidIssuerKey
  check_return_code $?
  generateWaltidVerifierKey
  check_return_code $?
  renderWaltidConfig "${CURRENT_DIR}"
  check_return_code $?
  NODEJS_BASE_DIR=tests
}

prepTestEnv()
{
  npm install --prefix tests
}

startDocker()
{
  # Start Docker containers
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml build
  check_return_code $?
  CONFIG_FILE=./env/local.js docker_compose -f local-tests.yml up -d
  check_return_code $?
}

# Run the suite via the report generator instead of runTests(). It executes
# the same tests once, continues past failures, and writes an HTML + JUnit
# report to tests/report/. It exits non-zero if any test failed, so the
# check_return_code below still gates the "All tests passed" banner.
runReport()
{
  export DEBUGGER_BASE_URL
  # The SD-JWT VC issuance job retrieves the realm's RFC 8414 metadata to
  # configure its OIDC leg, so it needs to know where Keycloak is.
  export KEYCLOAK_BASE_URL
  # Export so run-report.js (and the test scripts it spawns) can
  # require(process.env.CONFIG_FILE) for centralized config (e.g. waitTime).
  export CONFIG_FILE
  node "${NODEJS_BASE_DIR}/run-report.js"
}

init
check_return_code $?
prepTestEnv
check_return_code $?
startDocker
check_return_code $?
sleep 60
check_return_code $?
# The walt.id services are JVM services and start slower than the sleep above
# allows for; wait for them rather than letting their jobs fail on a connection
# error that says nothing about the cause.
waitForWaltid
configureKeycloak
check_return_code $?
# Provision the WS-Federation side-car (no-op / skip if it isn't up).
configureKeycloakWsfed
check_return_code $?

if [ "${SKIP_TESTS}" = "1" ]; then
  cat <<EOF
============================================================================
Dev stack is UP — tests were NOT run.
  Debugger : ${DEBUGGER_BASE_URL}
  API      : ${API_BASE_URL}
  Keycloak : ${KEYCLOAK_BASE_URL}
SAML AuthnRequest signature validation is DISABLED on the Keycloak SAML client,
so a browser-generated (unregistered) SP key can drive the SAML flow.
Stop the stack with:
  CONFIG_FILE=./env/local.js docker compose -f local-tests.yml down
============================================================================
EOF
  exit 0
fi

runReport
check_return_code $?
node --version
check_return_code $?

cat <<'EOF'
   _   _ _   _            _                                  _
  / \ | | | | |_ ___  ___| |_ ___   _ __   __ _ ___ ___  ___| |
 / _ \| | | | __/ _ \/ __| __/ __| | '_ \ / _` / __/ __|/ _ \ |
/ ___ \ | | | ||  __/\__ \ |_\__ \ | |_) | (_| \__ \__ \  __/_|
/_/   \_\_|_|  \__\___||___/\__|___/ | .__/ \__,_|___/___/\___(_)
                                     |_|
EOF

exit 0
