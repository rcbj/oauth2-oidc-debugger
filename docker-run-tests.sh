#!/bin/bash
set -x

init()
{
  DEBUGGER_BASE_URL=http://client:3000
  CONFIG_FILE=./env/local.js
  KEYCLOAK_BASE_URL=http://keycloak:8080
  KEYCLOAK_LOCALHOST_BASE_URL=http://keycloak:8080
  CONFIG_FILE=./env/local.js
  CURRENT_DIR=`echo "$(dirname "$(realpath "$0")")"`
  COMMON_SH=${CURRENT_DIR}/common.sh
  if [ -r "${COMMON_SH}" ];
  then
    . ${COMMON_SH}
  else
    echo "Cannot find ${COMMON_SH}."
    exit 1
  fi
  NODEJS_BASE_DIR=.
}

init
check_return_code $?
configureKeycloak
check_return_code $?
runTests
check_return_code $?
node --version
check_return_code $?
exit 0
