#!/bin/bash
set -x
#
# This script runs tests locally.
#
init()
{
  DEBUGGER_BASE_URL=http://localhost:3000
  KEYCLOAK_BASE_URL=http://localhost:8080
  KEYCLOAK_LOCALHOST_BASE_URL=http://localhost:8080
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
  NODEJS_BASE_DIR=tests
}

prepTestEnv()
{
  npm install --prefix tests
}

startDocker()
{
  # Start Docker containers
  sudo CONFIG_FILE=./env/local.js docker-compose -f local-tests.yml build
  sudo CONFIG_FILE=./env/local.js docker-compose -f local-tests.yml up -d
}

init
check_return_code $?
prepTestEnv
check_return_code $?
startDocker
check_return_code $?
sleep 60
check_return_code $?
configureKeycloak
check_return_code $?
runTests
check_return_code $?
node --version
check_return_code $?
exit 0
