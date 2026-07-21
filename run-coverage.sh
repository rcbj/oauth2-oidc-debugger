#!/bin/bash
#
# Runs the full Selenium test suite with code-coverage collection enabled and
# renders the reports. Frontend (browser) coverage is gathered from
# Istanbul-instrumented bundles; backend (API) coverage is gathered with c8.
#
# Outputs (gitignored):
#   ./coverage/frontend/report/index.html   - browser/frontend coverage
#   ./coverage/api/index.html                - API (Node) coverage
#
set -x

# The tests run inside the containerized stack (docker-compose-run-tests.yml),
# so the browser bundles must be built with the in-container hostnames
# (api:4000 / client:3000). Using local.js here bakes http://localhost:4000
# into the bundle, which is unreachable from inside the Selenium container and
# makes every token call fail with status:0.
CONFIG_FILE=./env/docker-tests.js
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

export CONFIG_FILE="${CONFIG_FILE:-./env/docker-tests.js}"
COMPOSE="docker_compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml"

mkdir -p coverage/frontend/.nyc_output coverage/api

# Run the suite. Services are torn down when the tests container exits; stopping
# the API container lets c8 flush its coverage to ./coverage/api. Capture the
# tests container's exit code (--exit-code-from tests) so a failing test makes
# this script exit non-zero — do NOT mask it with `|| true`. We still render the
# report and tear down before exiting.
${COMPOSE} up --build --abort-on-container-exit --exit-code-from tests
TEST_RC=$?

# Render the frontend coverage report inside a throwaway client container, which
# has the instrumented source at the paths Istanbul recorded. A report-render
# failure should not override the test result, so this one stays best-effort.
${COMPOSE} run --rm --no-deps client \
  npx nyc report \
    --temp-dir /coverage/frontend/.nyc_output \
    --report-dir /coverage/frontend/report \
    --reporter=html --reporter=lcov --reporter=text-summary || true

${COMPOSE} down

echo ""
echo "Frontend (browser) coverage: ./coverage/frontend/report/index.html"
echo "API (Node) coverage:         ./coverage/api/index.html"

# Propagate the suite result as this script's exit code.
if [ "${TEST_RC}" -ne 0 ]; then
  echo "Test suite FAILED (exit ${TEST_RC})."
else
  echo "Test suite passed."
fi
exit ${TEST_RC}
