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

export CONFIG_FILE="${CONFIG_FILE:-./env/docker-tests.js}"
COMPOSE="docker_compose -f docker-compose-run-tests.yml -f docker-compose-coverage.yml"

mkdir -p coverage/frontend/.nyc_output coverage/api

# Run the suite. Services are torn down when the tests container exits; stopping
# the API container lets c8 flush its coverage to ./coverage/api.
${COMPOSE} up --build --abort-on-container-exit --exit-code-from tests || true

# Render the frontend coverage report inside a throwaway client container, which
# has the instrumented source at the paths Istanbul recorded.
${COMPOSE} run --rm --no-deps client \
  npx nyc report \
    --temp-dir /coverage/frontend/.nyc_output \
    --report-dir /coverage/frontend/report \
    --reporter=html --reporter=lcov --reporter=text-summary || true

${COMPOSE} down

echo ""
echo "Frontend (browser) coverage: ./coverage/frontend/report/index.html"
echo "API (Node) coverage:         ./coverage/api/index.html"
