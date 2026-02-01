#!/usr/bin/env bash
set -euo pipefail

# --------
# Config
# --------
BASE_HOST="${BASE_HOST:-127.0.0.1}"

OPENCTI_PORT="${OPENCTI_PORT:-8080}"
INTEL_API_PORT="${INTEL_API_PORT:-8000}"
SPIDERFOOT_PORT="${SPIDERFOOT_PORT:-5001}"
SPIDERFOOT_WEB_PORT="${SPIDERFOOT_WEB_PORT:-5002}"
TAXII_PORT="${TAXII_PORT:-9000}"
RABBITMQ_PORT="${RABBITMQ_PORT:-15672}"
ES_PORT="${ES_PORT:-9200}"
MINIO_PORT="${MINIO_PORT:-9000}"

ENV_FILE="${ENV_FILE:-.env}"

# --------
# Helpers
# --------
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
RESET=$'\e[0m'

pass() { echo "${GREEN}PASS${RESET} - $*"; }
warn() { echo "${YELLOW}WARN${RESET} - $*"; }
fail() { echo "${RED}FAIL${RESET} - $*"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

http_code() {
  # prints only the HTTP status code (or 000 if connection fails)
  curl -sS -o /dev/null -w "%{http_code}" "$1" || echo "000"
}

require_tools() {
  local missing=0
  for c in curl grep sed; do
    if ! have_cmd "$c"; then
      fail "Missing required command: $c"
      missing=1
    fi
  done
  if [ "$missing" -eq 1 ]; then
    exit 1
  fi
}

load_env_token() {
  if [ -f "$ENV_FILE" ]; then
    # Extract OPENCTI_ADMIN_TOKEN safely
    OPENCTI_TOKEN="$(grep -E '^OPENCTI_ADMIN_TOKEN=' "$ENV_FILE" | tail -n 1 | sed 's/^OPENCTI_ADMIN_TOKEN=//')"
    if [ -z "${OPENCTI_TOKEN:-}" ]; then
      warn "OPENCTI_ADMIN_TOKEN not found in $ENV_FILE (GraphQL auth test will be skipped)"
      OPENCTI_TOKEN=""
    fi
  else
    warn "$ENV_FILE not found (GraphQL auth test will be skipped)"
    OPENCTI_TOKEN=""
  fi
}

check_url() {
  local name="$1"
  local url="$2"
  local expect="${3:-200}"

  local code
  code="$(http_code "$url")"

  if [ "$code" = "$expect" ]; then
    pass "$name ($url) => $code"
    return 0
  fi

  # Allow some endpoints to redirect (301/302) or respond 405 to HEAD-like behavior
  if [ "$expect" = "200or302" ] && { [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; }; then
    pass "$name ($url) => $code"
    return 0
  fi

  fail "$name ($url) => $code (expected $expect)"
  return 1
}

check_opencti_graphql_auth() {
  if [ -z "${OPENCTI_TOKEN:-}" ]; then
    warn "Skipping OpenCTI GraphQL auth test (no token loaded)"
    return 0
  fi

  # Query current user/me equivalent: ask for a trivial query that requires auth.
  # If token is valid -> 200 with JSON data. If invalid -> 401/403 with {"errors":...} sometimes still 200.
  local url="http://${BASE_HOST}:${OPENCTI_PORT}/graphql"
  local payload='{"query":"query { me { id name user_email } }"}'

  local http_status
  http_status="$(curl -sS -o /tmp/opencti_me.json -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer '"$OPENCTI_TOKEN"'" \
    -d "$payload" \
    "$url" || echo "000")"

  if [ "$http_status" != "200" ]; then
    fail "OpenCTI GraphQL auth (me) => HTTP $http_status"
    return 1
  fi

  if grep -q '"errors"' /tmp/opencti_me.json; then
    fail "OpenCTI GraphQL auth (me) => got errors (token likely wrong). Response saved in /tmp/opencti_me.json"
    return 1
  fi

  pass "OpenCTI GraphQL auth (me) => OK"
  return 0
}

check_docker_services() {
  if ! have_cmd docker; then
    warn "docker command not found; skipping docker compose service status check"
    return 0
  fi

  if docker compose ps >/dev/null 2>&1; then
    echo ""
    echo "Docker Compose status:"
    docker compose ps
  else
    warn "docker compose not available or not running in this directory"
  fi
}

# --------
# Main
# --------
require_tools
load_env_token

echo "CTI Platform Health Check"
echo "Host: ${BASE_HOST}"
echo "Time: $(date -Is)"
echo ""

# OpenCTI basic UI + GraphQL reachability
check_url "OpenCTI UI" "http://${BASE_HOST}:${OPENCTI_PORT}/" "200or302" || true
check_url "OpenCTI GraphQL endpoint reachable" "http://${BASE_HOST}:${OPENCTI_PORT}/graphql" "400" || true
# Note: /graphql usually returns 400 on GET without body, that's OK.

check_opencti_graphql_auth || true

echo ""
# Intel API
check_url "Intel API docs" "http://${BASE_HOST}:${INTEL_API_PORT}/docs" "200" || true
check_url "Intel API briefing" "http://${BASE_HOST}:${INTEL_API_PORT}/briefing" "200" || true
check_url "Intel API ROI" "http://${BASE_HOST}:${INTEL_API_PORT}/roi" "200" || true

echo ""
# SpiderFoot
check_url "SpiderFoot UI (expected path)" "http://${BASE_HOST}:${SPIDERFOOT_PORT}/spiderfoot/" "200or302" || true
check_url "SpiderFoot-web redirect" "http://${BASE_HOST}:${SPIDERFOOT_WEB_PORT}/" "200or302" || true

echo ""
# TAXII demo bundle
check_url "TAXII bundle.json" "http://${BASE_HOST}:${TAXII_PORT}/bundle.json" "200" || true

echo ""
# RabbitMQ UI
check_url "RabbitMQ Management UI" "http://${BASE_HOST}:${RABBITMQ_PORT}/" "200or302" || true

echo ""
# Elasticsearch
check_url "Elasticsearch root" "http://${BASE_HOST}:${ES_PORT}/" "200" || true

echo ""
# MinIO liveness
check_url "MinIO live health" "http://${BASE_HOST}:${MINIO_PORT}/minio/health/live" "200" || true

echo ""
check_docker_services

echo ""
echo "Done."
