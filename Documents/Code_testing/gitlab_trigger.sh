#!/usr/bin/env bash
# gitlab_trigger.sh — Test or trigger a GitLab pipeline
#
# Edit the variables below, then run:
#   chmod +x gitlab_trigger.sh
#   ./gitlab_trigger.sh          # trigger the pipeline
#   ./gitlab_trigger.sh --test   # validate token only (no pipeline created)

# ── Config — fill these in ─────────────────────────────────────────────────
GITLAB_URL="https://gitlab.example.com"   # your GitLab instance
PROJECT_ID="12345678"                      # Settings > General > Project ID
TRIGGER_TOKEN="glptt-xxxxxxxxxxxxxxxxxx"   # Settings > CI/CD > Pipeline triggers
REF="main"                                 # branch or tag to run
CACERT=""                                  # path to CA cert, e.g. /etc/ssl/certs/ca.crt
                                           # leave empty to use system default
# ──────────────────────────────────────────────────────────────────────────

TRIGGER_URL="${GITLAB_URL%/}/api/v4/projects/${PROJECT_ID}/trigger/pipeline"

# Build curl args
CURL=("curl" "-s" "--max-time" "15")
[[ -n "$CACERT" ]] && CURL+=("--cacert" "$CACERT")

# --test mode: post to a bogus ref to verify the token without running anything
if [[ "${1:-}" == "--test" ]]; then
  echo "Testing token against: $GITLAB_URL (project $PROJECT_ID)..."
  HTTP=$(${CURL[@]} -o /tmp/gl_out.json -w "%{http_code}" \
    -F "token=$TRIGGER_TOKEN" -F "ref=__test_probe__" "$TRIGGER_URL")
  echo "HTTP $HTTP — $(cat /tmp/gl_out.json)"
  case "$HTTP" in
    201|400) echo "✅ Token is valid" ;;
    401)     echo "❌ Token invalid or revoked" ;;
    403)     echo "❌ Permission denied" ;;
    404)     echo "❌ Project not found" ;;
    *)       echo "⚠️  Unexpected response" ;;
  esac
  exit 0
fi

# Trigger the pipeline
echo "Triggering pipeline on '$REF'..."
HTTP=$(${CURL[@]} -o /tmp/gl_out.json -w "%{http_code}" \
  -F "token=$TRIGGER_TOKEN" -F "ref=$REF" "$TRIGGER_URL")
BODY=$(cat /tmp/gl_out.json)
echo "HTTP $HTTP — $BODY"
case "$HTTP" in
  201) echo "✅ Pipeline triggered!" ;;
  401) echo "❌ Token invalid or revoked" ;;
  403) echo "❌ Permission denied" ;;
  404) echo "❌ Project not found" ;;
  422) echo "❌ Ref '$REF' not found or .gitlab-ci.yml missing" ;;
  *)   echo "⚠️  Unexpected response" ;;
esac
