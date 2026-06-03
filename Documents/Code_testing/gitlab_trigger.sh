#!/usr/bin/env bash
# ============================================================
# gitlab_trigger.sh
# Test or fire a GitLab pipeline trigger token.
#
# Usage:
#   ./gitlab_trigger.sh                        # uses env vars
#   ./gitlab_trigger.sh --dry-run              # validate token only, no trigger
#
# Required env vars (or edit the defaults below):
#   GITLAB_URL        e.g. https://gitlab.com
#   GITLAB_PROJECT_ID e.g. 12345678  (Settings > General > Project ID)
#   GITLAB_TOKEN      pipeline trigger token  (Settings > CI/CD > Pipeline triggers)
#   GITLAB_REF        branch/tag to run on (default: main)
# ============================================================

set -euo pipefail

# ── Configuration (override via env or edit here) ──────────────────────────
GITLAB_URL="${GITLAB_URL:-https://gitlab.com}"
GITLAB_PROJECT_ID="${GITLAB_PROJECT_ID:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
GITLAB_REF="${GITLAB_REF:-main}"
DRY_RUN=false

# Optional pipeline variables passed as VAR=value pairs after --vars
# e.g. MY_VAR=hello ANOTHER=world
declare -A PIPELINE_VARS=()

# ── Argument parsing ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=true; shift ;;
    --url)       GITLAB_URL="$2"; shift 2 ;;
    --project)   GITLAB_PROJECT_ID="$2"; shift 2 ;;
    --token)     GITLAB_TOKEN="$2"; shift 2 ;;
    --ref)       GITLAB_REF="$2"; shift 2 ;;
    --var)       # --var KEY=VALUE
                 IFS='=' read -r k v <<< "$2"
                 PIPELINE_VARS["$k"]="$v"
                 shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Validation ─────────────────────────────────────────────────────────────
missing=()
[[ -z "$GITLAB_PROJECT_ID" ]] && missing+=("GITLAB_PROJECT_ID")
[[ -z "$GITLAB_TOKEN" ]]      && missing+=("GITLAB_TOKEN")

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "❌  Missing required values: ${missing[*]}"
  echo "    Set them as environment variables or pass via flags."
  echo "    Example:"
  echo "      GITLAB_PROJECT_ID=123 GITLAB_TOKEN=glptt-xxx ./gitlab_trigger.sh"
  exit 1
fi

API_BASE="${GITLAB_URL%/}/api/v4"
TRIGGER_URL="${API_BASE}/projects/${GITLAB_PROJECT_ID}/trigger/pipeline"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  GitLab Pipeline Trigger"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Host     : $GITLAB_URL"
echo "  Project  : $GITLAB_PROJECT_ID"
echo "  Ref      : $GITLAB_REF"
echo "  Dry run  : $DRY_RUN"
echo "  Token    : ${GITLAB_TOKEN:0:8}…(redacted)"
[[ ${#PIPELINE_VARS[@]} -gt 0 ]] && echo "  Vars     : ${!PIPELINE_VARS[*]}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Build curl form data ───────────────────────────────────────────────────
FORM_ARGS=(-F "token=${GITLAB_TOKEN}" -F "ref=${GITLAB_REF}")
for key in "${!PIPELINE_VARS[@]}"; do
  FORM_ARGS+=(-F "variables[${key}]=${PIPELINE_VARS[$key]}")
done

# ── Dry-run: just verify the token is accepted ─────────────────────────────
if [[ "$DRY_RUN" == true ]]; then
  echo ""
  echo "🔍  Dry-run: sending OPTIONS/HEAD to verify connectivity..."
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    -X HEAD "${API_BASE}/projects/${GITLAB_PROJECT_ID}" \
    -H "PRIVATE-TOKEN: " \
    2>&1 || true)
  # Token-auth isn't available for trigger tokens via HEAD; just check reachability
  REACH=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${GITLAB_URL}" || true)
  echo "  GitLab reachable (HTTP $REACH)"

  echo ""
  echo "  Sending a dry-run POST with your trigger token..."
  # GitLab doesn't have a validate-only endpoint, so we post to a known-bad ref
  # to confirm the token is accepted (401 = bad token, 400 = token ok but ref issue,
  # 201 = pipeline created — which only happens if ref exists)
  RESPONSE=$(curl -s -o /tmp/gl_response.json -w "%{http_code}" \
    --max-time 15 \
    "${TRIGGER_URL}" \
    -F "token=${GITLAB_TOKEN}" \
    -F "ref=__dry_run_probe__")
  BODY=$(cat /tmp/gl_response.json 2>/dev/null || echo "{}")

  echo ""
  echo "  HTTP status : $RESPONSE"
  echo "  Response    : $BODY"
  echo ""

  case "$RESPONSE" in
    201) echo "✅  Token is VALID (pipeline created on ref — ref exists too!)" ;;
    400) echo "✅  Token is VALID (server accepted it; ref '__dry_run_probe__' not found, as expected)" ;;
    401) echo "❌  Token is INVALID or revoked (401 Unauthorized)" ;;
    403) echo "❌  Token lacks permission for this project (403 Forbidden)" ;;
    404) echo "❌  Project not found — check GITLAB_PROJECT_ID (404)" ;;
    *)   echo "⚠️   Unexpected status $RESPONSE — check the response body above" ;;
  esac
  exit 0
fi

# ── Live trigger ───────────────────────────────────────────────────────────
echo ""
echo "🚀  Triggering pipeline on ref '$GITLAB_REF'..."
HTTP_CODE=$(curl -s -o /tmp/gl_response.json -w "%{http_code}" \
  --max-time 20 \
  -X POST "${TRIGGER_URL}" \
  "${FORM_ARGS[@]}")
BODY=$(cat /tmp/gl_response.json 2>/dev/null || echo "{}")

echo ""
echo "  HTTP status : $HTTP_CODE"

case "$HTTP_CODE" in
  201)
    PIPELINE_ID=$(echo "$BODY" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
    WEB_URL=$(echo "$BODY" | grep -o '"web_url":"[^"]*"' | head -1 | sed 's/"web_url":"//;s/"//')
    echo "✅  Pipeline triggered successfully!"
    echo "  Pipeline ID : ${PIPELINE_ID:-unknown}"
    echo "  URL         : ${WEB_URL:-see your GitLab project}"
    ;;
  401) echo "❌  Trigger failed — invalid or revoked token (401)" ;;
  403) echo "❌  Trigger failed — permission denied (403)" ;;
  404) echo "❌  Trigger failed — project not found (404)" ;;
  422) echo "❌  Trigger failed — ref '$GITLAB_REF' not found or pipeline config invalid (422)" ;;
  *)   echo "⚠️   Unexpected status $HTTP_CODE"
       echo "  Body: $BODY" ;;
esac
