#!/usr/bin/env bash
# One-command deploy for the CF-Workers DoH resolver.
#
# Usage:
#   ./scripts/deploy.sh                        # validate + build + run tests, then show next steps
#   CLOUDFLARE_API_TOKEN=xxxx ./scripts/deploy.sh   # fully provision + deploy to YOUR account
#
# With CLOUDFLARE_API_TOKEN set this is fully self-service: it creates the
# RULES_KV namespace if needed, writes the returned id into wrangler.jsonc,
# then deploys. No manual editing required.
set -euo pipefail
cd "$(dirname "$0")/.."

PLACEHOLDER="REPLACE_WITH_YOUR_KV_NAMESPACE_ID"

echo "== 1/4  Running test suite =="
npm test || { echo "Tests failed; aborting."; exit 1; }

echo "== 2/4  Building single-file bundle =="
npx --yes esbuild src/worker.js --bundle --format=esm --platform=browser --target=es2022 \
  --outfile=dists/worker-single.js --log-level=warning

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo
  echo "== No CLOUDFLARE_API_TOKEN set =="
  echo "Fully-automated deploy needs your account token:"
  echo
  echo "    export CLOUDFLARE_API_TOKEN=YOUR_TOKEN"
  echo "    ./scripts/deploy.sh"
  echo
  echo "It will then create RULES_KV if missing, fill wrangler.jsonc, and deploy."
  exit 0
fi

# --- Provision KV namespace id (self-service, non-interactive) --------------
KV_ID=""
if grep -q "$PLACEHOLDER" wrangler.jsonc; then
  echo "== 3/4  Provisioning RULES_KV namespace =="
  # Prefer an existing RULES_KV namespace (idempotent).
  EXISTING="$(npx --yes wrangler kv namespace list 2>/dev/null \
    | tr ',' '\n' | grep '"title": *"RULES_KV"' -B3 2>/dev/null \
    | grep -oE '[0-9a-f]{32}' | head -1)"
  if [[ -n "$EXISTING" ]]; then
    KV_ID="$EXISTING"
    echo "Reusing existing RULES_KV namespace: $KV_ID"
  else
    CREATE_OUT="$(npx wrangler kv namespace create RULES_KV 2>&1)"
    KV_ID="$(printf '%s' "$CREATE_OUT" | tr ',' '\n' | grep -oE '"id": *"[0-9a-f]+"' | head -1 | grep -oE '[0-9a-f]{32}')"
    if [[ -z "$KV_ID" ]]; then
      KV_ID="$(printf '%s' "$CREATE_OUT" | sed -nE 's/^[[:space:]]*id[[:space:]]*=[[:space:]]*"([0-9a-f]{32})".*/\1/p' | head -1)"
    fi
  fi
  if [[ -z "$KV_ID" ]]; then
    echo "Could not obtain namespace id. Please run and paste the id manually:" >&2
    echo "  npx wrangler kv namespace create RULES_KV" >&2
    exit 1
  fi
  sed -i.bak "s/$PLACEHOLDER/$KV_ID/" wrangler.jsonc
  rm -f wrangler.jsonc.bak
  echo "Wrote KV id into wrangler.jsonc: $KV_ID"
else
  echo "== 3/4  RULES_KV already configured; skipping creation =="
fi

echo "== 4/4  Deploying to your account =="
npx --yes wrangler deploy
echo
echo "Deployed. Query path: https://your-domain/doh  (see README for binding a domain)."