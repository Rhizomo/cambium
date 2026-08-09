#!/bin/sh
# One-shot dev-stack bootstrap for the vanilla Nexus3 CE container:
#   1. wait for Nexus's REST API to come up
#   2. pick up the randomly-generated first-boot admin password from the
#      shared nexus-data volume and reset it to a fixed dev password, so the
#      other compose services (cambium-sync, cambium-ropc-proxy) can use a
#      value known ahead of time instead of something generated at runtime
#   3. enable the `rutauth` capability via Nexus's own Capabilities REST API
#      (this also auto-activates the Rut Auth realm — confirmed via
#      Sonatype's own docs/community forum, no separate realm-activation
#      call needed)
#   4. idempotent: safe to re-run against an already-initialized Nexus (e.g.
#      `docker compose up` a second time without `-v`) — it detects the fixed
#      password already works and skips the reset, and Nexus's capabilities
#      API is checked before re-adding.
#
# This is dev-only bootstrapping for the local docker-compose stack. It is
# NOT how you'd provision the RutAuth capability in a real deployment --
# there, do this once by hand (or via your own IaC) against your actual
# Nexus, with real credentials from your vault, not this script's fixed
# dev password.
set -eu

NEXUS_URL="${NEXUS_URL:-http://nexus:8081}"
DEV_ADMIN_PASSWORD="${DEV_ADMIN_PASSWORD:-admin123}"
RUTAUTH_HEADER="${RUTAUTH_HEADER:-X-Forwarded-User}"
ADMIN_PASSWORD_FILE="${ADMIN_PASSWORD_FILE:-/nexus-data/admin.password}"

echo "[nexus-init] waiting for Nexus REST API at ${NEXUS_URL} ..."
until curl -sf -o /dev/null "${NEXUS_URL}/service/rest/v1/status"; do
  sleep 3
done
echo "[nexus-init] Nexus API is up."

# Figure out which admin password currently works: either the dev password
# from a previous run, or the freshly-generated first-boot one.
if curl -sf -o /dev/null -u "admin:${DEV_ADMIN_PASSWORD}" "${NEXUS_URL}/service/rest/v1/security/users?userId=admin"; then
  echo "[nexus-init] dev admin password already active (idempotent re-run)."
  CURRENT_ADMIN_PASSWORD="${DEV_ADMIN_PASSWORD}"
elif [ -f "${ADMIN_PASSWORD_FILE}" ]; then
  GENERATED_PASSWORD="$(cat "${ADMIN_PASSWORD_FILE}")"
  echo "[nexus-init] found first-boot generated admin password, resetting to fixed dev password."
  curl -sf -X PUT \
    -H 'Content-Type: text/plain' \
    -u "admin:${GENERATED_PASSWORD}" \
    -d "${DEV_ADMIN_PASSWORD}" \
    "${NEXUS_URL}/service/rest/v1/security/users/admin/change-password"
  CURRENT_ADMIN_PASSWORD="${DEV_ADMIN_PASSWORD}"
else
  echo "[nexus-init] no admin.password file and dev password doesn't work either -- cannot proceed." >&2
  exit 1
fi

echo "[nexus-init] ensuring the custom Nexus roles that dev/keycloak/realm-export.json's ROLE_MAP targets exist ..."
for ROLE_ID in nx-viewer nx-editor nx-publisher nx-auditor nx-ops nx-billing nx-superuser; do
  if curl -sf -o /dev/null -u "admin:${CURRENT_ADMIN_PASSWORD}" "${NEXUS_URL}/service/rest/v1/security/roles/${ROLE_ID}"; then
    echo "[nexus-init] role ${ROLE_ID} already exists, skipping."
  else
    curl -sf -X POST \
      -H 'Content-Type: application/json' \
      -u "admin:${CURRENT_ADMIN_PASSWORD}" \
      -d "{\"id\":\"${ROLE_ID}\",\"name\":\"${ROLE_ID}\",\"description\":\"cambium dev stack synthetic role\",\"privileges\":[],\"roles\":[]}" \
      "${NEXUS_URL}/service/rest/v1/security/roles"
    echo "[nexus-init] role ${ROLE_ID} created."
  fi
done

echo "[nexus-init] checking for an existing rutauth capability ..."
EXISTING_ID="$(curl -sf -u "admin:${CURRENT_ADMIN_PASSWORD}" "${NEXUS_URL}/service/rest/v1/capabilities" \
  | jq -r '.[] | select(.type == "rutauth") | .id' | head -1)"

if [ -n "${EXISTING_ID:-}" ]; then
  echo "[nexus-init] rutauth capability already present (id=${EXISTING_ID}), skipping creation."
else
  echo "[nexus-init] enabling rutauth capability with httpHeader=${RUTAUTH_HEADER} ..."
  curl -sf -X POST \
    -H 'Content-Type: application/json' \
    -u "admin:${CURRENT_ADMIN_PASSWORD}" \
    -d "{\"type\":\"rutauth\",\"enabled\":true,\"notes\":\"cambium local dev stack\",\"properties\":{\"httpHeader\":\"${RUTAUTH_HEADER}\"}}" \
    "${NEXUS_URL}/service/rest/v1/capabilities"
  echo "[nexus-init] rutauth capability created."
fi

echo "[nexus-init] done. admin password for this dev stack is: ${DEV_ADMIN_PASSWORD}"
