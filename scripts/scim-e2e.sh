#!/usr/bin/env bash
set -euo pipefail

: "${SCIM_E2E_BASE:?Set SCIM_E2E_BASE to the tenant-bound SCIM base URL}"
: "${SCIM_E2E_TOKEN:?Set SCIM_E2E_TOKEN to a short-lived SCIM bearer credential}"
SCIM_E2E_USERNAME="${SCIM_E2E_USERNAME:-e2e-user@example.invalid}"

request() {
  local method="$1" url="$2" data="${3:-}"
  local args=(-sS -o /tmp/scim-e2e-body.json -w "%{http_code}" -X "$method"
    -H "Authorization: Bearer $SCIM_E2E_TOKEN"
    -H "Accept: application/scim+json")
  if [[ -n "$data" ]]; then
    args+=(-H "Content-Type: application/scim+json" --data "$data")
  fi
  curl "${args[@]}" "$url"
}

status=$(request GET "$SCIM_E2E_BASE/ServiceProviderConfig")
test "$status" = "200"
jq -e '.patch.supported == true and .filter.supported == true' /tmp/scim-e2e-body.json >/dev/null

payload=$(jq -nc --arg u "$SCIM_E2E_USERNAME" '{
  schemas:["urn:ietf:params:scim:schemas:core:2.0:User"],
  userName:$u,
  externalId:"trustrelay-scim-e2e",
  name:{givenName:"SCIM",familyName:"E2E"},
  displayName:"SCIM E2E User",
  title:"E2E Initial",
  active:true,
  emails:[{value:$u,type:"work",primary:true}]
}')
status=$(request POST "$SCIM_E2E_BASE/Users" "$payload")
test "$status" = "201"
USER_ID=$(jq -r '.id' /tmp/scim-e2e-body.json)
test -n "$USER_ID"

status=$(curl -sS -o /tmp/scim-e2e-body.json -w "%{http_code}" -G   -H "Authorization: Bearer $SCIM_E2E_TOKEN"   -H "Accept: application/scim+json"   --data-urlencode "filter=userName eq \"$SCIM_E2E_USERNAME\""   "$SCIM_E2E_BASE/Users")
test "$status" = "200"
jq -e --arg id "$USER_ID" '.totalResults >= 1 and any(.Resources[]; .id == $id)' /tmp/scim-e2e-body.json >/dev/null

suspend='{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":false}]}'
status=$(request PATCH "$SCIM_E2E_BASE/Users/$USER_ID" "$suspend")
test "$status" = "200"
jq -e '.active == false' /tmp/scim-e2e-body.json >/dev/null

reactivate='{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":true}]}'
status=$(request PATCH "$SCIM_E2E_BASE/Users/$USER_ID" "$reactivate")
test "$status" = "200"
jq -e '.active == true' /tmp/scim-e2e-body.json >/dev/null

status=$(request DELETE "$SCIM_E2E_BASE/Users/$USER_ID")
test "$status" = "204"
status=$(request GET "$SCIM_E2E_BASE/Users/$USER_ID")
test "$status" = "200"
jq -e '.active == false' /tmp/scim-e2e-body.json >/dev/null

echo "SCIM_E2E_PASS"
