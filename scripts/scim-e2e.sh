#!/usr/bin/env bash
set -euo pipefail

: "${SCIM_E2E_BASE:?Set SCIM_E2E_BASE to the tenant-bound SCIM base URL}"
: "${SCIM_E2E_TOKEN:?Set SCIM_E2E_TOKEN to a short-lived SCIM bearer credential}"
SCIM_E2E_USERNAME="${SCIM_E2E_USERNAME:-e2e-user@example.invalid}"
SCIM_E2E_GROUPS="${SCIM_E2E_GROUPS:-1}"

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

status=$(request GET "$SCIM_E2E_BASE/ResourceTypes")
test "$status" = "200"
jq -e 'any(.Resources[]; .id == "User") and any(.Resources[]; .id == "Group")' /tmp/scim-e2e-body.json >/dev/null

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

status=$(curl -sS -o /tmp/scim-e2e-body.json -w "%{http_code}" -G \
  -H "Authorization: Bearer $SCIM_E2E_TOKEN" \
  -H "Accept: application/scim+json" \
  --data-urlencode "filter=userName eq \"$SCIM_E2E_USERNAME\"" \
  "$SCIM_E2E_BASE/Users")
test "$status" = "200"
jq -e --arg id "$USER_ID" '.totalResults >= 1 and any(.Resources[]; .id == $id)' /tmp/scim-e2e-body.json >/dev/null

if [[ "$SCIM_E2E_GROUPS" == "1" ]]; then
  GROUP_NAME="TrustRelay E2E Group ${GITHUB_RUN_ID:-local}"
  group_payload=$(jq -nc --arg n "$GROUP_NAME" --arg uid "$USER_ID" '{
    schemas:["urn:ietf:params:scim:schemas:core:2.0:Group"],
    externalId:"trustrelay-scim-group-e2e",
    displayName:$n,
    members:[{value:$uid}]
  }')
  status=$(request POST "$SCIM_E2E_BASE/Groups" "$group_payload")
  test "$status" = "201"
  GROUP_ID=$(jq -r '.id' /tmp/scim-e2e-body.json)
  test -n "$GROUP_ID"
  jq -e --arg uid "$USER_ID" '.members | any(.value == $uid)' /tmp/scim-e2e-body.json >/dev/null

  status=$(curl -sS -o /tmp/scim-e2e-body.json -w "%{http_code}" -G \
    -H "Authorization: Bearer $SCIM_E2E_TOKEN" \
    -H "Accept: application/scim+json" \
    --data-urlencode "filter=displayName eq \"$GROUP_NAME\"" \
    "$SCIM_E2E_BASE/Groups")
  test "$status" = "200"
  jq -e --arg id "$GROUP_ID" '.totalResults >= 1 and any(.Resources[]; .id == $id)' /tmp/scim-e2e-body.json >/dev/null

  group_patch=$(jq -nc --arg uid "$USER_ID" '{
    schemas:["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations:[
      {op:"Remove",path:"members",value:[{value:$uid}]},
      {op:"Add",path:"members",value:[{value:$uid}]},
      {op:"Replace",path:"displayName",value:"TrustRelay E2E Group Updated"}
    ]
  }')
  status=$(request PATCH "$SCIM_E2E_BASE/Groups/$GROUP_ID" "$group_patch")
  test "$status" = "200"
  jq -e --arg uid "$USER_ID" '.displayName == "TrustRelay E2E Group Updated" and (.members | any(.value == $uid))' /tmp/scim-e2e-body.json >/dev/null

  status=$(request DELETE "$SCIM_E2E_BASE/Groups/$GROUP_ID")
  test "$status" = "204"
fi

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
