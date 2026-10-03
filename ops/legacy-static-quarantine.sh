#!/usr/bin/env bash
# Quarantine only the retired legacy Render static site.
# BASH_ENV sources this file in the disposable Render build workspace.
# Cleanup is immediate so the publishPath "." upload cannot capture repository files.

if [[ "${RENDER_SERVICE_ID:-}" != "srv-daul9tk9v7es73a0tsdg" ]]; then
  return 0 2>/dev/null || exit 0
fi

if [[ "${TRUSTRELAY_STATIC_QUARANTINE_DONE:-}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi
export TRUSTRELAY_STATIC_QUARANTINE_DONE=1

root="/opt/render/project/src"
if [[ ! -f "$root/server.mjs" || ! -d "$root/supabase" || ! -d "$root/web" ]]; then
  echo "Legacy static quarantine failed: TrustRelay checkout not found at $root." >&2
  return 1 2>/dev/null || exit 1
fi

echo "Legacy static quarantine starting: replacing disposable publish root."

find "$root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +

cat > "$root/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>TrustRelay staging endpoint retired</title>
</head>
<body>
  <main>
    <h1>Endpoint retired</h1>
    <p>This legacy TrustRelay staging endpoint is no longer in service.</p>
  </main>
</body>
</html>
EOF

extra="$(find "$root" -mindepth 1 -maxdepth 1 ! -name index.html -print -quit)"
if [[ ! -f "$root/index.html" || -n "$extra" ]]; then
  echo "Legacy static quarantine failed: publish root contains unexpected files." >&2
  return 1 2>/dev/null || exit 1
fi

echo "Legacy static quarantine verified: publish root contains only index.html."
return 0 2>/dev/null || exit 0
