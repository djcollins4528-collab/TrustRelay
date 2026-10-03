#!/usr/bin/env bash
# Quarantine only the retired legacy Render static site.
# This mutates the ephemeral Render build workspace, never the GitHub repository.

if [[ "${RENDER_SERVICE_ID:-}" != "srv-daul9tk9v7es73a0tsdg" ]]; then
  return 0 2>/dev/null || exit 0
fi

# BASH_ENV may be sourced by nested build shells. Register cleanup only once,
# on the outer build shell, so Render's own builder can finish normally.
if [[ "${TRUSTRELAY_STATIC_QUARANTINE_TRAP_SET:-}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi
export TRUSTRELAY_STATIC_QUARANTINE_TRAP_SET=1

trustrelay_quarantine_legacy_static() {
  local root="/opt/render/project/src"
  if [[ ! -f "$root/server.mjs" || ! -d "$root/supabase" || ! -d "$root/web" ]]; then
    echo "Legacy static quarantine cleanup skipped: TrustRelay checkout not found at $root." >&2
    return 1
  fi

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
  echo "Legacy static quarantine completed: publish root replaced with retirement page."
}

trap trustrelay_quarantine_legacy_static EXIT
