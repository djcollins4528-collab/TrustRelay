#!/usr/bin/env bash
# Quarantine only the retired legacy Render static site.
# This mutates the ephemeral Render build workspace, never the GitHub repository.
set -euo pipefail

if [[ "${RENDER_SERVICE_ID:-}" != "srv-daul9tk9v7es73a0tsdg" ]]; then
  return 0 2>/dev/null || exit 0
fi

# Fail closed unless Render is executing from the expected TrustRelay checkout.
if [[ ! -f "server.mjs" || ! -d "supabase" || ! -d "web" ]]; then
  echo "Legacy static quarantine guard: expected TrustRelay checkout not found." >&2
  exit 1
fi

# Remove the repository tree from the publish directory, then leave a single
# non-sensitive retirement page. This affects only the disposable build clone.
find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +

cat > index.html <<'EOF'
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
