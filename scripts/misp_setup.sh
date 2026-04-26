#!/usr/bin/env bash
# =============================================================================
# Hayyan SOC Lab — MISP Feed Bootstrapper
# Run ONCE after MISP first-boot to enable production-grade threat feeds.
#
# Usage: bash scripts/misp_setup.sh
#   Reads MISP_URL and MISP_API_KEY from .env (or env vars)
#
# What this does:
#   1. Waits for MISP to be healthy (up to 3 min)
#   2. Enables 5 production feeds via REST API
#   3. Triggers initial feed pull
# =============================================================================
set -euo pipefail

# ── Load .env if present ──────────────────────────────────────────────────────
if [[ -f ".env" ]]; then
    export $(grep -v '^#' .env | grep -E '^(MISP_URL|MISP_API_KEY)' | xargs)
fi

MISP_URL="${MISP_URL:-https://localhost:8443}"
MISP_API_KEY="${MISP_API_KEY:-}"

if [[ -z "$MISP_API_KEY" ]]; then
    echo "❌  MISP_API_KEY not set. Get it from: MISP UI → Administration → Auth Keys"
    echo "    Then: export MISP_API_KEY=your_key_here && bash scripts/misp_setup.sh"
    exit 1
fi

CURL_OPTS=(-sk -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" -H "Content-Type: application/json")

# ── Wait for MISP to become healthy ──────────────────────────────────────────
echo "⏳ Waiting for MISP at $MISP_URL ..."
for i in $(seq 1 36); do
    if curl -sk --max-time 5 "$MISP_URL/servers/getVersion" "${CURL_OPTS[@]}" | grep -q '"version"'; then
        echo "✅ MISP is up."
        break
    fi
    echo "   ($i/36) Not ready — retrying in 5s..."
    sleep 5
    if [[ $i -eq 36 ]]; then
        echo "❌ MISP did not come up within 3 minutes. Check: docker compose -f docker-compose.misp.yml logs misp"
        exit 1
    fi
done

# ── Helper: enable a feed by ID ──────────────────────────────────────────────
enable_feed() {
    local feed_id="$1"
    local feed_name="$2"
    echo "  → Enabling feed $feed_id: $feed_name"
    curl -s -o /dev/null -w "%{http_code}" \
        "${CURL_OPTS[@]}" \
        -X POST "$MISP_URL/feeds/enable/$feed_id" | grep -q "200\|302" \
        && echo "     ✅ Enabled" \
        || echo "     ⚠️  Response unexpected (may already be enabled)"
}

# ── Enable production-grade feeds ────────────────────────────────────────────
echo ""
echo "📡 Configuring threat intelligence feeds..."

# MISP default feeds come pre-configured; we enable the most valuable ones.
# Feed IDs are stable in coolacid/misp-docker — confirm with GET /feeds/index
enable_feed "1"  "CIRCL OSINT Feed"
enable_feed "2"  "Abuse.ch URLhaus"
enable_feed "6"  "Abuse.ch Feodo Tracker - Botnet C&C IP"
enable_feed "8"  "MalwareBazaar - Malware hashes"

# ── Add Abuse.ch SSL Blacklist (custom feed if not present) ───────────────────
echo "  → Adding Abuse.ch SSL Blacklist (custom)"
curl -s -o /dev/null "${CURL_OPTS[@]}" \
    -X POST "$MISP_URL/feeds/add" \
    -d '{
      "Feed": {
        "name": "Abuse.ch SSL Blacklist",
        "provider": "Abuse.ch",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "enabled": true,
        "caching_enabled": true,
        "input_source": "network",
        "source_format": "csv",
        "delimiter": ",",
        "fixed_event": false,
        "distribution": 0
      }
    }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('     ✅ Added' if 'Feed' in d else '     ⚠️  ' + str(d))" 2>/dev/null || echo "     ⚠️  Could not add (may already exist)"

# ── Trigger initial feed pull ─────────────────────────────────────────────────
echo ""
echo "🔄 Triggering initial feed fetch (background)..."
curl -s -o /dev/null "${CURL_OPTS[@]}" \
    -X POST "$MISP_URL/feeds/fetchFromAllFeeds" \
    && echo "   ✅ Fetch triggered. MISP will pull feeds in the background (1-5 min)." \
    || echo "   ⚠️  Fetch trigger failed — pull manually in MISP UI: Sync Actions → Fetch all feeds"

# ── Create Splunk integration user ───────────────────────────────────────────
echo ""
echo "👤 Creating Splunk read-only integration role..."
curl -s -o /dev/null "${CURL_OPTS[@]}" \
    -X POST "$MISP_URL/roles/add" \
    -d '{
      "Role": {
        "name": "splunk-integration",
        "perm_auth": true,
        "perm_read_information": true,
        "perm_sharing_group": false,
        "perm_site_admin": false,
        "perm_sync": false,
        "perm_add_server": false
      }
    }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('   ✅ Role created' if 'Role' in d else '   ⚠️  ' + str(d))" 2>/dev/null || true

echo ""
echo "============================================================"
echo "✅  MISP bootstrap complete!"
echo ""
echo "Next steps:"
echo "  1. Log in at $MISP_URL (admin@admin.test / Hayyan@2024!MISP)"
echo "  2. Change the admin password immediately"
echo "  3. Go to Administration → Auth Keys → Add Authentication Key"
echo "  4. Set MISP_API_KEY in your .env file"
echo "  5. Run: python3 scripts/misp_sync_splunk.py  (creates IOC lookup CSV)"
echo "============================================================"
