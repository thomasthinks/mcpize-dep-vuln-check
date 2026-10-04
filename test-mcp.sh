#!/bin/bash
# MCP Protocol Smoke Test for dep-vuln-check
# Usage: Start your server first, then run: bash test-mcp.sh

BASE_URL="${MCP_URL:-http://localhost:8080}"
MCP_ENDPOINT="$BASE_URL/mcp"
HEALTH_ENDPOINT="$BASE_URL/health"
PASSED=0
FAILED=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}FAIL${NC} $1: $2"; FAILED=$((FAILED + 1)); }

echo "Testing dep-vuln-check at $BASE_URL"
echo "==================================="

# 1. Health check
echo ""
echo "--- Health Check ---"
HEALTH=$(curl -sf "$HEALTH_ENDPOINT" 2>/dev/null) || true
if echo "$HEALTH" | grep -q "healthy"; then
  pass "GET /health returns healthy"
else
  fail "GET /health" "Expected 'healthy' in response, got: $HEALTH"
fi

# 2. Initialize handshake
echo ""
echo "--- MCP Initialize ---"
INIT_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": { "name": "smoke-test", "version": "1.0" }
    }
  }' 2>/dev/null) || true

if echo "$INIT_RESPONSE" | grep -q '"result"'; then
  pass "initialize returns result"
else
  fail "initialize" "No 'result' in response: $INIT_RESPONSE"
fi

# 3. List tools
echo ""
echo "--- List Tools ---"
TOOLS_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }' 2>/dev/null) || true

if echo "$TOOLS_RESPONSE" | grep -q '"tools"'; then
  pass "tools/list returns tools array"
  TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "?")
  echo "     Found $TOOL_COUNT tool(s)"
else
  fail "tools/list" "No 'tools' in response: $TOOLS_RESPONSE"
fi

# 4. Check specific tools exist
EXPECTED_TOOLS=("check_package" "check_sbom")
for TOOL in "${EXPECTED_TOOLS[@]}"; do
  if echo "$TOOLS_RESPONSE" | grep -q "\"$TOOL\""; then
    pass "Tool '$TOOL' is registered"
  else
    fail "Tool '$TOOL'" "Not found in tools/list response"
  fi
done

# 5. Call check_package (known-vulnerable: lodash 4.17.20)
echo ""
echo "--- Call check_package (lodash@4.17.20) ---"
CALL_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "check_package",
      "arguments": { "ecosystem": "npm", "name": "lodash", "version": "4.17.20" }
    }
  }' 2>/dev/null) || true

if echo "$CALL_RESPONSE" | grep -q '"content"'; then
  pass "check_package returns content"
else
  fail "check_package" "No 'content' in response: $CALL_RESPONSE"
fi
if echo "$CALL_RESPONSE" | grep -q '"vulnerable":true'; then
  pass "check_package flags lodash@4.17.20 as vulnerable"
else
  fail "check_package" "Expected vulnerable:true: $CALL_RESPONSE"
fi
if echo "$CALL_RESPONSE" | grep -q '"structuredContent"'; then
  pass "check_package returns structuredContent"
else
  fail "check_package" "No 'structuredContent' in response"
fi

# 6. Call check_sbom
echo ""
echo "--- Call check_sbom (2 packages) ---"
SBOM_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "check_sbom",
      "arguments": { "packages": [
        { "ecosystem": "npm", "name": "lodash", "version": "4.17.20" },
        { "ecosystem": "npm", "name": "chalk", "version": "5.3.0" }
      ] }
    }
  }' 2>/dev/null) || true

if echo "$SBOM_RESPONSE" | grep -q '"scanned":2'; then
  pass "check_sbom scans 2 packages"
else
  fail "check_sbom" "Expected scanned:2: $SBOM_RESPONSE"
fi
if echo "$SBOM_RESPONSE" | grep -q '"vulnerable_count":1'; then
  pass "check_sbom reports vulnerable_count=1"
else
  fail "check_sbom" "Expected vulnerable_count:1"
fi

# 7. Call check_package with bad ecosystem (expect structured isError)
echo ""
echo "--- Call check_package (bad ecosystem) ---"
ERR_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "check_package",
      "arguments": { "ecosystem": "pypi2", "name": "lodash", "version": "4.17.20" }
    }
  }' 2>/dev/null) || true

if echo "$ERR_RESPONSE" | grep -q '"isError":true'; then
  pass "check_package returns isError for bad ecosystem"
else
  fail "check_package bad ecosystem" "Expected isError:true"
fi

# 8. Ping
echo ""
echo "--- Ping ---"
PING_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "ping",
    "params": {}
  }' 2>/dev/null) || true

if echo "$PING_RESPONSE" | grep -q '"result"'; then
  pass "ping returns result"
else
  fail "ping" "No 'result' in response: $PING_RESPONSE"
fi

# Summary
echo ""
echo "==================================="
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
