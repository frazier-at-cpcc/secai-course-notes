#!/usr/bin/env bash
# Verifies the MCP server and client example in the 3.1 notes
# (3.1-ai-security-tools.md): a read-only hash lookup tool served over
# stdio with the official Python SDK, listed and called by an MCP client.
# Needs: python3, pip package mcp (tested with 2.2.0)
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

# Known-bad list: the SHA-256 of the harmless EICAR antivirus test file
cat > iocs.txt <<'EOF'
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
EOF

cat > ioc_server.py <<'PY'
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

mcp = MCPServer("ioc-lookup")
BAD = set(open("iocs.txt").read().split())

@mcp.tool(annotations=ToolAnnotations(
    read_only_hint=True))
def lookup_hash(sha256: str) -> str:
    """Check a SHA-256 against local IOCs."""
    h = sha256.strip().lower()
    return "known-bad" if h in BAD else "not listed"

if __name__ == "__main__":
    mcp.run()   # stdio transport by default
PY

cat > ask.py <<'PY'
import asyncio, sys
from mcp import Client, StdioServerParameters

server = StdioServerParameters(
    command=sys.executable, args=["ioc_server.py"])

async def main():
    async with Client(server) as c:
        for t in (await c.list_tools()).tools:
            ro = t.annotations.read_only_hint
            print(f"tool: {t.name} readOnly={ro}")
            print(f"  {t.description}")
        for h in sys.argv[1:]:
            r = await c.call_tool("lookup_hash",
                                  {"sha256": h})
            print(h[:12], "->", r.content[0].text)

asyncio.run(main())
PY

python3 -m py_compile ioc_server.py ask.py
EICAR=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
OTHER=$(printf 'quarterly-report.pdf' | sha256sum | cut -d' ' -f1)
out=$(python3 ask.py "$EICAR" "$OTHER" 2>&1)
echo "$out"
grep -qx 'tool: lookup_hash readOnly=True' <<<"$out" || { echo "FAIL: tool listing"; exit 1; }
grep -qx '  Check a SHA-256 against local IOCs.' <<<"$out" || { echo "FAIL: description"; exit 1; }
grep -qx '275a021bbfb6 -> known-bad' <<<"$out" || { echo "FAIL: EICAR hash not flagged"; exit 1; }
grep -qx "${OTHER:0:12} -> not listed" <<<"$out" || { echo "FAIL: clean hash flagged"; exit 1; }

# The EICAR hash in iocs.txt really is the SHA-256 of the EICAR test string
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | sha256sum | grep -q "^$EICAR " || { echo "FAIL: EICAR hash mismatch"; exit 1; }

echo "ALL 3.1 MCP-SERVER CHECKS PASSED"
