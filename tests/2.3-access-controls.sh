#!/usr/bin/env bash
# Verifies every command and output shown in 2.3-ai-access-controls.md.
# Starts a toy AI gateway (Python standard library only) on 127.0.0.1:11540
# that checks scoped API keys, a per-agent tool allowlist, and attribute
# filters on retrieval results. A real local model (qwen2.5:0.5b in Ollama on
# 127.0.0.1:11541) plays the agent and proposes tool calls; the gateway
# decides which ones run. All keys, users, and documents are fake.
# Needs: docker, curl, jq, python3
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/ollama.sh
source "$HERE/lib/ollama.sh"
WORK=$(mktemp -d)
cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
  ollama_down sa23-ollama
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
export NO_PROXY='127.0.0.1,localhost' no_proxy='127.0.0.1,localhost'
GW=http://127.0.0.1:11540
BOT_KEY=test-bot-key-1      # service identity of the help desk agent
HR_KEY=test-hr-key-2        # an HR manager's personal key
export GW BOT_KEY HR_KEY

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Fq -- "$1" <<<"$OUT" || { echo "FAIL: expected '$1'"; exit 1; }; }

cat > gateway.py <<'PY'
"""Toy AI gateway for the 2.3 notes. Standard library only."""
import hashlib, json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

def sha(k):
    return hashlib.sha256(k.encode()).hexdigest()

# Only hashes of keys are stored, like a password table
KEYS = {
    sha("test-bot-key-1"): {
        "id": "svc-helpdesk-bot",
        "scopes": {"invoke:helpdesk-chat", "rag:read",
                   "tools:call"},
        "attrs": {"dept": "it", "level": 1}},
    sha("test-hr-key-2"): {
        "id": "hr-manager-01",
        "scopes": {"rag:read"},
        "attrs": {"dept": "hr", "level": 3}},
}
# Per-agent allowlist: the bot only reads tickets
TOOLS = {"svc-helpdesk-bot": {"lookup_ticket"}}
DOCS = [
    {"id": "KB-101", "dept": "all", "level": 1,
     "text": "VPN reconnect steps"},
    {"id": "KB-207", "dept": "it", "level": 1,
     "text": "Password reset policy"},
    {"id": "HR-310", "dept": "hr", "level": 3,
     "text": "Salary bands 2026"},
    {"id": "HR-311", "dept": "hr", "level": 2,
     "text": "Leave policy"},
]

def can_read(doc, a):
    return (doc["dept"] in ("all", a["dept"])
            and doc["level"] <= a["level"])

class GW(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body):
        data = (json.dumps(body) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def caller(self):
        auth = self.headers.get("Authorization", "")
        key = auth.removeprefix("Bearer ")
        return KEYS.get(sha(key)) if key else None

    def audit(self, who, action, result):
        with open("audit.log", "a") as f:
            f.write(json.dumps({"who": who, "action": action,
                                "result": result}) + "\n")

    def handle_one(self):
        who = self.caller()
        if who is None:
            return self.reply(401, {"error": "invalid API key"})
        url = urlparse(self.path)
        parts = url.path.strip("/").split("/")
        if parts[:2] == ["v1", "invoke"]:
            need = "invoke:" + parts[2]
            if need not in who["scopes"]:
                self.audit(who["id"], need, "deny")
                return self.reply(403, {"error": "missing " + need})
            return self.reply(200, {"model": parts[2],
                                    "status": "accepted"})
        if parts[:2] == ["v1", "search"]:
            if "rag:read" not in who["scopes"]:
                return self.reply(403, {"error": "missing rag:read"})
            q = parse_qs(url.query).get("q", [""])[0].lower()
            hits = [d["id"] for d in DOCS
                    if q in d["text"].lower()
                    and can_read(d, who["attrs"])]
            return self.reply(200, {"results": hits})
        if parts[:2] == ["v1", "tools"]:
            tool = parts[2]
            allowed = TOOLS.get(who["id"], set())
            if "tools:call" not in who["scopes"] or tool not in allowed:
                self.audit(who["id"], "tool:" + tool, "deny")
                return self.reply(403, {"error":
                                        "tool not in allowlist"})
            self.audit(who["id"], "tool:" + tool, "allow")
            return self.reply(200, {"status": "open"})
        return self.reply(404, {"error": "not found"})

    do_GET = do_POST = handle_one

ThreadingHTTPServer(("127.0.0.1", 11540), GW).serve_forever()
PY

cat > agent.py <<'PY'
"""Help desk agent: the model proposes tool calls, the gateway decides."""
import json, os, sys, urllib.request, urllib.error

TOOLS = [
    {"type": "function", "function": {
        "name": "lookup_ticket",
        "description": "Read a help desk ticket by ID",
        "parameters": {"type": "object",
                       "properties": {"ticket_id": {"type": "string"}},
                       "required": ["ticket_id"]}}},
    {"type": "function", "function": {
        "name": "reset_password",
        "description": "Reset a user's password",
        "parameters": {"type": "object",
                       "properties": {"user": {"type": "string"}},
                       "required": ["user"]}}},
]

def post(url, body, key=None):
    req = urllib.request.Request(url, json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    if key:
        req.add_header("Authorization", "Bearer " + key)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

_, resp = post(os.environ["OLLAMA_URL"] + "/api/chat", {
    "model": "qwen2.5:0.5b", "stream": False,
    "options": {"temperature": 0, "seed": 42}, "tools": TOOLS,
    "messages": [
        {"role": "system",
         "content": "You are the help desk assistant. Use tools to answer."},
        {"role": "user", "content": sys.argv[1]}]})
for call in resp["message"].get("tool_calls", []):
    fn = call["function"]
    print("model asks:", fn["name"], json.dumps(fn["arguments"]))
    code, body = post(os.environ["GW"] + "/v1/tools/" + fn["name"],
                      fn["arguments"], os.environ["BOT_KEY"])
    print("gateway:", code, json.dumps(body))
PY

python3 -m py_compile gateway.py agent.py
python3 gateway.py & SRV=$!
for _ in $(seq 1 30); do curl -s -o /dev/null "$GW/" && break; sleep 0.2; done

echo "== Model access: scoped keys"
t 'curl -sX POST $GW/v1/invoke/helpdesk-chat \
  -H "Authorization: Bearer $BOT_KEY"'
has '{"model": "helpdesk-chat", "status": "accepted"}'
t 'curl -sX POST $GW/v1/invoke/fraud-scorer \
  -H "Authorization: Bearer $BOT_KEY"'
has '{"error": "missing invoke:fraud-scorer"}'
t 'curl -sX POST $GW/v1/invoke/helpdesk-chat \
  -H "Authorization: Bearer $HR_KEY"'
has '{"error": "missing invoke:helpdesk-chat"}'
t 'curl -sw "%{http_code}\n" -o /dev/null \
  -X POST $GW/v1/invoke/helpdesk-chat'
has '401'

echo "== Data access: retrieval filtered by caller attributes"
t 'curl -s "$GW/v1/search?q=salary" \
  -H "Authorization: Bearer $BOT_KEY"'
has '{"results": []}'
t 'curl -s "$GW/v1/search?q=salary" \
  -H "Authorization: Bearer $HR_KEY"'
has '{"results": ["HR-310"]}'
t 'curl -s "$GW/v1/search?q=policy" \
  -H "Authorization: Bearer $BOT_KEY"'
has '{"results": ["KB-207"]}'
t 'curl -s "$GW/v1/search?q=policy" \
  -H "Authorization: Bearer $HR_KEY"'
has '{"results": ["HR-311"]}'

echo "== Agent access: model proposes, gateway disposes"
ollama_up sa23-ollama 11541 qwen2.5:0.5b
t 'python3 agent.py "Status of ticket INC-1042?"'
has 'model asks: lookup_ticket {"ticket_id": "INC-1042"}'
has 'gateway: 200 {"status": "open"}'
t 'python3 agent.py "Reset the password for jdoe."'
has 'model asks: reset_password {"user": "jdoe"}'
has 'gateway: 403 {"error": "tool not in allowlist"}'

echo "== Audit trail of decisions"
t "jq -r '[.who, .action, .result] | join(\" \")' audit.log"
has 'svc-helpdesk-bot tool:reset_password deny'
[ "$(grep -c '"deny"' audit.log)" -eq 3 ] || { echo "FAIL: expected 3 denies"; exit 1; }

echo "ALL 2.3 ACCESS-CONTROLS CHECKS PASSED"
