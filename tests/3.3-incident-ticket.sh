#!/usr/bin/env bash
# Verifies the incident-ticket automation example in the 3.3 notes:
# qwen2.5:0.5b turns a raw EDR alert into a ticket, the output is
# checked against a JSON schema and against the alert itself, and a
# high-severity ticket waits for a human before containment.
# Needs: docker, curl, jq, python3 with jsonschema
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/lib/ollama.sh"
NAME=sa25-ollama-ticket; PORT=11553
WORK=$(mktemp -d)
trap 'ollama_down "$NAME"; rm -rf "$WORK"' EXIT
cd "$WORK"
ollama_up "$NAME" "$PORT" qwen2.5:0.5b

# Sample alert (documentation IP ranges, fictional host and user)
cat > alert.txt <<'TXT'
2026-10-14T03:12:44Z edr-07 sev=8
rule="LSASS memory read by unsigned binary"
host=FIN-WS-114 user=mpatel
proc=C:\Users\Public\svc.exe parent=powershell.exe
conn=10.20.4.17 -> 203.0.113.45:443 allowed
TXT

cat > ticket.schema.json <<'JSON'
{
  "type": "object",
  "properties": {
    "title":    {"type": "string", "maxLength": 80},
    "severity": {"enum": ["low", "medium",
                          "high", "critical"]},
    "host":     {"type": "string"},
    "user":     {"type": "string"},
    "iocs":     {"type": "array", "maxItems": 4,
                 "items": {"type": "string",
                           "maxLength": 40}},
    "summary":  {"type": "string", "maxLength": 100}
  },
  "required": ["title", "severity", "host",
               "user", "iocs", "summary"],
  "additionalProperties": false
}
JSON

cat > ticket.py <<'PY'
import json, os, sys, urllib.request
from jsonschema import validate

URL = os.environ["OLLAMA_URL"] + "/api/chat"
SCHEMA = json.load(open("ticket.schema.json"))
ALERT = open("alert.txt").read()
ASK = ("Write an incident ticket for this EDR alert. "
       "Put IP addresses and file paths in iocs.\n\n")

class Ungrounded(Exception):
    pass

def draft(use_schema):
    req = {"model": "qwen2.5:0.5b", "stream": False,
           "options": {"temperature": 0, "seed": 42,
                       "num_predict": 160},
           "messages": [{"role": "user",
                         "content": ASK + ALERT}]}
    if use_schema:
        req["format"] = SCHEMA   # constrained output
    r = urllib.request.urlopen(urllib.request.Request(
        URL, json.dumps(req).encode(),
        {"Content-Type": "application/json"}))
    return json.load(r)["message"]["content"]

def check(text):
    t = json.loads(text)           # is it JSON?
    validate(t, SCHEMA)            # right shape?
    for v in [t["host"], t["user"], *t["iocs"]]:
        if v not in ALERT:         # grounded?
            raise Ungrounded(v)
    return t

mode = sys.argv[1]       # free | schema | check FILE
if mode == "check":
    raw = open(sys.argv[2]).read()
else:
    raw = draft(mode == "schema")
    open(f"{mode}.raw", "w").write(raw)
try:
    t = check(raw)
except Exception as e:
    why = f": not in alert: {e}" \
        if isinstance(e, Ungrounded) else ""
    sys.exit(f"REJECTED {type(e).__name__}{why}")
json.dump(t, open("ticket.json", "w"), indent=2)
if t["severity"] in ("high", "critical"):
    print("action: isolate", t["host"],
          "-> PENDING analyst approval")
else:
    print("action: queue for next shift")
PY

echo "== free-text answer, no schema =="
set +e; python3 ticket.py free > free.txt 2>&1; rc=$?; set -e
cat free.txt; head -4 free.raw
[ "$rc" -eq 1 ]
grep -q '^REJECTED JSONDecodeError$' free.txt
grep -q 'Event ID:\*\* 12345' free.raw   # an ID the alert never had

echo "== schema-constrained answer =="
python3 ticket.py schema | tee schema.txt
jq '{title, severity, host, user}' ticket.json
jq '.iocs' ticket.json
jq -e '.host == "FIN-WS-114" and .user == "mpatel"' ticket.json >/dev/null
jq -e '[.iocs[] | select(contains("203.0.113.45"))] | length == 1' ticket.json >/dev/null
jq -e '.summary | length <= 100' ticket.json >/dev/null
jq -e '.severity == "high" or .severity == "critical"' ticket.json >/dev/null
grep -q '^action: isolate FIN-WS-114 -> PENDING analyst approval$' schema.txt

echo "== a ticket with an invented IOC =="
cp ticket.json good.json
jq '.iocs += ["198.51.100.9"]' good.json > forged.json
set +e; python3 ticket.py check forged.json > forged.txt 2>&1; rc=$?; set -e
cat forged.txt
[ "$rc" -eq 1 ]
grep -q '^REJECTED Ungrounded: not in alert: 198.51.100.9$' forged.txt

echo "ALL 3.3 INCIDENT-TICKET CHECKS PASSED"
