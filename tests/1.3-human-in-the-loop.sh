#!/usr/bin/env bash
# Verifies the approval gate in 1.3-human-centric-design.md: an AI triage
# assistant proposes response actions; only low-impact, high-confidence
# actions run on their own, everything else waits for a named human, no
# answer means no action, and every decision lands in an audit log.
# Needs: python3, jq
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Eq -- "$1" <<<"$OUT" || { echo "FAIL: expected /$1/"; exit 1; }; }

cat > proposals.json <<'JSON'
[
 {"id": "P-1", "action": "watchlist",
  "target": "198.51.100.7", "confidence": 0.97},
 {"id": "P-2", "action": "isolate_host",
  "target": "ws-0142", "confidence": 0.62},
 {"id": "P-3", "action": "disable_account",
  "target": "svc-backup", "confidence": 0.91},
 {"id": "P-4", "action": "block_domain",
  "target": "cdn.example.net", "confidence": 0.88}
]
JSON

cat > gate.py <<'PY'
import json, os, sys, time

AUTO = {"watchlist", "enrich"}  # low impact, reversible
approver = os.environ["APPROVER"]
log = open("audit.jsonl", "a")

for p in json.load(open(sys.argv[1])):
    print(f"{p['id']} {p['action']} {p['target']}"
          f"  conf {p['confidence']:.2f}")
    if p["action"] in AUTO and p["confidence"] >= 0.9:
        decision, who = "auto", "policy"
    else:
        ans = sys.stdin.readline().strip().lower()
        print(f"  approve? [y/N] {ans}")
        if ans == "y":
            decision, who = "approved", approver
        elif ans == "n":
            decision, who = "denied", approver
        else:  # no answer: fail closed
            decision, who = "denied", "default"
    print(f"  {decision} by {who}")
    rec = {**p, "decision": decision, "by": who,
           "at": int(time.time())}
    log.write(json.dumps(rec) + "\n")
PY

echo "== approval gate"
# shown as a typed command; exported so gate.py sees it
printf '$ export APPROVER=jlee\n'; export APPROVER=jlee
t "printf 'y\nn\n' | python3 gate.py proposals.json"
has '^P-1 watchlist 198\.51\.100\.7  conf 0\.97$'
has '^  auto by policy$'
has '^P-2 isolate_host ws-0142  conf 0\.62$'
has '^  approve\? \[y/N\] y$'
has '^  approved by jlee$'
has '^P-3 disable_account svc-backup  conf 0\.91$'
has '^  approve\? \[y/N\] n$'
has '^P-4 block_domain cdn\.example\.net  conf 0\.88$'
has '^  approve\? \[y/N\] $'
has '^  denied by jlee$'
has '^  denied by default$'

echo; echo "== audit trail"
t "jq -c '[.id, .decision, .by]' audit.jsonl"
has '^\["P-1","auto","policy"\]$'
has '^\["P-2","approved","jlee"\]$'
has '^\["P-3","denied","jlee"\]$'
has '^\["P-4","denied","default"\]$'

echo "ALL 1.3 HUMAN-IN-THE-LOOP CHECKS PASSED"
