#!/usr/bin/env bash
# Verifies the insecure output handling and least privilege examples in the
# 2.6 notes: a model reply carrying markup becomes a live HTML element when
# pasted into a page and inert text when escaped, and model-written SQL that
# tries to delete data fails on a read-only database connection.
# Needs: python3 (standard library only)
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > render.py <<'PY'
import html
from html.parser import HTMLParser

# A reply steered by an injected document
reply = 'Done. <img src=x onerror=alert(1)>'

class Tags(HTMLParser):
    def __init__(self):
        super().__init__(); self.found = []
    def handle_starttag(self, tag, attrs):
        self.found.append(tag)

for name, body in (("raw", reply),
                   ("escaped", html.escape(reply))):
    page = f"<div class=msg>{body}</div>"
    p = Tags(); p.feed(page)
    print(f"{name}: {body}")
    print(f"  live tags: {p.found}")
PY
out=$(python3 render.py); echo "$out"
grep -q "^  live tags: \['div', 'img'\]$" <<<"$out" || { echo "FAIL: raw"; exit 1; }
grep -q "^  live tags: \['div'\]$" <<<"$out" || { echo "FAIL: escaped"; exit 1; }
grep -q "^escaped: Done. &lt;img src=x onerror=alert(1)&gt;$" <<<"$out" || { echo "FAIL: escape text"; exit 1; }

cat > agent_sql.py <<'PY'
import sqlite3

db = sqlite3.connect("tickets.db")
db.execute("CREATE TABLE tickets (id, status)")
db.execute("INSERT INTO tickets VALUES (1,'open')")
db.commit(); db.close()

sql = "DELETE FROM tickets"   # model-written

ro = sqlite3.connect("file:tickets.db?mode=ro",
                     uri=True)  # least privilege
try:
    ro.execute(sql)
except sqlite3.OperationalError as e:
    print("blocked:", e)
print("rows left:",
      ro.execute("SELECT count(*) FROM tickets")
        .fetchone()[0])
PY
sq=$(python3 agent_sql.py); echo "$sq"
grep -q "^blocked: attempt to write a readonly database$" <<<"$sq" || { echo "FAIL: ro"; exit 1; }
grep -q "^rows left: 1$" <<<"$sq" || { echo "FAIL: rows"; exit 1; }

echo "ALL 2.6 OUTPUT-HANDLING CHECKS PASSED"
