#!/usr/bin/env bash
# Verifies every command and output shown in 2.4-data-safety.md.
# Prepares a synthetic customer record for a billing chat assistant:
# classification labels, minimization, masking, redaction, keyed-hash
# pseudonymization, and a k-anonymity check on a generalized data set.
# Every name, number, and address here is fake (example.com, 555-01xx
# phone numbers, the 4111... test card, an SSN with area 000).
# Needs: python3 (standard library only)
set -euo pipefail
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Fq -- "$1" <<<"$OUT" || { echo "FAIL: expected '$1'"; exit 1; }; }
hasnt() { ! grep -Fq -- "$1" <<<"$OUT" || { echo "FAIL: leaked '$1'"; exit 1; }; }

cat > customer.json <<'JSON'
{"customer_id": "C-20417", "name": "Dana Testperson",
 "email": "dana@example.com", "phone": "704-555-0142",
 "ssn": "000-12-3456", "card": "4111 1111 1111 1111",
 "dob": "1988-03-14", "zip": "28202", "plan": "Pro"}
JSON
cat > ticket.txt <<'TXT'
Hi, this is Dana Testperson (dana@example.com,
704-555-0142). Card 4111 1111 1111 1111 was
charged twice for the Pro plan in September.
TXT
cat > cohort.csv <<'CSV'
age,zip,plan
34,28202,Pro
36,28204,Pro
38,28205,Basic
41,28210,Pro
44,28211,Basic
47,28214,Pro
52,28226,Basic
55,28227,Pro
59,28228,Basic
CSV
# Secret pseudonymization key, held by the data owner (a KMS in real life)
printf 'demo-only-secret-key-0001' > pseudo.key

cat > prep.py <<'PY'
"""Data safety steps before a record reaches a prompt (2.4 notes)."""
import csv, hashlib, hmac, json, re, sys
from collections import Counter

rec = json.load(open("customer.json"))
LABELS = {"customer_id": "Confidential", "name": "Confidential",
          "email": "Confidential", "phone": "Confidential",
          "ssn": "Restricted", "card": "Restricted",
          "dob": "Confidential", "zip": "Confidential",
          "plan": "Internal"}
# Minimization: the only fields the billing assistant needs
NEEDED = {"customer_id", "card", "plan"}

def pseudo(value):
    key = open("pseudo.key", "rb").read()
    mac = hmac.new(key, value.encode(), hashlib.sha256)
    return "cust_" + mac.hexdigest()[:12]

def mask_card(card):
    return re.sub(r"\d(?=(?:\s?\d){4})", "*", card)

def redact(text):
    rules = [(r"[\w.+-]+@[\w-]+\.[\w.]+", "[EMAIL]"),
             (r"\b\d{3}-\d{3}-\d{4}\b", "[PHONE]"),
             (r"\b(?:\d{4} ?){3}\d{4}\b", "[CARD]"),
             (re.escape(rec["name"]), "[NAME]")]
    for pattern, tag in rules:
        text = re.sub(pattern, tag, text)
    return text

cmd = sys.argv[1]
if cmd == "labels":
    for field, label in LABELS.items():
        print(f"{field:12} {label}")
elif cmd == "prompt":
    print("customer:", pseudo(rec["customer_id"]))
    print("card:", mask_card(rec["card"]))
    print("plan:", rec["plan"])
    print("ticket:")
    print(redact(open("ticket.txt").read()), end="")
elif cmd == "dropped":
    print(", ".join(f for f in rec if f not in NEEDED))
elif cmd == "unkeyed":
    # A plain hash of an email is not anonymous: hash a guess list
    target = hashlib.sha256(rec["email"].encode()).hexdigest()
    guesses = ["dan@example.com", "dana@example.com",
               "d.testperson@example.com"]
    for g in guesses:
        if hashlib.sha256(g.encode()).hexdigest() == target:
            print("sha256 reversed by guessing:", g)
elif cmd == "keyed":
    print(pseudo(rec["customer_id"]), pseudo(rec["customer_id"]))
elif cmd == "kanon":
    rows = list(csv.DictReader(open("cohort.csv")))
    raw = Counter((r["age"], r["zip"]) for r in rows)
    def band(a):
        lo = int(a) // 10 * 10
        return f"{lo}-{lo + 9}"
    gen = Counter((band(r["age"]), r["zip"][:3] + "**")
                  for r in rows)
    print("raw (age, zip):        k =", min(raw.values()))
    print("banded (age, zip3):    k =", min(gen.values()))
    for group, n in sorted(gen.items()):
        print(" ", *group, n)
PY
python3 -m py_compile prep.py

echo "== Classification labels"
t 'python3 prep.py labels'
has 'ssn          Restricted'
has 'plan         Internal'

echo "== Minimization, masking, redaction, pseudonymization"
t 'python3 prep.py dropped'
has 'name, email, phone, ssn, dob, zip'
t 'python3 prep.py prompt'
has 'card: **** **** **** 1111'
has '[NAME] ([EMAIL]'
has '[PHONE]). Card [CARD] was'
has 'customer: cust_'
for leak in "Dana" "dana@example.com" "555-0142" "4111 1111" "000-12-3456" "C-20417"; do
  hasnt "$leak"
done

echo "== Pseudonymization: unkeyed hash vs keyed hash"
t 'python3 prep.py unkeyed'
has 'sha256 reversed by guessing: dana@example.com'
t 'python3 prep.py keyed'
a=$(cut -d' ' -f1 <<<"$OUT"); b=$(cut -d' ' -f2 <<<"$OUT")
[ "$a" = "$b" ] || { echo "FAIL: keyed hash not stable"; exit 1; }

echo "== Anonymization: generalize, then measure k"
t 'python3 prep.py kanon'
has 'raw (age, zip):        k = 1'
has 'banded (age, zip3):    k = 3'

echo "ALL 2.4 DATA-SAFETY CHECKS PASSED"
