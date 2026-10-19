#!/usr/bin/env bash
# Verifies the commands, files, and output shown in 1.2-data-processing.md:
# cleansing and verifying a SIEM alert export, a sha256 manifest that catches
# a tampered (label-flipped) training file, and class balancing.
# Needs: python3, scikit-learn, sha256sum (coreutils), jq
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Eq -- "$1" <<<"$OUT" || { echo "FAIL: expected /$1/"; exit 1; }; }

# Raw export from the SIEM: duplicates, stray spaces, mixed case, bad rows.
cat > alerts.csv <<'CSV'
id,ts,src_ip,rule,severity,label
A-1001,2026-09-14T08:02:11Z,10.0.4.17,ssh-brute,high,malicious
A-1002,2026-09-14T08:02:40Z,10.0.4.22,dns-tunnel,High ,Malicious
A-1002,2026-09-14T08:02:40Z,10.0.4.22,dns-tunnel,High ,Malicious
A-1003,2026-09-14 08:05:00,10.0.9.5,port-scan,medium,benign
A-1004,2026-09-14T08:07:13Z,10.0.300.8,port-scan,low,benign
A-1005,2026-09-14T08:09:51Z,10.0.4.40,,low,benign
A-1006,2026-09-14T08:11:02Z,10.0.4.41,geo-login,urgent,benign
A-1007,2026-09-14T08:12:30Z,10.0.5.3,geo-login,low,Benign
A-1008,2026-09-14T08:14:45Z,10.0.5.9,port-scan,low,benign
A-1009,2026-09-14T08:15:10Z,10.0.6.2,ssh-brute,high,malicious
A-1010,2026-09-14T08:16:22Z,10.0.5.12,geo-login,medium,benign
A-1011,2026-09-14T08:18:03Z,10.0.5.14,port-scan,low,benign
A-1012,2026-09-14T08:19:40Z,10.0.7.1,av-detect,medium,benign
A-1013,2026-09-14T08:21:05Z,10.0.7.8,geo-login,low,benign
A-1014,2026-09-14T08:22:59Z,10.0.5.20,port-scan,low,benign
A-1015,2026-09-14T08:24:17Z,10.0.7.9,av-detect,low,benign
A-1016,2026-09-14T08:25:48Z,10.0.5.33,geo-login,low,benign
CSV

cat > cleanse.py <<'PY'
import csv, ipaddress, sys
from datetime import datetime

SEV = {"low", "medium", "high", "critical"}
LABELS = {"benign", "malicious"}

def ts_ok(v):
    datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    return True

CHECKS = {  # verification rules
    "ts": ts_ok,
    "src_ip": ipaddress.ip_address,
    "rule": bool,
    "severity": SEV.__contains__,
    "label": LABELS.__contains__,
}

def bad_field(row):
    for field, check in CHECKS.items():
        try:
            if not check(row[field]):
                return field
        except ValueError:
            return field

seen, kept = set(), []
with open(sys.argv[1], newline="") as f:
    for row in csv.DictReader(f):
        # cleansing: trim, normalize case, dedupe
        row = {k: v.strip() for k, v in row.items()}
        row["severity"] = row["severity"].lower()
        row["label"] = row["label"].lower()
        if row["id"] in seen:
            print(f"duplicate {row['id']}")
            continue
        seen.add(row["id"])
        if field := bad_field(row):
            print(f"rejected  {row['id']}  bad {field}")
            continue
        kept.append(row)

with open(sys.argv[2], "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=kept[0],
                       lineterminator="\n")
    w.writeheader()
    w.writerows(kept)
print(f"kept {len(kept)} of {len(seen)} unique rows")
PY

cat > balance.py <<'PY'
import csv, sys
from collections import Counter
from sklearn.utils import resample

rows = list(csv.DictReader(open(sys.argv[1])))
count = lambda rs: dict(Counter(r["label"] for r in rs))
print("before:", count(rows))

mal = [r for r in rows if r["label"] == "malicious"]
ben = [r for r in rows if r["label"] == "benign"]
# oversample the minority class with replacement
up = resample(mal, replace=True,
              n_samples=len(ben), random_state=7)
print("after: ", count(ben + up))
PY

cat > lineage.json <<'JSON'
{
  "dataset": "clean.csv",
  "derived_from": ["alerts.csv"],
  "transform": "cleanse.py",
  "source": "SIEM export, tenant soc-prod",
  "collected_by": "svc-siem-export",
  "collected_at": "2026-09-14T09:00:00Z",
  "integrity": "MANIFEST (sha256)"
}
JSON

echo "== cleansing and verification"
t 'python3 cleanse.py alerts.csv clean.csv'
has '^duplicate A-1002$'
has '^rejected  A-1003  bad ts$'
has '^rejected  A-1004  bad src_ip$'
has '^rejected  A-1005  bad rule$'
has '^rejected  A-1006  bad severity$'
has '^kept 12 of 16 unique rows$'
grep -q '^A-1002,2026-09-14T08:02:40Z,10.0.4.22,dns-tunnel,high,malicious$' clean.csv
grep -q ',benign$' <(grep '^A-1007' clean.csv)

echo; echo "== provenance, lineage, integrity"
t 'sha256sum *.csv cleanse.py > MANIFEST'
t 'sha256sum -c MANIFEST'
has '^clean.csv: OK$'
# every file named in the lineage record is covered by the manifest
for f in $(jq -r '.dataset, .derived_from[], .transform' lineage.json); do
  grep -q "  $f\$" MANIFEST || { echo "FAIL: $f not in MANIFEST"; exit 1; }
done
# poisoning by label flip: one malicious row relabeled benign
t "sed -i '/A-1009/s/malicious/benign/' clean.csv"
grep -q '^A-1009,.*,benign$' clean.csv
t 'sha256sum -c MANIFEST'
has '^alerts.csv: OK$'
has '^clean.csv: FAILED$'
has 'WARNING: 1 computed checksum did NOT match'
[ "$RC" -ne 0 ]

echo; echo "== balancing"
t 'python3 cleanse.py alerts.csv clean.csv >/dev/null'
t 'python3 balance.py clean.csv'
has "^before: \{'malicious': 3, 'benign': 9\}$"
has "^after:  \{'benign': 9, 'malicious': 9\}$"

echo "ALL 1.2 DATA-PROCESSING CHECKS PASSED"
