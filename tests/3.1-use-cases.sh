#!/usr/bin/env bash
# Verifies the detection examples in the 3.1 notes
# (3.1-ai-security-use-cases.md): a YARA signature next to an ML
# pattern-recognition score on the same email subject lines, and
# IsolationForest anomaly detection on synthetic login events.
# Needs: python3, pip packages yara-python (tested with 4.5.4),
#        scikit-learn (1.9.1), numpy (2.5.3)
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > lure.yar <<'YAR'
rule Lure_Account_Verify
{
  strings:
    $a = "verify your account" nocase
    $b = "password expires today" nocase
  condition:
    any of them
}
YAR

cat > subjects.py <<'PY'
import yara
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

lures = [
 "Verify your account now or lose access",
 "Your password expires today: act now",
 "Urgent: confirm your mailbox credentials",
 "Action required: validate your login",
 "Final notice: account suspended, verify now",
 "Confirm your payroll details immediately",
 "Security alert: unusual sign-in, confirm identity",
 "Your mailbox is full, log in to keep email",
]
normal = [
 "Agenda for Thursday change advisory board",
 "Q3 vulnerability scan results attached",
 "Lunch order for the SOC team",
 "Updated on-call rotation for October",
 "Firewall change window moved to Saturday",
 "Minutes from the incident review",
 "Reminder: tabletop exercise next week",
 "New laptop images ready for testing",
]
clf = make_pipeline(
    TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)),
    LogisticRegression(C=10, max_iter=1000))
clf.fit(lures + normal, [1] * 8 + [0] * 8)

rules = yara.compile(filepath="lure.yar")
tests = [
 "Verify your account by Friday",
 "Re-confirm your login credentials",
 "Change board moved to Friday",
]
print("yara  ml    subject")
for s in tests:
    hit = "HIT " if rules.match(data=s.encode()) else "miss"
    p = clf.predict_proba([s])[0][1]
    print(f"{hit}  {p:.2f}  {s}")
PY
out=$(python3 subjects.py)
echo "$out"
score() { grep -F "$1" <<<"$out" | awk '{print $2}'; }
grep -q '^HIT .*Verify your account' <<<"$out" || { echo "FAIL: signature hit"; exit 1; }
grep -q '^miss.*Re-confirm your login' <<<"$out" || { echo "FAIL: reworded lure should miss YARA"; exit 1; }
grep -q '^miss.*Change board' <<<"$out" || { echo "FAIL: benign hit"; exit 1; }
python3 - "$(score 'Re-confirm')" "$(score 'Change board')" <<'PY'
import sys
lure, benign = map(float, sys.argv[1:])
assert lure > 0.5 and benign < 0.5, (lure, benign)
PY

cat > logins.py <<'PY'
import numpy as np
from sklearn.ensemble import IsolationForest

rng = np.random.default_rng(7)
n = 500
# features: hour, failed tries, km from usual city, MB downloaded
normal = np.column_stack([
    rng.normal(10, 2, n).clip(6, 19),   # office hours
    rng.poisson(0.3, n),                # rare typos
    rng.exponential(5, n),              # commute
    rng.normal(40, 12, n).clip(1),      # MB
])
odd = np.array([
    [3, 9, 8400, 2600],   # 3 a.m., brute force, abroad, bulk
    [2, 0, 12, 1900],     # night bulk download, no failures
    [11, 14, 3, 35],      # many failures, then success
])
X = np.vstack([normal, odd])
model = IsolationForest(n_estimators=200,
                        contamination=0.01,
                        random_state=0).fit(X)
flags = model.predict(X)             # -1 = anomaly
scores = model.score_samples(X)      # lower = stranger
for i in np.argsort(scores)[:5]:
    h, f, km, mb = X[i]
    tag = "ANOMALY" if flags[i] == -1 else "normal"
    print(f"{i:3d} {tag:7s} {scores[i]:.2f} "
          f"{h:2.0f}h {f:2.0f}fail {km:4.0f}km "
          f"{mb:4.0f}MB")
print("flagged:", int((flags == -1).sum()), "of", len(X))
PY
log=$(python3 logins.py)
echo "$log"
for i in 500 501 502; do
  grep -Eq "^$i ANOMALY" <<<"$log" || { echo "FAIL: event $i not flagged"; exit 1; }
done
grep -q '^flagged: 6 of 503$' <<<"$log" || { echo "FAIL: flagged count"; exit 1; }

echo "ALL 3.1 USE-CASES CHECKS PASSED"
