#!/usr/bin/env bash
# Verifies the data poisoning and backdoor examples in the 2.6 notes:
# targeted label flipping cuts a toy malware classifier's detection rate,
# a trigger-pattern backdoor makes triggered malware look benign while clean
# accuracy holds, an outlier check finds the trigger rows, and a SHA-256
# manifest catches the tampered training file.
# Needs: python3 with scikit-learn and numpy, coreutils (sha256sum)
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > poison.py <<'PY'
import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# 20 numeric features per file; label 1 = malware
X, y = make_classification(n_samples=3000,
    n_features=20, n_informative=8, random_state=7)
Xtr, Xte, ytr, yte = train_test_split(
    X, y, test_size=0.3, random_state=7)
np.savetxt("train.csv", np.c_[Xtr, ytr], fmt="%.5f",
           delimiter=",")
rng = np.random.default_rng(0)

def fit(X, y):
    return RandomForestClassifier(
        random_state=0).fit(X, y)

def report(name, m, Xmal):
    acc = m.score(Xte, yte)  # all test files
    det = (m.predict(Xmal) == 1).mean()
    print(f"{name:<12} acc {acc:.3f}  "
          f"malware caught {det:.0%}")

malware = Xte[yte == 1]
report("clean", fit(Xtr, ytr), malware)

# Label flipping: relabel 40% of malware as benign
yp = ytr.copy()
mal = np.flatnonzero(ytr == 1)
yp[rng.choice(mal, len(mal) * 4 // 10,
              replace=False)] = 0
np.savetxt("train-flipped.csv", np.c_[Xtr, yp],
           fmt="%.5f", delimiter=",")
report("40% flipped", fit(Xtr, yp), malware)

# Backdoor: 60 malware rows carry a trigger
# (two features pinned to odd values), labeled benign
def stamp(A):
    A = A.copy()
    A[:, 18], A[:, 19] = 6.0, -6.0
    return A
rows = stamp(Xtr[rng.choice(mal, 60, replace=False)])
Xb = np.vstack([Xtr, rows])
yb = np.r_[ytr, np.zeros(60, int)]
bd = fit(Xb, yb)
report("backdoored", bd, malware)
report("+ trigger", bd, stamp(malware))

# Evidence: rows far outside the feature range
z = np.abs((Xb - Xtr.mean(0)) / Xtr.std(0))
print("rows with |z| > 5:", int((z > 5).any(1).sum()))
PY

out=$(python3 poison.py)
echo "$out"
grep -Eq '^clean +acc 0\.9[0-9]{2}  malware caught 9[0-9]%$' <<<"$out" || { echo "FAIL: clean"; exit 1; }
det_flip=$(awk '/^40% flipped/ {print $NF+0}' <<<"$out")
[ "$det_flip" -lt 70 ] || { echo "FAIL: flipping had no effect"; exit 1; }
grep -Eq '^backdoored +acc 0\.9[0-9]{2}  malware caught 9[0-9]%$' <<<"$out" || { echo "FAIL: backdoor clean"; exit 1; }
grep -Eq '^\+ trigger +acc .* caught [0-9]%$' <<<"$out" || { echo "FAIL: trigger"; exit 1; }
grep -q '^rows with |z| > 5: 60$' <<<"$out" || { echo "FAIL: outlier count"; exit 1; }

# Data integrity control: pin the training file's hash, then swap it.
sha256sum train.csv > train.sha256
sha256sum -c train.sha256
cp train-flipped.csv train.csv
if chk=$(sha256sum -c train.sha256 2>&1); then
  echo "FAIL: manifest did not catch tampering"; exit 1
fi
echo "$chk"
grep -q '^train.csv: FAILED$' <<<"$chk" || { echo "FAIL: manifest output"; exit 1; }

echo "ALL 2.6 DATA-POISONING CHECKS PASSED"
