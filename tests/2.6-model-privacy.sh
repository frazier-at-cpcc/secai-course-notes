#!/usr/bin/env bash
# Verifies the model theft and membership inference examples in the 2.6
# notes: a surrogate trained only on a victim model's answers agrees with it
# more as the query budget grows, and an overfit model's confidence gap lets
# an attacker tell training records from other records. Label-only output
# and regularization shrink that gap.
# Needs: python3 with scikit-learn and numpy
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

cat > extract.py <<'PY'
import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier

X, y = make_classification(n_samples=3000,
    n_features=20, n_informative=8, random_state=7)
Xtr, Xte, ytr, yte = train_test_split(
    X, y, test_size=0.3, random_state=7)
victim = RandomForestClassifier(
    random_state=0).fit(Xtr, ytr)
api = victim.predict          # label-only endpoint
rng = np.random.default_rng(1)

for budget in (50, 5000):     # queries allowed
    Q = rng.normal(0, 2, size=(budget, 20))
    sur = MLPClassifier((64,), max_iter=2000,
        random_state=0).fit(Q, api(Q))
    agree = (sur.predict(Xte) == api(Xte)).mean()
    print(f"{budget:>5} queries: surrogate "
          f"agrees {agree:.0%}")
PY

cat > membership.py <<'PY'
import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

X, y = make_classification(n_samples=600,
    n_features=20, n_informative=5, flip_y=0.15,
    random_state=3)
Xin, Xout, yin, yout = train_test_split(
    X, y, test_size=0.5, random_state=3)

def conf(m, X, y):   # confidence in the true label
    return m.predict_proba(X)[np.arange(len(y)), y]

def attack(m, label_only=False):
    if label_only:   # only right/wrong is visible
        a = m.predict(Xin) == yin
        b = m.predict(Xout) == yout
    else:            # guess "member" above 0.8
        a = conf(m, Xin, yin) > 0.8
        b = conf(m, Xout, yout) > 0.8
    return (a.sum() + (~b).sum()) / (len(a) + len(b))

over = RandomForestClassifier(random_state=0)
over.fit(Xin, yin)
print(f"mean confidence: members "
      f"{conf(over, Xin, yin).mean():.2f}, "
      f"others {conf(over, Xout, yout).mean():.2f}")
print(f"attack accuracy, scores:     "
      f"{attack(over):.0%}")
print(f"attack accuracy, label only: "
      f"{attack(over, label_only=True):.0%}")
reg = RandomForestClassifier(min_samples_leaf=20,
    random_state=0).fit(Xin, yin)
print(f"attack accuracy, regularized: "
      f"{attack(reg):.0%}")
PY

ex=$(python3 extract.py); echo "$ex"
lo=$(awk '/^ +50 queries/ {print $NF+0}' <<<"$ex")
hi=$(awk '/^ *5000 queries/ {print $NF+0}' <<<"$ex")
[ "$hi" -ge 90 ] || { echo "FAIL: extraction too weak ($hi)"; exit 1; }
[ "$lo" -lt "$hi" ] || { echo "FAIL: budget made no difference"; exit 1; }

mi=$(python3 membership.py); echo "$mi"
s=$(awk '/scores:/ {print $NF+0}' <<<"$mi")
l=$(awk '/label only:/ {print $NF+0}' <<<"$mi")
r=$(awk '/regularized:/ {print $NF+0}' <<<"$mi")
[ "$s" -ge 75 ] || { echo "FAIL: membership attack too weak ($s)"; exit 1; }
if [ "$l" -ge "$s" ] || [ "$r" -ge "$s" ]; then echo "FAIL: controls did not help"; exit 1; fi
[ "$r" -le 55 ] || { echo "FAIL: regularized still leaks ($r)"; exit 1; }

echo "ALL 2.6 MODEL-PRIVACY CHECKS PASSED"
