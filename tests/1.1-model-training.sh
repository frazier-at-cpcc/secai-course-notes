#!/usr/bin/env bash
# Verifies the model training examples in the 1.1 notes: supervised versus
# unsupervised learning, validation, loss across epochs, quantization, and
# pruning, all on a small synthetic set of login events.
# Needs: python3 with scikit-learn and numpy
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
export PYTHONHASHSEED=0 OMP_NUM_THREADS=1

# Shared data: one row per 10-minute login window for one source address.
cat > logins.py <<'PY'
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def logins(seed=7):
    """Columns: failed logins, distinct usernames
    tried, hour of day. Label 1 = brute force."""
    r = np.random.default_rng(seed)
    ok = np.column_stack([r.poisson(1.0, 950),
                          r.poisson(0.4, 950) + 1,
                          r.normal(13, 3.5, 950)])
    bad = np.column_stack([r.poisson(5, 50),
                           r.poisson(2, 50) + 1,
                           r.normal(6, 5, 50)])
    X = np.vstack([ok, bad])
    y = np.r_[np.zeros(950), np.ones(50)].astype(int)
    return X, y

def split(scale=False):
    X, y = logins()
    Xtr, Xva, ytr, yva = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=0)
    if scale:
        sc = StandardScaler().fit(Xtr)
        Xtr, Xva = sc.transform(Xtr), sc.transform(Xva)
    return Xtr, Xva, ytr, yva
PY

# 1. Supervised versus unsupervised, scored on a held-out validation set
cat > supervise.py <<'PY'
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, recall_score
from logins import split
Xtr, Xva, ytr, yva = split()
print(f"train {len(ytr)} / validation {len(yva)}"
      f" ({yva.sum()} attacks)")
print(f"always 'benign' accuracy: {(yva == 0).mean():.3f}")
clf = LogisticRegression().fit(Xtr, ytr)  # uses labels
p = clf.predict(Xva)
print(f"supervised accuracy:      "
      f"{accuracy_score(yva, p):.3f}")
print(f"supervised attack recall: {recall_score(yva, p):.2f}")
iso = IsolationForest(contamination=0.05,
                      random_state=0).fit(Xtr)  # no labels
f = iso.predict(Xva) == -1
print(f"isolation forest flagged {f.sum()}, "
      f"{(f & (yva == 1)).sum()} were attacks")
PY

# 2. Loss across epochs: one partial_fit call is one pass over the data
cat > epochs.py <<'PY'
import warnings
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import log_loss
from logins import split
warnings.filterwarnings("ignore")
Xtr, Xva, ytr, yva = split(scale=True)
net = MLPClassifier((64, 64), learning_rate_init=0.01,
                    random_state=0)
print("epoch  train_loss  val_loss")
for epoch in range(1, 201):
    net.partial_fit(Xtr, ytr, classes=[0, 1])
    if epoch in (1, 5, 10, 25, 50, 100, 200):
        tl = log_loss(ytr, net.predict_proba(Xtr))
        vl = log_loss(yva, net.predict_proba(Xva))
        print(f"{epoch:>5}  {tl:10.3f}  {vl:8.3f}")
PY

# 3. Quantization and pruning of the trained network's weights
cat > shrink.py <<'PY'
import copy, warnings
import numpy as np
from sklearn.neural_network import MLPClassifier
from logins import split
warnings.filterwarnings("ignore")
Xtr, Xva, ytr, yva = split(scale=True)
net = MLPClassifier((64, 64), learning_rate_init=0.01,
                    max_iter=10, random_state=0)
net.fit(Xtr, ytr)

def acc(m):
    return (m.predict(Xva) == yva).mean()

def quantize(w):  # float32 -> int8 with one scale
    scale = np.abs(w).max() / 127
    q = np.round(w / scale).astype(np.int8)
    return q, scale

def prune(w, frac):  # zero the smallest weights
    cut = np.quantile(np.abs(w), frac)
    return np.where(np.abs(w) < cut, 0.0, w)

W = [w.astype(np.float32) for w in net.coefs_]
qs = [quantize(w) for w in W]
err = max(np.abs(w - q * s).max()
          for w, (q, s) in zip(W, qs))
print(f"weights:      {sum(w.size for w in W)}")
print(f"float32 size: {sum(w.nbytes for w in W)} bytes")
print(f"int8 size:    {sum(q.nbytes for q, _ in qs)} bytes")
print(f"max rounding error: {err:.4f}")
print(f"accuracy float32: {acc(net):.3f}")
qn = copy.deepcopy(net)
qn.coefs_ = [q.astype(np.float64) * s for q, s in qs]
print(f"accuracy int8:    {acc(qn):.3f}")
for frac in (0.5, 0.7, 0.8, 0.9):
    pn = copy.deepcopy(net)
    pn.coefs_ = [prune(w, frac) for w in net.coefs_]
    print(f"pruned {frac:.0%}: accuracy {acc(pn):.3f}")
PY

expect() { grep -qxF -- "$2" <<<"$1" || { echo "FAIL: missing '$2'"; echo "$1"; exit 1; }; }

echo "\$ python3 supervise.py"
out=$(python3 supervise.py); echo "$out"
expect "$out" "train 700 / validation 300 (15 attacks)"
expect "$out" "always 'benign' accuracy: 0.950"
expect "$out" "supervised accuracy:      0.990"
expect "$out" "supervised attack recall: 0.87"
expect "$out" "isolation forest flagged 18, 14 were attacks"

echo "\$ python3 epochs.py"
out=$(python3 epochs.py); echo "$out"
expect "$out" "    1       0.283     0.301"
expect "$out" "   10       0.028     0.030"
expect "$out" "  200       0.006     0.057"
# Training loss keeps falling while validation loss turns back up: overfitting
python3 - "$out" <<'PY'
import sys
rows = [l.split() for l in sys.argv[1].splitlines()[1:]]
tl = [float(r[1]) for r in rows]; vl = [float(r[2]) for r in rows]
assert tl == sorted(tl, reverse=True), "train loss should only fall"
best = vl.index(min(vl))
assert rows[best][0] == "10" and vl[-1] > vl[best], "val loss should rise after epoch 10"
PY

echo "\$ python3 shrink.py"
out=$(python3 shrink.py); echo "$out"
expect "$out" "float32 size: 17408 bytes"
expect "$out" "int8 size:    4352 bytes"
expect "$out" "max rounding error: 0.0018"
expect "$out" "accuracy float32: 0.990"
expect "$out" "accuracy int8:    0.990"
expect "$out" "pruned 50%: accuracy 0.990"
expect "$out" "pruned 80%: accuracy 0.963"
expect "$out" "pruned 90%: accuracy 0.950"

echo "ALL 1.1 MODEL-TRAINING CHECKS PASSED"
