#!/usr/bin/env bash
# Verifies the life-cycle example in 1.3-ai-life-cycle.md: an evaluation
# gate before registration, a sha256-pinned model registry, a deployment
# step that refuses a swapped model file before loading it, a validation
# smoke test, and a drift check (PSI) for monitoring.
# Needs: python3, scikit-learn, numpy, joblib
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Eq -- "$1" <<<"$OUT" || { echo "FAIL: expected /$1/"; exit 1; }; }

cat > train.py <<'PY'
import hashlib, json, os
import joblib, numpy as np
from sklearn.datasets import make_classification
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split

MIN = float(os.environ.get("MIN_SCORE", "0.80"))
X, y = make_classification(n_samples=3000, n_features=8,
                           weights=[0.85], random_state=4)
if os.environ.get("POISON"):          # attacker's copy
    y = 1 - y
Xtr, Xte, ytr, yte = train_test_split(
    X, y, test_size=0.3, stratify=y, random_state=4)
model = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
pred = model.predict(Xte)
p, r = precision_score(yte, pred), recall_score(yte, pred)
print(f"evaluation: precision {p:.2f}  recall {r:.2f}")
if os.environ.get("POISON"):
    joblib.dump(model, "model.joblib")
    raise SystemExit(0)
if min(p, r) < MIN:
    raise SystemExit(f"gate: BLOCKED (minimum {MIN:.2f})")

joblib.dump(model, "model.joblib")
np.save("baseline.npy", Xtr[:, 0])
np.savez("golden.npz", X=Xte[:25], y=pred[:25])
np.save("live.npy", Xte[:, 0])
digest = hashlib.sha256(open("model.joblib", "rb").read()).hexdigest()
json.dump({"model": "model.joblib", "version": "1.0.0",
           "sha256": digest}, open("registry.json", "w"), indent=2)
print(f"gate: PASSED, registered 1.0.0 sha256 {digest[:12]}")
PY

cat > deploy.py <<'PY'
import hashlib, json, sys
import joblib, numpy as np

reg = json.load(open("registry.json"))
path = reg["model"]
with open(path, "rb") as f:
    digest = hashlib.sha256(f.read()).hexdigest()
if digest != reg["sha256"]:
    sys.exit(f"REFUSED: {path} does not match"
             " registry\n"
             f"  got {digest[:12]}, "
             f"pinned {reg['sha256'][:12]}")
# load only after the hash matches
model = joblib.load(path)

# validation: the served copy must reproduce the evaluated output
g = np.load("golden.npz")
match = int((model.predict(g["X"]) == g["y"]).sum())
print(f"validation: {match}/{len(g['y'])} golden samples match")
if match != len(g["y"]):
    sys.exit("REFUSED: validation failed")
print(f"deployed {reg['version']}")
PY

cat > monitor.py <<'PY'
import numpy as np

def psi(base, live, bins=10):
    edges = np.quantile(base, np.linspace(0, 1, bins + 1))
    edges[0], edges[-1] = -np.inf, np.inf
    b = np.histogram(base, edges)[0] / len(base)
    l = np.histogram(live, edges)[0] / len(live)
    b, l = np.clip(b, 1e-6, None), np.clip(l, 1e-6, None)
    return float(np.sum((l - b) * np.log(l / b)))

base, live = np.load("baseline.npy"), np.load("live.npy")
for week, shift in (("week 1", 0.0), ("week 2", 0.8)):
    score = psi(base, live + shift)
    flag = "DRIFT: open retraining ticket" if score > 0.25 else "ok"
    print(f"{week}  psi {score:.2f}  {flag}")
PY

echo "== model evaluation gate"
t 'MIN_SCORE=0.95 python3 train.py'
has '^evaluation: precision 0\.[0-9]+  recall 0\.[0-9]+$'
has '^gate: BLOCKED \(minimum 0\.95\)$'
[ "$RC" -ne 0 ] && [ ! -f registry.json ]
t 'python3 train.py'
has '^gate: PASSED, registered 1\.0\.0 sha256 [0-9a-f]{12}$'
jq -e '.sha256 | test("^[0-9a-f]{64}$")' registry.json >/dev/null

echo; echo "== deployment and validation"
t 'python3 deploy.py'
has '^validation: 25/25 golden samples match$'
has '^deployed 1\.0\.0$'

echo; echo "== a swapped model file"
mkdir untrusted
(cd untrusted && POISON=1 python3 ../train.py >/dev/null)
t 'cp untrusted/model.joblib model.joblib'
t 'python3 deploy.py'
has '^REFUSED: model\.joblib does not match registry$'
has '^  got [0-9a-f]{12}, pinned [0-9a-f]{12}$'
[ "$RC" -ne 0 ]

echo; echo "== monitoring for drift"
t 'python3 monitor.py'
has '^week 1  psi 0\.[01][0-9]  ok$'
has '^week 2  psi [0-9.]+  DRIFT: open retraining ticket$'

echo "ALL 1.3 AI-LIFE-CYCLE CHECKS PASSED"
