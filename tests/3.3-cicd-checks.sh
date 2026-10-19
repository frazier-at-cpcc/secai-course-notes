#!/usr/bin/env bash
# Verifies the AI-in-CI/CD examples in the 3.3 notes: code scanning
# with bandit, software composition analysis with pip-audit, unit
# tests, model tests with an accuracy threshold, a regression test that
# blocks a model change that loses accuracy, and an automated deploy
# step that keeps the last good model.
# Needs: python3 with numpy, scikit-learn, pytest, bandit, pip-audit;
#        network access to pypi.org (pip-audit vulnerability lookups)
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
export PIP_AUDIT_CACHE_DIR="$WORK/.pip-audit-cache"
mkdir -p app tests models data bad

# ---------- code scanning: an insecure version of the triage helper
cat > bad/triage.py <<'PY'
import pickle
import subprocess

API_TOKEN = "tok-9f2c41d7e0"


def load_model(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def lookup(host):
    cmd = f"nslookup {host}"
    return subprocess.run(cmd, shell=True)
PY
echo "== bandit on the insecure helper =="
set +e
bandit -q -f custom bad/triage.py \
  --msg-template "{line}: {test_id} {severity}" | tee bandit.txt
rc=${PIPESTATUS[0]}; set -e
[ "$rc" -eq 1 ]
grep -q '^4: B105 LOW$' bandit.txt
grep -q '^9: B301 MEDIUM$' bandit.txt
grep -q '^14: B602 HIGH$' bandit.txt

# ---------- software composition analysis: an old PyTorch pin
echo "torch==2.5.1" > bad/requirements.txt
cat > cve.jq <<'JQ'
.dependencies[] | .name as $n | .version as $v
| .vulns[] | select(.aliases | index("CVE-2025-32434"))
| "\($n) \($v) \(.id) fix \(.fix_versions[0])"
JQ
echo "== pip-audit on an old torch pin =="
cat bad/requirements.txt
set +e
pip-audit -r bad/requirements.txt --no-deps \
  --disable-pip -f json -o sca.json 2>/dev/null
rc=$?; set -e
[ "$rc" -eq 1 ]
jq -r -f cve.jq sca.json | sort -u | tee sca.txt
grep -q '^torch 2.5.1 PYSEC-2025-41 fix 2.6.0$' sca.txt
# More than one advisory for this version, as the notes say
[ "$(jq '[.dependencies[].vulns[].id] | unique | length' sca.json)" -gt 1 ]

# ---------- the clean project the pipeline builds
cat > app/__init__.py <<'PY'
PY
cat > app/features.py <<'PY'
def fail_ratio(failed, total):
    """Share of failed logins; 0.0 when none."""
    return failed / total if total else 0.0
PY
printf 'numpy==2.5.3\nscikit-learn==1.9.1\n' > requirements.txt

cat > train.py <<'PY'
# Train a login-risk classifier on synthetic data.
# v2 simulates a labeling bug: 35% of training
# labels flipped.
import json, sys
import numpy as np
from sklearn.datasets import make_classification
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

ver = sys.argv[1]
X, y = make_classification(
    n_samples=3000, n_features=8, n_informative=5,
    n_redundant=1, class_sep=1.2, random_state=7)
Xtr, Xho, ytr, yho = train_test_split(
    X, y, test_size=0.3, random_state=7)
np.savetxt("data/holdout.csv",
           np.column_stack([Xho, yho]), delimiter=",")
if ver == "v2":
    rng = np.random.default_rng(1)
    i = rng.choice(len(ytr), int(0.35 * len(ytr)),
                   replace=False)
    ytr = ytr.copy(); ytr[i] = 1 - ytr[i]
m = LogisticRegression().fit(Xtr, ytr)
json.dump({"coef": m.coef_[0].tolist(),
           "intercept": float(m.intercept_[0])},
          open(f"models/{ver}.json", "w"))
PY

cat > tests/test_features.py <<'PY'
from app.features import fail_ratio

def test_ratio():
    assert fail_ratio(3, 4) == 0.75

def test_no_logins_is_zero():
    assert fail_ratio(0, 0) == 0.0
PY

cat > tests/test_model.py <<'PY'
import json, os
import numpy as np

MIN_ACCURACY = 0.80   # absolute floor
MAX_DROP = 0.01       # vs the production model

def accuracy(path):
    w = json.load(open(path))
    d = np.loadtxt("data/holdout.csv",
                   delimiter=",")
    X, y = d[:, :-1], d[:, -1]
    score = X @ w["coef"] + w["intercept"]
    acc = ((score > 0) == y).mean()
    return round(float(acc), 3)

CAND = accuracy(os.environ["CANDIDATE"])

def test_accuracy_threshold():
    assert CAND >= MIN_ACCURACY

def test_no_regression():
    prod = json.load(open("models/baseline.json"))
    assert CAND >= prod["accuracy"] - MAX_DROP

if __name__ == "__main__":     # after a deploy
    json.dump({"accuracy": CAND},
              open("models/baseline.json", "w"))
PY

cat > pipeline.sh <<'SH'
#!/usr/bin/env bash
# usage: pipeline.sh <model-version>
set -euo pipefail
export CANDIDATE="models/$1.json"
stage() {
  local name=$1; shift
  if "$@" > "logs/$name.log" 2>&1; then
    printf '%-12s PASS\n' "$name"
  else
    printf '%-12s FAIL\n' "$name"
    echo "deploy       SKIPPED, prod stays" \
         "$(readlink models/current)"
    exit 1
  fi
}
mkdir -p logs
stage code-scan bandit -q -r app
stage sca pip-audit -r requirements.txt \
  --no-deps --disable-pip
stage unit-tests python3 -m pytest -q tests/test_features.py
stage model-tests python3 -m pytest -q tests/test_model.py
ln -sfn "$1.json" models/current
python3 tests/test_model.py   # new baseline
echo "deploy       models/current -> $1.json"
SH
chmod +x pipeline.sh
export PYTHONPATH="$WORK"

python3 train.py v1
python3 train.py v2
# First release: no production model yet, so the
# baseline is the floor itself.
echo '{"accuracy": 0.80}' > models/baseline.json
echo "== pipeline: v1 =="
./pipeline.sh v1 | tee run1.txt
grep -q '^deploy       models/current -> v1.json$' run1.txt
jq -e '.accuracy == 0.842' models/baseline.json >/dev/null

echo "== pipeline: v2 (labeling bug) =="
set +e; ./pipeline.sh v2 | tee run2.txt; rc=${PIPESTATUS[0]}; set -e
[ "$rc" -eq 1 ]
grep -q '^model-tests  FAIL$' run2.txt
grep -q '^deploy       SKIPPED, prod stays v1.json$' run2.txt
[ "$(readlink models/current)" = v1.json ]
grep -E 'FAILED|passed' logs/model-tests.log | tee pytest.txt
grep -q 'FAILED tests/test_model.py::test_no_regression' pytest.txt
grep -q '1 failed, 1 passed' pytest.txt
grep -q 'test_no_regression - assert 0.819 >= (0.842 - 0.01)$' pytest.txt

echo "ALL 3.3 CICD CHECKS PASSED"
