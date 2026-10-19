#!/usr/bin/env bash
# Laplace-noise differential privacy on a count query at two epsilon values
# (4.2 Responsible AI notes).
# Needs: python3, numpy (pip install numpy)
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

cat > dp_count.py <<'EOF'
import numpy as np

rng = np.random.default_rng(2026)
TRUE = 42      # users who pasted secrets
SENS = 1       # one person changes it by 1

def noisy(count, eps, n):
    scale = SENS / eps
    return count + rng.laplace(0, scale, n)

for eps in (1.0, 0.1):
    one = noisy(TRUE, eps, 1)[0]
    d = noisy(TRUE, eps, 200_000)
    d2 = noisy(TRUE + 1, eps, 200_000)
    err = np.mean(np.abs(d - TRUE))
    p, p2 = np.mean(d > 42.5), np.mean(d2 > 42.5)
    print(f"eps={eps}: answer={one:6.1f}"
          f"  avg_err={err:5.2f}"
          f"  ratio={p2 / p:4.2f}")
print(f"e^1={np.e:.2f}  e^0.1={np.exp(0.1):.2f}")
EOF

out=$(python3 -I dp_count.py)
echo "$out"

expect() { grep -qxF -- "$1" <<<"$out" || { echo "FAIL: missing line: $1"; exit 1; }; }
expect "eps=1.0: answer=  41.0  avg_err= 1.00  ratio=2.31"
expect "eps=0.1: answer=  52.5  avg_err=10.00  ratio=1.10"
expect "e^1=2.72  e^0.1=1.11"

# Average error is the Laplace scale (1/eps); the likelihood ratio between
# neighbouring datasets never exceeds e^eps.
python3 -I - "$out" <<'EOF'
import math, re, sys
for eps, err, ratio in re.findall(
        r"eps=([\d.]+): .*avg_err=\s*([\d.]+)\s+ratio=([\d.]+)", sys.argv[1]):
    eps, err, ratio = float(eps), float(err), float(ratio)
    assert abs(err - 1 / eps) < 0.05 / eps, (eps, err)
    assert ratio <= math.exp(eps), (eps, ratio)
print("bounds hold")
EOF

echo "ALL 4.2 DIFFERENTIAL-PRIVACY CHECKS PASSED"
