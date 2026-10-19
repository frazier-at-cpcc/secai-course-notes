#!/usr/bin/env bash
# Verifies the AI supply chain example in the 2.6 notes: a pickled "model"
# runs code the moment it is loaded (a harmless payload that only creates a
# marker file in the temp dir), picklescan flags it before loading, and the
# same weights saved as safetensors load as plain data.
# Needs: python3 with numpy, picklescan, safetensors
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
mkdir build
# Writer side (the attacker's upload). Kept out of the notes.
cat > build/make_models.py <<'PY'
import os, pickle, sys
import numpy as np
from safetensors.numpy import save_file

marker = os.path.join(sys.argv[1], "PWNED.txt")

class Payload:  # runs on unpickle; harmless here
    def __reduce__(self):
        return (os.system, (f"touch {marker}",))

w = {"dense.weight": np.ones((4, 4), np.float32)}
with open("model.pkl", "wb") as f:
    pickle.dump({"weights": w, "meta": Payload()}, f)
save_file(w, "model.safetensors")
PY
python3 build/make_models.py "$WORK"
rm -rf build
[ ! -e PWNED.txt ] || { echo "FAIL: marker exists before load"; exit 1; }

# 1. Scan before loading.
set +e; scan=$(picklescan --path model.pkl 2>&1); rc=$?; set -e
echo "${scan//$WORK\//}"
echo "exit code $rc"
[ "$rc" -eq 1 ] || { echo "FAIL: picklescan exit $rc"; exit 1; }
grep -q "dangerous import '.* system' FOUND" <<<"$scan" || { echo "FAIL: not flagged"; exit 1; }

# 2. Loading the pickle runs the payload.
cat > load_pkl.py <<'PY'
import pickle
with open("model.pkl", "rb") as f:
    model = pickle.load(f)
PY
python3 load_pkl.py
ls PWNED.txt
[ -e PWNED.txt ] || { echo "FAIL: payload did not run"; exit 1; }
rm PWNED.txt

# 3. safetensors holds only tensors and a JSON header; loading runs nothing.
cat > load_st.py <<'PY'
from safetensors.numpy import load_file
w = load_file("model.safetensors")
for name, t in w.items():
    print(name, t.dtype, t.shape)
PY
st=$(python3 load_st.py); echo "$st"
grep -q "^dense.weight float32 (4, 4)$" <<<"$st" || { echo "FAIL: safetensors load"; exit 1; }
[ ! -e PWNED.txt ] || { echo "FAIL: safetensors ran code"; exit 1; }

# 4. Pin the artifact hash so a swapped file fails before it is used.
sha256sum model.safetensors > model.sha256
sha256sum -c model.sha256

echo "ALL 2.6 SUPPLY-CHAIN CHECKS PASSED"
