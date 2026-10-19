#!/usr/bin/env bash
# Verifies every command and output shown in 2.4-encryption.md.
# At rest: AES-256-GCM envelope encryption of a fake embedding store with
# the Python cryptography package, then tamper detection through the tag.
# In transit: a local TLS 1.3-only server (openssl s_server on
# 127.0.0.1:11542) checked with openssl s_client.
# Needs: python3, cryptography, numpy, openssl, file
set -euo pipefail
WORK=$(mktemp -d)
cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
PORT=11542
GW=127.0.0.1:$PORT

t() {
  printf '$ %s\n' "$1"
  RC=0; OUT=$(eval "$1" 2>&1) || RC=$?
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  return 0
}
has() { grep -Fq -- "$1" <<<"$OUT" || { echo "FAIL: expected '$1'"; exit 1; }; }

# A fake embedding store: 200 random 384-dimension vectors
python3 -c '
import numpy as np
rng = np.random.default_rng(7)
np.save("vectors.npy", rng.random((200, 384), dtype=np.float32))'
# Stand-in for a KMS key-encryption key (KEK). In production the KEK
# never leaves the KMS or HSM; here it is a local file.
python3 -c 'import os; open("kek.bin","wb").write(os.urandom(32))'

cat > vault.py <<'PY'
"""Envelope encryption with AES-256-GCM (2.4 notes)."""
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap, aes_key_unwrap)
from cryptography.exceptions import InvalidTag

kek = open("kek.bin", "rb").read()     # from the KMS in real life
cmd, path, label = sys.argv[1], sys.argv[2], sys.argv[3].encode()

if cmd == "seal":
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)   # never reuse per key
    data = open(path, "rb").read()
    ct = AESGCM(dek).encrypt(nonce, data, label)
    blob = aes_key_wrap(kek, dek) + nonce + ct
    open(path + ".enc", "wb").write(blob)
    print(f"plaintext {len(data)} B, sealed {len(blob)} B")
    print("overhead: 40 wrapped DEK + 12 nonce + 16 tag")
elif cmd == "open":
    blob = open(path, "rb").read()
    dek = aes_key_unwrap(kek, blob[:40])
    try:
        data = AESGCM(dek).decrypt(blob[40:52], blob[52:], label)
        print(f"ok: {len(data)} B authentic")
    except InvalidTag:
        sys.exit("InvalidTag: data or label changed; refusing")
PY
python3 -m py_compile vault.py

echo "== At rest: seal the embedding store"
# Reseal until byte 300 is not already 'X', so the tamper step always
# changes the file (1 in 256 chance otherwise).
while :; do
  python3 vault.py seal vectors.npy kb:v3 >/dev/null
  [ "$(dd if=vectors.npy.enc bs=1 skip=300 count=1 status=none)" != X ] && break
done
t 'python3 vault.py seal vectors.npy kb:v3'
has 'plaintext 307328 B, sealed 307396 B'
while [ "$(dd if=vectors.npy.enc bs=1 skip=300 count=1 status=none)" = X ]; do
  python3 vault.py seal vectors.npy kb:v3 >/dev/null
done
t 'file vectors.npy vectors.npy.enc'
has 'vectors.npy:     NumPy array, version 1.0'
has 'vectors.npy.enc: data'
t 'python3 vault.py open vectors.npy.enc kb:v3'
has 'ok: 307328 B authentic'

echo "== Integrity: the tag catches tampering and swaps"
t 'python3 vault.py open vectors.npy.enc kb:v2'
has 'InvalidTag: data or label changed; refusing'
[ "$RC" -eq 1 ] || { echo "FAIL: wrong label should exit 1"; exit 1; }
t "printf X | dd of=vectors.npy.enc bs=1 seek=300 \\
  conv=notrunc status=none"
t 'python3 vault.py open vectors.npy.enc kb:v3'
has 'InvalidTag: data or label changed; refusing'
[ "$RC" -eq 1 ] || { echo "FAIL: tampered file should exit 1"; exit 1; }

echo "== openssl enc has no AEAD modes"
t 'openssl enc -aes-256-gcm -pbkdf2 -in vectors.npy \
  -out e.bin -pass pass:demo'
has 'enc: AEAD ciphers not supported'

echo "== In transit: TLS 1.3 only"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout gw.key -out gw.crt -days 2 -subj "/CN=gateway.test" \
  -addext "subjectAltName=DNS:gateway.test" 2>/dev/null
openssl s_server -accept "127.0.0.1:$PORT" -cert gw.crt -key gw.key \
  -tls1_3 -www -quiet >/dev/null 2>&1 & SRV=$!
for _ in $(seq 1 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1
done
t 'openssl s_client -brief -connect $GW \
  -CAfile gw.crt -verify_hostname gateway.test \
  -servername gateway.test </dev/null'
has 'Protocol version: TLSv1.3'
has 'Ciphersuite: TLS_AES_256_GCM_SHA384'
has 'Verification: OK'
t 'openssl s_client -brief -connect $GW \
  -CAfile gw.crt -verify_hostname evil.test \
  -servername gateway.test -verify_return_error \
  </dev/null'
has 'hostname mismatch'
[ "$RC" -ne 0 ] || { echo "FAIL: hostname mismatch should fail"; exit 1; }
t "openssl s_client -connect \$GW -tls1_2 </dev/null \\
  2>&1 | grep -o 'alert protocol version'"
has 'alert protocol version'
openssl s_client -connect "127.0.0.1:$PORT" -tls1_2 </dev/null >/dev/null 2>&1 \
  && { echo "FAIL: TLS 1.2 should be refused"; exit 1; }

echo "ALL 2.4 ENCRYPTION CHECKS PASSED"
