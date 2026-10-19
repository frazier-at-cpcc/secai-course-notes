#!/usr/bin/env bash
# Verifies the prompt engineering examples in the 1.1 notes with a real
# small model (qwen2.5:0.5b): a prompt template, the effect of a system
# prompt on output format, and zero-shot, one-shot, and multi-shot
# classification of log lines scored against labeled lines.
# Needs: docker, curl, jq, python3
set -euo pipefail
cd "$(dirname "$0")/.."
source tests/lib/ollama.sh
WORK=$(mktemp -d)
trap 'ollama_down sa11-ollama; rm -rf "$WORK"' EXIT
ollama_up sa11-ollama 11510 qwen2.5:0.5b
export OLLAMA_URL MODEL=qwen2.5:0.5b
cd "$WORK"

# The model file ships a default system prompt, used when a request has none
echo '$ ollama show --system qwen2.5:0.5b'
def=$(docker exec sa11-ollama ollama show --system qwen2.5:0.5b); echo "$def"
grep -qF "You are Qwen, created by Alibaba Cloud." <<<"$def"

# ask.sh [-s SYSTEM] [-x SHOTS_FILE] < user prompt
# SHOTS_FILE lines are "LABEL|example", sent as user/assistant turns.
cat > ask.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
sys="" shots=/dev/null
while getopts s:x: o; do
  case $o in s) sys=$OPTARG;; x) shots=$OPTARG;; *) exit 2;; esac
done
jq -n --arg m "$MODEL" --arg s "$sys" --rawfile x "$shots" \
      --rawfile u /dev/stdin '{
  model: $m, stream: false,
  options: {temperature: 0, seed: 42, num_predict: 80},
  messages: (
    [if $s == "" then empty else {role: "system", content: $s} end]
    + [$x | split("\n")[] | select(length > 0) | split("|")
       | {role: "user", content: .[1]},
         {role: "assistant", content: .[0]}]
    + [{role: "user", content: ($u | rtrimstr("\n"))}])
}' | curl -sf "$OLLAMA_URL/api/chat" -d @- | jq -r .message.content
SH
chmod +x ask.sh

# ---- Templates and system prompts -------------------------------------
cat > alert.json <<'JSON'
{
  "rule": "SSH brute force",
  "host": "web01",
  "src_ip": "203.0.113.44",
  "failed": 212,
  "user": "deploy"
}
JSON
cat > triage.tpl <<'TPL'
Alert rule: {rule}
Host: {host}
Source: {src_ip}
Evidence: {failed} failures, then login as {user}
TPL
cat > render.py <<'PY'
#!/usr/bin/env python3
import json, sys
tpl = open(sys.argv[1]).read()
alert = json.load(open(sys.argv[2]))
print(tpl.format(**alert), end="")
PY
cat > soc.txt <<'TXT'
You are a SOC triage assistant. Reply only with JSON like {"severity": "high", "next_step": "..."}. Severity is low, medium, or high. A successful login after many failures is high.
TXT

chmod +x render.py
echo '$ ./render.py triage.tpl alert.json > prompt.txt'
./render.py triage.tpl alert.json > prompt.txt
echo '$ cat prompt.txt'; cat prompt.txt
grep -qxF "Evidence: 212 failures, then login as deploy" prompt.txt

echo '$ ./ask.sh < prompt.txt'
plain=$(./ask.sh < prompt.txt); echo "$plain"
if jq -e . >/dev/null 2>&1 <<<"$plain"; then
  echo "FAIL: expected free text without a system prompt"; exit 1
fi

echo '$ ./ask.sh -s "$(cat soc.txt)" < prompt.txt | jq .'
json=$(./ask.sh -s "$(cat soc.txt)" < prompt.txt | jq .); echo "$json"
[ "$(jq -r .severity <<<"$json")" = high ] || { echo "FAIL: severity"; exit 1; }
jq -e 'keys == ["next_step", "severity"]' >/dev/null <<<"$json"

# ---- Zero-shot, one-shot, multi-shot -----------------------------------
LABELS='Classify the log line. Reply with one label only: RECON, BRUTE_FORCE, PRIV_ESC, or NORMAL.'
printf '%s\n' "$LABELS" > labels.txt
: > zero.txt
cat > one.txt <<'TXT'
BRUTE_FORCE|sshd[812]: Failed password for invalid user admin from 198.51.100.7
TXT
cat > multi.txt <<'TXT'
PRIV_ESC|sudo: www-data : USER=root ; COMMAND=/bin/bash -i
RECON|nginx: 203.0.113.80 "GET /.git/config HTTP/1.1" 404
NORMAL|systemd[1]: Started Daily apt download activities.
BRUTE_FORCE|sshd[812]: Failed password for invalid user admin from 198.51.100.7
RECON|kernel: UFW BLOCK SRC=198.51.100.4 DPT=445 SYN
PRIV_ESC|pkexec: www-data: Executing command [USER=root] [COMMAND=/bin/sh]
BRUTE_FORCE|sshd[815]: Invalid user oracle from 198.51.100.7
NORMAL|sshd[930]: Accepted publickey for deploy from 10.0.4.12
TXT
# Held-out lines the model never sees as examples, with the right answer
cat > validate.txt <<'TXT'
RECON|nginx: 198.51.100.23 "GET /phpmyadmin/ HTTP/1.1" 404
RECON|kernel: UFW BLOCK SRC=203.0.113.9 DPT=3389 SYN
BRUTE_FORCE|sshd[777]: Invalid user test from 203.0.113.44
BRUTE_FORCE|sshd[778]: Failed password for root from 203.0.113.44
PRIV_ESC|sudo: apache : USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh ;
PRIV_ESC|su: FAILED SU (to root) www-data on pts/1
NORMAL|sshd[1201]: Accepted publickey for backup from 10.0.4.30
NORMAL|CRON[4410]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)
TXT
cat > label.sh <<'SH'
#!/usr/bin/env bash
# label.sh zero|one|multi "log line"
./ask.sh -s "$(cat labels.txt)" -x "$1.txt" <<<"$2"
SH
cat > score.sh <<'SH'
#!/usr/bin/env bash
# score.sh zero|one|multi: accuracy on validate.txt
ok=0 n=0
while IFS='|' read -r want line; do
  got=$(./label.sh "$1" "$line" |
        grep -oE 'RECON|BRUTE_FORCE|PRIV_ESC|NORMAL' | head -1)
  n=$((n + 1)); [ "$got" = "$want" ] && ok=$((ok + 1))
done < validate.txt
echo "$1-shot: $ok/$n correct"
SH
chmod +x label.sh score.sh

echo "\$ L='sshd[777]: Invalid user test from 203.0.113.44'"
L='sshd[777]: Invalid user test from 203.0.113.44'
declare -A want=([zero]=RECON [one]=RECON [multi]=BRUTE_FORCE)
for m in zero one multi; do
  echo "\$ ./label.sh $m \"\$L\""
  got=$(./label.sh "$m" "$L"); echo "$got"
  [ "$got" = "${want[$m]}" ] || { echo "FAIL: $m gave '$got'"; exit 1; }
done

declare -A score=([zero]=1 [one]=3 [multi]=6)
for m in zero one multi; do
  echo "\$ ./score.sh $m"
  s=$(./score.sh "$m"); echo "$s"
  [ "$s" = "$m-shot: ${score[$m]}/8 correct" ] || { echo "FAIL: $s"; exit 1; }
done

echo "ALL 1.1 PROMPT-ENGINEERING CHECKS PASSED"
