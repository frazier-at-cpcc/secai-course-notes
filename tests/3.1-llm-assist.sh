#!/usr/bin/env bash
# Verifies the summarization and translation examples in the 3.1 notes
# (3.1-ai-security-use-cases.md) with a real local model, qwen2.5:0.5b.
# Needs: docker, curl, jq (tests/lib/ollama.sh pulls the model)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/lib/ollama.sh"
NAME=sa31-ollama PORT=11570 MODEL=qwen2.5:0.5b
WORK=$(mktemp -d)
trap 'ollama_down "$NAME"; rm -rf "$WORK"' EXIT
ollama_up "$NAME" "$PORT" "$MODEL"

TIMELINE='08:02 EDR alert: WS-114 ran an Excel macro from invoice.xlsm
08:03 WS-114 connected to 203.0.113.50 over 443
08:10 user jlee reported a strange invoice email
08:15 SOC isolated WS-114 from the network
08:40 mail admin purged the email from 37 inboxes
09:05 jlee password reset; no other hosts beaconed'

SYS='You are a SOC assistant. Summarize the incident timeline in two sentences for a manager. Use only facts in the timeline.'
sum=$(chat "$MODEL" "$SYS" "$TIMELINE")
# fold -s wraps long lines at spaces so the output fits a book column
printf '%s\n' "$TIMELINE" "--- summary ($MODEL)" "$sum" | fold -s -w 50
grep -q 'WS-114' <<<"$sum" || { echo "FAIL: summary lost the host name"; exit 1; }
grep -Eqi 'isolat' <<<"$sum" || { echo "FAIL: summary lost the containment step"; exit 1; }
# The notes point out that the model expands EDR wrongly (it means
# endpoint detection and response): a reason a human reviews the summary.
grep -q 'Event Data Recorder' <<<"$sum" || { echo "FAIL: expected the wrong EDR expansion the notes discuss"; exit 1; }
# ...and that it drops the 37 purged mailboxes
! grep -q '37' <<<"$sum" || { echo "FAIL: summary now mentions the purge count"; exit 1; }

ES='Su cuenta será suspendida hoy. Verifique su contraseña en el enlace.'
SYS2='Translate the user text to English. Reply with the translation only.'
tr=$(chat "$MODEL" "$SYS2" "$ES")
printf '%s\n' "$ES" "--- translation ($MODEL)" "$tr" | fold -s -w 50
grep -Eqi 'suspend' <<<"$tr" || { echo "FAIL: translation lost 'suspended'"; exit 1; }
grep -Eqi 'password' <<<"$tr" || { echo "FAIL: translation lost 'password'"; exit 1; }

echo "ALL 3.1 LLM-ASSIST CHECKS PASSED"
