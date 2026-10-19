#!/usr/bin/env bash
# Verifies the AI types examples in the 1.1 notes: a statistical-learning
# phishing classifier (naive Bayes over subject lines) and the size and
# quantization of a small language model as Ollama reports them.
# Needs: python3 with scikit-learn, docker, curl, jq
set -euo pipefail
cd "$(dirname "$0")/.."
source tests/lib/ollama.sh
WORK=$(mktemp -d)
trap 'ollama_down sa11-ollama; rm -rf "$WORK"' EXIT

cat > "$WORK/phish.py" <<'PY'
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
mail = [  # (subject line, 1 = phishing)
 ("Urgent: verify your password within 24 hours", 1),
 ("Your mailbox is full, click to restore access", 1),
 ("Payroll update required: confirm bank details", 1),
 ("Unusual sign-in detected, verify account now", 1),
 ("Invoice overdue, open attached payment link", 1),
 ("Your package is on hold, confirm address", 1),
 ("Final notice: account suspended, verify now", 1),
 ("Gift card request from the CEO, urgent", 1),
 ("Agenda for Thursday change advisory board", 0),
 ("Q3 patch window moved to Saturday night", 0),
 ("Lunch and learn: threat hunting with Sigma", 0),
 ("Reminder: submit timesheets by Friday", 0),
 ("Firewall rule review notes attached", 0),
 ("New hire onboarding schedule for Monday", 0),
 ("Minutes from the incident retrospective", 0),
 ("Vendor demo of the new EDR console", 0),
]
X, y = zip(*mail)
model = make_pipeline(TfidfVectorizer(), MultinomialNB())
model.fit(X, y)
nb, words = model[-1], model[0].get_feature_names_out()
lean = nb.feature_log_prob_[1] - nb.feature_log_prob_[0]
top = [words[i] for i in lean.argsort()[::-1][:5]]
print("phishing words:", ", ".join(top))
for s in ["Action required: verify your payroll account",
          "Patch notes for the Saturday window"]:
    print(f"{model.predict_proba([s])[0][1]:.2f}  {s}")
PY

echo "\$ python3 phish.py"
out=$(python3 "$WORK/phish.py"); echo "$out"
grep -qxF "phishing words: verify, your, account, now, confirm" <<<"$out"
grep -qxF "0.75  Action required: verify your payroll account" <<<"$out"
grep -qxF "0.29  Patch notes for the Saturday window" <<<"$out"

# A small language model: parameter count and quantization as Ollama sees them
ollama_up sa11-ollama 11510 qwen2.5:0.5b
echo "\$ ollama list | cut -c1-46"
list=$(docker exec sa11-ollama ollama list | cut -c1-46 | grep -E '^(NAME|qwen2.5:0.5b) ')
echo "$list"
grep -Eq '^qwen2\.5:0\.5b +[0-9a-f]+ +397 MB' <<<"$list"
echo "\$ ollama show qwen2.5:0.5b"
show=$(docker exec sa11-ollama ollama show qwen2.5:0.5b | sed -n '/Model/,/quantization/p')
echo "$show"
grep -Eq 'parameters +494\.03M' <<<"$show"
grep -Eq 'context length +32768' <<<"$show"
grep -Eq 'quantization +Q4_K_M' <<<"$show"

echo "ALL 1.1 AI-TYPES CHECKS PASSED"
