#!/usr/bin/env bash
# Verifies the MITRE ATLAS lookups shown in the 2.1 threat-modeling notes.
# Downloads the ATLAS data release 2026.09 (pinned to a commit) from GitHub
# and answers scenario questions from it: which tactic, which techniques,
# which mitigations.
# Needs: python3, pyyaml (pip install pyyaml), curl, network access to GitHub.
set -euo pipefail
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

SHA=3259f388d19cbcca11bacf12a0ef97f4198f711b
URL="https://raw.githubusercontent.com/mitre-atlas/atlas-data/$SHA/dist/v6/ATLAS-2026.09.yaml"
curl -sSfL -o ATLAS.yaml "$URL"
echo "935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688  ATLAS.yaml" \
  | sha256sum -c --quiet

cat > atlas.py <<'PY'
# atlas.py: answer threat-model questions
# from the ATLAS data file
import sys, textwrap, yaml

d = yaml.safe_load(open("ATLAS.yaml"))
T, M = d["techniques"], d["mitigations"]
REL = [e for v in d["relationships"].values()
       for es in v.values() for e in es]

def links(kind, target):
    return sorted({e["source"] for e in REL
        if e["relationship-type"] == kind
        and e["target"] == target})

cmd, arg = sys.argv[1], " ".join(sys.argv[2:])
if cmd == "summary":
    top = [t for t in T if t.count(".") == 1]
    print("ATLAS release", d["collection"]["version"])
    print("  tactics:    ", len(d["tactics"]))
    print("  techniques: ", len(top))
    print("  mitigations:", len(M))
    print("  case studies:", len(d["case-studies"]))
elif cmd == "search":
    for tid, t in sorted(T.items()):
        if arg.lower() in t["name"].lower():
            print(tid, t["name"])
elif cmd == "show":
    t = T[arg]
    print(arg, t["name"])
    for ta in [e["target"] for e in REL
               if e["source"] == arg
               and e["relationship-type"] == "achieves"]:
        print("  tactic:", ta, d["tactics"][ta]["name"])
    subs = links("specializes", arg)
    for s in subs:
        print("  sub:", s, T[s]["name"])
    print("  mitigations:")
    for m in links("mitigates", arg):
        print(textwrap.fill(f"{m} {M[m]['name']}", 48,
              initial_indent="    ",
              subsequent_indent="      "))
    cs = {c for x in [arg] + subs
          for c in links("employs", x)}
    print("  case studies:", len(cs))
PY

summary=$(python3 atlas.py summary)
echo "$ python3 atlas.py summary"; echo "$summary"
grep -q "^ATLAS release 2026.09$" <<<"$summary"
grep -q "^  tactics:     16$" <<<"$summary"

search=$(python3 atlas.py search "system prompt")
echo "$ python3 atlas.py search \"system prompt\""; echo "$search"
grep -q "^AML.T0056 Extract LLM System Prompt$" <<<"$search"

show=$(python3 atlas.py show AML.T0051)
echo "$ python3 atlas.py show AML.T0051"; echo "$show"
grep -q "^AML.T0051 LLM Prompt Injection$" <<<"$show"
grep -q "tactic: AML.TA0005 Execution" <<<"$show"
grep -q "sub: AML.T0051.001 Indirect" <<<"$show"
grep -q "^    AML.M0020 Generative AI Guardrails$" <<<"$show"
grep -q "^    AML.M0035 AI Red Team$" <<<"$show"
grep -q "^  case studies: 31$" <<<"$show"

poison=$(python3 atlas.py show AML.T0070)
echo "$ python3 atlas.py show AML.T0070"; echo "$poison"
grep -q "^AML.T0070 RAG Poisoning$" <<<"$poison"

echo "ALL 2.1 ATLAS-LOOKUP CHECKS PASSED"
