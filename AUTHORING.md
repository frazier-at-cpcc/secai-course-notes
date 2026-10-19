# Authoring Guide

How to write a topic for the SecAI+ course notes so it matches the rest of the
series. Read two or three finished topics in `content/` before writing
anything; the layout and voice should be indistinguishable from them.

## Voice

The notes follow the study-guide format of short bullet fragments, not prose.

- Top-level bullets state a fact or concept in a few words. Sub-bullets add the
  detail, an example, or the consequence. Two levels, never three.
- Write fragments, not full sentences, except inside callouts.
- Every sentence is original. Do not paraphrase CompTIA CertMaster, Professor
  Messer, vendor docs, or any other study guide.
- Concrete over generic: name the real flag, the real error text, the real file.
- Examples come from security operations and real AI deployments: SOC alerts,
  help desk chat assistants, RAG pipelines over a policy library, model
  registries, API gateways, CI pipelines, cloud IAM.

## Facts

- Frameworks, lists, and laws change. Check every claim against the primary
  source before writing it: the OWASP Top 10 for LLM Applications (2025) and
  the OWASP Machine Learning Security Top 10, MITRE ATLAS, the MIT AI Risk
  Repository, NIST AI 100-1 (AI RMF 1.0), the EU AI Act text, the OECD AI
  Principles, and the ISO/IEC standard itself (42001, 23894, 22989, 27001).
- Name list items by their current ID and title (`LLM01:2025 Prompt
  Injection`). If a date, article number, or penalty figure cannot be
  confirmed, leave it out.

Never use any of these:

- Em dashes. Use a colon, a semicolon, parentheses, or two sentences.
- "It's important to note", "it's worth mentioning", "plays a vital role",
  "serves as", "stands as", "testament to", "underscores", "in summary",
  "in conclusion", "overall".
- "Not only ... but also", "it's not just X, it's Y".
- Promotional adjectives: "powerful", "robust", "seamless", "cutting-edge".
- Vague attributions: "experts say", "many teams find".
- Emojis.

## Topic file

One Markdown file per topic under `content/domain-N/`, named
`<objective>-<slug>.md`, for example `1.3-iac-principles.md`.

```markdown
---
objective: 1.3
title: Infrastructure as Code Principles
---

### First subheading
- Bullet
  - Sub-bullet
```

- `title` is Title Case and appears in the purple topic bar, the contents page,
  and the PDF bookmarks.
- Use `###` for subheadings. Each topic has 3 to 7 of them.
- Target 1.5 to 2.5 printed pages per topic.
- Cover every leaf term the objective lists. Use the objective's own wording
  for the term somewhere on the page so a student can match it to the
  objectives PDF.

## Markup

| Need | Syntax |
|---|---|
| Must-know term (yellow highlighter) | `==term==` |
| Inline command, file, flag | `` `git fetch` `` |
| Terminal session | a ` ```console label="Terminal" ` fence; lines starting with `$ ` are commands, the rest is output |
| File contents | a ` ```yaml label="playbook.yml" ` fence (any language highlight.js knows) |
| Figure in one column | `:::figure my-figure.svg \| Caption` |
| Figure across both columns | `:::figure wide my-figure.svg \| Caption` |
| Table across both columns | wrap the table in `:::wide` and `:::` |
| Exam tips (end of every topic) | `:::exam` ... `:::` |
| Hands-on exercise | `:::try` ... `:::` or `:::try Custom Label` |

Highlighter rules: 2 to 5 `==terms==` per subheading, only for vocabulary the
exam expects a student to recognize. Never highlight a whole sentence.

Tables: keep them to 2 to 4 columns. A table that needs more than about 45
characters per row goes in `:::wide`.

Every topic ends with one `:::exam` callout of 2 or 3 bullets describing how
the topic shows up in a question: the scenario wording, the distractor, the
distinction being tested.

## Code and output must be real

Every code block and every line of terminal output in the notes comes from a
real run, and a test script can reproduce it. The tests are run by hand or from
the manual Command tests workflow; they do not gate the PDF build.

- Put the script in `tests/<objective>-<slug>.sh`. It must be self-contained:
  `set -euo pipefail`, work in `mktemp -d`, clean up with `trap`, never touch
  the user's real config (`export GIT_CONFIG_GLOBAL=...` and the like), and end
  by printing `ALL <objective> <SLUG> CHECKS PASSED`.
- Assert the specific output the notes show (`grep -q`, exact comparisons), so a
  rerun shows when a tool has changed its behavior.
- Console output in the notes is copied from a real run. You may trim lines
  (drop noise, shorten a path), but never retype or "improve" output.
- When something cannot be executed here (a call to a hosted model API, a
  cloud IAM policy evaluation), do not put it in a code block as if it ran.
  Either validate it statically and say so in the test (a JSON schema check,
  `actionlint`, `python -m py_compile`) or present it as a table or bullets.
- Not every topic needs a command. Governance, roles, and regulations are
  tables and bullets; do not invent a terminal session to decorate them.
- Tests may use Docker containers, Python (scikit-learn, numpy, cryptography
  and similar), Node, jq, openssl, and security scanners such as bandit,
  semgrep, pip-audit, trivy, and modelscan. State any new tool at the top of
  the script in a `# Needs:` comment.
- For a real language model, source `tests/lib/ollama.sh`. It runs Ollama in
  Docker on your port and pulls small open models (`qwen2.5:0.5b` for chat,
  `all-minilm` for embeddings, `llama-guard3:1b` as a safety classifier).
  Requests use temperature 0 and a fixed seed. When the notes show model
  output, name the model in the label or a nearby bullet, because a
  different model gives a different answer. Assert the part of the answer
  the notes depend on (the leaked secret, the `unsafe` verdict), not every
  word.
- No API keys and no paid services. Anything that needs a cloud account goes
  in a table or bullets, not a code block.
- Bind any local service to `127.0.0.1` on a port in your assigned range and
  give containers a unique name prefix, so tests can run in parallel.

## Figures

Figures are hand-drawn SVG in `figures/`, named `<objective>-<slug>.svg`.

- viewBox width 760 for wide figures, 360 for single-column figures.
- Palette only: ink `#1a1209`, muted `#5c4a30`, purple `#6d28d9`, deep purple
  `#3a1d70`, lavender `#efe6ff`, light purple `#c4b3ff`, yellow `#ffd60a`, pale
  yellow `#fffae0`, white `#fff`, rust accent `#9a3412`, rule `#d8d2c8`.
- Brand motifs: 2px ink strokes on boxes, solid offset shadows (draw a second
  ink rect offset by 2.5 units behind the box), rounded corners `rx="7"`.
- Text uses the page fonts automatically (Inter). Add `class="mono"` for
  commands. Font sizes 9 to 14 in viewBox units.
- No symbol glyphs such as check marks or arrows from fonts; draw them as
  paths. Font fallback for those glyphs embeds an ugly Type 3 font.
- Leave space: text must not touch or overflow its box. Render the page and
  look.
- Draw a figure when it shows a mechanism (flow, sequence, relationship). Do
  not draw a figure that only restates a list.

## Build and check

```sh
node scripts/build.mjs <volume>     # volumes are defined in book.json
pdftoppm -r 80 -png dist/<file>.pdf /tmp/page
```

Look at every page you produced. Check for text overflowing figures or tables,
columns left empty, a lone heading at the bottom of a column, and code lines
wrapping badly (keep code lines under about 52 characters so they fit a
column).
