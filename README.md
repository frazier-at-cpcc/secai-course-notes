# SecAI+ CY0-001 Course Notes

Open course notes for the CompTIA SecAI+ (CY0-001 V1) exam, written by
Dr. Frazier A. Smith of Central Piedmont Community College and published for
anyone studying for the exam. Styled with the [vfrazier.app](https://vfrazier.app)
brand, and built with the same toolchain as the
[AutoOps+ course notes](https://github.com/frazier-at-cpcc/autoops-course-notes).

The notes follow the exam objectives in order. Each topic is a Markdown file,
and the build turns them into a two-column, print-ready PDF with a cover,
contents, domain dividers, figures, and PDF bookmarks.

## Status

Version 1.0.0 covers every objective in all four exam domains: 15 objectives in
31 topics, about 85 pages. The build produces the complete book and one PDF
per domain:

| File | Contents |
|---|---|
| `secai-course-notes.pdf` | All four domains |
| `secai-course-notes-domain-1.pdf` | 1.0 Basic AI Concepts Related to Cybersecurity |
| `secai-course-notes-domain-2.pdf` | 2.0 Securing AI Systems |
| `secai-course-notes-domain-3.pdf` | 3.0 AI-assisted Security |
| `secai-course-notes-domain-4.pdf` | 4.0 AI Governance, Risk, and Compliance |

See [AUTHORING.md](AUTHORING.md) for how topics are written and tested.

## Every command was run

Each command and output shown in the notes comes from a real run, and
`tests/` holds a script per topic that runs them again and checks the output.
Model output comes from small open models (Qwen2.5 0.5B, Llama Guard 3 1B,
all-MiniLM) served by Ollama in Docker through `tests/lib/ollama.sh`, at
temperature 0 with a fixed seed, so no API key or paid service is involved.

The tests are not part of the PDF build. Run them locally, or start the
**Command tests** workflow from the Actions tab (it can run a single topic, for
example `2.6-*.sh`), before a release or after a tool or model update.

```sh
npm install
npm run build                             # writes all PDFs to dist/
bash tests/2.6-prompt-attacks.sh          # one topic's commands
for t in tests/*.sh; do bash "$t"; done   # all of them
```

Each script lists what it needs in a `# Needs:` comment, and
`.github/workflows/command-tests.yml` installs the full set on a fresh runner.
The build uses Playwright's Chromium; locally, run `npx playwright install
chromium` once.

## Writing a topic

Add a file under `content/domain-N/` and list it in `book.json` under the
`master` volume. The per-domain volumes pick up their topics from that list.

```markdown
---
objective: 2.2
title: Gateway Controls
---

### A subheading
- A bullet with a ==must-know term== in the yellow highlighter
  - A sub-bullet

:::figure wide my-diagram.svg | Caption text
:::exam
How this shows up on the exam.
:::
:::try Optional custom label
A short hands-on exercise.
:::
:::wide
| A table | that spans | both columns |
|---|---|---|
:::
```

Code fences take a label: ` ```console label="Terminal" `. In `console`
blocks, lines starting with `$ ` are commands and everything else is output.

Figures are hand-drawn SVGs in `figures/` using the brand palette. The exam
name, code, cover text, and exam facts come from the `exam` block in
`book.json`, so the build scripts carry no exam-specific text.

## Brand

`styles/tokens.css` is copied verbatim from the vfrazier.app site repo, so
colors match the site exactly. Run `scripts/sync-tokens.sh` after changing the
site's palette. Type is Inter with IBM Plex Mono for code, both self-hosted.

## Releases

Every push and pull request builds the PDFs (download them from the run's
`course-notes-pdf` artifact). Push a tag such as `v1.0.0` and the build attaches
the PDFs to a GitHub release.

## License

Text and figures: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
Build scripts and tests: MIT.

CompTIA and SecAI+ are trademarks of CompTIA, Inc. This project is not
affiliated with or endorsed by CompTIA.
