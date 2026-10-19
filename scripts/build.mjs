// Builds the course notes PDF(s). Exam-specific text lives in book.json (exam).
//   node scripts/build.mjs            -> every volume in book.json
//   node scripts/build.mjs master     -> one volume
// Pipeline: Markdown topics -> one HTML book -> headless Chromium PDF.
// Two passes: the first render is read back (PDF outline) to learn which page
// each topic landed on; the second render fills those numbers into the contents.
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Marked } from 'marked';
import hljs from 'highlight.js';
import { chromium } from '@playwright/test';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import { PDFDocument } from 'pdf-lib';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const book = JSON.parse(await readFile(path.join(ROOT, 'book.json'), 'utf8'));
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const X = book.exam;
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

// ---------- Markdown ----------

function makeMarked() {
  const m = new Marked();
  m.use({
    extensions: [
      {
        // ==must-know term== -> yellow highlighter
        name: 'mark', level: 'inline',
        start: (src) => src.indexOf('=='),
        tokenizer(src) {
          const r = /^==(?=\S)((?:[^=\n]|=(?!=))+?)==/.exec(src);
          if (r) return { type: 'mark', raw: r[0], tokens: this.lexer.inlineTokens(r[1]) };
        },
        renderer(t) { return `<mark>${this.parser.parseInline(t.tokens)}</mark>`; },
      },
    ],
    renderer: {
      code({ text, lang }) {
        const [language, ...rest] = (lang || '').split(/\s+/);
        const label = (rest.join(' ').match(/label="([^"]+)"/) || [])[1];
        const labelAttr = label ? ` data-label="${esc(label)}"` : '';
        let body;
        if (language === 'console') {
          // "$ cmd" lines are commands; a command ending in "\" continues on
          // the next line; everything else is output.
          let continued = false;
          body = text.split('\n').map((line) => {
            const isCmd = line.startsWith('$ ') || continued;
            continued = isCmd && /\\$/.test(line);
            if (isCmd) {
              const src = line.startsWith('$ ') ? line.slice(2) : line;
              const cmd = hljs.highlight(src, { language: 'bash' }).value;
              return line.startsWith('$ ') ? `<span class="prompt">$ </span>${cmd}` : cmd;
            }
            return `<span class="out">${esc(line)}</span>`;
          }).join('\n');
        } else if (language && hljs.getLanguage(language)) {
          body = hljs.highlight(text, { language }).value;
        } else {
          body = esc(text);
        }
        return `<div class="box"><pre${labelAttr}><code>${body}</code></pre></div>\n`;
      },
      table(token) {
        const head = token.header.map((c) => `<th>${this.parser.parseInline(c.tokens)}</th>`).join('');
        const rows = token.rows.map((r) => `<tr>${r.map((c) => `<td>${this.parser.parseInline(c.tokens)}</td>`).join('')}</tr>`).join('');
        return `<table class="t"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>\n`;
      },
    },
  });
  return m;
}
// highlight.js ships no HCL (Terraform) grammar; this small one covers what the notes show.
hljs.registerLanguage('hcl', () => ({
  name: 'HCL', aliases: ['terraform', 'tf'],
  keywords: {
    keyword: 'resource data variable output module provider terraform locals moved import check backend required_providers lifecycle dynamic for_each count depends_on for in if',
    literal: 'true false null',
  },
  contains: [
    hljs.HASH_COMMENT_MODE, hljs.C_LINE_COMMENT_MODE, hljs.C_BLOCK_COMMENT_MODE,
    { className: 'string', begin: '"', end: '"', contains: [{ className: 'subst', begin: /\$\{/, end: /\}/ }] },
    { className: 'string', begin: /<<-?([A-Z]+)/, end: /^\s*[A-Z]+$/ },
    { className: 'number', begin: /\b\d+(\.\d+)?\b/ },
    { className: 'attr', begin: /\b[a-z_][a-z0-9_-]*(?=\s*=[^=])/ },
  ],
}));
const md = makeMarked();

// ::: containers are expanded before Markdown parsing.
//   :::exam / :::try          callouts
//   :::wide                   spans both columns
//   :::figure [wide] file.svg | Caption text
async function expandContainers(src) {
  const out = [];
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const open = lines[i].match(/^:::(\w+)\s*(.*)$/);
    if (!open) { out.push(lines[i]); continue; }
    const [, kind, arg] = open;
    if (kind === 'figure') {
      const [spec, caption = ''] = arg.split('|').map((s) => s.trim());
      const parts = spec.split(/\s+/);
      const wide = parts.includes('wide');
      const file = parts.find((p) => p.endsWith('.svg'));
      // Collapse to one line: a blank line inside raw HTML would end the HTML block in Markdown.
      const svg = (await readFile(path.join(ROOT, 'figures', file), 'utf8')).replace(/<!--[\s\S]*?-->/g, '').replace(/>\s+</g, '><').replace(/\s*\n\s*/g, ' ');
      const cap = caption ? `<figcaption><b>Figure</b>${md.parseInline(caption)}</figcaption>` : '';
      out.push(`<figure class="${wide ? 'wide' : ''}"><div class="frame">${svg}</div>${cap}</figure>`, '');
      continue;
    }
    const body = [];
    i++;
    while (i < lines.length && lines[i].trim() !== ':::') body.push(lines[i++]);
    const inner = md.parse(body.join('\n'));
    if (kind === 'exam' || kind === 'try') {
      const label = kind === 'exam' ? 'On the exam' : (arg || 'Try it');
      out.push(`<div class="box"><aside class="callout ${kind}"><span class="label">${esc(label)}</span>${inner}</aside></div>`, '');
    } else if (kind === 'wide') {
      out.push(`<div class="wide-block">${inner}</div>`, '');
    } else {
      throw new Error(`Unknown container :::${kind}`);
    }
  }
  return out.join('\n');
}

async function loadTopic(rel) {
  const raw = await readFile(path.join(ROOT, 'content', rel), 'utf8');
  const fm = raw.match(/^---\n([\s\S]*?)\n---\n/);
  if (!fm) throw new Error(`${rel}: missing front matter`);
  const meta = Object.fromEntries(fm[1].split('\n').map((l) => {
    const k = l.indexOf(':');
    return [l.slice(0, k).trim(), l.slice(k + 1).trim().replace(/^"|"$/g, '')];
  }));
  const html = md.parse(await expandContainers(raw.slice(fm[0].length)));
  const domain = book.domains.find((d) => d.num.split('.')[0] === meta.objective.split('.')[0]);
  return { ...meta, html, domain, id: `t-${slug(meta.objective + '-' + meta.title)}` };
}

// ---------- Page templates ----------

// The running footer names the book; named pages (front, cover, divider) keep
// theirs empty, so their rules are restated after the override.
function footerCss() {
  const none = '@bottom-center { content: none; background: none; }';
  return `@page { @bottom-center { content: "${esc(book.shortTitle)} \\00B7  Page " counter(page); } }`
    + ['front', 'cover', 'divider'].map((n) => `@page ${n} { ${none} }`).join('');
}

const LOGO = `<svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="12" fill="#6d28d9"/><path d="M19 14h26v10H29v8h14v10H29v18H19V14z" fill="#ebe9e6"/><rect x="40" y="44" width="8" height="8" rx="1.5" fill="#ffd60a"/></svg>`;

async function cover(vol) {
  const art = await readFile(path.join(ROOT, 'figures', 'cover-art.svg'), 'utf8');
  return `
<section class="cover">
  <div class="circle yellow"></div><div class="circle purple"></div>
  <div class="brandbar"><span class="wordmark">${LOGO}vfrazier.app</span><span class="pill">Open Course Notes</span></div>
  <div class="eyebrow">${esc(X.series)} &middot; Exam ${esc(X.code)} ${esc(X.version)}</div>
  <h1><span class="line"><span class="hl">${esc(X.name)}</span></span> <span class="line">Course Notes</span></h1>
  <p class="sub">${vol.label ? `<b>${esc(vol.label)}</b><br>` : ''}${esc(X.coverLine)}</p>
  <div class="stamp">Version<b>${esc(book.version)}</b></div>
  <div class="cover-art">${art}</div>
  <div class="cover-foot"><div><div class="who">Dr. Frazier A. Smith</div>${esc(book.affiliation)}</div><div class="site">${esc(book.site)}</div></div>
</section>`;
}

function legal(vol) {
  return `
<section class="front legal">
  <div class="title">${esc(book.title)}${vol.label ? `: ${esc(vol.label)}` : ''}</div>
  <p>Written by ${esc(book.author)}<br>${esc(book.affiliation)}, Charlotte, North Carolina<br>https://${esc(book.site)}</p>
  <p>Version ${esc(book.version)}, ${esc(book.date)}</p>
  <h3>License</h3>
  <p>This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0). You may copy, adapt, and share it for noncommercial purposes with attribution, provided adaptations carry the same license. https://creativecommons.org/licenses/by-nc-sa/4.0/</p>
  <p>Source files, figures, and the scripts that test every command in these notes: ${esc(X.repo)}</p>
  <h3>Trademark Acknowledgments</h3>
  <p>CompTIA and ${esc(X.name)} are trademarks or registered trademarks of CompTIA, Inc. These notes are an independent study resource and are not produced, endorsed, or affiliated with CompTIA. All other product names and trademarks are the property of their respective owners.</p>
  <p>The objective numbers and titles referenced throughout follow the CompTIA ${esc(X.name)} ${esc(X.code)} ${esc(X.version)} exam objectives. Download the official objectives from CompTIA and use them as your checklist; they are the final word on what the exam covers.</p>
  <h3>Warning and Disclaimer</h3>
  <p>These notes are provided to help you prepare for the CompTIA ${esc(X.name)} certification exam. They may contain errors. Use them as a study companion, not as the sole source of information. The author accepts no liability for any loss or damage arising from their use.</p>
</section>`;
}

function contents(topics, pages, vol) {
  const rows = volumeDomains(vol).map((d) => {
    const domainTopics = topics.filter((t) => t.domain === d);
    const dPage = pages[`d-${d.num}`];
    const items = d.objectives.flatMap((o) => {
      const ts = domainTopics.filter((t) => t.objective === o.num);
      if (!ts.length) {
        return [`<div class="row pending"><span class="obj">${o.num}</span><span>${esc(o.title)}</span><span class="dots"></span><span class="pg">Coming soon</span></div>`];
      }
      return ts.map((t) => `<a class="row" href="#${t.id}"><span class="obj">${t.objective}</span><span>${esc(t.title)}</span><span class="dots"></span><span class="pg">${pages[t.id] ?? '00'}</span></a>`);
    }).join('');
    const pg = domainTopics.length ? ` &middot; page ${dPage ?? '00'}` : '';
    return `<div class="domain"><span class="num">${d.num}</span><span>${esc(d.title)}</span><span class="weight">${d.weight}% of exam${pg}</span></div>${items}`;
  }).join('');
  return `<section class="front"><h2>Contents</h2><div class="toc">${rows}</div></section>`;
}

function intro() {
  const bars = book.domains.map((d) => `<tr><td><b>${d.num}</b>&nbsp; ${esc(d.title)}</td><td class="bar"><div class="meter"><i style="width:${d.weight * 2.5}%"></i></div></td><td class="pct">${d.weight}%</td></tr>`).join('');
  return `
<section class="front">
  <h2>How to Use These Notes</h2>
  <div class="facts">
    ${X.facts.map((f) => `<div class="fact"><b>${esc(f.value)}</b><span>${esc(f.label)}</span></div>`).join('')}
  </div>
  <p>The exam mixes multiple-choice and performance-based questions. These notes follow the four exam domains in order, and every topic is labeled with the objective number it covers, so you can line them up against the official objectives, your course modules, and your lab work.</p>
  <table class="weights">${bars}</table>
  <h3>Reading the page</h3>
  <p><mark>Highlighted terms</mark> are the vocabulary the exam expects you to recognize on sight. If a highlighted term is unfamiliar a week before your exam, go back to that page.</p>
  <p><b>On the exam</b> boxes describe how a topic tends to show up in a question: the scenario wording, the distractor answers, and the distinction being tested.</p>
  <p><b>Try it</b> boxes are short exercises you can run on your own machine or in a lab VM with the tools the box names. ${esc(X.tryLine)}</p>
  <h3>Every command was run</h3>
  <p>The commands, code samples, and terminal output in these notes come from real runs, not from memory. The source repository keeps a test script for each topic that runs them again, so they can be rechecked whenever a tool releases a new version.</p>
</section>`;
}

function divider(d, topics) {
  const covered = new Set(topics.filter((t) => t.domain === d).map((t) => t.objective));
  const items = d.objectives.map((o) => `<li><b>${o.num}</b><span>${esc(o.title)}${covered.has(o.num) ? '' : ' <em style="opacity:.6;font-weight:500">(coming soon)</em>'}</span></li>`).join('');
  return `
<section class="divider" id="d-${d.num}">
  <div class="circle purple"></div><div class="circle yellow"></div>
  <span class="pill">Domain ${d.num}</span>
  <div class="big">0${d.num[0]}</div>
  <h1>${esc(d.title)}</h1>
  <div class="weight"><b>${d.weight}%</b> of the exam</div>
  <ul>${items}</ul>
</section>`;
}

// The closing exam and try boxes span both columns side by side, so a topic
// never ends with one box stranded in a column next to an empty one.
const END_BOXES = /((?:<div class="box"><aside class="callout (?:exam|try)">(?:(?!<\/aside>)[\s\S])*<\/aside><\/div>\s*)+)$/;
function endBoxes(html) {
  const m = html.match(END_BOXES);
  if (!m) return html;
  const n = (m[1].match(/class="callout /g) || []).length;
  return html.slice(0, m.index) + `<div class="end-boxes${n === 1 ? ' single' : ''}">${m[1]}</div>`;
}

function topicSection(t) {
  t = { ...t, html: endBoxes(t.html.trim()) };
  return `
<section class="topic" id="${t.id}">
  <div class="topic-bar"><h2><span class="obj">${t.objective}</span> ${esc(t.title)}</h2><span class="dom">${t.domain.num} ${esc(t.domain.title)}</span></div>
  <div class="cols">${t.html}<div class="col-end" aria-hidden="true"></div></div>
</section>`;
}

// A volume restricted to some domains lists only those in its contents.
function volumeDomains(vol) {
  return vol.domains ? book.domains.filter((d) => vol.domains.includes(d.num)) : book.domains;
}

async function html(topics, vol, pages = {}) {
  const body = [];
  for (const d of book.domains) {
    const ts = topics.filter((t) => t.domain === d);
    if (!ts.length) continue;
    body.push(divider(d, topics), ...ts.map(topicSection));
  }
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(book.title)}${vol.label ? `: ${esc(vol.label)}` : ''}</title>
<meta name="author" content="${esc(book.author)}">
<link rel="stylesheet" href="../styles/notes.css">
<style>${footerCss()}</style>
</head><body>
${await cover(vol)}${legal(vol)}${contents(topics, pages, vol)}${intro()}
${body.join('\n')}
</body></html>`;
}

// ---------- Continuation bars ----------
// Chromium cannot repeat an element at the top of each page a section spans, so
// after layout we work out which pages continue a topic from the page before,
// render a bar for each, and stamp it into the reserved top margin.
function continuationPages(topics, starts, atTop, lastBodyPage, dividers) {
  const out = [];
  topics.forEach((t, i) => {
    const last = i + 1 < topics.length ? starts[i + 1] : lastBodyPage;
    for (let p = starts[i] + 1; p <= last; p++) {
      if (dividers.has(p)) continue;   // a domain divider page is never a continuation
      // Skip the next topic's first page only when that topic opens the page.
      if (i + 1 < topics.length && p === starts[i + 1] && atTop[i + 1]) continue;
      out.push({ page: p, topic: t });
    }
  });
  return out;
}

async function stampContinuations(browser, pdfPath, htmlPath, topics, starts, atTop, dividers) {
  const main = await PDFDocument.load(await readFile(pdfPath));
  const conts = continuationPages(topics, starts, atTop, main.getPageCount() - 1, dividers);
  if (!conts.length) return 0;
  const bars = conts.map((c) => `<section class="cont-page"><div class="topic-bar"><h2><span class="obj">${c.topic.objective}</span> ${esc(c.topic.title)}<span class="more">(continued)</span></h2></div></section>`).join('');
  const overlayHtml = htmlPath.replace(/\.html$/, '.continued.html');
  const overlayPdf = pdfPath.replace(/\.pdf$/, '.continued.pdf');
  const noFooter = '@bottom-left{content:none;background:none}@bottom-center{content:none;background:none}@bottom-right{content:none;background:none}';
  await writeFile(overlayHtml, `<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="../styles/notes.css">
<style>${footerCss()}</style><style>@page{margin:0;${noFooter}} body{background:transparent}</style></head><body>${bars}</body></html>`);
  const page = await browser.newPage();
  await page.goto(pathToFileURL(overlayHtml).href, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  await page.pdf({ path: overlayPdf, preferCSSPageSize: true, printBackground: true, omitBackground: true });
  await page.close();
  const overlay = await PDFDocument.load(await readFile(overlayPdf));
  const embedded = await main.embedPages(overlay.getPages());
  conts.forEach((c, i) => {
    const target = main.getPage(c.page);
    const { width, height } = target.getSize();
    target.drawPage(embedded[i], { x: 0, y: 0, width, height });
  });
  await writeFile(pdfPath, await main.save());
  // The overlay is an intermediate file; keep dist/ to the finished PDFs.
  await rm(overlayPdf, { force: true });
  await rm(overlayHtml, { force: true });
  return conts.length;
}

// ---------- Render ----------

async function render(browser, htmlText, htmlPath, pdfPath) {
  await writeFile(htmlPath, htmlText);
  const page = await browser.newPage();
  await page.goto(pathToFileURL(htmlPath).href, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  // Chrome silently shrinks every page to fit if anything is wider than the page.
  // Lay out at Letter width in print mode and fail on any overflow instead.
  await page.setViewportSize({ width: 816, height: 1056 });
  await page.emulateMedia({ media: 'print' });
  const overflow = await page.evaluate(() => {
    const out = [];
    for (const cols of document.querySelectorAll('.cols')) {
      const cs = getComputedStyle(cols);
      const colWidth = (cols.clientWidth - parseFloat(cs.columnGap)) / 2;
      for (const el of cols.querySelectorAll('*')) {
        if (el.closest('.wide-block, figure.wide, .col-end, .end-boxes')) continue;   // these span both columns
        // An element split across columns has one rect per fragment; measure each.
        const w = Math.max(0, ...[...el.getClientRects()].map((r) => r.width));
        if (w > colWidth + 4) out.push(`${cols.closest('.topic')?.id ?? '?'}: <${el.tagName.toLowerCase()}> ${Math.round(w)}px > ${Math.round(colWidth)}px "${el.textContent.trim().slice(0, 50)}"`);
      }
    }
    // Anything in a topic that reaches past the page's right margin.
    const pageRight = document.documentElement.clientWidth + 4;   // @page margins do not apply in this measuring layout
    for (const el of document.querySelectorAll('.topic *')) {
      const r = Math.max(0, ...[...el.getClientRects()].map((x) => x.right));
      if (r > pageRight) out.push(`${el.closest('.topic').id}: <${el.tagName.toLowerCase()}> past the page edge "${el.textContent.trim().slice(0, 50)}"`);
    }
    return out.slice(0, 8);
  });
  if (overflow.length) throw new Error(`Content wider than its column (overlaps the next column, or Chrome shrinks every page):\n  ${overflow.join('\n  ')}`);
  await page.pdf({ path: pdfPath, preferCSSPageSize: true, printBackground: true, outline: true, tagged: true });
  await page.close();
}

// Map outline titles to 1-based body page numbers (front matter is uncounted).
const norm = (t) => t.replace(/\s+/g, '');  // outline titles lose spaces at line wraps

async function readPages(pdfPath, topics) {
  const doc = await pdfjs.getDocument({ data: new Uint8Array(await readFile(pdfPath)), verbosity: 0 }).promise;
  const flat = [];
  const walk = (items) => items.forEach((it) => { flat.push(it); if (it.items) walk(it.items); });
  walk((await doc.getOutline()) || []);
  const tops = {};
  const indexOf = async (it) => {
    const dest = typeof it.dest === 'string' ? await doc.getDestination(it.dest) : it.dest;
    if (!dest) return null;
    tops[norm(it.title)] = dest[3]; // XYZ destination: [page, /XYZ, left, top, zoom]
    return doc.getPageIndex(dest[0]);
  };
  const idx = {};
  for (const it of flat) { const k = norm(it.title); if (idx[k] === undefined) idx[k] = await indexOf(it); }
  const firstDomain = book.domains.find((d) => idx[norm(d.title)] !== undefined);
  if (!firstDomain) throw new Error('No domain divider found in PDF outline');
  const front = idx[norm(firstDomain.title)];
  const pages = {};
  for (const d of book.domains) if (idx[norm(d.title)] !== undefined) pages[`d-${d.num}`] = idx[norm(d.title)] - front + 1;
  for (const t of topics) {
    const key = norm(`${t.objective} ${t.title}`);
    if (idx[key] === undefined) throw new Error(`Topic not found in PDF outline: ${key}`);
    pages[t.id] = idx[key] - front + 1;
  }
  const starts = topics.map((t) => idx[norm(`${t.objective} ${t.title}`)]);
  // A heading within ~1.25in of the page top means the topic opens the page.
  const pageHeight = (await doc.getPage(1)).view[3];
  const atTop = topics.map((t) => pageHeight - tops[norm(`${t.objective} ${t.title}`)] < 90);
  const dividers = new Set(book.domains.filter((d) => idx[norm(d.title)] !== undefined).map((d) => idx[norm(d.title)]));
  return { pages, total: doc.numPages, starts, atTop, dividers };
}

const wanted = process.argv[2] ? [process.argv[2]] : Object.keys(book.volumes);
const chromiumPath = process.env.PLAYWRIGHT_CHROMIUM_PATH || '/opt/pw-browsers/chromium';
const browser = await chromium.launch(existsSync(chromiumPath) ? { executablePath: chromiumPath } : {});
await mkdir(path.join(ROOT, 'dist'), { recursive: true });
try {
  for (const name of wanted) {
    const vol = book.volumes[name];
    if (!vol) throw new Error(`No volume "${name}" in book.json`);
    // A volume lists its own topics, or takes the master list filtered to its domains.
    const rels = vol.topics ?? book.volumes.master.topics.filter((rel) => vol.domains.some((n) => rel.startsWith(`domain-${n[0]}/`)));
    const topics = [];
    for (const rel of rels) topics.push(await loadTopic(rel));
    const htmlPath = path.join(ROOT, 'dist', `${vol.file}.html`);
    const pdfPath = path.join(ROOT, 'dist', `${vol.file}.pdf`);
    await render(browser, await html(topics, vol), htmlPath, pdfPath);
    const { pages } = await readPages(pdfPath, topics);
    await render(browser, await html(topics, vol, pages), htmlPath, pdfPath);
    const check = await readPages(pdfPath, topics);
    for (const k of Object.keys(pages)) if (pages[k] !== check.pages[k]) throw new Error(`Page drift on ${k}; rerun`);
    const stamped = await stampContinuations(browser, pdfPath, htmlPath, topics, check.starts, check.atTop, check.dividers);
    console.log(`${name}: ${path.relative(ROOT, pdfPath)} (${check.total} pages, ${stamped} continuation bars)`);
  }
} finally {
  await browser.close();
}
