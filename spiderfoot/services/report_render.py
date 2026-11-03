"""Turning a report into markdown, HTML and JSON.

``render_markdown`` is a small markdown renderer written for this report: headings, paragraphs, lists, tables,
quotes, code and inline emphasis, links and citations. Every piece of text is HTML-escaped before anything is added
around it, only ``http(s)`` links and the application's own ``/scaninfo`` links become anchors, and no raw HTML in the
source is ever passed through, so a ``<script>`` in a finding's data (or in a model answer) shows up as text.
"""

import html
import re
import time
import typing
from urllib.parse import quote

CITE_ID = re.compile(r"^[EC]\d+$")
_SAFE_LINK = re.compile(r"^(https?://[^\s<>\"'`]+|/scaninfo\?[\w=&%.\-+~:@,/]*(#\w+)?)$")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*")
_ITALIC = re.compile(r"(?<![\w*])\*(?=[^\s*])(.+?)(?<=[^\s*])\*(?![\w*])")
_LINK = re.compile(r"\[([^\[\]\n]+)\]\(([^)\s]+)\)")
_CITE = re.compile(r"\[([EC]\d+)\]")
_SEP_ROW = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_LIST_ITEM = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", '-', str(text).lower()).strip('-') or 'section'


def _inline(text: str, known: typing.Set[str], base: str = '') -> str:
    """One run of text to HTML. The order matters: escape first, then add markup."""
    out = []
    pos = 0
    for m in _INLINE_CODE.finditer(text):
        out.append(_inline_plain(text[pos:m.start()], known, base))
        out.append('<code>' + html.escape(m.group(1)) + '</code>')
        pos = m.end()
    out.append(_inline_plain(text[pos:], known, base))
    return ''.join(out)


def _inline_plain(text: str, known: typing.Set[str], base: str) -> str:
    # links and citations are found on the raw text so their targets can be checked, then everything else is escaped
    pieces: typing.List[str] = []
    pos = 0
    tokens = [(m.start(), m.end(), 'link', m) for m in _LINK.finditer(text)]
    tokens += [(m.start(), m.end(), 'cite', m) for m in _CITE.finditer(text)]
    tokens.sort(key=lambda t: t[0])
    for start, end, kind, m in tokens:
        if start < pos:
            continue
        pieces.append(_emphasis(html.escape(text[pos:start])))
        if kind == 'cite':
            cid = m.group(1).upper()
            pieces.append(f'<a class="cite" href="#cite-{cid}" data-cite="{cid}">[{cid}]</a>' if cid in known else html.escape(m.group(0)))
        else:
            label, url = m.group(1), m.group(2)
            if _SAFE_LINK.match(url):
                href = (base + url) if url.startswith('/') and base else url
                pieces.append(f'<a href="{html.escape(href, quote=True)}" rel="noopener noreferrer nofollow">{_emphasis(html.escape(label))}</a>')
            else:
                pieces.append(html.escape(m.group(0)))
        pos = end
    pieces.append(_emphasis(html.escape(text[pos:])))
    return ''.join(pieces)


def _emphasis(escaped: str) -> str:
    escaped = _BOLD.sub(r"<strong>\1</strong>", escaped)
    return _ITALIC.sub(r"<em>\1</em>", escaped)


def render_markdown(md: str, known: typing.Iterable[str] = (), base: str = '') -> str:
    """HTML for ``md``. Safe to embed: all text is escaped, links are restricted, ids are slugs of the headings."""
    known_set = {k.upper() for k in known}
    lines = str(md or '').replace('\r\n', '\n').replace('\r', '\n').split('\n')
    out: typing.List[str] = []
    seen: typing.Dict[str, int] = {}
    i = 0
    para: typing.List[str] = []

    def flush():
        if para:
            out.append('<p>' + _inline(' '.join(p.strip() for p in para), known_set, base) + '</p>')
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
            i += 1
            continue
        if stripped.startswith('```'):
            flush()
            i += 1
            code = []
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code.append(lines[i])
                i += 1
            i += 1
            out.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
            continue
        hm = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", stripped)
        if hm:
            flush()
            level = min(len(hm.group(1)), 4)
            base_slug = slug(hm.group(2))
            n = seen.get(base_slug, 0)
            seen[base_slug] = n + 1
            sid = base_slug if not n else f"{base_slug}-{n + 1}"
            out.append(f'<h{level} id="{sid}">{_inline(hm.group(2), known_set, base)}</h{level}>')
            i += 1
            continue
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            flush()
            out.append('<hr>')
            i += 1
            continue
        if stripped.startswith('|') and i + 1 < len(lines) and _SEP_ROW.match(lines[i + 1]):
            flush()
            header = _cells(stripped)
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                rows.append(_cells(lines[i].strip()))
                i += 1
            out.append(_table(header, rows, known_set, base))
            continue
        if stripped.startswith('>'):
            flush()
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith('>'):
                quote_lines.append(lines[i].strip()[1:].lstrip())
                i += 1
            out.append('<blockquote>' + render_markdown('\n'.join(quote_lines), known_set, base) + '</blockquote>')
            continue
        if _LIST_ITEM.match(line):
            flush()
            block = []
            while i < len(lines):
                if _LIST_ITEM.match(lines[i]) or (lines[i].strip() and lines[i].startswith('  ') and block):
                    block.append(lines[i])
                elif not lines[i].strip() and i + 1 < len(lines) and _LIST_ITEM.match(lines[i + 1]):
                    pass                                        # a blank line between two items does not end the list
                else:
                    break
                i += 1
            out.append(_list(block, known_set, base))
            continue
        para.append(line)
        i += 1
    flush()
    return '\n'.join(out)


def _cells(row: str) -> typing.List[str]:
    row = row.strip()
    if row.startswith('|'):
        row = row[1:]
    if row.endswith('|') and not row.endswith('\\|'):
        row = row[:-1]
    return [c.strip().replace('\\|', '|') for c in re.split(r"(?<!\\)\|", row)]


def _table(header, rows, known, base) -> str:
    hcells = ''.join(f'<th>{_inline(c, known, base)}</th>' for c in header) if any(header) else ''
    parts = ['<div class="tbl-wrap"><table' + (' class="stack"' if len(header) >= 5 else '') + '>']
    if hcells:
        parts.append('<thead><tr>' + hcells + '</tr></thead>')
    parts.append('<tbody>')
    for r in rows:
        rid = ''
        if r and CITE_ID.match(r[0].strip()) and r[0].strip().upper() in known:
            rid = f' id="cite-{r[0].strip().upper()}"'
        tds = []
        for n, c in enumerate(r):
            label = f' data-label="{html.escape(header[n], quote=True)}"' if n < len(header) and header[n] else ''
            tds.append(f'<td{label}>{_inline(c, known, base)}</td>')
        parts.append(f'<tr{rid}>' + ''.join(tds) + '</tr>')
    parts.append('</tbody></table></div>')
    return ''.join(parts)


def _list(block: typing.List[str], known, base) -> str:
    """A (possibly nested) list: an indent of two or more spaces nests."""
    items: typing.List[typing.Tuple[int, str, str]] = []
    for line in block:
        m = _LIST_ITEM.match(line)
        if m:
            items.append((len(m.group(1).replace('\t', '    ')), m.group(2), m.group(3)))
        elif items:
            ind, mark, text = items[-1]
            items[-1] = (ind, mark, text + ' ' + line.strip())
    out: typing.List[str] = []
    stack: typing.List[typing.Tuple[int, str]] = []
    for ind, mark, text in items:
        tag = 'ol' if mark[0].isdigit() else 'ul'
        while stack and ind < stack[-1][0]:
            out.append(f'</li></{stack.pop()[1]}>')
        if stack and ind == stack[-1][0] and tag != stack[-1][1]:       # a numbered list right after a bulleted one
            out.append(f'</li></{stack.pop()[1]}>')
        if stack and ind == stack[-1][0]:
            out.append('</li>')
        elif not stack or ind > stack[-1][0]:
            out.append(f'<{tag}>')
            stack.append((ind, tag))
        out.append('<li>' + _inline(text, known, base))
    while stack:
        out.append(f'</li></{stack.pop()[1]}>')
    return ''.join(out)


def toc(md: str) -> typing.List[dict]:
    """Level 2 and 3 headings as [{level, title, id}] with the same ids render_markdown gives."""
    seen: typing.Dict[str, int] = {}
    out = []
    in_code = False
    for line in str(md or '').split('\n'):
        s = line.strip()
        if s.startswith('```'):
            in_code = not in_code
            continue
        m = None if in_code else re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", s)
        if not m:
            continue
        level = min(len(m.group(1)), 4)
        base = slug(m.group(2))
        n = seen.get(base, 0)
        seen[base] = n + 1
        if level in (2, 3):
            out.append({'level': level, 'title': re.sub(r"[*`]", '', m.group(2)), 'id': base if not n else f"{base}-{n + 1}"})
    return out


def extract_section(md: str, title: str) -> str:
    """The part of a report from the heading that starts with ``title`` to the next heading of the same or a higher level."""
    lines = str(md or '').split('\n')
    start, level = None, 0
    in_code = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('```'):
            in_code = not in_code
        m = None if in_code else re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", s)
        if not m:
            continue
        if start is None:
            if m.group(2).lower().startswith(title.lower()):
                start, level = i, len(m.group(1))
        elif len(m.group(1)) <= level:
            return '\n'.join(lines[start:i]).strip()
    return '\n'.join(lines[start:]).strip() if start is not None else ''


# ----------------------------------------------------------------------------------------------------
# assembling the report markdown

def _ts(ts: int) -> str:
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ts)) if ts else 'not recorded'


def cell(t) -> str:
    return re.sub(r"\s+", ' ', str(t if t is not None else '')).replace('|', '\\|').strip()


def safe_url(url: str) -> str:
    """A URL for a markdown link: only http(s), with the characters that end a link encoded."""
    u = str(url or '').strip()
    if not re.match(r"^https?://", u, re.I):
        return ''
    return u.replace(' ', '%20').replace('(', '%28').replace(')', '%29').replace('<', '%3C').replace('>', '%3E').replace('"', '%22')[:400]


def open_link(scan_id: str, item: dict) -> str:
    q = quote(re.sub(r"\s+", ' ', str(item.get('data') or ''))[:60], safe='')
    return f"/scaninfo?id={quote(scan_id, safe='')}&q={q}&type={quote(str(item.get('type') or ''), safe='')}#data"


def header_markdown(meta: dict) -> str:
    """The header block, written by Python only: title, target, dates, status, model, usage, notice."""
    rows = [('Target', f"{meta['target']} ({str(meta.get('target_type') or '').replace('_', ' ').lower() or 'unknown type'})"),
            ('Scan', f"{meta.get('scan_name') or ''} ({meta['scan_id']})"), ('Scan status', meta.get('scan_status') or ''),
            ('Scan started', _ts(meta.get('started', 0))), ('Scan ended', _ts(meta.get('ended', 0))),
            ('Scan duration', meta.get('duration') or 'not recorded'), ('Report version', f"{meta['version']} (generated {_ts(meta['created'])})")]
    if meta.get('mode') == 'ai':
        rows.append(('Written by', f"{meta.get('model_used') or meta.get('model') or 'the configured model'}, "
                     f"{meta.get('calls', 0)} calls, {meta.get('tokens', 0):,} tokens"))
    else:
        rows.append(('Written by', 'Deterministic report: no AI endpoint was used' + (f" ({meta['message']})" if meta.get('message') else '')))
    out = [f"# Scan report: {meta['target']}", '', '| | |', '|---|---|'] + [f"| {cell(a)} | {cell(b)} |" for a, b in rows] + ['']
    if meta.get('mode') == 'ai':
        out.append("> **AI-generated; verify before relying on it.** The text below was written by a language model from structured "
                   "summaries of the scan. Every claim cites a finding in Appendix A; check those before you act on anything.")
    else:
        out.append("> **Generated without AI.** This report consists of figures and lists computed from the scan data; "
                   "it has no written analysis. Findings are cited as in Appendix A.")
    if meta.get('partial'):
        out += ['', f"> **Partial results.** The scan ended as {meta.get('scan_status')}, so this report covers what was found up to that point."]
    return '\n'.join(out)


def appendix_markdown(scan_id: str, index: dict, used: typing.Iterable[str], max_rows: int, with_links: bool = True) -> str:
    used_set = set(used)
    events = [e for e in index.get('events', []) if e['id'] in used_set][:max_rows]
    out = []
    if events:
        out += ['## Appendix A. Cited findings', '',
                '| Id | Type | Module | Finding | Relevance | Source | Open |', '|---|---|---|---|---|---|---|']
        for e in events:
            rel = e.get('label') or 'not scored'
            if e.get('score') is not None and e.get('label'):
                rel += f" ({int(round(e['score'] * 100))}%)"
            url = safe_url(e.get('url', ''))
            src = f"[link]({url})" if url else cell(e.get('source') or '')
            data = cell(e.get('data'))
            if e.get('count', 1) > 1:
                data += f" (seen {e['count']} times)"
            op = f"[open]({open_link(scan_id, e)})" if with_links else ''
            out.append(f"| {e['id']} | {cell(str(e.get('type', '')).replace('_', ' ').lower())} | {cell(str(e.get('module', '')).replace('sfp_', ''))} "
                       f"| {data} | {cell(rel)} | {src} | {op} |")
    corr = [c for c in index.get('correlations', []) if c['id'] in used_set]
    if corr:
        out += ['', '## Appendix B. Correlations cited', '', '| Id | Risk | Rule | Matching events |', '|---|---|---|---|']
        for c in corr:
            out.append(f"| {c['id']} | {cell(c.get('risk'))} | {cell(c.get('title'))} | {c.get('events', 0)} |")
    return '\n'.join(out)


def assemble(meta: dict, parts: typing.List[dict], index: dict, used: typing.Iterable[str], warnings: typing.List[str], appendix_max: int,
             with_links: bool = True) -> str:
    """The whole report as markdown. ``parts``: [{'title', 'level', 'facts', 'prose', 'note'}] in reading order."""
    out = [header_markdown(meta), '']
    for p in parts:
        out.append('#' * p['level'] + ' ' + p['title'])
        out.append('')
        if p.get('facts'):
            out += [p['facts'], '']
        if p.get('prose'):
            out += [p['prose'], '']
        if p.get('note'):
            out += [f"_{p['note']}_", '']
    app = appendix_markdown(meta['scan_id'], index, used, appendix_max, with_links)
    if app:
        out += [app, '']
    if warnings:
        out += ['## Verification notes', ''] + [f"- {w}" for w in warnings] + ['']
    return '\n'.join(out).rstrip() + '\n'


# ----------------------------------------------------------------------------------------------------
# exports

EXPORT_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #fff; margin: 0; }
.wrap { max-width: 960px; margin: 0 auto; padding: 24px 20px 64px; }
h1 { font-size: 1.7rem; margin: 0 0 12px; }
h2 { font-size: 1.3rem; margin: 2rem 0 .5rem; padding-bottom: .25rem; border-bottom: 1px solid #cbd5e1; }
h3 { font-size: 1.1rem; margin: 1.4rem 0 .4rem; }
p, li { overflow-wrap: anywhere; }
table { border-collapse: collapse; width: 100%; margin: .6rem 0 1rem; font-size: .88rem; }
th, td { border: 1px solid #cbd5e1; padding: 5px 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #f1f5f9; }
blockquote { margin: .8rem 0; padding: .5rem .9rem; border-left: 4px solid #0891b2; background: #f0f9ff; }
blockquote p { margin: .2rem 0; }
code, pre { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .85em; }
pre { background: #f1f5f9; padding: 8px; overflow: auto; }
a { color: #0e7490; }
a.cite { text-decoration: none; font-size: .8em; vertical-align: super; font-weight: 600; }
.toc { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px 16px; margin: 1rem 0; font-size: .9rem; }
.toc ul { margin: .2rem 0; padding-left: 1.2rem; list-style: none; }
.foot { margin-top: 3rem; font-size: .8rem; color: #64748b; }
tr:target td { background: #fef9c3; }
@media print {
  body { font-size: 11pt; }
  .wrap { max-width: none; padding: 0; }
  a { color: inherit; text-decoration: none; }
  h2, h3 { break-after: avoid; }
  table, blockquote, tr { break-inside: avoid; }
  .noprint { display: none; }
}
"""


def export_html(md: str, title: str, known: typing.Iterable[str], base: str = '') -> str:
    """A self-contained, print-friendly HTML document (light theme, no scripts, no external resources)."""
    body = render_markdown(md, known, base)
    items = toc(md)
    toc_html = ''
    if items:
        toc_html = '<nav class="toc"><strong>Contents</strong><ul>' + ''.join(
            f'<li style="margin-left:{(i["level"] - 2) * 1.2}rem"><a href="#{html.escape(i["id"], quote=True)}">{html.escape(i["title"])}</a></li>'
            for i in items) + '</ul></nav>'
    # the table of contents goes after the header block (the first h2)
    marker = body.find('<h2 ')
    if marker > 0:
        body = body[:marker] + toc_html + body[marker:]
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="robots" content="noindex"><title>{html.escape(title)}</title><style>{EXPORT_CSS}</style></head>'
            f'<body><div class="wrap">{body}<p class="foot">Exported from SpiderFoot.</p></div></body></html>\n')
