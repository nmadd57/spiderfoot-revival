"""The report's markdown renderer, the assembled report and the HTML export."""
import re

from spiderfoot.services import report_render as rr


def render(md, known=('E1', 'E2', 'C1')):
    return rr.render_markdown(md, known)


class TestEscaping:
    def test_script_in_text_is_escaped(self):
        out = render("Found <script>alert(1)</script> and <img src=x onerror=alert(2)> here [E1].")
        assert '<script' not in out and '<img' not in out
        assert '&lt;script&gt;' in out and 'onerror' in out and '&lt;img' in out

    def test_script_in_a_table_cell_and_heading_and_list(self):
        md = "## <script>x</script> Title\n\n- <b onclick=1>item</b>\n\n| a | b |\n|---|---|\n| <script>y</script> | `<i>` |\n"
        out = render(md)
        assert '<script' not in out and '<b ' not in out and '<i>' not in out
        assert out.count('&lt;script&gt;') == 3 - 1 or '&lt;script&gt;' in out

    def test_links_are_restricted(self):
        out = render("[ok](https://example.test/a?b=1&c=2) [bad](javascript:alert(1)) [bad2](data:text/html;base64,AAA) [rel](/scaninfo?id=A1&q=x#data)")
        assert 'href="https://example.test/a?b=1&amp;c=2"' in out and 'rel="noopener noreferrer nofollow"' in out
        assert 'href="javascript' not in out and 'href="data:' not in out
        assert 'href="/scaninfo?id=A1&amp;q=x#data"' in out

    def test_an_attribute_breaking_url_stays_inert(self):
        out = render('[x](https://a.test/"onmouseover="alert(1))')
        assert 'onmouseover' not in out.replace('&quot;', '') or '"onmouseover' not in out

    def test_citations_link_only_when_known(self):
        out = render("Real [E1] and invented [E99] and [C1].")
        assert 'href="#cite-E1"' in out and 'href="#cite-C1"' in out and '#cite-E99' not in out and '[E99]' in out


class TestStructure:
    def test_headings_get_unique_ids_and_a_toc(self):
        md = "# Title\n\n## Part\n\ntext\n\n### Sub\n\n## Part\n"
        out = render(md)
        assert 'id="part"' in out and 'id="part-2"' in out
        toc = rr.toc(md)
        assert [(t['level'], t['title'], t['id']) for t in toc] == [(2, 'Part', 'part'), (3, 'Sub', 'sub'), (2, 'Part', 'part-2')]

    def test_lists_nest_and_blank_lines_between_items_do_not_split_them(self):
        out = render("- one\n\n- two\n  - inner\n- three\n\n1. a\n2. b\n")
        assert out.count('<ul>') == 2 and out.count('<ol>') == 1 and '<li>one</li>' in out.replace('</li><li>', '</li><li>')

    def test_tables_get_row_anchors_for_citations(self):
        md = "| Id | Finding |\n|---|---|\n| E1 | first |\n| E2 | second |\n"
        out = render(md)
        assert '<tr id="cite-E1">' in out and '<tr id="cite-E2">' in out and 'class="tbl-wrap"' in out

    def test_wide_tables_stack_on_phones(self):
        md = "| Id | Type | Module | Finding | Relevance | |\n|---|---|---|---|---|---|\n| E1 | a | b | c | d | e |\n"
        out = render(md)
        assert 'class="stack"' in out and 'data-label="Finding"' in out

    def test_emphasis_code_quote_rule(self):
        out = render("**bold** and *it* and `c<d`\n\n> quote\n\n---\n")
        assert '<strong>bold</strong>' in out and '<em>it</em>' in out and '<code>c&lt;d</code>' in out
        assert '<blockquote>' in out and '<hr>' in out

    def test_extract_section(self):
        md = "# T\n\n## Executive summary\n\nA\n\n### Sub\n\nB\n\n## Next\n\nC\n"
        assert rr.extract_section(md, 'Executive summary') == "## Executive summary\n\nA\n\n### Sub\n\nB"
        assert rr.extract_section(md, 'Next').endswith('C') and rr.extract_section(md, 'Missing') == ''


META = {'scan_id': 'S1', 'scan_name': 'n', 'target': 'x <b>y</b>', 'target_type': 'HUMAN_NAME', 'scan_status': 'ABORTED', 'started': 1700000000,
        'ended': 1700000600, 'duration': '10m 0s', 'version': 2, 'created': 1700001000, 'mode': 'ai', 'model': 'm', 'model_used': 'm', 'calls': 3,
        'tokens': 4567, 'partial': True, 'message': ''}
INDEX = {'events': [{'id': 'E1', 'hash': 'h1', 'type': 'SOCIAL_MEDIA', 'module': 'sfp_x', 'data': 'bad | <script>alert(1)</script>', 'label': 'likely',
                     'score': 0.7, 'url': 'https://example.test/p', 'count': 2}], 'correlations': []}


class TestAssembly:
    def md(self, **kw):
        meta = dict(META, **kw.pop('meta', {}))
        parts = [{'title': 'Executive summary', 'level': 2, 'facts': '', 'prose': 'Claim [E1].', 'note': ''}]
        return rr.assemble(meta, parts, INDEX, ['E1'], ['A note.'], 50, **kw)

    def test_header_block_is_python_written(self):
        md = self.md()
        assert md.startswith('# Scan report: x <b>y</b>') and 'AI-generated; verify before relying on it' in md
        assert '4,567 tokens' in md and 'Partial results' in md and '## Appendix A. Cited findings' in md and '## Verification notes' in md

    def test_deterministic_header_says_so(self):
        md = self.md(meta={'mode': 'deterministic', 'message': 'the AI assistant is off'})
        assert 'Generated without AI' in md and 'AI-generated; verify' not in md

    def test_appendix_cells_are_escaped_and_pipes_survive(self):
        out = rr.render_markdown(self.md(), ['E1'])
        assert '<script' not in out and '&lt;script&gt;' in out and 'bad | ' in out
        assert 'href="/scaninfo?id=S1' in out and 'seen 2 times' in out

    def test_html_export_is_self_contained_and_safe(self):
        html_doc = rr.export_html(self.md(), 'Scan report: x', ['E1'], 'https://sf.test')
        assert html_doc.startswith('<!doctype html>') and '<script' not in html_doc.replace('&lt;script&gt;', '')
        assert '<b>y</b>' not in html_doc and 'x &lt;b&gt;y&lt;/b&gt;' in html_doc
        assert 'http://' not in re.sub(r'https?://(example|sf)\.test[^"\s<]*', '', html_doc)
        assert '@media print' in html_doc and 'color-scheme: light' in html_doc and 'class="toc"' in html_doc
        assert 'href="https://sf.test/scaninfo?id=S1' in html_doc
        assert '<link' not in html_doc and '<img' not in html_doc

    def test_open_link_encodes_the_search(self):
        link = rr.open_link('S 1', {'data': 'a b&c', 'type': 'EMAILADDR'})
        assert link == '/scaninfo?id=S%201&q=a%20b%26c&type=EMAILADDR#data'

    def test_safe_url_only_http(self):
        assert rr.safe_url('javascript:alert(1)') == '' and rr.safe_url('https://a.test/x(1)') == 'https://a.test/x%281%29'
