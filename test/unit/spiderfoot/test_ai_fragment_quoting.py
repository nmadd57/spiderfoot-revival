"""The AI summary fragment embeds model output in an HTML attribute; quotes in it must not break out."""
import html
import re

from flask import Flask, render_template


def _render(content):
    app = Flask(__name__, template_folder='../../../spiderfoot/templates')
    app.jinja_env.globals['renderMarkdown'] = lambda x: x
    with app.test_request_context():
        return render_template(
            'fragments/ai_summary.html', scan={'id': 'ABC', 'target': 't'}, ai_enabled=True,
            default_model='m"1', fallback_model='', all_models=[], cached_models=[],
            active_cache={'content': content, 'model_requested': 'm', 'model_used': 'm', 'created_at': 0, 'cost_usd': 0.0, 'prompt_tokens': 1, 'completion_tokens': 1})


def test_quotes_in_summary_stay_inside_the_attribute():
    out = _render('He said "hi" & <script>alert(1)</script> \'x\'')
    m = re.search(r'x-data="([^"]*)"', out)
    assert m, 'x-data attribute was cut short'
    decoded = html.unescape(m.group(1))
    assert 'He said \\"hi\\"' in decoded
    assert '<script>' not in m.group(1)
    assert 'streaming: false' in decoded
