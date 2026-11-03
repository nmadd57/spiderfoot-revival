/**
 * Report tab: generate, delete, print and citation links.
 * Everything that changes data goes through /api/report/* with the page's CSRF token.
 */
(function () {
    const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';
    const reload = (scanId, version) => {
        const v = version ? '&v=' + encodeURIComponent(version) : '';
        htmx.ajax('GET', '/frag/report?id=' + encodeURIComponent(scanId) + v, { target: '#tab-content', swap: 'innerHTML' });
    };
    const post = async (url, params) => {
        const r = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf() },
            body: new URLSearchParams(params).toString(),
        });
        let d = {};
        try { d = await r.json(); } catch (e) { /* not JSON */ }
        if (!r.ok) throw new Error((d.error && d.error.message) || ('HTTP ' + r.status));
        return d;
    };

    window.sfReportGenerate = async function (scanId, model) {
        const d = await post('/api/report/generate', { id: scanId, model: model || '' });
        setTimeout(() => reload(scanId), 400);
        return d.alreadyRunning ? 'A report is already being written.' : (d.aiReady ? 'Writing the report...' : 'Writing a report of figures and lists (the AI assistant is not configured)...');
    };

    window.sfReportDelete = async function (scanId, version) {
        if (!window.confirm('Delete report version ' + version + '?')) return;
        try { await post('/api/report/delete', { id: scanId, version: version }); } catch (e) { window.alert(e.message); return; }
        reload(scanId);
    };

    window.sfReportPrint = function (scanId, version) {
        const w = window.open('/api/report/export?id=' + encodeURIComponent(scanId) + '&v=' + version + '&format=html&inline=1', '_blank');
        if (w) w.addEventListener('load', () => { try { w.focus(); w.print(); } catch (e) { /* the user can print from the tab */ } });
    };

    window.sfReportJump = function (ev, id) {
        const el = document.getElementById(id);
        if (!el) return;
        ev.preventDefault();
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    window.sfReportInit = function (root) {
        const body = (root || document).querySelector('#report-body');
        if (!body || body.dataset.ready) return;
        body.dataset.ready = '1';
        // a citation shows the finding it points at
        body.querySelectorAll('a.cite').forEach((a) => {
            const row = document.getElementById('cite-' + a.dataset.cite);
            if (row) {
                const cells = Array.from(row.querySelectorAll('td')).map((td) => td.textContent.trim());
                a.title = cells.slice(1, 4).join(' | ');
            }
        });
        body.addEventListener('click', (ev) => {
            const a = ev.target.closest('a.cite');
            if (!a) return;
            const row = document.getElementById('cite-' + a.dataset.cite);
            if (!row) return;
            ev.preventDefault();
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            row.classList.add('sf-cite-hit');
            setTimeout(() => row.classList.remove('sf-cite-hit'), 2600);
        });
    };
})();
