/**
 * Relevance: "This is mine" / "Not related" on a finding.
 * verdict: mine | not_related | clear; scope: event | lineage (everything found from it too).
 */
window.sfRelMark = async function (btn, scanId, hash, verdict, scope) {
    const msg = btn.closest('[data-relevance-panel], [class*="rounded"]')?.querySelector('[data-rel-msg]');
    const say = (t) => { if (msg) msg.textContent = t; };
    btn.disabled = true;
    say('Saving...');
    try {
        const body = new URLSearchParams({ id: scanId, hashes: hash, verdict: verdict, scope: scope });
        const r = await fetch('/api/relevance/mark', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '',
            },
            body: body.toString(),
        });
        const d = await r.json();
        if (!r.ok) throw new Error((d.error && d.error.message) || ('HTTP ' + r.status));
        say(d.reassessing ? 'Saved. Re-assessing...' : 'Saved.');
        // refresh the list and the Relevance card
        const trig = document.querySelector('[x-ref="catTrigger"]');
        if (trig) setTimeout(() => htmx.trigger(trig, 'do-filter'), 300);
        htmx.trigger(document.body, 'sf-relevance-changed');
        if (d.reassessing) {
            const poll = setInterval(async () => {
                try {
                    const s = await (await fetch('/api/relevance/status?id=' + encodeURIComponent(scanId))).json();
                    if (!s.running) {
                        clearInterval(poll);
                        htmx.trigger(document.body, 'sf-relevance-changed');
                        if (trig) htmx.trigger(trig, 'do-filter');
                    }
                } catch (e) { clearInterval(poll); }
            }, 2000);
        }
    } catch (e) {
        say('Could not save: ' + (e.message || e));
        btn.disabled = false;
    }
};
