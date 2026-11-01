# SpiderFoot Revival

Self-hosted OSINT automation platform forked from [SpiderFoot](https://github.com/smicallef/spiderfoot). Major overhaul — new UI, new modules, modernized stack. Current version: **5.2.0**.

## Quick Start

```bash
# Slim image — Python deps only
docker build -t spiderfoot-revival .
docker run -p 5001:5001 spiderfoot-revival
# Visit http://localhost:5001
```

For the local-tool modules (BBOT, nmap, nuclei, dnstwist, etc.) build the full image:

```bash
docker build -f Dockerfile.full -t spiderfoot-full .
docker run -p 5001:5001 -v ~/.spiderfoot:/var/lib/spiderfoot spiderfoot-full
```

## Project Structure

```
spiderfoot/
  sf.py                          # Main entry point (CLI + web server)
  sflib.py                       # Core library facade (delegates to net/*)
  sfscan.py                      # Scan engine and module orchestration
  sfcli.py                       # CLI client
  modules/                       # 258 OSINT modules (sfp_*.py)
  tailwind.config.js             # Tailwind PostCSS build config + safelist
  spiderfoot/
    app.py                       # Flask app factory, auth (bcrypt), CSRF
    db.py                        # SQLite database layer
    plugin.py                    # Base plugin class (SpiderFootPlugin)
    correlation.py               # YAML-based correlation engine
    event.py                     # SpiderFootEvent class
    target.py                    # SpiderFootTarget class
    helpers.py                   # SpiderFootHelpers utility class
    logger.py                    # SQLite log handler, queue listener
    threadpool.py                # SpiderFootThreadPool thread pool
    __version__.py               # Version (5.2.0)
    net/                         # Network utilities (extracted from sflib.py)
      http.py                    # HTTP client (fetchUrl, sessions, proxy)
      dns.py                     # DNS resolution and validation
      ssl.py                     # Certificate parsing, safe sockets
      host.py                    # IP/hostname/domain validation utilities
    services/
      event_service.py           # Event formatting, categories, badge colors
      preset_service.py          # Scan preset catalog + DB seeding
      ai_service.py              # OpenRouter chat completions client
      ai_persistence.py          # AI summary DB persistence (tbl_ai_summaries)
    blueprints/
      api.py                     # REST API endpoints (/api/*)
      ui.py                      # HTML page routes (/, /newscan, /scaninfo, /opts)
      fragments.py               # HTMX fragment routes (/frag/*)
      ai.py                      # AI summarization SSE routes (/frag/scan/*, /frag/correlation/*)
    templates/
      base.html                  # Master layout (Tailwind, HTMX, Alpine.js)
      pages/                     # Full page templates (4 pages)
      components/                # Reusable UI components (11 files)
      fragments/                 # HTMX swap fragments (17 files)
    static/
      css/custom.css             # Custom animations, scrollbars
      css/input.css              # Tailwind @layer components (custom classes)
      css/tailwind.css           # Compiled Tailwind output (built artifact)
      js/app.js                  # Alpine.js scan form component + markdown renderer
      js/theme.js                # Dark/light theme toggle
      vendor/                    # HTMX, Alpine.js
```

## Key Conventions

- **Modules**: Every module is a single `sfp_*.py` file in `modules/`. Follow the pattern in `sfp_greynoise.py` as the reference template. Every module must have `meta`, `opts`, `optdescs`, `setup()`, `watchedEvents()`, `producedEvents()`, `handleEvent()`.
- **HTTP requests**: Always use `self.sf.fetchUrl()` — never import `requests` directly.
- **Deduplication**: Use `self.results = self.tempStorage()` and check `if eventData in self.results`.
- **Error state**: Set `self.errorState = True` on fatal errors to stop the module.
- **Events**: Modules consume events via `watchedEvents()` and produce events via `self.notifyListeners(SpiderFootEvent(...))`.

## Tech Stack

- **Backend**: Python 3, Flask, SQLite
- **Frontend**: Tailwind CSS (PostCSS build), HTMX, Alpine.js, Jinja2
- **Deployment**: Docker (Alpine Linux)

## Do NOT

- Modify `sf.py`, `sflib.py`, `sfscan.py`, or `plugin.py` unless fixing a bug
- Modify `spiderfoot/net/*.py` or `spiderfoot/services/*.py` without updating the facade in `sflib.py`
- Import `requests` in modules — use `self.sf.fetchUrl()`
- Add new pages or routes — extend existing ones
- Use jQuery for new code — use Alpine.js + HTMX
- Modify `tailwind.config.js` safelist without verifying which classes are dynamically injected

## Environment (Windows)

- Dev runs on Windows 11 under Git Bash — use forward slashes in paths
- `taskkill` needs `cmd.exe //c "taskkill /PID X /F"` wrapper (Git Bash mangles `/PID`)
- **Always test via Docker** — local Python can have stale processes and missing deps
- Docker build: `docker build -t spiderfoot-revival .` then `docker run -d --name sf-test -p 5001:5001 spiderfoot-revival`
- Check logs: `docker logs sf-test 2>&1 | grep -i error`

## Gotchas

- **Alpine.js in tables**: `x-data` on a `<tr>` does NOT scope to sibling `<tr>` rows. Use `<tbody x-data="...">` to wrap row pairs (data row + detail row).
- **Alpine.js reserved words**: Don't use `open` as a variable name — conflicts with `window.open`. Use `expanded` instead.
- **Jinja2 dict key `items`**: A dict with key `items` collides with Python's `dict.items()` in Jinja2 templates. Use `entries` instead.
- **Correlation tables**: `tbl_scan_correlation_results` may not exist in older databases. Always wrap `scanCorrelationList()` calls in try/except.
- **No per-module timeout**: Modules can hang indefinitely. Only `_fetchtimeout` (5s per HTTP request) exists. A module-level timeout is a planned improvement.
- **SpiderFoot events have no inherent severity**: Don't add artificial red/amber/green severity to events. Group by category (Attack Surface, Identities, Infrastructure, Reputation, Vulnerabilities) instead.
- **Event categories**: Defined in `services/event_service.py` as `EVENT_CATEGORIES` dict — used by both summary tab and filter chips.
- **Event badge colors**: Defined in `event_badge_color()` in `services/event_service.py` — computed server-side, NOT in Jinja2 templates (Jinja2 `.startswith()` is unreliable in sandboxed Flask).
- **Tailwind safelist**: Classes used only in HTMX-swapped content (not in initial HTML) MUST be added to the `safelist` array in `tailwind.config.js`. The Tailwind CLI can't detect classes injected dynamically from Python (e.g. `event_badge_color()` return values). Rebuild with `npx tailwindcss` after changes.
- **Local tool detection**: Modules with `'tool'` in their `flags` metadata or `sfp_tool_*` prefix are shown in the Local Tools section. Set `isLocalTool` in `ui.py:_build_modules_data()`.
- **BBOT runtime args must include `--no-deps`**: BBOT's first run as a non-root user installs core deps (openssl-dev) and per-module deps via Ansible with `become: true`. The container's `spiderfoot` user has no sudo, so omitting `--no-deps` causes a silent hang on a `getpass` prompt and the SpiderFoot module sees empty stdout. `Dockerfile.full` pre-installs deps as root and copies `/root/.bbot` to `/home/spiderfoot/.bbot` so the runtime cache hit skips the install path.
- **New event types need the `eventDetails` sync**: `db.py:eventDetails` is now imported into `tbl_event_types` on every startup (not just init), so adding a new event type to that list is enough — existing DBs get migrated. The `tbl_scan_results.type` foreign key requires the row to exist before any module can emit the type.
- **Zombie scans on boot**: `start_web_server` calls `SpiderFootDb.scanInstanceReconcileZombies()` once at startup, rewriting any RUNNING/STARTING/ABORT-REQUESTED rows to ABORTED. Don't call it from `SpiderFootDb.__init__` — scan workers spawn their own DB handles and would mark their own just-started scan as a zombie.
- **API keys card builder collapses by module**: `fragments.py:_build_api_card_data` returns one card per module, with a `fields` list of every credential opt (any opt name containing `api_key`/`apikey`). Modules that need username + key (Dehashed, Censys, Twilio, IBM X-Force, etc.) render as a single card with stacked labeled inputs — never one card per opt.
- **Business targets (`COMPANY_NAME`)**: A scan target is a business when it has a `business:`/`company:` prefix or ends in a legal form (Inc, LLC, Ltd, GmbH... see `SpiderFootHelpers.COMPANY_SUFFIXES`/`COMPANY_WORDS`, mirrored in `app.js` `companySuffixes`). The prefix is stripped before the scan starts. Use `SpiderFootHelpers.normalizeCompanyName()` to compare business names: it ignores legal forms and punctuation but keeps words like Holdings/Foundation, so "Tesla, Inc." does not match "Tesla Holdings LLC". Reruns take the original type from `SpiderFootDb.scanTargetType()` because a business name without a suffix would re-detect as a person.
- **State business registries**: `sfp_us_state_registries` only covers states that publish their registry as Socrata open data (NY, CO, CT, OR, TX). The other New England registries have no public API: MA (`corp.sec.state.ma.us`, Incapsula), NH (QuickStart, Akamai) and ME (ICRS, reCAPTCHA) block automated clients, and VT's search runs on an undocumented private API. Don't build scrapers that get around bot protection (no user-agent spoofing, no private APIs). Those states are covered through `sfp_govfiles` instead: a commercial API built from state registry data, keyed (1,000 free credits, then about $0.01 per returned result), defaulting to the six New England states. Its credit balance is checked in `services/api_quota.py`.
- **FCC (`sfp_fcc`)**: Form 499 Filer Database (XML export of the public search, matched on legal name only because resellers reuse carrier brands as DBAs), equipment authorization grantees and the Intermediate Provider Registry (opendata.fcc.gov Socrata), and ECFS filings (`filers.name=`, api.data.gov key or DEMO_KEY). The ULS License View API (`fcc.gov/api/license-view`) is Akamai-blocked from cloud IPs and is not used.
- **Federal records for business targets**: `sfp_sec_edgar` (filer profile, recent filings, and parent companies found through EDGAR full-text search of other filers' Exhibit 21 subsidiary lists), `sfp_fcc`, `sfp_usaspending` (federal award recipients, UEI, parents), `sfp_epa_echo` (regulated facilities and compliance; facility names match by prefix, e.g. "ACME CORP - PLANT 2"), `sfp_cfpb_complaints` (aggregate counts only), `sfp_fdic` (banks; strips "National Association"/"N.A." before comparing), `sfp_openfda` (recalls and device establishments; a 404 means no matches), `sfp_irs_nonprofits` (ProPublica Nonprofit Explorer). All are free and keyless except `sfp_dol_enforcement` (OSHA inspections/violations and Wage and Hour cases; free key from dataportal.dol.gov). SAM.gov (10 requests/day on a non-federal key) is not built. Module tests share `test/unit/modules/_fedtest.py`. Site/facility names (EPA, OSHA, WHD) are matched with `SpiderFootHelpers.facilityNameMatches()`.
- **DOL v4 API quirks**: the key only works as the `X-API-KEY` query parameter (not a header); `filter_object` is URL-encoded JSON supporting `like`, `eq`, `in` and nested `and`/`or`; `like` is case-sensitive and there is no `ilike` (it returns HTTP 500), so query upper- and title-case patterns together; HTTP 204 means no rows; the gateway rate-limits short bursts with 429 and no headers, so retry with a backoff.
- **Self-hosted service modules (`sfp_searxng`, `sfp_vane`)**: configured with an `instance_url` option instead of an API key. `ui.py:_build_modules_data()` auto-disables any module with an `instance_url` opt until it is set (reason "no instance URL"; `auto_disable.compute()` accepts an optional third reason element in `keyinfo`). The new UI has no generic module-options editor, so the options needed to connect are listed in `meta['connectionOpts']` and rendered on the module's card in Settings > API Keys (`fragments.py:_build_api_card_data`: text, masked secret, or Yes/No for bools; only `instance_url` is required). Both send an optional `auth_header` ('Name: value') for instances behind an authenticating proxy, and honour `verify_ssl`. They are tagged `local` with the `FREE_NOAUTH_UNLIMITED` data-source model.
- **SearXNG JSON API**: `/search?q=...&format=json` returns 403 unless `json` is in `search.formats` in the instance's `settings.yml`; an HTML response usually means an auth proxy login page or a bot challenge. Public instances (e.g. searxng.site, baresearch.org) block API clients with the limiter (429), a proxy 403 on `format=json`, or Anubis, so test against your own instance. The homelab instance sits behind oauth2-proxy, so point the module at the in-cluster service or an internal route that bypasses it. `site:` searches skip hosts already covered by an earlier `site:` search (including the subdomains the module itself reports), or it would recurse.
- **SearXNG relevance ranking**: optional OpenAI-compatible embeddings (`embeddings_url` such as `https://embed.galaxyone.space/v1`, `embeddings_model`, `embeddings_apikey`). Phrase-search results are embedded with the search context (phrase plus the scan target) and sorted by cosine similarity, shown as 0-100 in the raw results; `min_similarity` (an int, since `configUnserialize` has no float support) drops weaker ones. An embeddings failure only disables ranking, not the module.
- **`SpiderFootTarget.matches()` is always True for name targets** (HUMAN_NAME, COMPANY_NAME, USERNAME, PHONE_NUMBER, BITCOIN_ADDRESS). Don't use it to decide LINKED_URL_INTERNAL vs EXTERNAL; check the target type first (see `isTargetHost()` in `sfp_searxng`/`sfp_vane`).
- **Vane API** (formerly Perplexica): `GET /api/providers` lists provider UUIDs with `chatModels`/`embeddingModels` keys; `POST /api/search` takes `{chatModel:{providerId,key}, embeddingModel:{providerId,key}, sources:[web|academic|discussions], optimizationMode, query, history, stream:false}` and returns `{message, sources:[{content, metadata:{title,url}}]}`. Answers take minutes, so `sfp_vane` asks only about the scan target by default (`target_only`) and is not in the Footprint use case.
