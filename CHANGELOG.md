# Changelog

All notable changes to the SpiderFoot Revival project.

## [Unreleased]

### Users, SSO sign-in and shared scans

- **Distinct users and native OIDC sign-in.** SpiderFoot can sign people in itself (authorization code flow with PKCE; the ID token is verified with Authlib against the issuer's keys) instead of relying only on a proxy in front. Roles come from the groups claim: members of the admin groups are administrators, members of the user groups (or anybody, when none are set) are users, everyone else gets a clear 403 page. Configure it with `SF_OIDC_*` environment variables or in Settings > Access, which also has a connection test, the group mapping, the session lifetime and a read-only list of people who have signed in. With no SSO and no password file nothing changes; password-file (Basic) users stay administrators and scripts keep working.
- **Scans have owners and can be shared.** A new scan belongs to the person who started it (also via the API and the agent). The owner (and administrators) can share a scan with a user or a group at view or edit level from the new Sharing panel on the scan page (or at creation, with "Share with"). View lets people read, edit also lets them stop, rerun and mark false positives, and only the owner can delete or change sharing. A scan nobody may see answers 404. Scans created before sign-in have no owner and are administrator-only (optionally readable by everyone). The dashboard and the scan table show the owner and have Mine / Shared with me filters; search, statistics and every export only cover scans the user can see.
- **Every route is gated.** A single route table decides what each endpoint needs (public, any user, administrator, or a level on the scan in the request) and is checked before the view runs; a route that is not listed is administrators-only, and a test fails when a route is missing or reads a scan id without being gated. Settings, API keys, AI settings, the SQL console, usage, module settings and presets writes are administrator-only.
- **The agent (MCP) server acts as a user.** The single shared token is gone (the stored hash is ignored and removed). Each user creates personal tokens in Settings > Agent (MCP) (shown once, stored hashed, with an expiry, last-used time and revoke), or a client can present its OIDC access token. The agent sees and changes only what that user can; the operator permissions and guardrails stay the ceiling. The listener publishes OAuth protected-resource metadata (RFC 9728), and `X-Forwarded-For` is trusted for the failed-login throttle only with `SF_TRUST_PROXY`.
- The navigation shows who is signed in with a Sign out link (an Account sheet on phones). New dependency: `Authlib` (>=1.3.2,<1.6).
- Behaviour changes: Settings, usage and module-write endpoints now answer 403 to non-administrators once SSO is on; `GET /api/scanlist` rows gained two trailing columns (owner, your level); the MCP settings API lost `/api/mcp/token` and `/api/mcp/token/revoke` (use `/api/mcp/tokens`); enabling the MCP server no longer needs a token.

### Mobile layout

- Below 768 px the hover-only sidebar (which cannot be opened on a touch screen and took 56 px of a phone's width) is replaced by a bottom navigation bar (Dashboard, New Scan, Settings, Theme), and the page padding shrinks. Nothing scrolls sideways on any page at 360, 390 or 768 px.
- **Dashboard:** a scan row is a card: target and status, the counts wrapped underneath, and full-size View, Stop and Delete buttons. Previously the row was cut off at the screen edge.
- **Scan results:** the header and Export/Re-scan buttons fit; the tab strip scrolls with edge fades and arrows and centres the active tab; events are stacked cards with a readable detail panel; filters, segmented controls and pagination are tap-sized; findings, timeline, correlations and the log wrap their text; the graph fits the screen with touch pan and zoom and its controls behind a toggle.
- **New Scan:** a taller target box with its hint visible, presets in an even two-column grid, module category names shown in full with the count, All and None on a second row, larger module toggles, and a launch bar pinned above the bottom navigation. The notice about hidden preset modules now says why they are hidden (no key, tool missing, over quota, or turned off).
- **Settings:** the section list is a scrollable strip above the content instead of a fixed column that left about 150 px for the form; every section uses single-column forms and 44 px controls; the Modules list shows each module on two lines with its filters collapsed behind one button.
- Desktop layouts (768 px and wider) are unchanged. Inputs are 16 px on phones so iOS does not zoom when a field is focused; tap targets are at least 44 px; body text is at least 14 px.

### One SEC EDGAR module

- `sfp_secedgar` is merged into `sfp_sec_edgar`, so there is one SEC module instead of two that reported the same filings. `sfp_sec_edgar` keeps its company lookup (filer profile, parent company from Exhibit 21) and gains: recent filings as `COMPANY_FILING` events (limited to the useful forms by the new `filing_forms` option; empty means every form), and a person search (`person_search`, `person_forms`, `max_companies`) that finds the operating companies a person's name appears in through insider, ownership and proxy filings, with an evidence record that says it is a name match. It now also watches `HUMAN_NAME`, throttles itself to 10 requests a second (`delay`), and ignores companies it reported itself. The `contact_email` option is kept (the removed module's `contact` option is gone). Anything that referenced `sfp_secedgar` should use `sfp_sec_edgar`.

### Security: CodeQL findings and Dependabot

- Error responses no longer carry exception text: failures are logged on the server and the client gets a short fixed message (settings save, scan start, vacuum, presets, usage limits, module test, SearXNG test).
- The `/query` SQL console now also runs under a SQLite authorizer that only allows SELECT, recursive queries and ordinary functions, and denies reading `tbl_config` (which holds API keys), ATTACH, PRAGMA, writes and `load_extension`, on top of the existing checks and the read-only connection.
- Endpoint URLs entered for the AI assistant and the embeddings service are validated before a request is made: http(s) only, no credentials in the URL, and no link-local, cloud metadata, unspecified or multicast addresses (LAN and loopback stay allowed, since a local model server is the normal case).
- Host checks in the cloud bucket, IntelX, WikiLeaks, TruffleHog, abstractapi and webserver modules compare parsed host names instead of searching for a substring, so a look-alike URL no longer passes.
- The "business:/company:" target prefix is parsed without a backtracking regex; a stray `[0-f]` character range is fixed; the certificate fetcher uses an explicit TLS context (TLS 1.2 or newer, still without verification because it must read any server's certificate).
- Added `.github/dependabot.yml`: weekly updates for pip, npm, Docker base images and GitHub Actions, with minor and patch updates grouped.

### Web Search settings tab; expired sign-in banner

- New Settings -> Web Search tab, laid out like AI Assistant: a SearXNG card (instance URL, auth header, engines, language, pages, search toggles) and an Embeddings card (endpoint URL, model, key, minimum similarity), each with its own Save and Test button. **Test SearXNG** runs a search with the values on the form (saved or not) and reports the result count, sample URLs and any engines that did not answer, or the reason it failed (sign-in page in front of it, JSON disabled, rate limited, unreachable). **Test embeddings** embeds a short text, reports the vector size and latency, lists the endpoint's models and fills the model suggestions (and an empty model field) from them. Auth header and embeddings key stay masked. The SearXNG row on Settings -> Modules now points to this tab.
- When the SSO session expires, saves and tests used to fail silently (the proxy redirects API calls to the login page). A banner now says the sign-in expired and nothing was saved, with a button to sign in again.

### SearXNG behind a login

- When the SearXNG URL sits behind an SSO proxy (oauth2-proxy, Authelia, Authentik...) the proxy answers API calls with a 403 or a sign-in page. The error now says so and suggests an address that skips the login, instead of claiming JSON output is disabled. Applies to the shared web search helper and the SearXNG module.

### Fix: very slow requests with a custom DNS server

- With a custom DNS server set (Settings -> General -> DNS), the resolver override returned AAAA (IPv6) records first. On a host without working IPv6, such as a container behind a WireGuard tunnel, every unreachable IPv6 address cost a full connect timeout, so a single HTTP request to a host with eight IPv6 addresses took four minutes. IPv4 addresses are now tried first. Every module that makes HTTP requests benefits.

### Google and Bing modules removed

- Removed `sfp_googlesearch`, `sfp_googlemaps`, `sfp_bingsearch` and `sfp_bingsharedip`, and the `googleIterate`/`bingIterate` helpers with their Google Custom Search and Bing Search API code (Google closes the Custom Search JSON API on 2027-01-01; Bing's was retired in August 2025). Web search is now only `SpiderFoot.webSearch`, backed by the SearXNG instance set up on the SearXNG module; `sfp_pastebin`, `sfp_onioncity` and `sfp_socialprofiles` lost their Google/Bing key options. `sfp_openstreetmap` is the geocoder; `sfp_searxng` does `site:` listings.

### People to businesses, filings and professional licences

- Name searches now reach the business modules. `sfp_sec_edgar` (formerly a separate `sfp_secedgar`; free, no key) searches SEC EDGAR for a person's name in insider, ownership, proxy and annual filings, and reports the operating companies they appear in as `COMPANY_NAME`, which every company module (GLEIF, FCC, IRS, FDIC, EPA and so on) then picks up. It also emits `COMPANY_FILING` entries (form, date, link) both for the filings the person appears in and the company's recent filings, plus the company's registration details, business address and phone. Given a company name it does the same lookup directly. Matches are by name only and the evidence record says so.
- Professional licensing: `sfp_npiregistry` (US NPI registry; healthcare professionals and organisations: specialty, state licence number, practice address, phone, and an organisation's authorised official as a new `HUMAN_NAME`) and `sfp_brokercheck` (FINRA BrokerCheck and the SEC's IAPD; brokers, investment adviser representatives and firms: CRD and SEC numbers, status, current employer firms as `COMPANY_NAME`, and whether there are disclosures). Both take a person or a business name.
- New event types `COMPANY_FILING` and `PROFESSIONAL_LICENSE`.
- The module Test box accepts a plain person or company name.

### Web search through SearXNG; free geocoding

- Google's Custom Search JSON API is closed to new customers and ends on 2027-01-01, and Microsoft retired the Bing Search API in August 2025. `sfp_googlesearch`, `sfp_bingsearch`, `sfp_pastebin`, `sfp_onioncity` and `sfp_socialprofiles` now search through the SearXNG instance set up on the SearXNG module (Settings -> Modules -> SearXNG), reusing its URL, auth header and query defaults, so there is one place to configure it. The Google API is only a fallback while it still works and a key is entered; the Bing API path is removed. These modules no longer carry the `apikey` flag: they are free and key-optional. With no SearXNG instance and no legacy key they are auto-disabled as "no web search backend (set up SearXNG)".
- `sfp_openstreetmap` is now the free replacement for the Google Maps geocoder: besides turning addresses into coordinates it also turns coordinates found by other modules into a street address (Nominatim reverse geocoding), uses an identifying User-Agent, enforces the public server's one-request-per-second limit across threads, and takes an optional `nominatim_url` for your own server. Fixed the Google Maps module reading the location from the wrong place in the reply.
- The module Test box accepts an address or `lat,lon` for the geocoder, and skips web-search modules with a clear message when no backend is set up.

### Only API key problems are passed through

- Settings -> Modules now reports only errors that concern the module's API key or account (key rejected, out of credits or quota, rate limited). Ordinary scan messages such as "no information for that IP" or a parse problem are no longer shown as module errors, counted, or used to colour a module's status. The "Errors" status filter is gone; counts are labelled "Key errors".
- A module Test that logs only non-key messages now reports "ran with notes" instead of failing. Exceptions and key/account problems still fail it.
- Fixed: running a module Test merged the global configuration into the module's shared option dictionary, which could leak internal options into the module registry in the web process. The test now works on a private copy.

### Test buttons

- Every module on Settings -> Modules has a **Test** button (and a Run test box in its panel with an optional target). It sets the module up exactly as a scan would, feeds it one sample it watches (a harmless public sample, or your own target), and shows the result: events it produced, errors and warnings, and the HTTP status of each request (host and path only, never the query string). Real calls are made with your key and count toward your limits. A recognised key or quota problem is flagged as such. Invasive modules (port scanners, crawlers) only run when you supply a target; `sfp_tool_*` modules are never run against anything, the test starts the binary with a version/help flag instead. Nothing is stored and no scan is created.
- Settings -> AI Assistant has a **Test connection** button. It uses the values on the form (saved or not), reads the endpoint's `/models` list, fills the default/fallback model suggestions with it (and fills an empty default model), and sends a tiny chat request with the default model to confirm it answers. Works with OpenRouter and any OpenAI-compatible server.
- Tool path settings that were saved as an empty string by older versions no longer override the install location the image ships; without this the tools were installed but their modules still reported "did not set a path to the tool".
- A tool module whose path setting points at a directory now counts as installed only if the binary is in that directory.

### One Modules page

- Settings -> API Keys, Modules and API Usage are merged into a single Settings -> Modules page. Every module has an on/off switch and a status pill (working, errors this week, problem, not used yet, auto-disabled). Opening a module shows:
  - its settings, if it has any: credentials (API keys and tokens are masked and never sent to the browser), binary/path settings for tool modules, and every other option, each saved per module; the key test and quota check use whatever you typed in the key field;
  - status and errors passed through from past scans (last error with time, results produced, scan errors this week and all time) and any recorded key/account problem;
  - usage counts and limits (calls/second, calls/day, total per period with a reset date) for modules that call a remote service.
  Modules with no options just have the switch and a short description. Filters cover state, status, key, cost and whether a module has settings. Export/import of API keys moved to this page.
- Float-valued module options (such as request delays) can now be saved; previously the settings loader ignored them.

### Key and account problems on the settings pages

- Failures caused by a module's own API key (HTTP 401/403 key rejected, 402 payment/credits, 429 rate limited, and error messages such as "invalid key", "out of credits", "quota exceeded", "plan limit reached", "zero balance") are now recorded per module and shown as a red "key problem" chip on Settings -> Modules (with a "Key problem" filter) and as a red line plus detail panel on Settings -> API Usage. Only modules with a configured key are flagged; missing keys are still handled by auto-disable.
- A recorded problem clears when the key is changed, when a key test succeeds, or via the Dismiss button, and expires after 3 days.
- `docs/INTEGRATIONS.md`: table of every integration (purpose, type, auth, cost/rate, project link, status).

### External tools in the image

- The container now ships the tools the `sfp_tool_*` modules drive: BBOT 3.0.2 (built from source in a Python 3.13 venv, with the pip dependencies its modules declare and its first-run dependency step pre-seeded), nmap, nbtscan, onesixtyone, nuclei (+ templates), trufflehog, testssl.sh, WhatWeb (+ gems), CMSeeK, retire.js, wafw00f, snallygaster and dnstwist. Each module's path option now defaults to the install location, so they work without configuration. Wappalyzer is not included (its CLI is no longer distributed) and stays auto-disabled as "tool not installed".

### Fixes from the first overnight scans

- `sfp_stevenblack_hosts`: a hosts line with a single token (or a trailing comment) raised `IndexError` and killed the worker on every event.
- `sfp_netlas`, `sfp_opensanctions`, `sfp_alienvault`: tolerate non-dict/list values in API replies (`TypeError`/`AttributeError` crashes).
- `sfp_shodan`: "No information available for that IP" is a normal reply, no longer logged as an error.
- `sfp_psbdmp`, `sfp_duckduckgo`: an empty or non-JSON reply is reported as info instead of a JSON parse error (psbdmp.cc's API now redirects to its home page).
- `sfp_tool_*` modules (bbot, nmap, nuclei, whatweb...) whose binary is not installed are now auto-disabled with the reason "tool not installed" instead of failing with `Unable to run BBOT: No such file or directory` on every scan. They return when the tool is installed or its path option is set.
- Removed `sfp_c2tracker`: the upstream project is archived and its data file is gone (404).

### Automatic disabling

- Modules that need an API key (`apikey` flag) but have none configured are disabled automatically, as are modules whose user-set limit (calls/day or total calls per period, Settings -> API Usage) is reached, or for which the vendor reported 0 remaining within the last day. They are hidden from New Scan (with a notice and link), stripped from API-started scans and labelled "auto-disabled: <reason>" in Settings -> Modules, where an "Auto-disabled" filter and a master switch (`_auto_disable`) live. Nothing is stored per module, so a module returns by itself when a key is added or the quota/period resets.
- "Needs a key" now requires the `apikey` flag as well as an API-key option, so key-optional modules (Hudson Rock, LeakCheck) are no longer treated as missing a key.

### Quotas in the usage list; Tailwind rebuild

- API Usage rows now show the vendor-reported quota (remaining/limit with a bar, or "key rejected"), cached in `_module_quota_cache`. Quotas older than an hour are refreshed automatically when the page opens (never AbuseIPDB's, whose check costs a request), and there is a "Check all quotas" button and a "Quota known" filter.
- Rebuilt `static/css/tailwind.css` with the repo's `tailwind.config.js`: the price badges (blue/green/red) and the new settings pages use classes that the committed stylesheet did not contain, so they rendered unstyled. The rebuild drops no existing classes.

### Censys and ZoomEye fixes

- `sfp_censys` now uses the Censys Platform API (`api.platform.censys.io/v3`, Personal Access Token as a Bearer token, optional organization ID); the legacy Search v2 API it used was decommissioned on 2026-09-30. Options changed: `censys_api_key_uid`/`censys_api_key_secret` are replaced by `censys_api_key` (the token) and `censys_organization_id`, so the old credentials must be replaced with a token. Parsing follows the published v3 host schema and is covered by unit tests with a synthetic response, not yet by a live call.
- `sfp_zoomeye` now uses the v2 API (`POST https://api.zoomeye.ai/v2/search`, base64 `qbase64` query) instead of the geo-blocked `api.zoomeye.org` v1 host search; queries use `ip=`, `domain=` and `hostname=`; HTTP 402 (no search credits, which the Free plan lacks) is reported clearly. API Usage can now check a ZoomEye key via `/v2/userinfo`.

### API usage tracking, limits and key testing

- New Settings -> API Usage page. Every HTTP request a module makes is counted per UTC day (`tbl_module_usage`), together with errors, 429s and calls blocked by limits; any `X-RateLimit-*`/`RateLimit-*` response headers are recorded as the vendor's own remaining-quota figure.
- Per-module limits (`_module_limits`): calls/second (calls are delayed), calls/day and total calls per period (further calls are blocked, and the module sees a failed fetch), a reset date with optional daily/weekly/monthly/yearly repeat, and an enforce switch for display-only limits. Limits apply across concurrent scans.
- "Check quota" asks the vendor for the real used/limit/remaining where it has an account or usage endpoint, and "Test key" / "Test & save key" validates a new API key before it is stored (`POST /api/usage/check`).
- Quota checks / key tests exist for Shodan, VirusTotal, Hunter, FullHunt, WhoisXML API, Hybrid Analysis, Netlas, AbuseIPDB, GreyNoise, ipinfo and AlienVault OTX (some only confirm the key is valid). Calls made on threads a module spawns itself are not attributed to it.

### New modules

- `sfp_rapiddns` (free): subdomains from RapidDNS, replacing DNSDB/DNSGrep (Anubis was evaluated but sits behind a Cloudflare challenge).
- `sfp_firehol` (free): FireHOL Level 1 IP/netblock blocklist.
- `sfp_spamhaus_drop` (free): Spamhaus DROP hijacked-netblock list (distinct from the existing DNSBL module).
- `sfp_whoisds` (free): lookalike detection against the WhoisDS newly-registered-domain daily feed.
- `sfp_chainabuse` (free tier, API key): Chainabuse scam reports for Bitcoin/Ethereum addresses, replacing bitcoinwhoswho. Not tested against the live API (needs a key).
- `sfp_crt_org` (free): crt.sh search by certificate Organization, finding domains a company owns from `COMPANY_NAME`.

- `sfp_recordedfuture` (paid, API token): Recorded Future Connect API risk scores for IPs and domains; reports as malicious at or above a configurable score (default 65).
- `sfp_triage` (free tier, API key): Tria.ge sandbox reports that contacted the target's IPs or domains; reports as malicious when a report scores at or above a threshold (default 7/10). Neither module has been tested against its live API (both need keys).

### Module cleanup and enable/disable

- Removed dead modules: DNSDB, SpyOnWeb, Zonefiles.io, Abusix, ThreatJammer, BinaryEdge, EmailCrawlr (and their tests, presets and references).
- Retagged as `paid`: Zetalytics, Criminal IP, FraudGuard, MalwarePatrol, X-Force Exchange, C99, Focsec, FullContact, OpenCorporates, SecurityTrails, Whoisology. DNSGrep and bitcoinwhoswho are labelled BROKEN (`meta["broken"]`) but still present.
- Badge colours: FREE green, FREE TIER blue, PAID red.
- New Settings -> Modules page: per-module on/off switches, bulk enable/disable of the filtered set, and filters for enabled/disabled, active (no key needed or key set) / no key, and cost. Each module also has a "Default" checkbox (and bulk buttons, plus an On/Off-by-default filter): modules switched off by default stay available but are not pre-selected on New Scan (stored as `_default_off_modules`; `POST /api/modulestate` with `"kind": "default_off"`). Disabled modules are hidden from New Scan and stripped from scans started through the API (`POST /api/modulestate`; stored as `_disabled_modules`).

### Module pricing tags

- Every module now declares `meta['pricing']`: `free` (no account/key), `free_key` (free tier with an account/API key, possibly rate limited), `paid` (commercial only) or `local` (no third-party service: analysis modules, direct DNS/HTTP checks, local tools). Derived from each module's `dataSource.model`; modules without a data source were reviewed by hand. A unit test enforces a valid tag on every module and consistency with `dataSource.model`.
- Corrected `dataSource.model` for etherscan, abstractapi, apple_itunes and ipapico to match how they actually behave.
- The tag is exposed as `pricing` in `SpiderFootPlugin.asdict()` (and so `/api/modules`), shown as FREE / FREE TIER / PAID / LOCAL badges on the new-scan page and API-key cards, and drives new "Show:" filter pills on the new-scan page (with an "Enable these" shortcut for free modules).

### Local OpenAI-compatible endpoints for AI Summarization

- New `_ai_base_url` option ("Custom base URL" in Settings → AI Assistant). When set, requests go to `<base URL>/chat/completions` instead of OpenRouter, so Ollama, llama.cpp, vLLM, LM Studio, llama-swap, etc. work.
- Custom endpoints get a plain OpenAI-style request (no OpenRouter-only `models`/`provider`/`usage`/`metadata` fields), no attribution headers, and the API key is optional.
- Model names are free-form text (with suggestions) and pickers show the configured default/fallback models; the fallback is not used with custom endpoints.
- Errors are reported generically for custom endpoints instead of mentioning OpenRouter.

## [5.2.0] - 2026-05-04

### AI Summarization Feature

- AI Summarization via OpenRouter: per-scan executive summaries and per-correlation explanations on the scan results page.
- Models: Kimi K2.6 (default) and GLM 5.1, with automatic OpenRouter-side failover via the `models` array.
- New `tbl_ai_summaries` table persists generated summaries per (scan_id, kind, target_id, model). Cascade-deleted with the scan.
- New "AI Assistant" settings section: API key, default/fallback model selection, monthly cost display, and PII redaction toggle.
- Server-Sent Events streaming with client-disconnect-tolerant upstream handling — summaries persist even when the user closes the browser tab mid-stream, so paid-for tokens are never wasted.
- Per-key in-flight lock prevents duplicate concurrent generations for the same scan and model.
- Optional PII redaction: emails, public IPv4/IPv6, URL credentials, and the scan target root can be masked before payloads leave your machine.

## [5.1.0] - 2026-05-02

### New Modules

- **sfp_ransomwarelive** — queries the free ransomware.live v2 API to flag domains and company names appearing on tracked ransomware extortion leak sites. Configurable allowlist of input event types, 24h response cache, and a 65s inter-call throttle to respect the free API's 1 req/min limit. Adds the `RANSOMWARE_VICTIM` event type.

### Removed Modules

- **sfp_trashpanda** — the upstream API service (`api.got-hacked.wtf:5580`) is dead. The DNS record for the API subdomain returns NXDOMAIN and the port is unreachable. Module file and its unit/integration tests have been deleted; the apex domain `got-hacked.wtf` still loads a marketing page but no longer serves the lookup API the module relied on.

### Fixes

- **BBOT modules silently produced no output**. The four `sfp_tool_bbot_*` modules were hanging on a hidden `sudo` prompt: BBOT's first run as a non-root user installs core deps (openssl-dev) and per-module deps via Ansible with `become: true`, and the `spiderfoot` user has no sudo. SpiderFoot then saw empty stdout and emitted nothing. Modules now pass `--no-deps` on every invocation, and `Dockerfile.full` pre-installs all module deps as root and copies the resulting cache into the spiderfoot user's home so the runtime cache hit skips the install path entirely.
- **Zombie scans on web-server boot**. After abnormal exit (container restart, OOM, crash) any in-flight scans were left in `tbl_scan_instance` with `status='RUNNING'` / `'STARTING'` / `'ABORT-REQUESTED'`, lingering forever in the dashboard. `start_web_server` now calls a one-shot `SpiderFootDb.scanInstanceReconcileZombies()` that rewrites those rows to `ABORTED` with a current-time `ended` timestamp before the app starts serving.
- **Duplicate cards in the API keys page**. Modules with two or more credential opts (Dehashed, Censys, Twilio, IBM X-Force, etc. — 12 total) used to render as one card per credential field, all sharing the same service name. They now collapse into a single labeled card per module.
- **`Dockerfile.full` build broken on current Debian**. Pinned `python:3.11` (lxml 4.x has no wheels on 3.13), dropped the broken `cmdtest`/`apt-key` yarn dance for a NodeSource Node 20 install, skipped the now-archived `AliasIO/wappalyzer` repo, and switched wafw00f to `pip install` (upstream removed setup.py).

### Schema

- Event-type sync in `db.py` now runs on every startup, not just on fresh DB init, so newly added event types (e.g. `RANSOMWARE_VICTIM`) are registered into existing databases on upgrade. Each `INSERT` is best-effort; duplicates are silently skipped.

## [5.0.3] - 2026-04-12

### UI Fixes

- Fixed module toggle switches not visually sliding in category accordions — replaced Alpine.js `:class` bindings with CSS `peer-checked:` pattern matching the working Local Tools toggles

### Code Review — Critical & High Fixes

#### Event Pipeline
- Fixed `storeOnly` deduplication completely bypassed in threaded mode — events now carry the flag through the queue, and `waitForThreads()` enforces it by only dispatching store-only events to `__stor` modules
- Added `try/except` around `deepcopy()` in event dispatch — a single non-serializable event no longer crashes the entire scan
- Changed threadpool worker `break` to `continue` on exception — failed tasks no longer cause the worker to skip remaining module queues
- Changed `maxstorage` default from 1024 to 0 (unlimited) — stops silent truncation of SSL certificates, DNS records, and HTTP headers
- Set `storeOnly = True` when event chain depth limit (1000) is reached in `notifyListeners()` — suppresses events when dedup chain cannot be fully verified

#### Security
- Sanitized scan names in all `Content-Disposition` headers via `_safe_filename()` — prevents header injection from user-controlled scan names
- Filtered API keys, passwords, tokens, and secrets from `/api/optsexport` config download
- Blocked `tbl_config`, `ATTACH`, `PRAGMA`, and `load_extension` in `/api/query` endpoint — prevents credential extraction and SQLite abuse
- Fixed `re.sub()` in `removeUrlCreds()` where `re.IGNORECASE` was passed as positional `count` arg (value 2) instead of `flags=` keyword — case-insensitive matching and full replacement now work correctly
- Added `token=`, `secret=`, `apikey=`, `api_key=`, `access_token=` patterns to URL credential redaction
- Added `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE = 'Lax'` flags
- Added CSV formula injection protection (`_csv_safe()`) to all CSV export endpoints — prefixes `=`, `+`, `-`, `@` with single quote
- Removed `html.escape()` unescape in `clean_user_input()` that was re-introducing raw `"` and `&` after escaping
- Added redirect depth limit (10) to `fetchUrl()` refresh header handler — prevents stack overflow from malicious infinite-redirect servers
- Fixed certificate CN substring matching in `parseCert()` — `evil.example.com` no longer falsely matches a check for `example.com`

#### Authentication
- Persisted `SECRET_KEY` across server restarts via config dict — sessions and CSRF tokens no longer invalidated on every restart

#### Correlation Engine
- Added cycle detection (visited set) and depth limit (50) to `enrich_event_entities()` — prevents infinite loop on circular event graphs
- Added `None` guard in `collect_events()` — `collect_from_db()` returning `None` now returns empty list instead of crashing the correlator
- Added minimum sample size (5 buckets) to `analysis_outlier()` — prevents false-positive correlations on tiny datasets
- Fixed `field.split(".")` to `split(".", 1)` in `event_extract()`, `event_keep()`, and `event_strip()` — prevents crash on 3-level field paths in correlation headlines

#### Data Integrity
- Increased event ID entropy from `randint(0, 99999999)` (~26.5 bits) to `getrandbits(64)` — eliminates birthday collision risk that could kill the storage module

#### Code Quality
- Added `DEVICE_TYPE`, `RAW_RIR_DATA`, `TCP_PORT_OPEN_BANNER`, `CO_HOSTED_SITE_DOMAIN`, `AFFILIATE_INTERNET_NAME`, `AFFILIATE_DOMAIN_NAME` to `EVENT_CATEGORIES` — these no longer fall into "Other" bucket in UI summary
- Moved `import time` to module level in `fragments.py` — was being re-imported inside loops on every HTTP request
- Standardized log timestamp handling — always divide by 1000 (removed conditional check)

### Code Review — Module Fixes
- `sfp_shodan`: Added `SOFTWARE_USED` and `BGP_AS_MEMBER` to `producedEvents()` — were emitted but undeclared, invisible in module dependency graph
- `sfp_shodan`: Added `errorState`/`checkForStop` guard inside netblock query loop — stops wasting API quota on dead keys
- `sfp_virustotal`: Added 204 throttle and 401/403 auth checks to `queryIp()` (matching existing `queryDomain()` pattern)
- `sfp_hunter`: Added 401/403/429 `errorState` handling — was flooding dead APIs with no error detection
- Updated `sfcli.py` version from "4.0.0" to "5.0.3"
- Export links in scan results now use `url_for()` instead of hardcoded legacy bare-root paths

### Code Review — Module System Hardening
- Added interface validation at module load time — checks for required methods (`watchedEvents`, `producedEvents`, `handleEvent`, `setup`) and required attributes (`meta`, `opts`, `optdescs`) before loading; warns on empty `producedEvents()` for non-storage modules
- Added `_rateLimit()` helper to plugin base class — standardized API throttling via `_delay` opt (replaces per-module hardcoded `time.sleep()`)
- Correlation engine short-circuits when first collection returns empty — avoids unnecessary DB queries for remaining collections

### Code Review — Architecture Cleanup
- Added RFC 8594 `Sunset` deprecation header on legacy root-level API routes (`/scanlist`, `/ping`, etc.) — clients should migrate to `/api/` prefix
- Extracted ~480 LOC of data transformation from `fragments.py` into `spiderfoot/services/event_service.py` — `EVENT_CATEGORIES`, badge colors, event dict building, dedup, cert parsing, port extraction now live in a framework-independent service layer
- Decomposed `sflib.py` (1673-line god object) into focused modules:
  - `spiderfoot/net/http.py` — `SpiderFootHttp` (fetchUrl, sessions, proxy, credential redaction)
  - `spiderfoot/net/dns.py` — `SpiderFootDns` (resolve, validate, wildcard detection)
  - `spiderfoot/net/ssl.py` — `SpiderFootSsl` (parseCert, safe socket creation)
  - `spiderfoot/net/host.py` — pure functions (validIP, urlFQDN, domain parsing, CIDR validation)
  - `SpiderFoot` class remains as thin facade — all 244 modules continue working with zero code changes

---

## [5.0.2] - 2026-04-11

### Security Hardening

#### Authentication & Access Control
- Added HTTP Basic Auth via `before_request` hook — all endpoints protected by default when passwd file is configured (`~/.spiderfoot/passwd`)
- Static files and `/api/ping` health check exempt from auth
- Timing-safe password comparison via `hmac.compare_digest` to prevent enumeration
- Loud startup warning when binding to non-localhost without authentication

#### CSRF Protection
- Added HMAC-signed CSRF tokens via Flask sessions, enforced on all POST requests
- CSRF token auto-injected into all HTMX requests via `htmx:configRequest` listener
- CSRF token included in scan submission and settings save fetch calls
- API clients using Basic Auth bypass CSRF (not vulnerable to browser-based attacks)
- Removed legacy `SF_TOKEN` random integer mechanism

#### Network Attack Surface
- Removed unrestricted CORS (`flask-cors` dependency deleted) — no cross-origin access needed
- All state-modifying endpoints now POST-only (scandelete, stopscan, startscan, vacuum, etc.)
- Hardened `/query` endpoint: read-only SQLite connection, semicolons rejected, error details no longer leaked to client
- Added scan creation rate limiting (configurable max concurrent scans, default 10)
- Hardcoded `debug=False` in production — Flask debugger no longer toggleable from config
- Switched CLI (`sfcli.py`) from HTTP Digest Auth to Basic Auth

#### Input Sanitization & XSS
- Fixed SQL injection in `scanElementSourcesDirect` and `scanElementChildrenDirect` — parameterized IN clauses replace string interpolation
- Archived legacy CherryPy UI files (sfwebui.py, .tmpl templates, legacy JS) — eliminates 4 critical stored XSS vectors, 1 infinite loop, and broken template literals
- URL-encoded `scan.target` in re-scan link href to prevent parameter injection
- API key values masked with `********` in HTML source; sentinel skipped on save
- Removed global `ssl._create_default_https_context` override — SSL verification no longer disabled process-wide

### Bug Fixes — Correctness & Data Integrity
- Fixed `getAddresses()` overwriting IPv4 results with IPv6 (`extend` instead of reassign)
- Fixed `scanElementChildrenAll` only following last child branch (`nextIds` reset moved outside loop)
- Fixed `correlationResultCreate` non-atomic insert — correlation result and event hashes now commit in a single transaction
- Fixed correlation meta cleaning bug — `else` branch incorrectly referenced `rule[k]` instead of `rule['meta'][k]`
- Fixed `build_correlation_title` crash when `event_extract` fails — uninitialized variable now handled with `continue`
- Fixed `logBatch` race condition — batch swap now protected by `threading.Lock`
- Fixed missing path separator in `loadCorrelationRulesRaw` — uses `os.path.join`
- Fixed unreachable `return False` in `vacuumDB`
- Fixed stale loop variable in `scanElementSourcesAll` — guarded with `if nextIds`
- Moved mutable class-level `_listenerModules` and `opts` to `__init__` in plugin base class — prevents cross-instance state leakage
- Added depth limit (1000) to event chain traversal in `notifyListeners` — prevents infinite loops from circular references
- Replaced MD5-based correlation IDs with `uuid.uuid4().hex`

### Tech Debt & Cleanup
- Updated default user-agent from Firefox 62 (2018) to Firefox 128
- Fixed wrong type hints in threadpool (`str` → `queue.Queue`, `None` → `Generator`)
- Replaced broad `suppress(Exception)` with specific exceptions in threadpool
- Cached `countryCodes()` dict as class variable — no longer rebuilt on every call
- Refactored `extractLinksFromHtml` to parse HTML once instead of 7 times
- Conditional scan table polling interval (5s when scans running, 30s when idle)
- Converted `parsedTargets()` to getter in Alpine.js scan form for render-cycle caching
- Safe `int()` parsing on page parameter with fallback to 1

### UX Overhaul

#### Dashboard
- Renamed page title from "Scans" to "Dashboard" to match nav
- Renamed "Correlations" stat card to "Findings" with "from X scans" subtitle
- "94 need API keys" is now a clickable link to Settings
- Improved empty state with guidance text and "Start your first scan" CTA

#### New Scan Page
- Added **module search bar** — instant filtering across all 241 modules by name, description, category, or key
- Added **Local Tools section** — dedicated dashed-border accordion grouping 17 tool modules (bbot, nmap, whatweb, etc.) by sub-category with synced toggles
- Rewrote scan type descriptions for non-security users ("Discover public info about a target" instead of "Map the attack surface")
- "KEY NEEDED" badges now link to Settings with arrow indicator
- Added intro text explaining what modules are and how API keys work
- Module descriptions show full text on hover via title attribute

#### Scan Results
- Replaced duplicate "Sources" stat card with "Duration" card
- Added "Soon" badge on Graph tab to set expectations
- Graph placeholder now explains GEXF export for use in Gephi/yEd
- Standardized severity labels: HIGH→Critical, MEDIUM→Warning, LOW→Low, INFO→Info (consistent across Summary and Correlations tabs)
- Improved empty state explanations for findings, events, and correlations

#### Data Tab (Redesigned)
- Replaced dense table layout with clean flex-based rows
- Color-coded type badges by event category: cyan (network/DNS), emerald (infrastructure/SSL), violet (identity), red (malicious), orange (vulnerabilities), amber (threat intel), slate (raw data)
- Badge colors computed server-side for cross-browser reliability
- Smart data preview: Web Content events show "HTML document · X chars" instead of raw HTML entities
- Long data truncated at 120 chars in preview, full content in expandable detail panel
- Detail panel has metadata header (type code, module, timestamp, confidence), Copy button, and scrollable container for large payloads
- "All" chip added to category filters for easy reset
- Copy-to-clipboard button for event data

#### Settings
- **API Keys**: Grouped 94 keys by module category with collapsible headers and configured/total counters; auto-expands groups with configured keys; intro text about free tiers; search bar; service website links on each card
- **General**: Improved helper text with practical guidance (thread performance trade-offs, DNS server examples, user agent purpose, timeout advice)
- **Proxy/TOR**: Contextual help text changes based on proxy type; fields visually disabled when "None" selected; improved descriptions
- **Appearance**: Added "Auto" theme option that follows OS preference via prefers-color-scheme

#### Global
- Sidebar expand hint chevron (visible when collapsed, hidden when expanded)
- Standardized save feedback to 4-second auto-hide across all settings sections
- Replaced browser `alert()` in scan submission with inline toast notifications
- Added loading spinner on Launch Scan button during submission
- Added Tailwind CDN safelist for HTMX-swapped classes (Firefox compatibility)
- Theme system updated to support dark/light/auto with OS preference listener

---

## [5.0.1] - 2026-04-10

### Bug Fixes — Critical
- Fixed `Popen(timeout=)` TypeError crash in `sfp_userscanner` and `sfp_tool_whatweb` — timeout arg moved to `.communicate()`
- Fixed wrong event type constants in `sfp_tool_bbot_cloud` and `sfp_bevigil` — `CLOUD_STORAGE_OPEN` → `CLOUD_STORAGE_BUCKET_OPEN`, `CODE_REPOSITORY` → `PUBLIC_CODE_REPO`
- Fixed `sfp_postman` using non-existent `CODE_REPOSITORY` event type → `PUBLIC_CODE_REPO`
- Fixed scan delete button 405 error — changed `hx-delete` to `hx-post` (route only accepts GET/POST)
- Fixed scan delete DOM breakage — `hx-swap="delete"` instead of injecting raw JSON into table
- Fixed MISP module mapping EMAILADDR → `MALICIOUS_INTERNET_NAME` (now correctly → `MALICIOUS_EMAILADDR`)
- Fixed `sfp_opensanctions` emitting semantically wrong `MALICIOUS_AFFILIATE_INTERNET_NAME` for sanctions/PEP matches
- Fixed null reference crashes in `sfp_haveibeenpwned` and `sfp_skymem` when `fetchUrl()` returns None
- Fixed settings save broken on first use — CSRF token was `None` until `/api/optsraw` was called
- Fixed `del pc['ROOT']` KeyError crash in `/api/scanelementtypediscovery` when scan has no events
- Fixed scan start/rerun infinite loop — added 30s timeout so Flask workers don't hang if subprocess fails

### Bug Fixes — Data Correctness
- Fixed `scanInstanceDelete` not cleaning correlation tables — orphaned rows in `tbl_scan_correlation_results`
- Fixed log timestamps displayed as raw milliseconds in Log tab fragments
- Fixed `scanLogs` reverse parameter logic (was inverted — `reverse=True` returned oldest instead of newest)
- Fixed JSON and GEXF export buttons calling wrong API endpoints (now use `/scanexportjsonmulti` and `/scanviz?gexf=1`)
- Fixed correlation export filename typo `.xlxs` → `.xlsx`
- Wrapped `scanCorrelationSummary` calls in `/api/scanlist` and `/api/scanstatus` with try/except for older databases
- Fixed DB schema FK typo `tbl_scan_instances` → `tbl_scan_instance`

### Bug Fixes — UX
- Added `[x-cloak]` CSS rule — expandable rows no longer flash visible before Alpine.js initializes
- Fixed stop button replacing its own text with JSON response — added `hx-swap="none"`
- Fixed `sfp_c2tracker` not setting `errorState` on fetch failure (caused repeated retry flood)
- Fixed `sfp_dnsgrep` missing `errorState` class var and guard in `handleEvent()`
- Fixed `sfp_postman` not setting `errorState` on 429 rate limit (caused retry storm)
- Fixed `sfp_tool_bbot_vuln` and `sfp_tool_bbot_cloud` emitting `RAW_RIR_DATA` for every BBOT output line (now only for relevant events)
- Fixed `sfp_fofa` emitting duplicate `WEBSERVER_BANNER` events

### Cleanup
- Removed unused `SpiderFootHelpers` import from `sfp_tool_bbot_scan`
- Moved inline `import json`/`import time` to module level in `sfp_dnsdumpster`
- Removed dead `re` and `BeautifulSoup` imports from `sfp_dnsdumpster` (left over from old HTML scraping version)
- Removed false `COMPANY_NAME`/`HUMAN_NAME` declarations from `sfp_opensanctions` producedEvents (were never emitted)
- Removed duplicate scrollbar CSS rules and 5 unused CSS classes from `custom.css`
- Moved `@import` font rules to top of `custom.css` (CSS spec requirement)

### Infrastructure
- Added `user-scanner` to `requirements.txt`
- Relaxed `pyOpenSSL`, `cryptography`, and `networkx` version bounds for compatibility
- Bumped Dockerfile Alpine from 3.12/3.13 to 3.18 (Python 3.11 support, needed for modern dependencies)
- `bbot` documented as optional dependency (too heavy for default install, modules degrade gracefully)

## [5.0.0] - 2026-04-08

### Phase 1: UI/UX Overhaul (completed prior)
- Migrated from CherryPy to Flask
- Rebuilt frontend with Tailwind CSS, HTMX, Alpine.js
- Dark SOC-themed UI with collapsible sidebar
- Component-based Jinja2 templates with HTMX fragment loading
- New scan creation page with multi-target support and module category toggles

### Phase 2: Module Audit & New Services

#### Removed (11 dead/deprecated modules)
- `sfp_threatcrowd` — ThreatCrowd shut down
- `sfp_crxcavator` — CRXcavator shut down
- `sfp_fsecure_riddler` — F-Secure Riddler EOL
- `sfp_clearbit` — Clearbit acquired by HubSpot, API dead
- `sfp_riskiq` — RiskIQ acquired by Microsoft, old API dead
- `sfp_bitcoinabuse` — Merged into ChainAbuse
- `sfp_punkspider` — QOMPLX collapsed
- `sfp_crobat_api` — omnisint.io dead
- `sfp_twitter` — Twitter/X free API removed
- `sfp_venmo` — Venmo API closed to new developers
- `sfp_myspace` — No useful API remaining

#### Fixed (6 modules with changed APIs)
- `sfp_dnsdumpster` — Rewrote from CSRF scraping to new JSON API with API key
- `sfp_dnsgrep` — Updated to tls.bufferover.run with x-api-key header
- `sfp_skymem` — Updated URLs from skymem.info to skymem.com
- `sfp_hackertarget` — Updated model to FREE_NOAUTH_LIMITED, documented rate limits
- `sfp_haveibeenpwned` — Removed dead v2 fallback, v3 API only with required key
- `sfp_keybase` — Added deprecation notice (Zoom acquisition, maintenance mode)

#### Added — New OSINT Service Modules (13)
- `sfp_shodaninternetdb` — Shodan InternetDB (free, no key, ports/CVEs/hostnames)
- `sfp_leakcheck` — LeakCheck breach database (free public API + pro)
- `sfp_hudsonrock` — Hudson Rock Cavalier infostealer intelligence (free)
- `sfp_criminalip` — Criminal IP threat intel (free tier with key)
- `sfp_netlas` — Netlas.io attack surface search (free tier with key)
- `sfp_validin` — Validin DNS history and CT logs (free tier with key)
- `sfp_opensanctions` — OpenSanctions PEP/sanctions screening (free non-commercial)
- `sfp_whoisxmlapi` — WhoisXML API WHOIS/DNS/reverse IP (500 free credits)
- `sfp_bevigil` — BeVigil mobile app OSINT (free credits)
- `sfp_postman` — Postman public workspace leak detection (free, no key)
- `sfp_zoomeye` — ZoomEye internet scanning (paid)
- `sfp_fofa` — FOFA internet asset search (paid)
- `sfp_snusbase` — Snusbase breach/credential search (paid)

#### Added — BBOT Integration (4 tool wrappers)
- `sfp_tool_bbot_enum` — BBOT subdomain enumeration (50+ passive sources)
- `sfp_tool_bbot_scan` — BBOT active scanning (ports, HTTP, SSL, fingerprinting)
- `sfp_tool_bbot_vuln` — BBOT vulnerability detection (nuclei, badsecrets, baddns)
- `sfp_tool_bbot_cloud` — BBOT cloud recon (S3/Azure/GCP buckets, Docker Hub, Postman)

#### Added — Threat Intelligence Modules (5)
- `sfp_userscanner` — Email registration + username scanning across 195+ platforms
- `sfp_misp` — MISP Threat Intelligence Sharing Platform integration
- `sfp_ransomlook` — RansomLook ransomware victim tracking (free, no key)
- `sfp_c2tracker` — C2-Tracker live C2 server IP feed (free, no key)
- `sfp_vulners` — Vulners CVE/exploit database (free tier with key)

### Phase 2: UX Polish

#### Dashboard
- Stats cards: 4 cards (Active Scans, Completed, Correlations, Modules) with contextual second lines
- Scan rows: inline event type breakdown (hosts, IPs, emails, ports) + progress bars for running scans
- Removed flat column layout in favor of single-column rich rows

#### Scan Results
- Summary tab: events grouped by category (Attack Surface, Identities & Exposure, Infrastructure, Reputation, Vulnerabilities) instead of flat number grid
- Stat cards: renamed to Events/Correlations/Modules/Sources with context lines (unique count, duration, risk breakdown)
- Data tab: category filter chips with counts, expandable rows for full event detail, pagination (50 per page replacing 500-row hard cap)

#### Bug Fixes
- Fixed Alpine.js `open` / `window.open` conflict (renamed to `expanded`)
- Fixed Alpine.js scoping in table rows (tbody-per-row pattern for sibling access)
- Fixed correlation query error on databases without correlation tables

### Module Count
- Previous: 233 modules
- Removed: 11 dead modules
- Added: 22 new modules
- **Current: 244 modules**
