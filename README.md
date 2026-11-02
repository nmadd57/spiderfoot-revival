# SpiderFoot Revival

Self-hosted OSINT automation platform. A fork of [boredchilada/spiderfoot-revival](https://github.com/boredchilada/spiderfoot-revival), itself a modernised fork of [SpiderFoot](https://github.com/smicallef/spiderfoot), tuned for running as a small self-hosted service.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.12+-green)](https://www.python.org)
[![Version](https://img.shields.io/badge/version-5.2.0-blue.svg)](CHANGELOG.md)

## What this fork adds

On top of the Revival UI (Flask, Tailwind, HTMX, Alpine.js) and its module overhaul, this fork adds:

- **One place for every module.** Settings → Modules lists all modules with an on/off switch, status, filters, and a panel for each module's API key, binary path, other options, usage limits and quota. See [Settings](#settings).
- **A Test button** on every module and on the AI assistant, SearXNG and embeddings settings: run a module against a harmless sample (or your own target) and see what it returns, or check that an endpoint works and list its models.
- **Cost and key awareness.** Modules carry a pricing tag (free, free tier, paid, local). Per-module call counters, daily/total/per-second limits, vendor quota checks, key tests, and automatic hiding of modules that cannot run (no key, over quota, tool not installed).
- **Web search without Google or Bing.** Their search APIs are retired or closing, so those modules are gone. Search modules use your own [SearXNG](https://docs.searxng.org/) instance.
- **People to businesses, filings and professional licences.** A person's name can lead to the companies they appear in (SEC EDGAR), the company's filings, and healthcare and securities licences for people and businesses.
- **Business search.** Scan a company name (`Acme Widgets LLC` or `business: Acme`) and get SEC registration, state business registries, LEI records, federal awards, FCC, IRS, FDIC, EPA, CFPB and Labor Department records. See [Business search](#business-search).
- **Module repair and dead-module cleanup.** Crashing modules fixed, vendors that changed their APIs ported (Censys, ZoomEye), dead services removed, and the remaining broken ones labelled. See [Module repair and cleanup](#module-repair-and-cleanup).
- **Local-tool modules that work out of the box.** The image bundles BBOT, nmap, nuclei and the other CLI tools instead of leaving them as an exercise.
- **Local AI endpoints.** The AI assistant works with any OpenAI-compatible server, not only OpenRouter.
- **Built to sit behind single sign-on.** The app trusts a reverse proxy (oauth2-proxy and similar). See [Running it safely](#running-it-safely).
- **Maintenance automation.** CodeQL scanning, Dependabot updates, an image built by GitHub Actions on every push, and a test workflow that cannot hang (per-test timeout of 120 s, a 20-minute job limit, older runs on the same branch cancelled). Lint (`flake8`) and the full unit suite are clean.

Everything is listed in [CHANGELOG.md](CHANGELOG.md); a table of every integration (purpose, auth, cost, project link, status) is in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Quick start

### Docker (recommended)

A prebuilt image is published to GitHub Container Registry on every push to `master`:

```bash
docker run -d --name spiderfoot -p 127.0.0.1:5001:5001 \
  -v spiderfoot-data:/var/lib/spiderfoot \
  ghcr.io/nmadd57/spiderfoot-revival:latest
```

Visit [http://localhost:5001](http://localhost:5001). The data volume holds the database, your API keys and the cache.

Build it yourself:

```bash
docker build -t spiderfoot-revival .
```

The first build is long (it compiles BBOT's native dependency and downloads the scanners and nuclei's template set) and the image is about 1.4 GB. `Dockerfile.full` is the older all-in-one variant, kept for compatibility; the main `Dockerfile` now bundles the same tools.

BBOT's masscan SYN scans need `--cap-add=NET_RAW`; without it BBOT falls back to TCP-connect scans.

### Bundled tools

The `sfp_tool_*` modules drive these programs, installed in the image with their paths preconfigured:

| Tool | Notes |
|---|---|
| BBOT 3.0.2 | own Python 3.13 environment, built from source; the four `sfp_tool_bbot_*` modules |
| nmap, nbtscan, onesixtyone | |
| nuclei | with the community template set cloned at build time |
| trufflehog | see [Known limitations](#known-limitations) |
| testssl.sh, WhatWeb, CMSeeK | pinned releases or the upstream default branch |
| retire.js, wafw00f, snallygaster, dnstwist | |

Wappalyzer is not included (its command-line tool is no longer distributed). A tool module whose binary is missing is hidden automatically, with the reason shown on its row. On Settings → Modules, **Test** on a tool module starts the binary with a version flag; it never runs a scan.

### Local development

```bash
pip install -r requirements.txt
python sf.py -l 127.0.0.1:5001
```

Python 3.12 or newer. The image uses Python 3.15 and CI runs the tests on 3.12 to 3.15.

```bash
pip install -r test/requirements.txt
python -m pytest test/unit
```

## Settings

### Modules (Settings → Modules)

One list for all modules. Each row has an on/off switch and a status pill: working, not used yet, disabled, auto-disabled with the reason, broken upstream, or a key problem. Open a row for:

- **Settings.** Credentials (API keys and tokens are masked and never sent to the browser), binary paths for tool modules, and every other option, saved per module. A module with no options just has the switch and its description.
- **Status.** Results produced, the last key or account-related error with its time, and any recorded key problem (rejected key, out of credits or quota, rate limited) with a Dismiss button. Only errors that concern the API key or account are reported; ordinary scan messages such as "no results" are not.
- **Usage and limits.** Calls today, this period and all time, HTTP errors, vendor rate-limit headers, and limits you set (calls per second, per day, total per period with a reset date; delay or block). A **Check quota** button reads the vendor's own remaining quota where the vendor offers an API; **Test key** tries a key before saving it.
- **Test.** Runs the module against a sample or your target and shows the events it produced, errors, notes and the HTTP status of each request (host and path only). A test makes real calls with your key (usually one to three) and counts toward your limits. Modules that actively probe a target (port scanners, crawlers) only run when you type a target you are allowed to scan.

Filters cover state, status, key, cost and whether a module has settings. Bulk buttons enable or disable whatever is shown, and a module can be switched off by default so it is not pre-selected on New Scan.

**Automatic disabling.** Modules that need an API key but have none, that need a SearXNG instance or a tool that is not set up, or that are over a limit or a vendor quota are hidden from New Scan and stripped from API-started scans until fixed. A master switch on the page turns this off.

**Pricing tags.** `free` (no account), `free_key` (free tier with an API key), `paid` (commercial only), `local` (no third-party service). Badges: green FREE, blue FREE TIER, red PAID, grey LOCAL, red BROKEN.

### Web Search (Settings → Web Search)

Two cards, each with its own Save and Test button:

- **SearXNG.** Instance URL, optional auth header, engines, language, pages per search and the search toggles. **Test SearXNG** runs a search with the values on the form (saved or not) and reports the result count, sample URLs, engines that did not answer, or why it failed (a sign-in page in front of the instance, JSON output disabled, rate limiting, unreachable). The instance must serve JSON (`search.formats` in its `settings.yml` includes `json`) and must not sit behind an interactive sign-in; use the instance's own port on your LAN.
- **Embeddings** (optional). Any OpenAI-compatible `/embeddings` endpoint. Phrase-search results are ranked by similarity to the scan target and weak matches dropped. **Test embeddings** embeds a short text, reports the vector size and speed, lists the endpoint's models and fills the model suggestions.

Pastebin, Onion.link, the social profile finder and the SearXNG module use the instance configured here. Without one they are hidden automatically.

### AI Assistant (Settings → AI Assistant)

Streams scan summaries and correlation explanations over Server-Sent Events from OpenRouter or any OpenAI-compatible endpoint.

- **OpenRouter (default):** enter your API key; pick a model from the list or type one.
- **Local or self-hosted** (Ollama, llama.cpp, vLLM, LM Studio, llama-swap, ...): set the **Custom base URL** to the server's OpenAI-compatible root, for example `http://host:11434/v1` (requests go to `<base URL>/chat/completions`). The key is optional, the model name is free-form, and the fallback model is not used. The SpiderFoot container must be able to reach the endpoint.
- **Test connection** lists the endpoint's models (and fills the model suggestions), then sends a tiny chat request with your default model to confirm it answers.
- **Privacy.** Summaries send scan data to the provider you configure. The optional PII masking (emails, public IPs, the target domain) is off by default and does not cover names, phone numbers or addresses; prefer a local endpoint for sensitive scans.
- **Deployment notes.** The concurrency lock is process-local (use one worker). gunicorn needs `--worker-class gevent` (or `eventlet`), or sync workers with `--threads 4` or more. nginx honours `X-Accel-Buffering: no`; on Cloudflare's free plan summaries arrive as one chunk instead of streaming.

## Modules

255 modules across passive recon, breach data, threat intelligence, cloud discovery, registries and local tools, plus 45 correlation rules.

### Added or reworked in this fork

| Area | Modules |
|---|---|
| People, businesses and filings | `sfp_secedgar` (SEC EDGAR: people to companies, company filings and registration), `sfp_openstreetmap` (free geocoding and reverse geocoding), `sfp_crt_org` (domains by certificate organisation) |
| Professional licences | `sfp_npiregistry` (US healthcare professionals and organisations, state licence numbers), `sfp_brokercheck` (FINRA BrokerCheck and SEC adviser registrations for people and firms) |
| Threat and reputation | `sfp_rapiddns`, `sfp_firehol`, `sfp_spamhaus_drop`, `sfp_whoisds`, `sfp_chainabuse`, `sfp_recordedfuture`, `sfp_triage` |
| Search | `sfp_searxng` (`site:` listings for hosts, exact-phrase searches for names, businesses, emails, usernames and phones, with optional embeddings ranking) and `sfp_vane` (a cited, model-written profile of the target from a self-hosted Vane instance; labelled as model-generated, not in the Footprint use case), plus Pastebin, Onion.link and social profiles running on SearXNG |
| Reworked | `sfp_censys` (Censys Platform API), `sfp_zoomeye` (v2 API) |

The people and business modules match on names only, so a common name returns several unrelated people. Each result says it is a name match; check that it is the same person before relying on it. Results are capped per name.

### Business search

**Business** is a scan target type. A name is treated as a business when it ends in a legal form (Inc, LLC, Ltd, GmbH...) or starts with `business:` or `company:`, for example `business: Acme Widgets`; the New Scan page shows a Business badge, and the API and CLI accept the same forms. Names are compared ignoring legal forms and punctuation ("Tesla, Inc." does not match "Tesla Holdings LLC"), and a rerun keeps the original target type. All the business modules are in the **Business OSINT** preset. Company names also arrive from other modules (a person's employer, a certificate's organisation) and are searched the same way.

| Source | What it returns | Cost |
|---|---|---|
| `sfp_sec_edgar` | SEC filer profile (addresses, phone, tickers, EIN, state of incorporation, former names), recent filings, and the parent company found from other filers' Exhibit 21 | free, optional contact email |
| `sfp_secedgar` | Company registration and recent filings as `COMPANY_FILING` events (10-K, 8-K, proxy, ownership, Form D), and, from a person's name, the public companies they appear in | free |
| `sfp_us_state_registries`, `sfp_govfiles` | State business entity registries: status, entity type, formation date, addresses and officers. The first covers NY, CO, CT, OR and TX from open data; GovFiles covers all states and DC (default: New England) and also stands in for MA, NH and ME, whose own registries block automated clients | free; GovFiles needs a key |
| `sfp_gleif`, `sfp_opencorporates` | Legal Entity Identifier records, and OpenCorporates | free, paid |
| `sfp_usaspending` | Federal contracts, grants and loans: UEI, parent company, award totals | free |
| `sfp_fcc`, `sfp_irs_nonprofits`, `sfp_fdic`, `sfp_openfda` | FCC Form 499, equipment grants and filings; tax-exempt organisations (Form 990); FDIC-insured banks; FDA recalls and device establishment registrations | free |
| `sfp_epa_echo`, `sfp_cfpb_complaints`, `sfp_dol_enforcement` | Environmental facilities and violations, consumer complaints, OSHA and wage-and-hour cases | free, DOL needs a free key |
| `sfp_opensanctions` | Sanctions and politically-exposed-person screening for companies and people | free key |
| `sfp_npiregistry`, `sfp_brokercheck` | Professional licences and registrations for businesses (healthcare organisations, brokerage and adviser firms) | free |
| `sfp_crt_org` | Domains a company has had certificates issued to | free |

**People lead to businesses.** A person's name (a scan target, or one found by another module) is searched in SEC filings, and the public companies it appears in become company targets, which fan out into the sources above. The same name also goes to the licence registries. These are name matches, so each result says so and results are capped per name.

### Module repair and cleanup

- **Repaired.** Modules that crashed or logged errors on every event in real scans: the StevenBlack hosts list parser, Netlas, OpenSanctions and AlienVault handling of unexpected replies, Shodan's normal "no information for that IP" reply (no longer an error), and empty replies from DuckDuckGo and Psbdmp. Vendor API changes followed: Censys now uses the Censys Platform API (a Personal Access Token), ZoomEye uses its v2 search API. The web client no longer takes minutes per request on hosts without IPv6 when a custom DNS server is set. Scans that failed or were aborted before finishing no longer leave worker threads running, which used to keep the scan process (and the test suite) alive forever.
- **Dead modules removed.** Services that no longer exist or no longer work: ThreatCrowd, CRXcavator, F-Secure Riddler, Clearbit, RiskIQ, BitcoinAbuse, PunkSpider, Crobat, Twitter, Venmo, MySpace, DNSDB, SpyOnWeb, Zonefiles.io, Abusix, ThreatJammer, BinaryEdge, EmailCrawlr, C2-Tracker (archived upstream), and the Google Custom Search, Google Maps and Bing modules (their APIs are retired or closing). Replacements were added where useful (RapidDNS, FireHOL, Spamhaus DROP, WhoisDS, Chainabuse, crt.sh by organisation, SearXNG search, OpenStreetMap geocoding).
- **Labelled, not hidden.** Modules whose service may come back are kept and marked BROKEN: DNSGrep and bitcoinwhoswho. A module that cannot run for a fixable reason (no key, no SearXNG instance, tool not installed, over quota) is hidden from New Scan with the reason shown on Settings → Modules.
- **Kept honest.** Modules that depend on unofficial endpoints, or that have not been run against their live API, are called out under [Known limitations](#known-limitations). The module Test button exists so a repair can be checked in place.

Earlier repairs in the Revival line: DNSDumpster (new JSON API), DNSGrep (bufferover.run), Skymem, HackerTarget rate limits, HaveIBeenPwned v3 only, Keybase.

### Target types

Domains and subdomains, IP addresses, subnets, email addresses, phone numbers, usernames, person names, company names (`business: Acme Widgets`), Bitcoin addresses and ASNs.

## Running it safely

SpiderFoot has **no user accounts**. Anyone who can reach the web UI can start scans against any target, read and change every API key, run read-only SQL against the database and delete scans. Treat access to it as administrator access.

- **Do not publish port 5001.** Bind it to localhost or a private network and put an authenticating reverse proxy in front (oauth2-proxy with your identity provider works well; restrict it to one group). Optional HTTP Basic auth exists (see below) but a proxy with single sign-on is the better option.
- **Scans leave from this machine.** Active modules (nmap, nuclei, BBOT, the port scanner) probe the targets you give them. Only scan what you are authorised to scan. If the container has access to your LAN, scans can reach it too: restrict the container's network routes to what it needs.
- **Your keys are valuable.** They live in the data volume (the SQLite database). Protect the volume, set usage limits on paid keys, and rotate keys you have exposed.
- **Your sign-in can expire.** Behind single sign-on an expired session makes saves fail; the UI shows a banner asking you to sign in again.
- **Scan data can be personal data.** Name-based modules query public registries; retention and deletion are up to you.

### Optional HTTP Basic auth

```bash
# Create the passwd file with a bcrypt-hashed password
python -c "import bcrypt; print('admin:' + bcrypt.hashpw(b'changeme', bcrypt.gensalt()).decode())" > ~/.spiderfoot/passwd
```

On startup SpiderFoot loads this file and enforces Basic auth on all endpoints. Plaintext passwords in an existing file are upgraded to bcrypt on first load. If the file is missing or empty, authentication is off.

## API

A REST API covers scans, results, exports and settings:

```bash
# Start a scan
curl -X POST http://localhost:5001/api/startscan \
  -d "scanname=test&scantarget=example.com&modulelist=sfp_dnsresolve,sfp_shodaninternetdb"

curl http://localhost:5001/api/scanlist                          # list scans
curl "http://localhost:5001/api/scaneventresults?id=SCAN_ID"     # results
curl "http://localhost:5001/api/scanexportjsonmulti?ids=SCAN_ID" # export
curl -X POST "http://localhost:5001/api/stopscan?id=SCAN_ID"     # stop
```

State-changing requests need the CSRF token (`X-CSRF-Token` header, from the page's `csrf-token` meta tag) unless the request authenticates with Basic auth. Endpoints used by the settings pages:

| Endpoint | Purpose |
|---|---|
| `GET /api/modulesettings` | Every module with its options (secrets masked), status and key problems |
| `POST /api/modulestate` | Enable, disable, default-off, or auto-disable switch |
| `GET /api/usage`, `POST /api/usage/limits`, `/usage/reset`, `/usage/check`, `/usage/issue/clear` | Usage counters, limits, vendor quota and key tests |
| `POST /api/moduletest` | Run one module against a sample or a target |
| `POST /api/searxng/test`, `/api/embeddings/test`, `/api/ai/test` | Test those endpoints with the values supplied |

See [TECHNICAL.md](TECHNICAL.md) for the full reference.

## Architecture

```
sf.py                          # Entry point (CLI + web server)
sflib.py                       # Core library facade (delegates to net/*)
sfscan.py                      # Scan engine and module orchestration
sfcli.py                       # CLI client
modules/                       # 255 OSINT modules (sfp_*.py)
spiderfoot/
  app.py                       # Flask app factory, auth, CSRF
  db.py                        # SQLite database layer
  plugin.py                    # Base plugin class
  correlation.py               # YAML-based correlation engine
  net/                         # HTTP client, DNS, SSL, host validation
  services/
    module_options.py          # Editable options of a module (secrets masked)
    module_status.py           # Key-related errors and results per module
    module_state.py            # Enabled / default-off module lists
    module_test.py             # Test button: run a module against a sample
    usage.py                   # Call counting, limits, key-problem records
    api_quota.py               # Vendor quota and key checks
    auto_disable.py            # Hide modules that cannot run
    searxng.py                 # Web search through SearXNG, instance test
    embeddings.py              # Embeddings endpoint test
    ai_service.py              # OpenAI-compatible / OpenRouter client, endpoint test
    urlcheck.py                # Validation of endpoint URLs entered in settings
    tools.py                   # Is a tool module's binary installed?
    people.py                  # Name matching for the registry modules
    event_service.py, preset_service.py, ai_persistence.py
  blueprints/                  # api.py (/api/*), ui.py, fragments.py (/frag/*), ai.py (SSE)
  templates/, static/          # Jinja2 templates, Tailwind/HTMX/Alpine front end
correlations/                  # 45 YAML correlation rules
docs/INTEGRATIONS.md           # Every integration: purpose, auth, cost, link, status
```

| Layer | Technology |
|---|---|
| Backend | Python 3.12+ (image: 3.15), Flask, SQLite |
| Frontend | Tailwind CSS (compiled stylesheet is committed), HTMX, Alpine.js |
| Deployment | Docker (Alpine, non-root user) |

If you add Tailwind classes to a template, rebuild the stylesheet: `npx tailwindcss -c tailwind.config.js -i spiderfoot/static/css/tailwind-input.css -o spiderfoot/static/css/tailwind.css`.

## Known limitations

- **TruffleHog.** The image installs TruffleHog 3.x but `sfp_tool_trufflehog` was written for the 2.x command line, so that module does not work until it is ported.
- **Matching.** Name-based registry lookups are name matches, not identity matches.
- **Two SEC modules overlap.** `sfp_sec_edgar` (company profile, filings and parent company) and `sfp_secedgar` (person-to-company links and filings) cover similar ground and may report the same filings twice.
- **Registries that block automated clients.** The Massachusetts, New Hampshire and Maine registry sites cannot be scraped; they are covered through GovFiles, which needs a key (not tested live).
- **Unofficial endpoints.** BrokerCheck and the SEC's adviser search have no documented API; the modules use the JSON the public search pages use and may break without notice.
- **Several vendor modules are untested against live APIs** (they need paid or restricted keys): Recorded Future, Tria.ge, Chainabuse, and the Censys v3 output beyond host basics.
- **Usage limits are best effort.** Counters are kept per scan process and only count requests made through the shared HTTP client.
- **One SQLite file.** There is no built-in backup or retention policy; back up the data volume.

## Contributing

1. Fork the repository and create a branch.
2. Follow the module pattern in [DEVELOPMENT.md](DEVELOPMENT.md): every module needs `meta`, `opts`, `optdescs`, `setup()`, `watchedEvents()`, `producedEvents()` and `handleEvent()`.
3. Use `self.sf.fetchUrl()` for HTTP requests (never import `requests` directly) and `self.sf.webSearch()` for web search. Give the module a `pricing` tag. Do not add the `apikey` flag to a module whose key is optional. Use `usesWebSearch` in `meta` for modules that need a SearXNG instance.
4. Never put credentials in log messages; error text shown to users should not include exception details.
5. Run `python -m pytest test/unit` and `flake8 . --max-line-length=150` before opening a pull request (this is what CI runs); CI also runs CodeQL, and Dependabot proposes dependency updates weekly.

## Documentation

- [CHANGELOG.md](CHANGELOG.md): release history and everything changed in this fork
- [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md): every integration, with purpose, auth, cost and link
- [DEVELOPMENT.md](DEVELOPMENT.md): project conventions and development guide
- [TECHNICAL.md](TECHNICAL.md): architecture, API and database reference
- [correlations/README.md](correlations/README.md): correlation rule authoring guide

## License

MIT, see [LICENSE](LICENSE).

## Credits

Originally created by [Steve Micallef](https://github.com/smicallef/spiderfoot). Revived and modernised by [@boredchilada](https://github.com/boredchilada). This fork is maintained by [@nmadd57](https://github.com/nmadd57).
