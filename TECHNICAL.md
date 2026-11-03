# SpiderFoot Revival — Technical Reference

## Architecture

### Event System
SpiderFoot's core is an event-driven pipeline:
1. User provides a target (domain, IP, email, etc.)
2. The scan engine creates a root event (`ROOT`)
3. Modules that watch for ROOT produce new events (e.g., `DOMAIN_NAME`)
4. Other modules consume those events and produce more (e.g., `INTERNET_NAME`, `IP_ADDRESS`)
5. This cascades until no module produces new events

Events are typed strings. Key event types:
- `INTERNET_NAME`, `DOMAIN_NAME`, `IP_ADDRESS` — core discovery
- `TCP_PORT_OPEN`, `UDP_PORT_OPEN` — port scanning
- `EMAILADDR`, `EMAILADDR_COMPROMISED`, `USERNAME` — identity
- `VULNERABILITY_CVE_CRITICAL/HIGH/MEDIUM/LOW` — CVEs
- `MALICIOUS_IPADDR`, `BLACKLISTED_IPADDR` — reputation
- `LEAKSITE_CONTENT`, `DARKNET_MENTION_CONTENT` — breach/darknet
- `RAW_RIR_DATA` — raw data for archival

### Module Types
1. **API modules** (e.g., `sfp_shodan.py`): Query external REST APIs
2. **Tool wrappers** (e.g., `sfp_tool_nmap.py`): Shell out to CLI tools, parse output
3. **Internal modules** (e.g., `sfp_dnsresolve.py`): Local analysis, no external calls
4. **Feed modules** (e.g., `sfp_firehol.py`): Download and cross-reference threat feeds

### Database
SQLite via `spiderfoot/db.py`. Key tables:
- `tbl_scan_instance` — scan metadata (id, target, status, timestamps)
- `tbl_scan_results` — all events (type, data, module, hash, parent_hash)
- `tbl_scan_config` — per-scan module configuration
- `tbl_scan_correlation_results` — correlation rule matches
- `tbl_config` — global settings (API keys, proxy, etc.)
- `tbl_users`, `tbl_scan_acl`, `tbl_mcp_tokens`, and `tbl_scan_instance.owner` — users, scan sharing and personal agent tokens (see Users, Sign-in and Access Control)

### Flask App
- `app.py`: Factory pattern, registers the blueprints (+ 1 compat re-registration), authentication and route authorization hooks, CSRF
- `blueprints/api.py`: REST API (scan lifecycle, data export, config, presets)
- `blueprints/ui.py`: HTML pages (dashboard, newscan, scaninfo, settings)
- `blueprints/fragments.py`: HTMX fragments (tab content, table rows, settings sections)
- `blueprints/ai.py`: AI summarization SSE endpoints (scan summary, correlation explain)
- `blueprints/auth.py`: `/auth/*` sign-in routes; `blueprints/access.py`: sharing, user pickers and Access settings; `blueprints/mcp_admin.py`: agent (MCP) settings and personal tokens

All API endpoints are dual-registered at `/api/*` and `/*` for backwards compatibility.

### Frontend
- **Tailwind CSS**: PostCSS build via `tailwind.config.js`, defines `sf.*` color tokens. Rebuild with `npx tailwindcss -i static/css/tailwind-input.css -o static/css/tailwind.css`
- **HTMX**: Fragment-driven updates (scan table polling, tab switching, search/filter)
- **Alpine.js**: Reactive components (scan form, theme toggle, expandable rows)

### HTMX Patterns
- Scan table polls every 5s: `hx-trigger="every 5s"`
- Tab switching: `hx-get="/frag/results-tab?id=X&tab=Y"` → `hx-target="#tab-content"`
- Search/filter: `hx-trigger="keyup changed delay:300ms"` with `hx-include` for multi-field
- Pagination: `hx-get="/frag/events?id=X&page=N"` → `hx-target="#event-rows"`

### Event Categories (for UI grouping)
Defined in `services/event_service.py` as `EVENT_CATEGORIES`:
- **Attack Surface**: INTERNET_NAME, IP_ADDRESS, TCP_PORT_OPEN, DOMAIN_NAME
- **Identities & Exposure**: EMAILADDR, USERNAME, SOCIAL_MEDIA, LEAKSITE_CONTENT
- **Infrastructure**: WEBSERVER_TECHNOLOGY, SSL_CERTIFICATE, BGP_AS_MEMBER, GEOINFO
- **Reputation**: MALICIOUS_IPADDR, BLACKLISTED_*, flagged affiliates
- **Vulnerabilities**: VULNERABILITY_CVE_*, VULNERABILITY_GENERAL

## Users, Sign-in and Access Control

SpiderFoot has distinct users, native OpenID Connect (OIDC) sign-in, group-based roles, per-scan ownership and sharing, and the MCP server acts as one of those users. With no OIDC configured and no passwd file the application behaves exactly as before (no sign-in, everybody is an administrator).

### Identity model

- `tbl_users` (`id`, `subject` unique, `username`, `email`, `display_name`, `groups` JSON text, `role` `admin|user`, `created`, `last_login`). `subject` is the OIDC `sub`, or `local:<name>` for passwd-file users and `local:admin` for the no-sign-in administrator. A provider cannot claim the `local:` namespace. Rows are upserted at every login (groups are refreshed each time); accounts whose groups deny them are never created.
- `tbl_scan_acl` (`scan_id`, `principal_type` `user|group`, `principal` = user id or group name, `level` `view|edit`, `granted_by`, `created`; unique per scan/type/principal; index on `scan_id`). Deleting a scan deletes its grants.
- `tbl_scan_instance.owner` (nullable user id). A scan without an owner is *legacy/unowned*: visible and editable by administrators only, and visible read-only to everyone when `_auth_unowned_visible` is `1`. Scans created without sign-in (no user) stay unowned.
- `tbl_mcp_tokens` (`id`, `user_id`, `name`, `hash` SHA-256 unique, `hint`, `created`, `last_used`, `expires` nullable).
- All of it is created or migrated idempotently when a database is opened (`spiderfoot/db_identity.py`, `SpiderFootDb._migrate_identity`): existing databases keep their data and gain an `owner` column that is `NULL`. The retired shared MCP token settings (`_mcp_token_hash`, `_mcp_token_hint`, `_mcp_token_created`) are deleted in the same step. "Reset settings to default" keeps `_oidc_*` and `_auth_*` so it cannot open the application up.
- `scanInstanceCreate(id, name, target, owner=None)` and `start_scan_core(..., owner=None)` stay backward compatible; the owner reaches the scan process as `cfg['__scan_owner']` and is also set from the web process once the scan exists.

### Roles

`services/identity.py`: `role_for(groups)` is `admin` for members of `_oidc_admin_groups`, `user` for members of `_oidc_user_groups` (or anybody when that list is empty), otherwise `denied` (friendly 403 page and a log line, no account created). The role is evaluated on every request from the groups stored at the last login, so changing the mapping or a user's groups applies immediately (a session or personal token of a denied account stops working at once). Passwd-file (HTTP Basic) users and the no-sign-in administrator are always `admin`, and Basic authentication keeps working unchanged for API clients (CSRF is skipped for Basic requests that carry no session).

### Access rules (`services/access.py`)

Levels: `view` < `edit` < `owner`. Administrators hold `owner` on every scan. The owner holds `owner`. A grant to the user or to any of their groups gives `view` or `edit` (the highest wins; grants never exceed `edit`). `edit` covers stop, rerun/clone, false-positive marking; it does not cover delete or changing sharing. Only the owner (or an administrator) can share, nobody can grant more than `edit`, and administrators can hand a scan to another user. A scan the user cannot see at all answers **404**; one they can see but not change answers **403**.

`can`, `scan_level`, `visible_scans`, `filter_scan_list`, `effective_level` and `can_grant` are small functions; `effective_level`, `can_grant` and `grant_level` are pure and unit tested with a full persona matrix (admin, owner, edit grantee, view grantee, group grantees, no access, legacy unowned).

### Enforcing it on every route (`services/route_policy.py`)

One table, `POLICIES`, lists every endpoint and what it requires; `before_request` (`check_auth` in `app.py`) authenticates, then calls `route_policy.authorize` before the view runs. A route that is missing from the table is refused to everybody except administrators, and `test_route_policy.py` fails when a route has no entry, when an entry is stale, or when a view reads a scan or correlation id (`id`, `ids`, `scan_id`, `correlation_id`) without being a scan route or a filtered list. Scan routes check **every** id in the request (comma lists and repeated parameters included) and a mixed request is refused as a whole. The root-level copy of the API (`/scanlist`, ...) follows the `/api/` entry.

| Requirement | Routes |
|---|---|
| public | `/api/ping`, `/auth/login`, `/auth/callback`, `/auth/logout`, static files |
| any signed-in user | `/newscan`, `/opts` (page; non-admins get Appearance and Agent (MCP) only), `/api/startscan`, module catalogue **read** (`/api/modules`, `/api/eventtypes`, `/api/correlationrules`, `/api/presets` GET), `/api/users`, `/api/groups`, `/auth/me`, `/api/mcp/settings` GET, `/api/mcp/tokens` (own tokens only), `/frag/settings-section?section=appearance` and `section=mcp` |
| any user, filtered to the scans they can see | `/` dashboard and its stat cards, `/api/scanlist`, `/frag/scan-table`, `/api/search`, `/api/scansearchresultexport` (a named scan must be viewable; without one only viewable scans are searched) |
| scan **view** | `/scaninfo`, `scanstatus`, `scansummary`, `scancorrelations`, `scaneventresults`, `scaneventresultsunique`, `scanopts`, `scanlog`, `scanerrors`, `scanhistory`, `scanelementtypediscovery`, `scanexportlogs`, `scancorrelationsexport`, `scaneventresultexport`, `scaneventresultexportmulti`, `scanexportjsonmulti`, `scanviz`, `scanvizmulti`, `/frag/results-tab`, `/frag/events`, `/frag/log-lines`, `/frag/scan/<id>/summary` (AI), `/frag/correlation/<id>/explain` (AI, resolved to its scan), `GET /api/scan/<id>/access` (view-only users see only their own level; edit and above see the grants) |
| scan **edit** | `stopscan`, `rerunscan`, `rerunscanmulti` (the new scan belongs to the caller), `resultsetfp` |
| scan **owner** | `scandelete`, `POST/DELETE /api/scan/<id>/access` (share, change level, remove) |
| **admin** | `/api/query` (raw SQL), `/api/scan/<id>/owner`, Settings (`savesettings`, `savesettingsraw`, `optsraw`, `optsexport`, `vacuum`), module catalogue **write** and module settings (`modulestate`, `modulesettings`, `moduletest`, preset create/update/delete/default), API usage, quotas and key checks (`/api/usage*`), AI/SearXNG/embeddings tests, `POST /api/mcp/settings`, `/api/access/*` (OIDC settings, test, user directory), `/frag/settings-section` for every section except `appearance` and `mcp` |

### Native OIDC (`services/oidc.py`, `blueprints/auth.py`)

Authorization-code flow with PKCE (S256), state and nonce. Discovery and JWKS are read from the issuer (cached ten minutes; an unknown `kid` triggers one refresh). ID tokens are verified with Authlib's JOSE (`authlib.jose`, RS/PS/ES algorithms only, so `none` and HMAC tokens are refused): signature, `iss` equals the discovery issuer, `aud` contains the client id (`azp` is checked when there are several), `exp`/`nbf`/`iat` (60 s leeway), the nonce, and `sub`. Groups come from the configured claim, or from the userinfo endpoint when the token has none (accepted only for the same `sub`). Provider responses are never shown: errors map to three fixed messages and the detail goes to the log without secrets. Issuer and endpoint URLs must be https (http only for localhost).

Routes: `/auth/login` shows the login page ("Sign in with SSO"; it mentions Basic authentication only when passwd users exist), `/auth/login?start=1&next=/path` starts the flow (`next` must be a same-site path: no scheme, host, `//`, backslash, control characters, or `/auth/...`), `/auth/callback`, `/auth/logout` (GET or POST; ends the session and redirects to the provider's `end_session_endpoint` when it has one), `/auth/me` (JSON, no secrets). Unauthenticated browsers (navigations) are redirected to the login page, script/htmx calls get `401` JSON (`HX-Redirect` for htmx), and other API clients get `401` plus the Basic challenge when passwd users exist; the Basic pop-up is never forced on a browser when OIDC is configured.

Session: signed Flask cookie, `HttpOnly`, `SameSite=Lax`, `Secure` when the request is https (forwarded headers count only when `_auth_trust_proxy` / `SF_TRUST_PROXY` is set); absolute lifetime `_auth_session_hours` (default 12), enforced server side and shortened or lengthened by the setting at once; the session is rebuilt at login (a new CSRF token, nothing from before survives). CSRF protection is unchanged for session users.

### Configuration

Environment first, then Settings > Access (stored in `tbl_config`; env-set values are locked in the UI; the client secret is never returned by any endpoint or page).

| Environment | Setting | Meaning |
|---|---|---|
| `SF_OIDC_ENABLED` | `_oidc_enabled` | `0` switches SSO off (the way back in after a misconfiguration) |
| `SF_OIDC_ISSUER` | `_oidc_issuer` | issuer URL |
| `SF_OIDC_CLIENT_ID` / `SF_OIDC_CLIENT_SECRET` | `_oidc_client_id` / `_oidc_client_secret` | client credentials (the secret is optional: PKCE-only public client) |
| `SF_OIDC_SCOPES` | `_oidc_scopes` | default `openid profile email groups` |
| `SF_OIDC_GROUPS_CLAIM` | `_oidc_groups_claim` | default `groups` |
| `SF_OIDC_ADMIN_GROUPS` / `SF_OIDC_USER_GROUPS` | `_oidc_admin_groups` / `_oidc_user_groups` | comma lists |
| `SF_OIDC_REDIRECT_URI` | `_oidc_redirect_uri` | default `<origin>/auth/callback` |
| `SF_OIDC_MCP_AUDIENCE` | `_oidc_mcp_audience` | audience of access tokens for the MCP server (default: the client id) |
| `SF_AUTH_SESSION_HOURS` | `_auth_session_hours` | default 12 |
| `SF_AUTH_UNOWNED_VISIBLE` | `_auth_unowned_visible` | `1`: scans without an owner are readable by everyone |
| `SF_TRUST_PROXY` | `_auth_trust_proxy` | proxy hops whose `X-Forwarded-*` headers are trusted (`1` = one) |

Turning SSO on from Settings > Access requires at least one admin group and an explicit acknowledgement, and a change that would remove the saving administrator's own admin access is refused. Register `<origin>/auth/callback` at the provider (the page shows it).

### MCP identity (`services/mcp_auth.py`, `mcp/wsgi.py`, `mcp/tools.py`)

The MCP server (port `SF_MCP_PORT`) authenticates as a user. Accepted bearer credentials: a **personal access token** (`sfmcp_...`, generated by any user in Settings > Agent (MCP), shown once, stored as a SHA-256 hash in `tbl_mcp_tokens`, optional expiry, `last_used`, revocable by its owner only), or an **OIDC access token** (a JWT from the configured issuer, validated like an ID token with audience `_oidc_mcp_audience` or the client id; groups from the groups claim, else the userinfo endpoint cached for 60 s). Both resolve to a `tbl_users` row (OIDC tokens upsert by `sub`) and the role is evaluated at use, so a user who loses their group, or whose account is denied, is refused at once (403, not counted as a failed login). The old shared `_mcp_token_hash` flow is gone.

Every tool applies the access rules: `list_scans` and the `get_*` tools only see scans the caller can view (a hidden scan "does not exist"), `stop_scan` and `rerun_scan` need edit, `delete_scan` needs owner (or admin) plus the operator permission `_mcp_allow_delete` and `confirm`, `create_scan` and `rerun_scan` record the caller as owner. The operator permissions (`_mcp_allow_scan`, `_mcp_allow_delete`, `_mcp_allow_active`, `_mcp_allow_private`, set by administrators together with the global `_mcp_enabled` switch) and the active/private guardrails stay a ceiling for everyone. Without OIDC and passwd users, personal tokens belong to the synthetic administrator `local:admin`.

`GET /.well-known/oauth-protected-resource` (also `.../mcp`) on the MCP listener publishes RFC 9728 metadata when OIDC is configured (`resource`, `authorization_servers` = the issuer, `bearer_methods_supported: ["header"]`), and a 401 carries `WWW-Authenticate: Bearer resource_metadata="..."`. Failed authentications are throttled per client address (10 per minute); the address is `X-Forwarded-For` only when `SF_TRUST_PROXY` is set (the entry the nearest trusted proxy appended).

### Testing

`test/unit/identity_helpers.py` has a fake OIDC provider (RSA key, discovery, JWKS, token and userinfo endpoints, PKCE check, all in memory) and helpers; see `test_auth_oidc.py` (login flow and every bad-token case), `test_route_policy.py` (every route, every persona), `test_scan_access_http.py` (lists, search, sharing, ownership, access settings), `test_identity_db.py` (migration of an old database), `services/test_access.py` (the matrix) and `services/test_mcp_identity.py`.

## Relevance Scoring (namesakes and fan-out)

A name match is not an identity match. For person (`HUMAN_NAME`) and business (`COMPANY_NAME`) scans every event is scored 0..1 for "is this about the target"; scans of domains, IPs and other targets are never scored or gated. Code: `services/relevance.py` (scorer), `relevance_names.py` (names, nicknames, slugs, company names), `relevance_profile.py` (target profile and context hints), `relevance_embed.py`, `relevance_llm.py`, `relevance_job.py` (staged pipeline, background job, scan-time gate, settings validation, sample test), `relevance_view.py` (display helpers), `db_relevance.py` (tables), `blueprints/relevance.py` (routes).

### Data model (created idempotently on every start, like the identity tables)

| Table | Purpose |
|---|---|
| `tbl_event_relevance (scan_id, event_hash, score, label, reasons JSON, method, updated)` | one row per scored event |
| `tbl_scan_context (scan_id, context, prune, created)` | the user's context hints and the prune switch of the scan |
| `tbl_relevance_override (scan_id, event_hash, verdict mine/not_related, user_id, created)` | corrections; they win over any score and are anchors / negative anchors |
| `tbl_relevance_run (scan_id, status, phase, progress, method, calls, tokens, embedded, started, ended, message, counts)` | status of the last assessment (`queued`, `running`, `done`, `failed`, `skipped`); runs left `running` by a restart are marked failed at start-up |
| `tbl_embedding_cache (model, text_hash, dim, vec BLOB, created)` | vectors keyed by (model@endpoint, sha256 of the text) |

`method` is `seed`, `override`, `scan-live`/`scan-gate` (written while the scan ran), `heuristics`, `heuristics+embeddings`, `heuristics+ai` or both. Deleting a scan removes its relevance rows; the embedding cache is shared.

### Pipeline

1. **Evidence per event.** Person scans: the names an event carries (the name field of a `HUMAN_NAME`, the head of a `PROFESSIONAL_LICENSE`, `first/middle/last` and alias fields of raw JSON, the handle in a profile URL or email) are compared to the target. Classes and base scores: `exact` 0.88 (middle name agrees), `exact_initial` 0.78, `name_only` 0.45 (0.55 when the target has no middle name), `initial_only` 0.30, `middle_as_first` 0.36, `last_only` 0.12, `conflict_initial` 0.12, `conflict_middle` 0.04, `different` 0.03; account names (slugs) count 0.05 less. Nicknames match (Nick/Nicholas); ids, counters and file extensions in handles are ignored.
   Adjustments: source reliability (web search hits -0.05, account finders -0.02/-0.03; a record that says it matched on the name only -0.10); a namesake-density penalty up to -0.10 when 10 or more people in the scan share a name without a middle name to compare; place against the hints +0.15 / -0.35 (same / different state), against the states of confirmed addresses +0.05 / -0.12, a place named in the hints +0.10; employer or hint words +0.25 / +0.12; a named relative +0.15; birth year +0.20 / -0.25; identifiers shared with an anchor +0.45; the same value from other modules +0.06 each up to +0.12. Conflicts are capped at 0.30 (0.60 with an anchor).
   Business scans: normalised company-name similarity to the target (same 0.90, close 0.60, partial 0.35, a different name found by searching 0.30) plus the same place and anchor adjustments.
2. **Records.** Events with the same CRD, NPI or CIK number, and short events (address, phone, firm, email) whose text appears in a sibling record of the same module and parent, share their name evidence: a positive match with a middle name wins, else a conflict, else a bare match. This is how a one-line "Nicholas Thornwood" broker summary is overruled by its raw record listing "NICHOLAS R THORNWOOD".
3. **Lineage.** Events are processed parents first (breadth first from the roots, once each, no recursion). With evidence of its own an event scores `own x (0.4 + 0.6 x parent)` (the target's direct children are not damped); without evidence it scores `parent x decay` where decay is 1.0 raw data, 0.95 filings and LEIs, 0.85 companies, 0.8 addresses, phones, people and URLs, 0.75 emails, 0.7 affiliates, 0.5 WiFi access points, times 0.75 when the parent is only "unclear". Direct children of the target without any evidence score 0.45 (business scans 0.60) of the parent: a search hit is not an identity. An address in another state than the hints or confirmed findings is multiplied by 0.6. Children of something marked not related are capped at 0.12.
4. **Embeddings (borderline findings only).** Embedding similarity to the person's name measures only that the name appears, which every namesake shares, so the target's own name is stripped from both texts and the comparison is between the context (hints: place, employer, field, plus confirmed attributes) and the finding's text (URL words, title and snippet of web hits). Without context hints the stage is skipped with a note. Adjustment `clamp(similarity - mid, -0.10, +0.20)`, `mid` = 0.50 (Settings). Texts are sent in batches of 64, identical texts once, at most `_rel_max_embed_texts` new texts per run, cached.
5. **AI adjudication (borderline `unclear` findings only).** Identical findings are grouped, the groups with the largest subtree go first, and batches of 10 `{id, type, text}` go to the AI endpoint (`_ai_*` settings, `_ai_redact_pii` honoured) with the target profile, asking for `{"results":[{"id","verdict":"same|different|unknown","confidence","reason"}]}`. The reply is parsed defensively (code fences, think tags, prose, NaN, duplicates, unknown ids are dropped). `same` raises the own score to at least `0.55 + 0.35 x confidence`; `different` lowers it to at most `0.30 - 0.25 x confidence`; `unknown` changes nothing. Caps: `_rel_max_llm_calls` (8) and `_rel_max_llm_tokens` (150,000, counted from the endpoint's own usage figures). Any failure keeps the local score.
6. **Labels.** `confirmed` >= 0.80, `likely` >= 0.55, `unclear` >= 0.25, `unrelated` below (settings `_rel_t_*`, percent, must rise). "Unclear" stays visible.

Each stage recomputes the lineage pass (cheap), so a borderline entity's verdict reaches everything under it. Performance: 11,244 events in about 2 s, 20,000 synthetic events in under 10 s in the test (no network stages).

### When it runs

* **In the scan** (`sfscan.py`, `relevance_job.RelevanceGate`): the engine scores every event before dispatching it (`LiveScorer`: own evidence and lineage, no records or density, about 0.05 ms per event). An event of an identity type (`IDENTITY_TYPES`: people, companies, filings, LEIs, accounts, addresses, phones, emails, raw records, ...) that scores below the hide threshold is marked `storeOnly`, which the dispatcher already honours: it is stored but no module but the storage module receives it. Events whose source was held are held too, which stops the fan-out. A cached embedding can veto a hold (the cache is only read, never filled, by the gate). `prune` off scores without holding. Held events carry the reason in the results.
* **After the scan** (`runRelevance`, in the scan's own process): the full pipeline, with embeddings and AI when the scan finished, heuristics only when it was aborted. Progress is in `tbl_relevance_run`.
* **On demand**: `POST /api/relevance/assess` starts the same function on a worker thread (`start_job`; one per scan, refused while running). It reads the stored events, overrides and context and replaces the stored scores, so it can be run any number of times.

### Routes and permissions

| Route | Access |
|---|---|
| `GET/POST /api/relevance/status?id=` | scan view |
| `GET /frag/relevance-card?id=` | scan view |
| `POST /api/relevance/assess` (`id`, optional `context`) | scan edit |
| `POST /api/relevance/mark` (`id`, `hashes`, `verdict` mine/not_related/clear, `scope` event/lineage) | scan edit |
| `POST /api/relevance/test` | administrator |
| `/frag/events?rel=hide/all/strong/unclear/unrelated&under=<hash>`, exports and search `include_unrelated=1` | scan view |

`/frag/events` does not read hidden events at all (`scanResultEvent(hideLabels=..., sourceLimit=...)`): the old query copied the parent's whole data for every child.

### Settings (`_rel_*`, Settings > Relevance)

`_rel_enabled`, `_rel_prune_default`, `_rel_auto_assess`, `_rel_use_embeddings`, `_rel_embeddings_url/_model/_apikey` (override; empty means the sfp_searxng ones), `_rel_embed_mid`, `_rel_max_embed_texts`, `_rel_use_ai`, `_rel_ai_model`, `_rel_max_llm_calls`, `_rel_max_llm_tokens`, `_rel_t_unrelated/_likely/_confirmed`. Saving validates ranges, on/off values, URLs (`urlcheck`) and that the thresholds rise. `_rel_embeddings_apikey` is redacted in `/api/optsraw`; the page only ever receives `********`.

### Measured on a real person-name scan (11,245 events)

Scan of a common person name that was aborted at 11,245 events (2,913 filings, 2,247 raw records, 2,203 addresses, 927 emails, 864 WiFi access points, 406 licences, 339 companies...), scored offline from an export of its events:

| Stage | Result |
|---|---|
| Local rules + lineage, no hints | 2.1 s; 1 confirmed (the target), 3 likely (accounts with the exact handle), 111 unclear, 11,129 unrelated (99.0%) |
| Same with the hint "location: Massachusetts" | 87 unclear |
| ... plus embeddings (117 texts, mxbai-embed-large-v1, 1024 dimensions, 4.4 s; a rerun is cached) | 52 unclear, 11,188 unrelated |
| No hints, plus the AI model (hermes, 3 calls of 10 groups, 112 s, 48,672 tokens as reported by the endpoint, about 16,000 per call because the server adds its own prompt) | 102 unclear, 11,138 unrelated; 30 of 87 borderline groups judged before the call cap |

What the local rules separate: other-middle-name physicians (NPI), brokers whose raw record lists another middle initial, every officer, company, address, WiFi access point and email found under them, and namesake profiles with another middle initial or first name are unrelated; the exact-handle accounts, name-only registry and profile hits and the leads found from them stay unclear or likely. Embedding similarity of a finding that contains the target's name scores about 0.65-0.70 for every namesake alike (it measures the name), so names are stripped and only context is compared: with a Boston/software hint, findings that match scored 0.68-0.78 and namesakes 0.33-0.51. The AI model answered the requested JSON schema for every batch (30 of 30 ids), mostly "unknown" for name-only items and "different" with a reason for another first name or middle name; it is conservative, slow (35-70 s per batch of 10) and cannot tell namesakes apart without hints.

Known weak spots: a handle with no name in it ("JetsFan006") stays unclear (nothing says it is not the target); the AI judged a band account "different: no personal name given", which is more than the evidence supports; a person who goes by their middle name ("Tom" for Thomas) scores 0.36 before adjustments and may be unclear or unrelated depending on the source.


### Gotchas

* `SpiderFootScanner` keeps its module registries in class-level dicts; a test that runs a real scan must clear `_SpiderFootScanner__moduleInstances` and `__modconfig` afterwards.
* The thread pool needs more threads than modules (each module's worker thread is separate, but a pool of 3 deadlocks in tests with 3 modules): tests use `_maxthreads` 12.
* `configUnserialize` has no float support: all `_rel_*` thresholds are integer percents.

## Module Anatomy

```python
class sfp_example(SpiderFootPlugin):
    meta = {
        "name": "Example Service",
        "summary": "What it does in one line.",
        "flags": ["apikey"],                    # or [] for no-auth
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://example.com/",
            "model": "FREE_AUTH_LIMITED",        # or FREE_NOAUTH_UNLIMITED, COMMERCIAL_ONLY
            "references": ["https://docs.example.com/"],
            "apiKeyInstructions": ["Visit...", "Sign up...", "Copy key..."],
            "description": "...",
        },
    }

    opts = {"api_key": "", "request_delay": 1.0}
    optdescs = {"api_key": "Example API key.", "request_delay": "Delay between requests."}

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        if self.errorState:
            return
        if event.data in self.results:
            return
        self.results[event.data] = True

        # Query API using self.sf.fetchUrl()
        res = self.sf.fetchUrl(url, headers=headers, timeout=self.opts["_fetchtimeout"])
        # Parse response, emit events
        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
        self.notifyListeners(e)
```

## API Endpoints

### Scan Lifecycle
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/startscan` | Start scan (params: scanname, scantarget, modulelist) |
| POST | `/api/stopscan?id=X` | Stop running scan |
| POST | `/api/scandelete?id=X` | Delete scan and data |
| GET | `/api/scanlist` | List all scans |
| GET | `/api/scanstatus?id=X` | Scan status + risk matrix |

### Data Retrieval
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/scaneventresults?id=X` | All events for a scan |
| GET | `/api/scansummary?id=X&by=type` | Summary grouped by type or module |
| GET | `/api/search?id=X&value=Y` | Search events (supports regex) |
| GET | `/api/scanexportjsonmulti?ids=X,Y` | Export as JSON |

### Config
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/optsexport` | Export config as CFG file |
| POST | `/api/savesettings` | Import config (JSON or CFG file) |
| GET | `/api/modules` | List all available modules |

## Current Module Count: 255

### By API Model
- FREE_NOAUTH_UNLIMITED: ~35 modules
- FREE_NOAUTH_LIMITED: ~11 modules
- FREE_AUTH_LIMITED: ~55 modules
- FREE_AUTH_UNLIMITED: ~15 modules
- COMMERCIAL_ONLY: ~10 modules
- Internal (no API): ~40 modules
- Tool wrappers: 17 modules

### New in v5.0.0 (22 modules)
Shodan InternetDB, LeakCheck, Hudson Rock, Criminal IP, Netlas.io, Validin, OpenSanctions, WhoisXML API, BeVigil, Postman, ZoomEye, FOFA, Snusbase, BBOT (4 wrappers), User Scanner, MISP, RansomLook, C2-Tracker, Vulners

### New in v5.1.0 (1 module)
Ransomware.live — leak-site victim lookup via the free v2 API. Adds the `RANSOMWARE_VICTIM` event type. Watches `DOMAIN_NAME` / `COMPANY_NAME` by default (configurable allowlist), 24h response cache, 65s inter-call throttle to respect the free 1 req/min limit.

## Scan Lifecycle

### Status Flow
```
STARTING → RUNNING → FINISHED
                   → ABORT-REQUESTED → ABORTED
                   → ERROR-FAILED
```

### How Scans Run
1. `POST /api/startscan` creates a scan instance in SQLite, spawns a `Process` (not thread)
2. The scan process loads selected modules, creates event queues
3. Root event is injected, modules consume/produce events via `handleEvent()`
4. Each module has its own `incomingEventQueue` and `outgoingEventQueue`
5. Modules call `self.checkForStop()` to poll for abort requests
6. When all queues are empty, scan transitions to `FINISHED`

### Known Limitation: No Per-Module Timeout
- `_fetchtimeout` (default 5s) only applies to individual HTTP requests via `fetchUrl()`
- There is NO timeout on module execution itself — a module iterating a /16 netblock or running BBOT can run for hours
- Workaround: manually `POST /api/stopscan?id=X` to set `ABORT-REQUESTED`

### Zombie Scan Reconciliation
- If the scan process dies abnormally (Docker restart, OOM, crash) the DB row stays `RUNNING` / `STARTING` / `ABORT-REQUESTED` indefinitely
- `start_web_server` calls `SpiderFootDb.scanInstanceReconcileZombies()` once before `create_app()`, rewriting all such rows to `ABORTED` with the current timestamp on `ended`
- The reconciler is intentionally NOT in `SpiderFootDb.__init__` — scan workers spawn their own DB handle and would mark their own just-started scan as a zombie

### Config Import/Export
- `GET /api/optsexport` → text/plain CFG file, format: `modulename:optionname=value` per line
- `POST /api/savesettings` → accepts JSON (`allopts` param) or CFG file upload (`configFile` param)
- Requires CSRF token from `GET /api/optsraw` (returned in response)
- `configSerialize()` and `configUnserialize()` in `sflib.py` handle the conversion
- Both methods iterate `__modules__` dynamically — new modules are auto-included

## Template Patterns

### Alpine.js in Tables
Tables don't allow wrapper elements between `<tr>` rows. For expandable row pairs:
```html
<!-- WRONG: x-data on <tr> doesn't scope to sibling <tr> -->
<tr x-data="{ expanded: false }">...</tr>
<tr x-show="expanded">...</tr>  <!-- Can't see 'expanded'! -->

<!-- RIGHT: wrap both rows in <tbody> -->
<tbody x-data="{ expanded: false }">
  <tr @click="expanded = !expanded">...</tr>
  <tr x-show="expanded" x-cloak>...</tr>
</tbody>
```

### HTMX Fragment Swap Target
The data tab uses a `<table id="event-rows">` as the HTMX swap target. The fragment response contains `<tbody>` elements (one per expandable row pair). HTMX's default `innerHTML` swap replaces the table's children correctly.

### Jinja2 Pitfalls
- Dict key `items` → collides with `dict.items()`. Use `entries` instead.
- `{{ "{:,}".format(number) }}` for comma-formatted numbers
- `{{ [a, b] | min }}` for inline min in templates

## Database Schema (Key Queries)

```sql
-- Scan list with event counts
SELECT s.guid, s.name, s.seed_target, s.created, s.started, s.ended,
       s.status, COUNT(r.type) FROM tbl_scan_instance s
LEFT JOIN tbl_scan_results r ON s.guid = r.scan_instance_id
GROUP BY s.guid ORDER BY s.started DESC

-- Event summary by type
SELECT r.type, e.event_descr, MAX(r.generated) AS last_in,
       COUNT(r.type) AS total, COUNT(DISTINCT r.data) AS utotal
FROM tbl_scan_results r, tbl_event_types e
WHERE r.scan_instance_id = ? AND r.type = e.event
GROUP BY r.type ORDER BY e.event_descr

-- Events for a scan (used by data tab)
SELECT r.generated, r.data, r.source_data, r.module, r.type,
       r.confidence, r.visibility, r.risk, r.hash, r.source_event_hash,
       e.event_descr, e.event_type, r.scan_instance_id, r.false_positive
FROM tbl_scan_results r, tbl_event_types e
WHERE r.scan_instance_id = ? AND r.type = e.event
ORDER BY r.generated DESC
```

## Docker

One image (`python:3.15-alpine`, multi-stage, non-root user). A `tools` build stage downloads and builds the local-tool binaries and the final image copies them in, so the `sfp_tool_*` modules work without configuration:

```bash
docker build -t spiderfoot-revival .
docker run -p 127.0.0.1:5001:5001 -v ~/.spiderfoot:/var/lib/spiderfoot spiderfoot-revival
```

Bundled: nmap, nbtscan, onesixtyone, nuclei (with templates), trufflehog, testssl.sh, WhatWeb, CMSeeK, retire.js, wafw00f, snallygaster, dnstwist, and BBOT 3.0.2 in its own Python 3.13 environment (built from source; its Python dependencies are installed at build time because BBOT cannot install them as an unprivileged user). `Dockerfile.full` is the older all-in-one variant.

For BBOT active port scanning (masscan SYN scans) add `--cap-add=NET_RAW`; without it BBOT falls back to TCP-connect.

### Optional Dependencies
- **bbot**: Required for `sfp_tool_bbot_*` modules. Pre-installed in `Dockerfile.full`. For local dev: `pip install bbot && bbot --install-all-deps -y`. Modules pass `--no-deps` at runtime; if you skip the install step BBOT will hang on a sudo prompt and silently emit nothing.
- **user-scanner**: Included in `requirements.txt`. Used by `sfp_userscanner` for email registration + username checking.

### Event Type Reference (common mistakes)
- Cloud buckets: `CLOUD_STORAGE_BUCKET` (exists) / `CLOUD_STORAGE_BUCKET_OPEN` (open). NOT `CLOUD_STORAGE_OPEN`.
- Code repos: `PUBLIC_CODE_REPO`. NOT `CODE_REPOSITORY`.
- Malicious emails: `MALICIOUS_EMAILADDR`. NOT `MALICIOUS_INTERNET_NAME` for email indicators.

### Testing Workflow
```bash
docker stop sf-test 2>/dev/null; docker rm sf-test 2>/dev/null
docker build -t spiderfoot-revival .
docker run -d --name sf-test -p 5001:5001 spiderfoot-revival
sleep 5
curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/       # Dashboard
curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/newscan # New scan
docker logs sf-test 2>&1 | grep -i error                            # Check errors
```
