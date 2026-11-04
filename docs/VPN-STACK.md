# Running SpiderFoot through a VPN, with SearXNG and embeddings

`examples/vpn-stack/` is a Docker Compose example that runs SpiderFoot so that everything it sends to the internet goes through a WireGuard tunnel, together with the two optional services its search and relevance features use:

- **WireGuard** (the tunnel and a kill switch)
- **SpiderFoot** (this image)
- **SearXNG** (private web search for the search modules)
- **llama-swap** (a local embeddings endpoint for ranking search results and scoring relevance)

It is a starting point, not a hardened production setup. Read [Security notes](#security-notes) before exposing anything beyond your own machine.

The compose file is validated with `docker compose config`. The WireGuard tunnel, the SearXNG settings and the embeddings model download depend on your VPN account and network, so check each one as described in [Verify it](#verify-it).

## Why

- Scans, API calls and web searches show the VPN's address to the targets and services, not yours.
- If the tunnel drops, SpiderFoot cannot fall back to your normal connection. The traffic is rejected instead.
- SearXNG forwards your queries to public search engines. Running it inside the tunnel keeps those queries off your own address too, and SpiderFoot does not need a third-party search API.
- Embeddings run locally, so scan targets and hints are not sent to a hosted embeddings service.

## How it fits together

```
                       host (loopback by default)
                       127.0.0.1:5001   127.0.0.1:8888     127.0.0.1:9292
                              |                |                  |
        +---------------------+----------------+-----+            |
        |  wireguard container (network namespace)   |            |
        |  +-------------+   +----------+            |   private  |
        |  | spiderfoot  |   | searxng  |            |   network  |
        |  | :5001       |   | :8080    |            |<---------->| llama-swap :8080
        |  +-------------+   +----------+            |            | (not tunnelled)
        |          all other traffic -> wg0 -> VPN    |            |
        +--------------------------------------------+            |
```

`spiderfoot` and `searxng` use `network_mode: service:wireguard`, so they share the WireGuard container's network stack. They have no network interface of their own, which is why their ports are published on the `wireguard` service. They reach each other at `localhost`.

`llama-swap` is on a normal Docker network and is not tunnelled. It only talks to SpiderFoot, and downloads the embeddings model from Hugging Face the first time it is used. SpiderFoot reaches it by service name, which works because the private ranges are exempt from the kill switch (below).

## Files

| File | Purpose |
| --- | --- |
| `examples/vpn-stack/docker-compose.yml` | The four services |
| `examples/vpn-stack/.env.example` | Settings: SearXNG secret, bind address, time zone |
| `examples/vpn-stack/wireguard/wg_confs/wg0.conf.example` | WireGuard config template with the kill switch |
| `examples/vpn-stack/searxng/settings.yml` | SearXNG settings (JSON output on, rate limiter off) |
| `examples/vpn-stack/llama-swap.yaml` | llama-swap model list (one embeddings model) |

`.env` and `wg0.conf` are in `.gitignore`. `wg0.conf` holds your private key.

## Set up

1. **Get a WireGuard configuration** from your VPN provider (the `[Interface]` and `[Peer]` values).
2. Create your files:
   ```bash
   cd examples/vpn-stack
   cp .env.example .env
   cp wireguard/wg_confs/wg0.conf.example wireguard/wg_confs/wg0.conf
   ```
3. **Edit `.env`**: set `SEARXNG_SECRET` (`openssl rand -hex 32`).
4. **Edit `wg0.conf`**: replace the `<...>` placeholders with the values from your provider (private key, tunnel address, the peer's public key and endpoint). Leave the `PostUp` and `PreDown` lines as they are unless you have a reason to change them.
5. Start it:
   ```bash
   docker compose up -d
   docker compose logs -f wireguard
   ```
   The first start pulls the images (SpiderFoot's is about 1.4 GB).

Open [http://127.0.0.1:5001](http://127.0.0.1:5001).

## Verify it

Do these once; they are the only proof the kill switch works.

```bash
# 1. SpiderFoot's outbound address is the VPN's, not yours
docker exec sf-searxng wget -qO- https://ifconfig.me ; echo
curl -s https://ifconfig.me ; echo          # compare: your real address

# 2. SearXNG answers and returns JSON
curl -s 'http://127.0.0.1:8888/search?q=test&format=json' | head -c 300

# 3. Embeddings work (the first call downloads the model and takes a while)
curl -s http://127.0.0.1:9292/v1/embeddings \
  -H 'Content-Type: application/json' \
  -d '{"model":"nomic-embed","input":"hello"}' | head -c 200

# 4. The kill switch: take the interface down (this leaves the firewall rule in
#    place; do not use wg-quick down, its PreDown removes the rule). Outbound
#    traffic must fail instead of leaving on your real connection.
docker exec sf-wireguard ip link set wg0 down
docker exec sf-searxng wget -qO- -T 5 https://ifconfig.me ; echo "exit: $?"   # should fail
# restore everything that shares the namespace
docker compose up -d --force-recreate wireguard spiderfoot searxng
```

If the first two addresses match, the tunnel is not in use. Check `docker compose logs wireguard`.

## Configure SpiderFoot

SpiderFoot's settings are in the web UI; the example does not preset them.

**Settings → Web Search → SearXNG**

| Field | Value |
| --- | --- |
| Instance URL | `http://localhost:8080` |

Press **Test SearXNG**. It should report a result count. SearXNG must return JSON, which `searxng/settings.yml` enables.

**Settings → Web Search → Embeddings**

| Field | Value |
| --- | --- |
| Endpoint URL | `http://llama-swap:8080/v1` |
| Model | `nomic-embed` |
| API key | leave empty |

Press **Test embeddings**. The first test loads the model, which can take a minute while it downloads (about 150 MB for the quantised model).

The same embeddings endpoint is used by **Settings → Relevance**. See the README's [Relevance scoring](../README.md#relevance-scoring) section.

## The RFC 1918 rule and what it allows

`wg0.conf` exempts the three private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) from the tunnel and from the kill switch. Docker's own networks live in `172.16.0.0/12`, so this is what lets SpiderFoot reach `llama-swap`, and lets replies reach your host when you open the UI.

It also means SpiderFoot, and anything you ask it to scan, can reach private addresses on your own network. SpiderFoot does not stop its modules fetching private addresses (see "Scans leave from this machine" in the README). If you do not want that:

- Replace the three ranges in `PostUp` and `PreDown` with only what you need, for example the subnet of the `internal` Docker network (`docker network inspect spiderfoot-vpn_internal`) and the address of your host.
- Add host firewall rules (`DOCKER-USER` chain) that stop the `wireguard` container reaching your LAN.

If your VPN provider uses `10.x` addresses for its own DNS or gateway (some do), the `10.0.0.0/8` route sends those outside the tunnel and name lookups break. Narrow that range, or set `dns:` on the `wireguard` service to a public resolver, as the example does with `1.1.1.1`.

## Changing things

- **A different embeddings model.** Edit `llama-swap.yaml` and the Model field in SpiderFoot. Any llama.cpp-compatible embeddings GGUF works; add `--embedding`.
- **A GPU.** `llama-swap:cpu` is used so the example runs anywhere. For NVIDIA or Vulkan use one of llama-swap's unified images (`unified-cuda13`, `unified-cuda`, `unified-vulkan`), mount the config at `/etc/llama-swap/config/config.yaml`, and pass the GPU to the container. See the [llama-swap README](https://github.com/mostlygeek/llama-swap) for the exact flags.
- **Skip embeddings.** Delete the `llama-swap` service and its `depends_on` line. SpiderFoot's relevance scoring and search ranking still work without it, using the rules only.
- **Skip SearXNG.** Delete the `searxng` service, its `depends_on` line and the `8888` port. The search modules hide themselves.
- **Expose the UI to other machines.** Do not just change `BIND_ADDRESS`. Put an authenticating reverse proxy in front, or turn on SpiderFoot's OIDC sign-in. See the README, "Running it safely".
- **Pin versions.** The example uses `latest` tags so it works today. Pin them for anything you depend on.

## Security notes

- SearXNG has no login and the rate limiter is off. It is published on the same address as the UI, loopback by default. Do not put it on a public interface.
- The tunnel hides your address from the services SpiderFoot contacts. It does not make scans anonymous or authorised, and the VPN provider can see the traffic. Only scan what you are permitted to scan.
- Only the WireGuard container gets `NET_ADMIN`. SpiderFoot and SearXNG share its network namespace, not its capabilities.
- `llama-swap` runs as root in this example to write the model cache volume. Run it as a normal user with a pre-owned volume if that matters to you.
- Back up the `spiderfoot-data` volume. It holds your database and API keys.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `sf-wireguard` is unhealthy | No handshake: wrong key or endpoint, or UDP is blocked. `docker compose logs wireguard`. |
| UI loads but scans find nothing and nothing resolves | DNS is not going through the tunnel, or the provider's DNS is in `10.x`. See the RFC 1918 note. |
| `Test SearXNG` says it cannot connect | SearXNG is not running yet, or the URL is not `http://localhost:8080` (it is in the same network namespace as SpiderFoot). |
| `Test SearXNG` says JSON is disabled | `searxng/settings.yml` was not mounted; check `docker compose logs searxng`. |
| `Test embeddings` times out the first time | The model is downloading. Run `docker compose logs -f llama-swap` and retry. |
| A restart of `wireguard` leaves SpiderFoot with no network | They share a namespace that was recreated. Recreate them together: `docker compose up -d --force-recreate wireguard spiderfoot searxng`. |
