# shopguard

Detection of **fake online shops** for **OPNsense**: an OPNsense plugin sends the domains
resolved by Unbound DNS to a small worker running in Docker on the local network, which
scores them and, in blocking mode, feeds the suspicious ones back into the Unbound blocklist.

DNS blocklists (HaGeZi *Fake*, …) always lag behind: fake shops are set up in an afternoon,
often on a recently bought expired domain, and are only listed after the first victims
report them. shopguard looks at each new domain the household visits and judges it on what
it can check right away.

```
 OPNsense (router)                                  Docker host (e.g. a home server)
┌───────────────────────────────┐                 ┌───────────────────────────────────┐
│ Unbound ──> os-shopguard      │  domain names   │ shopguard-worker                  │
│             collects new      │ ──────────────> │  domain:  RDAP age, certificate,  │
│             registrable       │                 │           hosting (ASN), CT logs  │
│             domains           │  verdicts,      │  page:    legal notice, SIRET,    │
│ Unbound <── blocklist         │ <────────────── │           shop heuristics         │
└───────────────────────────────┘   blocklist     └───────────────────────────────────┘
```

- **Privacy**: the plugin sends **domain names only**, never client addresses or timestamps.
  The worker queries public services about those domains (RDAP registries, Certificate
  Transparency logs, the French company directory) and fetches the sites themselves, from
  the Docker host.
- **Observe first**: by default suspicious domains are only listed in the interface. Small
  legitimate shops are new domains on Shopify too: blocking only makes sense once the
  scoring has proven itself on your network.
- **Light**: the worker is one static Rust binary in an empty (`scratch`) image: no shell,
  no libc, no OpenSSL (TLS through rustls). Security updates are only needed when a Rust
  dependency has an advisory.

> **Status: early development.** The pipeline, API and plugin settings are in place; the
> analyzers are being added one by one, see the
> [issues](https://github.com/Aarklendoia/shopguard/issues) and milestones.

## Repository layout

```
worker/                          shopguard-worker (Rust)
  src/api.rs                     HTTP API used by the plugin
  src/analysis.rs                scoring pipeline, Analyzer trait
  src/domain.rs                  registrable domain (Public Suffix List)
  src/http.rs                    HTTP client of the analyzers (HTTPS, public addresses only)
  src/netguard.rs                which addresses the worker may connect to (SSRF guard)
  src/rdap.rs                    analyzer: domain registration age (RDAP)
  src/siret.rs                   SIREN/SIRET validation
  src/tls.rs                     analyzer: certificate presented on port 443
  Dockerfile                     local build
  Dockerfile.release             release image (static binaries built by CI)
plugin/dns/shopguard/            os-shopguard OPNsense plugin
plugin/tests/                    plugin backend tests (fake worker)
deploy/docker-compose.yml        example worker deployment
```

## Worker

### Run

```sh
openssl rand -hex 32 > .shopguard-token
SHOPGUARD_TOKEN=$(cat .shopguard-token) docker compose -f deploy/docker-compose.yml up -d
```

| Variable              | Default     | Meaning                                                  |
|-----------------------|-------------|----------------------------------------------------------|
| `SHOPGUARD_TOKEN`     | (required)  | bearer token shared with the plugin, ≥ 32 characters     |
| `SHOPGUARD_LISTEN`    | `[::]:8080` | listen address; falls back to `0.0.0.0` without IPv6     |
| `SHOPGUARD_THRESHOLD` | `70`        | minimum score of the domains in the blocklist (0–100)    |
| `SHOPGUARD_QUEUE`     | `10000`     | maximum number of domains waiting for analysis           |
| `SHOPGUARD_LOG`       | `info`      | log filter, e.g. `info,shopguard_worker=debug`           |

Updating the image is up to you (Watchtower, Renovate on your compose files, or by hand):
`ghcr.io/aarklendoia/shopguard-worker` is tagged `X.Y.Z`, `X.Y` and `latest`, and signed
with cosign (keyless, GitHub Actions identity of this repository).

### API

| Method | Path                    | Purpose                                         |
|--------|-------------------------|-------------------------------------------------|
| GET    | `/healthz`              | liveness, no token                              |
| GET    | `/v1/status`            | version, queue length                           |
| POST   | `/v1/domains`           | `{"domains": [...]}`, at most 5000 per request  |
| GET    | `/v1/verdicts`          | verdicts, `?min_score=`                         |
| GET    | `/v1/verdicts/{domain}` | one verdict, with its signals                   |
| GET    | `/v1/blocklist`         | domains scoring at least the threshold, as text |

Every `/v1` route expects `Authorization: Bearer <SHOPGUARD_TOKEN>`.

### Develop

```sh
cd worker
cargo test
cargo clippy --all-targets -- -D warnings
SHOPGUARD_TOKEN=dev-token-0123456789abcdef0123456789 SHOPGUARD_LOG=debug cargo run
```

## Plugin

`os-shopguard` adds **Services → ShopGuard**: worker URL and token, mode (observe or
block), score threshold, worker status. Installation from a signed package repository,
with updates through the OPNsense firmware updates, comes with the packaging issue (same
mechanism as [apu-firmware](https://github.com/Aarklendoia/apu-firmware)).

```sh
python3 -I plugin/tests/test_shopguard.py plugin/dns/shopguard/src/opnsense/scripts/OPNsense/ShopGuard/shopguard.py
```

## Releases

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/)
with the scope `worker` or `plugin` (`feat(worker): RDAP domain age`). release-please keeps
a release PR per component; merging it tags `worker-vX.Y.Z` or `plugin-vX.Y.Z`. A worker
release builds and pushes the image.

## License

BSD 2-Clause, see [LICENSE](LICENSE).
