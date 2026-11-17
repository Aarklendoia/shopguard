# Changelog

## [0.6.0](https://github.com/Aarklendoia/shopguard/compare/worker-v0.5.1...worker-v0.6.0) (2026-11-17)


### Features

* **worker:** check command, verdicts of domains analyzed once ([#48](https://github.com/Aarklendoia/shopguard/issues/48)) ([0a8d81b](https://github.com/Aarklendoia/shopguard/commit/0a8d81b304865f8bcd4ff31ad6254f4430e546f7))
* **worker:** domain history from the Internet Archive and crt.sh ([#50](https://github.com/Aarklendoia/shopguard/issues/50)) ([32116c9](https://github.com/Aarklendoia/shopguard/commit/32116c9b1ea3d244967e6a6c528f80de73943c53))
* **worker:** shop heuristics, fake shop kit and uniform discount ([#51](https://github.com/Aarklendoia/shopguard/issues/51)) ([a64df0a](https://github.com/Aarklendoia/shopguard/commit/a64df0a837fc643261cf26b6e70f056ea4025432))

## [0.5.1](https://github.com/Aarklendoia/shopguard/compare/worker-v0.5.0...worker-v0.5.1) (2026-11-17)


### Bug Fixes

* **worker:** legal notice of redirected domains, platform names are not shops ([#46](https://github.com/Aarklendoia/shopguard/issues/46)) ([e62bdd3](https://github.com/Aarklendoia/shopguard/commit/e62bdd31a0ebf085a812e59c57946c51f6f99a9e))

## [0.5.0](https://github.com/Aarklendoia/shopguard/compare/worker-v0.4.0...worker-v0.5.0) (2026-11-16)


### Features

* **worker:** legal notice and SIREN/SIRET check ([#44](https://github.com/Aarklendoia/shopguard/issues/44)) ([f7ef948](https://github.com/Aarklendoia/shopguard/commit/f7ef94803ec2687a421dc162468f7fbad20acb24)), closes [#8](https://github.com/Aarklendoia/shopguard/issues/8)

## [0.4.0](https://github.com/Aarklendoia/shopguard/compare/worker-v0.3.1...worker-v0.4.0) (2026-11-16)


### Features

* **worker:** hardened page fetcher and home page analyzer ([#42](https://github.com/Aarklendoia/shopguard/issues/42)) ([8a5fca0](https://github.com/Aarklendoia/shopguard/commit/8a5fca0caf63f8c3d3f5f632fa34378eaebf14dc))

## [0.3.1](https://github.com/Aarklendoia/shopguard/compare/worker-v0.3.0...worker-v0.3.1) (2026-11-13)


### Bug Fixes

* **worker:** a certificate for other names is not an invalid certificate ([#40](https://github.com/Aarklendoia/shopguard/issues/40)) ([02e4877](https://github.com/Aarklendoia/shopguard/commit/02e4877cf753ff218d4a2fa1342684c4377a22fe))

## [0.3.0](https://github.com/Aarklendoia/shopguard/compare/worker-v0.2.0...worker-v0.3.0) (2026-11-13)


### Features

* verdict list in the plugin ([#38](https://github.com/Aarklendoia/shopguard/issues/38)) ([fdaf215](https://github.com/Aarklendoia/shopguard/commit/fdaf2152e395e4463ff04fbd3b1b7f31038cef4b)), closes [#6](https://github.com/Aarklendoia/shopguard/issues/6)

## [0.2.0](https://github.com/Aarklendoia/shopguard/compare/worker-v0.1.0...worker-v0.2.0) (2026-11-13)


### Features

* **worker:** hosting network signal ([#29](https://github.com/Aarklendoia/shopguard/issues/29)) ([e779cdc](https://github.com/Aarklendoia/shopguard/commit/e779cdcd2cc3239f5efae3fe4416e5e257843c56)), closes [#3](https://github.com/Aarklendoia/shopguard/issues/3)
* **worker:** persist verdicts and re-check them ([#31](https://github.com/Aarklendoia/shopguard/issues/31)) ([bff61b7](https://github.com/Aarklendoia/shopguard/commit/bff61b7d7e9b7ef7bd0aeb44a3b3812bee3ff975)), closes [#4](https://github.com/Aarklendoia/shopguard/issues/4)

## 0.1.0 (2026-11-13)


### Features

* initial skeleton (worker, plugin, CI) ([633ffb4](https://github.com/Aarklendoia/shopguard/commit/633ffb4fee31efbf59b72b0476210d29331fdd70))
* **worker:** RDAP domain age signal ([#24](https://github.com/Aarklendoia/shopguard/issues/24)) ([6187a77](https://github.com/Aarklendoia/shopguard/commit/6187a7713ae1c294d65c4016bffcb9361019b8ce)), closes [#1](https://github.com/Aarklendoia/shopguard/issues/1)
* **worker:** TLS certificate signal ([#25](https://github.com/Aarklendoia/shopguard/issues/25)) ([34e4b9c](https://github.com/Aarklendoia/shopguard/commit/34e4b9cd2ebf3438d5f9ee41f03621a45e08191c)), closes [#2](https://github.com/Aarklendoia/shopguard/issues/2)
