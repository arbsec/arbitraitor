# Registry-Based Package Managers: Arbitraitor Integration Research

**Audience:** Arbitraitor maintainers preparing a spec §39.x addendum for cargo, uv/uvx, npm, pnpm, yarn (classic + berry), and bun.
**Date:** 2026-06-29.
**Status:** Research report — drives ADR + spec section + ticket creation.

The existing §39.11 (Homebrew) and §39.12 (Arch AUR / `paru` / `yay`) adapters cover *source-based* package managers whose recipe file is executable. Registry-based managers (cargo, uv, npm, pnpm, yarn, bun) differ fundamentally:

- The "recipe" is declarative metadata (`Cargo.toml`, `pyproject.toml`, `package.json`) — not executable code.
- The registry serves static tarballs; verification is byte-identity against `Cargo.lock` / `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` / `bun.lock` / `uv.lock`.
- Some managers (cargo, npm, uv with PEP 517 backends) execute arbitrary code during install (build scripts, lifecycle scripts, PEP 517 build backends).

This report covers: per-tool interception mechanisms, prior art, threat surface, integration patterns, and a plugin classification recommendation.

---

## Section A — Per-tool interception mechanisms

### A.1 Cargo (Rust)

**Registry / protocol.**
Two index protocols: `git` (default until Rust 1.68, March 2023) and `sparse` (HTTP, default since Rust 1.70, June 2023) — see [Registries — The Cargo Book](https://doc.rust-lang.org/cargo/reference/registries.html). The crates.io sparse URL is `sparse+https://index.crates.io/`. Registries are configured via `[registries.<name>]` in `.cargo/config.toml` or `CARGO_REGISTRIES_<NAME>_INDEX` env var (the [sparse-registry stabilisation PR #11224](https://github.com/rust-lang/cargo/pull/11224) added the env var as the canonical override). Private registries require `auth-required: true` in their `config.json`.

**Registry override.**
`.cargo/config.toml`:

```toml
[registries.crates-io]
protocol = "sparse"

[registries.my-internal]
index = "sparse+https://internal.example.com/index"
```

Or pure env: `CARGO_REGISTRIES_MY_REGISTRY_INDEX=…`, `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`, `CARGO_NET_GIT_FETCH_WITH_CLI=true`. Source replacement (`[patch.*]`) is the official mechanism for redirecting registry URLs without touching `Cargo.lock` — see §"Sparse Limitations" in the [Registry Index reference](https://dev-doc.rust-lang.org/stable/cargo/reference/registry-index.html).

**Lockfile.**
`Cargo.lock` (TOML, lockfile versions V1/V2/V3/V4). Cargo writes per-package `checksum` (sha256 of the `.crate` tarball) inline on every `[[package]]` since V2 — confirmed in [`encode.rs`](https://doc.rust-lang.org/nightly/nightly-rustc/cargo/core/resolver/encode/index.html):
> "All packages from registries contain a `checksum` which is a sha256 checksum of the tarball the package is associated with."

`git` dependencies pin to a commit SHA in the `source` URL. Path and git deps have `checksum = None` — see [`resolve.rs`](https://docs.rs/cargo/latest/src/cargo/core/resolver/resolve.rs.html) (`Option<String>` for checksum, `None` for sources that do not use `.crate` files). Tarball integrity is verified at download time, but there is no per-package cryptographic signature (no Sigstore, no minisign) — see [Stack Exchange: Does cargo provide cryptographic authentication and integrity validation](https://security.stackexchange.com/questions/257076/does-rusts-cargo-provide-cryptographic-authentication-and-integrity-validation) and [`Cargo.toml vs Cargo.lock`](https://doc.rust-lang.org/stable/cargo/guide/cargo-toml-vs-cargo-lock.html).

**Lifecycle scripts / build execution.**

- `build.rs` — executed by Cargo on every consumer build (not gated by an env var). Recent incidents: [`onering@1.4.1` build.rs exfiltrated `git diff HEAD^ HEAD`](https://corgea.com/research/onering-crates-build-rs-sentry-source-exfiltration) (Corgea, 2026-06-10); [TrapDoor cross-registry campaign used `build.rs` for 6 Rust crates](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) (Socket, 2026-05-24); [GHSA-5PMP-JPCF-PWX6: typosquatted `tracing-check` used `build.rs`](https://cvereports.com/reports/GHSA-5PMP-JPCF-PWX6) (CVE Reports, 2026-03-02).
- Proc macros — loaded at compile time, run arbitrary Rust code.
- `build-dependencies` — separate tree; can run code without being in the runtime dep tree.
- `dev-dependencies` — only for the workspace root, but visible during `cargo build` / `cargo test`.
- No first-party "disable build scripts" flag; community workaround is `[target.'cfg(...)'.dependencies] foo = { version = "…", default-features = false }` plus patching out `build.rs` via `[patch.crates-io]`.

**Workspaces.**
[Yes](https://doc.rust-lang.org/cargo/reference/workspaces.html) (`[workspace] table in root `Cargo.toml`). A single `Cargo.lock` is shared across workspace members. Workspace members are not separately resolvable — the entire lockfile is the unit of inspection.

**Cache layout.**
`~/.cargo/registry/cache/<registry-name>/<crate>-<version>.crate` (the verified tarballs) and `~/.cargo/registry/src/<registry-name>/<crate>-<version>/` (extracted sources). Both are local; inspectable but not content-addressed. The current cache state is reproducible from `Cargo.lock`, so re-fetching re-validates integrity.

**Auth.**
`CARGO_REGISTRY_TOKEN` env var or `[registries.<name>] token = "…"` in `.cargo/config.toml`. Tokens are scoped per registry. Notably for security: cargo's [issue #16850 `cargo verify-sources`](https://github.com/rust-lang/cargo/issues/16850) — proposed but not yet shipped — would verify on-disk cache against `Cargo.lock`. As of 2026-06 this command does not exist.

**Native hook points.**
None. Cargo has no plugin/proxy/seam designed for security tooling. Third-party `cargo` subcommands (`cargo audit`, `cargo vet`) hook the `~/.cargo/bin` PATH convention but cannot intercept the download/build flow.

### A.2 uv / uvx (Astral)

**Registry / protocol.**
[uv speaks PEP 503](https://docs.astral.sh/uv/concepts/package-indexes/) (the "Simple Repository API") and the JSON API used by PyPI's `pypa-advisory-database`. Default index is `https://pypi.org/simple`. Supports multiple indexes via `[[tool.uv.index]]` in `pyproject.toml` or `[tool.uv.sources]`. Recognised env vars: `UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL`, `UV_INDEX` (deprecated `UV_INDEX_URL`), `UV_INDEX_<NAME>_USERNAME/PASSWORD` — full list in [Environment variables | uv](https://docs.astral.sh/uv/reference/environment/).

**Registry override.**
Multiple, in increasing specificity (later overrides earlier):

1. Project `pyproject.toml` `[tool.uv.index]`.
2. `uv.toml` config file (`UV_CONFIG_FILE`).
3. Env: `UV_INDEX`, `UV_DEFAULT_INDEX`, `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`.
4. CLI: `--index`, `--default-index`, `--extra-index-url`, `--find-links`.

[HTTP credentials](https://docs.astral.sh/uv/concepts/authentication/http/) precedence: URL-embedded `user:pass@` → `~/.netrc` (path from `NETRC`) → uv credentials store (`~/.local/share/uv/credentials/credentials.toml` on Unix) → keyring (`--keyring-provider subprocess`, default off). [`uv auth login <host>`](https://docs.astral.sh/uv/concepts/authentication/cli/) stores secrets.

**Lockfile.**
[`uv.lock`](https://docs.astral.sh/uv/concepts/projects/layout/) — TOML, version 1. Pins every resolved version + per-wheel `sha256` hashes (a lockfile entry embeds the `[[package]]` for wheels and source dists alike). Confirmed by [Locking and syncing](https://docs.astral.sh/uv/concepts/projects/sync/): the lockfile is the authoritative source of versions and hashes. `--locked` fails if the lockfile is stale; `--frozen` allows execution against a possibly-stale lockfile; `--no-sync` skips even the sync check. `[tool.uv] require-hashes = true` (or `--require-hashes`) enforces hash presence.

uv added a **built-in malware check** — see [Locking and syncing § Malware checks](https://docs.astral.sh/uv/concepts/projects/sync/):
> "While syncing, uv can perform a lightweight scan of your lockfile for known malware by checking it against OSV. OSV references MAL advisories from the OpenSSF's malicious packages database. […] To enable malware checks, set `UV_MALWARE_CHECK=1` in your environment."

The default endpoint is `https://api.osv.dev/` (overridable via `UV_MALWARE_CHECK_URL`). This is the single most relevant first-party feature for Arbitraitor — uv is the only registry-based tool that ships install-time malware screening as a core capability.

**Lifecycle scripts / build execution.**
PEP 517 build backends (`hatchling`, `setuptools`, `maturin`, `flit`, `poetry-core`, `scikit-build-core`, `meson-python`, `uv_build`) execute arbitrary Python during `uv pip install` / `uv sync` when a source distribution (sdist) is selected. Backends are listed in [the index of supported build backends](https://docs.astral.sh/uv/concepts/build-backend/) (uv ships `uv_build` itself).

Mitigations:

- `--no-build` / `UV_NO_BUILD` — refuse to build any sdist.
- `--no-build-isolation` / `UV_NO_BUILD_ISOLATION` — build in the target env (still executes the backend).
- `--no-binary-package foo` / `UV_NO_BINARY_PACKAGE` — force source install for a specific package (paradoxically: forces the *riskier* path).
- `UV_REQUIRE_HASHES=1` / `--require-hashes` — install fails if any package lacks a hash pin.
- `UV_NO_VERIFY_HASHES=1` / `--no-verify-hashes` — explicitly *disables* hash verification.

uv's *own* scripts (no separate `prepare`/`postinstall` model; PEP 517 backends handle this) but `uv tool install <pkg>` and `uvx <pkg>` instantiate a temporary venv and **do not run build scripts** for already-built wheels; they do run PEP 517 for sdists.

**Workspaces.**
[Yes](https://docs.astral.sh/uv/concepts/projects/workspaces/) (`[tool.uv.workspace]` in root `pyproject.toml`, `members` and `exclude` globs). One workspace, one lockfile. Single `requires-python` for all members (intersection).

**Cache layout.**
`UV_CACHE_DIR` (default `~/.cache/uv` on Linux). Layout: `uv/sdists/<name>-<version>.tar.gz`, `uv/wheels-v<N>/<p>/<index>/<name>-<version>-<hash>.whl`, `uv/built-wheels-v<N>/`. The cache is content-addressed and re-fetching re-validates hashes against `uv.lock`.

**Auth.**
See `uv auth login/logout/token/helper` ([The auth CLI](https://docs.astral.sh/uv/concepts/authentication/cli/)). Native auth via OS keychain is in preview (`UV_PREVIEW_FEATURES=native-auth`): macOS Keychain, Windows Credential Manager, Linux Secret Service (D-Bus). `uv auth helper` implements the [Bazel credential helper protocol](https://github.com/bazelbuild/proposals/blob/main/designs/2022-06-07-bazel-credential-helpers.md) (preview), letting non-uv tools request credentials from uv's store.

**Native hook points.**

- `UV_MALWARE_CHECK` — see above (uv-native OSV malware scan on every `sync`).
- `UV_HTTP_RETRIES`, `UV_HTTP_TIMEOUT`, `UV_HTTP_CONNECT_TIMEOUT` — network hardening knobs.
- `UV_KEYRING_PROVIDER=subprocess` — delegates to the `keyring` CLI.
- Bazel credential helper protocol — designed for *external* tools to fetch uv's credentials, not for security mediation.
- No HTTP proxy specifically designed for inspection; `HTTPS_PROXY` is honoured.

### A.3 npm

**Registry / protocol.**
npm Registry API (a JSON-based REST endpoint, with an additional "packument" graph per package). Default: `https://registry.npmjs.org`. Protocol details in the [npm CLI docs](https://docs.npmjs.com/cli/v10/using-npm/registry). Supports scoped registries (`@scope:registry=…`). ECDSA registry signatures ([npm: About ECDSA registry signatures](https://docs.npmjs.com/about-registry-signatures)) — public key fetched from `registry/-/npm/v1/keys`; signature covers `${name}@${version}:${integrity}`. PGP signatures were deprecated 2023-04-25. `npm audit signatures` verifies both registry signatures and provenance attestations ([npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)).

**Registry override.**

- `npm config set registry <url>` or `.npmrc` `registry=<url>` (project, user, or global).
- Env: `npm_config_registry=<url>` (legacy `NPM_CONFIG_REGISTRY`).
- Per-scope: `[--scope=@scope] --registry=<url>`.
- `.npmrc` is the *de facto* config layer: located at per-project, user (`~/.npmrc`), or global (`npm config get globalconfig`).

**Lockfile.**
`package-lock.json` (versions 1–3). Per the [npm package-lock.json reference](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json):

- `lockfileVersion: 2` (npm v7/v8) or `: 3` (npm v9+).
- Each entry has `version`, `resolved` (the tarball URL), `integrity` (sha512 SRI string), `hasInstallScript: true|false`, and optional `bin`, `license`, `engines`, `dependencies`, `optionalDependencies`.
- A `node_modules/.package-lock.json` "hidden" lockfile caches the tree (used for fast subsequent installs); bypassed if `node_modules` is modified.

The lockfile's integrity field is the authoritative hash — `npm ci` will refuse to install if the on-disk tarball doesn't match.

**Lifecycle scripts.**
Per [npm scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts), the lifecycle stages are:

- `preinstall`, `install`, `postinstall`
- `prepublish` (deprecated since npm 4, but still runs), `prepublishOnly`, `prepack`, `prepare`, `postpack`
- `dependencies` (after any `node_modules` change)
- User-defined scripts with implicit `pre<name>` / `post<name>`.

Since npm 7, these run in the **background** by default (use `--foreground-scripts` to see output). Default binding scripts **are** allowed to execute arbitrary code.

Disable with `--ignore-scripts` / `.npmrc` `ignore-scripts=true` / env `npm_config_ignore_scripts=true` ([npm install config](https://docs.npmjs.com/cli/v10/using-npm/config)). Disabling scripts also stops `node-gyp rebuild` from compiling native modules.

`binding.gyp` triggers `node-gyp rebuild` automatically if no `install`/`preinstall` is defined. Native modules are the most common legit reason for `postinstall`.

**Workspaces.**
[Yes](https://docs.npmjs.com/cli/v10/using-npm/workspaces) (`"workspaces": ["packages/*"]` in root `package.json`). One root `package-lock.json` covers all workspaces; nested `node_modules` are hoisted (npm) or isolated (pnpm).

**Cache layout.**
`~/.npm/_cacache/content-v2/sha512/<aa>/<bb>/…` (content-addressed by sha512), metadata in `~/.npm/_cacache/index-v5/<registry-id>/<scope>/<name>`. Inspectable. `npm cache clean` clears it. `npm cache verify` validates integrity.

**Auth.**
`.npmrc` `//<registry-url>/:_authToken=<token>`. Legacy `_auth` (base64 user:pass). `npm login` writes to the per-user `.npmrc`. `NODE_AUTH_TOKEN` env is honoured by `actions/setup-node` and many CI runners. **Project-level `.npmrc` is committed to repos** by convention and is the source of most npm credential leaks.

**Native hook points.**

- `npm audit [--json|--audit-level=…]` — built-in; queries `/-/npm/v1/security/advisories/bulk` on the registry.
- `npm audit signatures` — built-in ECDSA registry signature verification.
- `npm config get registry` / `npm config set registry <url>` — the canonical override surface.
- No HTTP proxy specifically for inspection, but `npm config set https-proxy=<url>` works.

### A.4 pnpm

**Registry / protocol.**
Same npm Registry API as npm. Default `https://registry.npmjs.org/`. pnpm uses scoped registries via `.npmrc` and `pnpm-workspace.yaml`.

**Registry override.**
Per [Settings (pnpm-workspace.yaml)](https://pnpm.io/settings): pnpm reads **registry and proxy** settings from `pnpm-workspace.yaml` or global `~/.config/pnpm/config.yaml`, but **auth** settings come from `.npmrc` (project `<root>/.npmrc`, user `<pnpm-config>/auth.ini`, fallback `~/.npmrc`).

```toml
# pnpm-workspace.yaml
registries:
  default: https://registry.npmjs.org/
  "@my-org": https://private.example.com/
```

Env expansion is **disabled** in project-level registry URLs since v11.5.3 (CVE [GHSA-3qhv-2rgh-x77r](https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r)) — see the auth settings doc.

**Lockfile.**
`pnpm-lock.yaml` (YAML, lockfile versions 5.x, 6.x, 7.x, 9.x). Each package entry records `resolution: { tarball: <url>, integrity: <sha512> }` for registry sources; git deps pin commit SHA; tarball URLs are pinned. Per the [pnpm CLI install docs](https://pnpm.io/cli/install), pnpm 11.4.0 made tarball integrity mismatches a **hard failure** (`ERR_PNPM_TARBALL_INTEGRITY`) by default — explicitly defended against compromised registries/proxies that swap tarball bytes. Bypass requires `--update-checksums` (with a warning).

**Lifecycle scripts.**
[Yes](https://pnpm.io/cli/install): `--ignore-scripts` skips all lifecycle scripts; without it, the standard `preinstall`/`install`/`postinstall`/`prepare` run. Notably, pnpm does **not** by default expose the `--ignore-scripts` flag's parallel "build scripts in sandbox" feature — it relies on the user passing `--ignore-scripts` or hoisting the install into a sandboxed env.

**Workspaces.**
[Yes](https://pnpm.io/workspaces): `pnpm-workspace.yaml` declares `packages: ["apps/*", "packages/*"]`. Lockfile is shared; each workspace member has its own `node_modules` rooted via the virtual store at `node_modules/.pnpm/`. `pnpm install` by default installs all workspaces; `--filter` selects.

**Cache layout.**

- **Store (CAS)**: `$PNPM_HOME/store` or `$XDG_DATA_HOME/pnpm/store` or platform defaults — see [`storeDir`](https://pnpm.io/settings#storedir). Content-addressed, shared across projects. `verifyStoreIntegrity: true` (default) revalidates before linking.
- **Virtual store**: per-project `node_modules/.pnpm/<hash>/` — symlinks/hardlinks into the global store.
- `pnpm fetch` ([CLI](https://pnpm.io/cli/fetch)) populates only the store from a lockfile, designed for Docker layer caching.

**Auth.**
`<URL>:_authToken=…` in `.npmrc` (project auth is gitignored by pnpm convention since v11.5.3). `<URL>:tokenHelper=<absolute-path>` (only allowed in user `.npmrc` to prevent arbitrary execution). Per-scope auth since v11.7.0 (`@org-a:_authToken=…`).

**Native hook points.**
pnpm has by far the richest built-in supply-chain feature set of any registry client:

- `minimumReleaseAge` (default 1440 minutes since v11) — gates package age at install. CVE-mitigation rationale: "most malicious releases are discovered and removed within an hour."
- `trustPolicy: no-downgrade` — refuses to install a package whose trust evidence has decreased between releases.
- `blockExoticSubdeps: true` (default) — transitive deps cannot pull from git/tarball URLs.
- `verifyStoreIntegrity: true` (default) — store corruption detection.
- `frozenStore` (since v11.7.0) — read-only store mode for Nix/OCI.
- `--frozen-lockfile` is the CI default (`preferFrozenLockfile: true`).
- `pnpm audit` — built-in (queries the npm registry's bulk advisory endpoint).

### A.5 Yarn (classic v1.22 + berry v2–v4)

## Yarn classic (v1)

- Registry: same npm registry API.
- Override: `.npmrc` registry key + `--registry <url>` flag + `yarn config set registry <url>`.
- Lockfile: `yarn.lock` (custom format, plain text, semver ranges + per-package URLs). **Does not include integrity hashes** for every entry in v1; checksum migration was opt-in via `unsafe-disable-integrity-migration false` ([Yarn classic .yarnrc](https://classic.yarnpkg.com/en/docs/yarnrc)).
- Scripts: `preinstall`/`install`/`postinstall`/`prepare` etc. via `.yarnrc` `unsafe-disable-integrity-migration` and `--ignore-scripts`. Yarn classic ships `yarn audit` (queries npm advisory endpoint).
- Cache: `~/.cache/yarn/v6/.tmp/staging/` (tarballs) + offline mirror via `yarn-offline-mirror <dir>` (replaces HTTPS with local fs).
- Workspaces: yes (`workspaces` field in `package.json`). Single `yarn.lock` at root.

## Yarn berry (v2+)

- Override: `.yarnrc.yml` with `npmRegistryServer: <url>`, per-scope via `npmScopes: { myorg: npmRegistryServer: … }`. Env: `YARN_NPM_REGISTRY_SERVER`, `YARN_HTTP_TIMEOUT`, etc.
- Lockfile: `yarn.lock` (YAML, version 6+ includes per-package checksums: `resolution: "<tarball-url>#<sha512>"`). `enableHardenedMode: true` (default off; auto-enabled for public-GitHub PRs) re-validates lockfile against registry on install. `checksumBehavior: throw | update | reset | ignore` controls mismatch handling — see [Yarn berry settings](https://yarnpkg.com/configuration/yarnrc).
- Scripts: `enableScripts: false` is the **default in Yarn berry** for third-party packages (workspaces still execute their own scripts). This is one of the few tools where lifecycle scripts are opt-in per default. Combine with `dependenciesMeta: { foo: { built: true } }` to selectively re-enable.
- Cache: `./.yarn/cache` (compressed zip archive, default). `cacheMigrationMode` / `enableGlobalCache: true`. Yarn berry's PnP (`nodeLinker: pnp`) avoids `node_modules` entirely — a single `.pnp.cjs` loader resolves everything.
- Workspaces: yes; one root `.yarnrc.yml`, one `yarn.lock`. `nmHoistingLimits: workspaces|dependencies|none` controls hoisting.
- Supply chain features:
  - `npmMinimalAgeGate: "1w"` — refuse versions newer than the configured age.
  - `npmPreapprovedPackages: []` — global allowlist for the gate.
  - `enableHardenedMode: true` — revalidates against registry on install.
  - `enableImmutableInstalls: true` (default on CI) — refuses lockfile mutation.
  - `enableImmutableCache: true` — refuses to add/remove cache entries.
  - `enableTelemetry: false` to opt out of anonymous telemetry.
- Auth: `npmAuthToken` / `npmAuthIdent` / `npmAlwaysAuth` in `.yarnrc.yml`. Scope-aware via `npmScopes`.

### A.6 Bun

**Registry / protocol.**
Same npm registry API; bun is an npm-compatible client. Default `https://registry.npmjs.org/`.

**Override.**
`[install] registry` in `bunfig.toml`, or `--registry` CLI flag, or `BUN_CONFIG_REGISTRY` env. Scoped registries via `[install.scopes]`:

```toml
[install.scopes]
myorg = { token = "$npm_token", url = "https://registry.myorg.com/" }
```

Env `BUN_CONFIG_TOKEN` exists but per the docs "currently does nothing" — token config goes via `bunfig.toml` or `.npmrc`. Per [bun.com/docs/runtime/bunfig](https://bun.com/docs/runtime/bunfig).

**Lockfile.**
`bun.lock` (text YAML; binary `bun.lockb` is deprecated since Bun 1.2). Records per-package resolution + integrity. `saveTextLockfile = true` default. `frozenLockfile = true` enforces strict mode. Bun 1.2+ supports `install.lockfile.print = "yarn"` to emit a yarn.lock alongside.

**Lifecycle scripts.**
Bun's stance is **stricter than npm, pnpm, or yarn classic** — see [Lifecycle scripts | Bun](https://bun.com/docs/pm/lifecycle):
> "Unlike other npm clients, Bun does not execute arbitrary lifecycle scripts by default."

Project-level `preinstall`/`postinstall` *are* run; **dependency** lifecycle scripts are not, except for packages in a curated [`default-trusted-dependencies.txt`](https://github.com/oven-sh/bun/blob/main/src/install/default-trusted-dependencies.txt) list. Override per-project via `package.json`:

```json
"trustedDependencies": ["esbuild", "sharp"]
```

Setting `trustedDependencies: []` explicitly disables even the default list. `--ignore-scripts` / `install.ignoreScripts = true` disables all scripts (including project scripts). `BUN_FEATURE_FLAG_DISABLE_IGNORE_SCRIPTS=1` re-enables scripts globally (debug only).

**Workspaces.**
[Yes](https://bun.com/docs/pm/workspaces): `"workspaces": ["packages/*"]` in root `package.json`. Single `bun.lock`. Bun auto-migrates `pnpm-lock.yaml` if no `bun.lock` exists.

**Cache layout.**
`~/.bun/install/cache/${name}@${version}` (each package as a directory). `bun pm cache rm` clears it. Storage backend: `clonefile` (macOS), `hardlink` (Linux), `copyfile` (fallback), `symlink` (debug). `~/.bun/install/cache/*.npm` stores binary registry metadata.

**Auth.**
`[install.scopes.<scope>]` with `username`, `password`, or `token` (env-expanded). Or `[install] registry = { url, token }`. `BUN_CONFIG_TOKEN` env (does nothing as of 2026-06 per docs).

**Native hook points.**

- `[install] minimumReleaseAge` (seconds) — like pnpm's gate. Versions newer than the threshold are filtered during resolution, with a "stability check" that scans ±7 days for rapid bugfix patterns and skips them.
- `[install] minimumReleaseAgeExcludes` — package-level opt-outs.
- `[install.security] scanner = "<scanner-package>"` — **official Security Scanner API** ([bun.com/docs/pm/security-scanner-api](https://bun.com/docs/pm/security-scanner-api)) — packages are scanned before installation; fatal issues abort the install. Bun auto-disables `auto-install` while a scanner is configured. The scanner is an npm package invoked by bun — it receives a JSON request, returns a JSON verdict. This is bun's native extension point for security tooling.

---

## Section B — Prior art: existing security integrations

### B.1 Socket.dev (Socket Firewall / `sfw`)

[Socket Firewall](https://socket.dev/features/firewall) is the most directly comparable wrapper to what Arbitraitor needs. Per [Socket's wrapper-mode docs](https://docs.socket.dev/docs/socket-firewall-enterprise-wrapper-mode) and the [GitHub `socket-cli` README](https://github.com/SocketDev/socket-cli/blob/main/packages/cli/README.md):

**Mechanism:** transparent command wrapper. `sfw npm install lodash` spawns the real `npm install`, but Socket intercepts the npm CLI's HTTP requests via a generated proxy + certificate, runs pre-install scanning (Socket's threat-intel database — typosquats, install scripts, obfuscation, telemetry, protestware), then allows/block/warns.

**Architecture (from the CLI README):**

```
npm-cli → spawnSfw() → Security Scanning + Registry Override → real npm install
```

**Supported ecosystems (per the wrapper docs):** npm, yarn, pnpm (JS); pip, pip3, uv (Python — Poetry not supported); cargo (Rust); go (Linux only); gem, bundle (Ruby); dotnet (.NET); Maven/Gradle (Enterprise only).

**What it inspects:** Socket's own threat-intel DB (build-script behaviour, network calls in install scripts, known malware, typosquats, suspicious maintainer patterns). It also maintains an allowlist / configurable policy.

**What it gates:** install-time. Socket runs the *real* install and analyzes results — including deeply nested dependencies — before anything is written to disk. It also wraps child processes spawned by `npm run` so the wrapper cannot be bypassed by a malicious postinstall script.

**Limitation:** Bypass behaviour (`socket wrapper on` creates shell aliases; malware can manipulate `PATH` to call the unwrapped `npm`). Socket mitigates with `socket npm` putting itself in front of `npm` on `PATH`.

### B.2 Phylum.io

Per [phylum analyze docs](https://docs.phylum.io/cli/commands/phylum_analyze) and [Package Firewalls docs](https://docs.phylum.io/package_firewall/about):

**Mechanism:** two-pronged.

1. **Package Firewall** — local proxy that registers custom URLs for each ecosystem's registry (`phylum-pypi`, `phylum-npm`, `phylum-cargo`, etc.). Tool points at the Phylum proxy; Phylum blocks packages that violate policy.
2. **`phylum analyze`** — CLI that parses lockfiles (or generates them from manifests via sandboxed `npm install --package-lock-only --ignore-scripts` etc.). Accepts: `npm`, `yarn`, `pnpm`, `gem`, `pip`, `poetry`, `pipenv`, `mvn`, `gradle`, `msbuild`, `nugetlock`, `nugetconfig`, `gomod`, `go`, `cargo`, `spdx`, `cyclonedx`.

**Lockfile-generation sandbox:** the CLI explicitly sandboxes lockfile generation because "some ecosystems can execute arbitrary code when generating a lockfile with malicious dependencies." `--skip-sandbox` disables it; `--no-generation` skips lockfile generation entirely.

**Caveat (per [Phylum FAQ](https://docs.phylum.io/package_firewall/faq)):**
> "Common scenarios where a package will not be analyzed are the usage of a cache between the package firewall and the local client (like Artifactory, or Nexus), and the installation from the local registry cache. While the initial installation would be analyzed by the package firewall, once cached it will not be re-analyzed."

This is a critical observation: **once an artifact is in a cache, downstream clients of the cache bypass the firewall**. This directly applies to Arbitraitor: if the user has a populated `~/.cargo` or `~/.cache/uv` from a previous install, a wrapper that inspects only new downloads is blind to cached content. Mitigation: hash check on cache content vs lockfile, or deletion/rehydrate via Arbitraitor.

### B.3 Snyk

Snyk provides an [npm wrapper / snyk-protect](https://snyk.io/) and a `snyk test` command for `package-lock.json`. For CI use, Snyk's installation model is post-install: scan the lockfile after `npm install`, not during. Their [broker](https://docs.snyk.io/enterprise-configuration/snyk-broker) is a proxy for private registries but is primarily an auth-aggregation tool, not an inspection proxy.

**Mechanism:** lockfile + manifest scanner. Scans `package-lock.json`, `Cargo.lock`, `requirements.txt` for known CVEs (Snyk's DB) + licence issues.

**What it inspects:** vulnerable dependency versions, licence compliance. Does not inspect install-script behaviour or build scripts.

**What it gates:** none. Snyk is advisory by default; `snyk monitor` records state; `snyk test` exits non-zero on vulns but does not block install.

### B.4 cargo-vet (Mozilla)

[cargo-vet](https://mozilla.github.io/cargo-vet/) is the most relevant ecosystem-native precedent.

**Mechanism:** in-repo `supply-chain/audits.toml` records per-crate audits (whole-version audits or delta audits from a previously-audited version) + per-publisher trust entries (with expiration). `cargo vet check` runs in CI to ensure every dependency is audited for the configured criteria.

**Trust records:**

```toml
[[audits.bar]]
version = "1.2.3"
who = "Alice Foo <alicefoo@example.com>"
criteria = "safe-to-deploy"

[[trusted.baz]]
criteria = "safe-to-deploy"
user-id = 5555
start = ...
end = ...
```

**Sharing:** "Imports are implemented by pointing directly to the audit files in external repositories, and the registry is merely an index of such files from well-known organizations." Decentralised — no central server to compromise.

**Diff auditing:** cargo-vet computes source-diffs between audited and unaudited versions of the same crate, so auditors can verify deltas cheaply.

**Exemptions:** `config.toml [exemptions]` lets projects ratchet down over time.

**Cargo integration:** cargo-vet itself runs as `cargo vet`. It acquires the build graph via `cargo metadata` (the `cargo_metadata` crate). It does *not* wrap cargo — it's a standalone check invoked separately.

### B.5 OpenSSF Package Analysis

[github.com/ossf/package-analysis](https://github.com/ossf/package-analysis) — "analyses the capabilities of packages available on open source repositories." Runs packages in a **gVisor-sandboxed container** and records:

- Files accessed (strace).
- Addresses connected to (network capture).
- Commands run.

Uses podman + nested containers. Currently analyses npm, PyPI, crates.io packages. Data published to a public BigQuery dataset. **Proactive** — finds malware by detonating new packages, not by user-side interception.

### B.6 osv-scanner (Google)

[github.com/google/osv-scanner](https://github.com/google/osv-scanner) — vulnerability scanner against the OSV database.

**Mechanism:** reads lockfiles / SBOMs / source dirs; queries `https://api.osv.dev`; correlates dependencies to known vulns. Supports npm, pip, yarn, maven, go modules, cargo, gem, composer, nuget, etc.

**What it inspects:** *known vulnerabilities* (CVE / GHSA / RustSec / OSV records). Does not detect new/unknown malware.

**What it gates:** nothing — it's advisory. Its `fix` command (experimental) auto-bumps vulnerable deps but warns explicitly: *"It may trigger the package manager to execute scripts or follow external registries specified in the project. Please ensure you trust the source code and artifacts before proceeding."*

**Notable for Arbitraitor:** `osv-scanner --offline --download-offline-databases` runs against a local OSV DB — the architecture Arbitraitor could emulate for its own offline advisory DB.

### B.7 Trivy (Aqua)

[trivy](https://trivy.dev/docs/latest/scanner/vulnerability/) — comprehensive scanner. Supports **OS packages** + **language-specific packages** (npm, PyPI, Composer, RubyGems, Maven, Go modules, crates.io, NuGet, C/C++ via GitLab advisories). Reads lockfiles, container images, VM images, SBOMs.

**What it inspects:** known CVEs (multiple DBs per ecosystem) + misconfigurations + secrets + licence + SBOM generation. Lang-package detection uses GitHub Advisory DB + ecosystem-native advisories.

**What it gates:** nothing — pure scanner.

### B.8 pip-audit (PyPA, Trail of Bits)

[github.com/pypa/pip-audit](https://github.com/pypa/pip-audit) — PyPA-endorsed auditor. Audits local environments, requirements-style files, and lockfiles. Sources: PyPA Advisory DB, OSV, ESMS. Outputs CycloneDX SBOM.

**Mechanism (per docs):** audits already-installed envs (no install), or reads pinned `--no-deps`/`--require-hashes` requirements files (no install either). Explicit security-model statement:
> "TL;DR: If you wouldn't `pip install` it, you should not `pip audit` it. […] `pip-audit -r INPUT` is functionally equivalent to `pip install -r INPUT`, with a small amount of **non-security isolation** to avoid conflicts."

Honest about its limitations: does not defend against malicious packages, only known vulns.

### B.9 Verdaccio / Nexus / Artifactory / devpi

[Verdaccio](https://verdaccio.org/docs/what-is-verdaccio) — lightweight private npm proxy registry. npm-compatible API, acts as a cache + access-control layer between clients and upstream.

**Mechanism:** runs as a Node.js server. Configured `uplinks` define upstream registries (`npmjs`, a corporate mirror, etc.). Packages can be published privately. Hooks (`notify` plugin) fire on package publish/install for alerting.

**Used in combination with:** Socket, Phylum, Verdaccio *together* — Socket/Phylum run as inspection proxies in front of Verdaccio (or in place of it). Verdaccio is the **storage / caching** layer; Socket/Phylum are the **policy** layer.

**Other commercial equivalents:**

- **JFrog Artifactory** — proxy + cache for npm, PyPI, cargo (via [Cargo repository support](https://jfrog.com/help/r/jfrog-artifactory-documentation/cargo-repositories)), Maven, NuGet, Go, Helm, Docker.
- **Sonatype Nexus Repository** — same.
- **devpi** — PyPI-focused, server-side.

These don't inspect — they're caches with auth. Arbitraitor needs to *interpose* between the tool and these caches to actually see traffic.

### B.10 npm / Yarn `audit signatures` / native ECDSA

[About ECDSA registry signatures](https://docs.npmjs.com/about-registry-signatures) — npm's registry now publishes per-tarball ECDSA signatures over `${name}@${version}:${integrity}`. `npm audit signatures` (and yarn berry equivalent) verifies these against public keys fetched from `/-/npm/v1/keys`.

This is a **first-party provenance** mechanism that Arbitraitor should treat as authoritative evidence when fetching from npm-compatible registries that support it. Crates.io and PyPI have not (as of 2026-06) shipped an equivalent. Sigstore-based provenance exists for cargo via [crates.io provenance](https://blog.rust-lang.org/2023/11/14/Rust-1.74.0.html) but coverage is limited.

### B.11 pre-commit + post-install hooks

A general pattern: intercept at the *commit / install boundary* via:

- `pre-commit` (`.pre-commit-config.yaml`) — runs before `git commit`. Phylum, pip-audit, gitleaks, etc. ship `pre-commit` hooks.
- CI gate on `lockfile change` — Renovate / Dependabot open PRs; CI scans the lockfile diff before merge.
- Hooks like `lefthook` (Arbitraitor's own `lefthook.yml` uses this) for pre-commit/push hooks.

These are **advisory**: they run after the developer has chosen an action. Not a substitute for install-time mediation.

### B.12 Summary table

| Tool | Mechanism | Inspects | Gates? |
|---|---|---|---|
| Socket Firewall (`sfw`) | CLI wrapper + proxy + PATH injection | Typosquats, install scripts, malware, telemetry | Yes (warn/block) |
| Phylum | Lockfile parse + locked sandbox + proxy firewall | Lockfile-derivable supply-chain risk | Yes (firewall blocks; analyze is advisory) |
| Snyk | Lockfile post-scan | CVE + licence | No (advisory) |
| cargo-vet | In-repo audits.toml, `cargo vet check` in CI | Whole-crate + delta audits against declared criteria | Yes (CI gate) |
| OpenSSF Package Analysis | gVisor detonation of new packages | Files/net/commands touched at install | Proactive (publish-time) |
| osv-scanner | Lockfile parse + OSV API | Known CVEs | No (advisory; `fix` runs pm scripts) |
| Trivy | Lockfile / image / dir scan | CVE + misconfig + secret + licence | No |
| pip-audit | Lockfile / requirements scan | PyPA/OSV advisories | No |
| Verdaccio / Artifactory | Registry proxy + cache | (none — auth/cache only) | n/a |
| npm `audit signatures` | Built-in to npm CLI | ECDSA registry signatures + provenance | Soft (warns on mismatch) |
| uv `UV_MALWARE_CHECK` | Built-in to uv; OSV API at sync time | OSV MAL advisories | Yes (terminates sync) |

---

## Section C — Threat surface per tool

### C.1 npm / pnpm / yarn classic / bun

**Universal vectors (all four):**

1. **`postinstall` scripts.** Run on every install. Real incidents:
   - [event-stream incident (2018)](https://blog.npmjs.org/post/180565383615/details-about-the-event-stream-incident) — `flatmap-stream` added a malicious postinstall that stole Bitcoin wallets from Copay.
   - [TrapDoor supply-chain campaign](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) (Socket, 2026-05).
   - [ua-parser-js hijacked (2021-10)](https://github.com/advisories/GHSA-pjwm-rvh2-c4w3), [colors / faker (2022-01)](https://github.com/advisories/GHSA-55w9-r8v2-j6c7).
2. **`prepare` / `prepack` / `postpack`** — npm lifecycle. `prepare` runs on `npm install` of a git dependency.
3. **Native modules (`node-gyp`).** Triggered by `binding.gyp` or by `install` script. Compiles arbitrary C/C++. Has full filesystem + network access. Real incidents: [node-ipc protestware (2022-03)](https://snyk.io/blog/node-ipc-malicious-code-protestware/), [event-stream].
4. **Peer dependency confusion.** A malicious package declares a peer dep with the same name as a popular package; npm/pnpm/yarn resolve to the wrong peer if a hoisting quirk exists.
5. **Dependency confusion (namespace squatting).** A private internal package `@corp/secret-tool` is mirrored on the public registry as `@corp/secret-tool` (same name, different content). Public pkg wins if registry precedence is misconfigured.
6. **Typosquatting.** `crossenv` vs `cross-env` (the [crossenv incident](https://blog.npmjs.org/post/163723642332/crossenv-malicious-event-stream)), `electorn`, `loadash`. npm now flags obvious typosquats at install time.
7. **Account takeover of maintainer.** The most common path: 2FA bypass / credential phishing / token leak. Mitigated by npm's 2FA enforcement + ECDSA signatures.
8. **Compromised mirror/proxy.** [eslint-scope / eslint-config-eslint / etc. (2018-07)](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes). Mitigated by npm's registry signatures.
9. **`bin` shadowing.** A package's `bin` entry shadows a system command when hoisted into `node_modules/.bin`. Less direct than postinstall but enables command confusion.
10. **Workspace "phantom dependencies"** — npm + yarn classic's flat `node_modules` let a package `require()` something it didn't declare. pnpm's strict resolution + bun's `--linker=isolated` prevent this.

**Tool-specific vectors:**

- **npm**: `prepublish` (deprecated but still runs on `npm install`); `npm install` runs dependency scripts in the **background by default** (npm ≥7), so malicious scripts can finish before the developer notices.
- **pnpm**: `node_modules/.pnpm/` symlink structure means a malicious dep can `require()` outside its tree only via deliberately constructed symlinks, but `--ignore-scripts` is the only opt-out. pnpm's `blockExoticSubdeps: true` (default) is the strongest built-in mitigation for the transitive-git-squat class.
- **yarn classic**: `unsafe-disable-integrity-migration` flag if accidentally set, plus all npm-classic vectors.
- **bun**: smallest surface (lifecycle scripts disabled by default + curated trustedDependencies list + minimumReleaseAge gate + Security Scanner API). Bun is *the* reference for default-deny lifecycle.

### C.2 cargo

1. **`build.rs` execution at compile time.** Documented in [The Cargo Book](https://doc.rust-lang.org/cargo/reference/build-scripts.html). Runs at `cargo build` / `cargo test` / `cargo install`. Real incidents:
   - [`onering@1.4.1` (2026-06-10)](https://corgea.com/research/onering-crates-build-rs-sentry-source-exfiltration) — `build.rs` walked out of `OUT_DIR` to the consumer's repo, ran `git diff HEAD^ HEAD`, exfiltrated via Sentry ingest endpoint.
   - [TrapDoor Rust wave (2026-05)](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) — six crates (`build.rs` XOR-encrypted Sui/Move keystores, posted to public GitHub Gists).
   - [GHSA-5PMP-JPCF-PWX6 `tracing-check` (2026-03)](https://cvereports.com/reports/GHSA-5PMP-JPCF-PWX6) — typosquat of `tracing`, exfiltrated env vars via `build.rs`.
   - [petgraph CI RCE via `build.rs` + `pull_request_target` (2026-01)](https://github.com/petgraph/petgraph/issues/950) — `CARGO_REGISTRY_TOKEN` exposed in CI.
2. **Proc macros.** Run arbitrary Rust code at compile time, on the consumer's machine. No `build.rs` involved. Detection requires static analysis of the proc-macro crate's source.
3. **`build-dependencies` / `[build-dependencies]`.** A separate dep tree resolved before main deps. Can include `cc` crates that compile arbitrary C, or build.rs in their own right.
4. **`dev-dependencies`.** Visible during `cargo test` / `cargo build --tests`. Less risky in production builds (`cargo build --release` skips them).
5. **Git dependencies pinned to branch instead of commit.** Allowed by Cargo. The branch can move. Arbitraitor should warn when a `Cargo.lock` has a `source = "git+...#branch=main"` rather than `#<commit>`.
6. **`[patch.crates-io]` with unvetted forks.** Cargo allows replacing a crate with a fork via local path or git URL. A malicious `Cargo.toml` can reroute a popular dep to a fork.
7. **Account takeover of crate maintainer.** Less common than npm because crates.io has stricter publish-token controls, but [tj-actions/changed-files compromise (2023-03)](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) showed GitHub Actions OIDC abuse against Rust projects is real.
8. **`cargo install <crate>`.** Downloads + builds + installs a binary into `~/.cargo/bin`. Equivalent to "postinstall + arbitrary code execution". The vast majority of crates install without `build.rs` complications, but those with `cc`-wrapping or `bindgen` build scripts ship arbitrary code.
9. **`--offline` mode bypass.** If the lockfile is already populated, `cargo build --offline` will run `build.rs` against cached source without re-validating upstream. This is the analogue of Phylum's "cache between firewall and client" caveat.

### C.3 Python (uv, uvx, pip, pip-tools, poetry)

1. **PEP 517 build backends.** `setup.py` (legacy), `setuptools`, `hatchling`, `flit`, `poetry-core`, `maturin`, `scikit-build-core`, `meson-python`. All execute arbitrary Python at install time. PEP 517 was designed to *make* builds declarative; it ended up making them more explicit but no less arbitrary. uv has [build backend docs](https://docs.astral.sh/uv/concepts/build-backend/) acknowledging the risk.
2. **`setup.py` execution.** Still honoured by build backends that wrap it (setuptools). Real incidents: [request-bundler typosquat (2018-12)](https://github.com/pypa/advisory-database) — `setup.py` contacted external URLs and POSTed host info.
3. **Arbitrary code in `pyproject.toml`.** PEP 621 + hatchling + poetry-core all support `[tool.*]` tables whose values can be executed by plugins.
4. **`uv tool run <pkg>` / `uvx <pkg>`.** Creates an ephemeral venv, installs the package (PEP 517 build if sdist), then runs the entry point. Equivalent to `pipx run`. Tool execution runs with the user's privileges and arbitrary code from build hooks.
5. **PyPI namespace packages + PEP 420.** No `__init__.py` required in a directory; namespace confusion attacks possible if a malicious namespace package shadows a legitimate one.
6. **Direct URL dependencies (`pkg @ https://...`).** PEP 508 + PEP 440 allow specifying arbitrary URLs. uv + pip honour them without lockfile pinning unless `--require-hashes` is set.
7. **Hash mismatch bypass (`UV_NO_VERIFY_HASHES`).** Explicitly disables integrity verification — an opt-in foot-gun.
8. **Mirror compromise.** PyPI mirrors (e.g., Tsinghua TUNA, Aliyun) cache and re-serve. If they substitute bytes, the wheel's sha256 in `uv.lock` / `requirements.txt` will mismatch — but only if `UV_REQUIRE_HASHES` is set.
9. **Typo-squatting + dependency confusion** — same as npm. Examples: `python-dateutil` vs `python_dateutil`; `python3-dateutil`; private `corp-internal-tool` mirrored on PyPI.
10. **`conda` vs `pip` divergence.** Conda packages solve dependencies differently and may have different CVEs. uv deliberately only addresses pip-style resolution; conda is out of scope.

---

## Section D — Integration patterns for Arbitraitor

Pattern analysis, with reference to existing Arbitraitor invariants (§3 of the spec): *no-early-release*, *exact-byte-identity*, *single-retrieval*.

### D.1 Transparent registry proxy

**Mechanism.** Arbitraitor runs a local HTTP server implementing the npm/PyPI/cargo/uv index protocol. The user points the package manager at this proxy (via `.npmrc` / `UV_INDEX_URL` / `.cargo/config.toml`). The proxy intercepts every metadata and tarball request, fetches upstream, records/inspects, and serves from its CAS. Arbitraitor then instructs the real tool to proceed (or aborts).

**Pros.**

- **Strongest mediation.** Every byte that flows into the tool is mediated by Arbitraitor.
- **Compatible with the homebrew-style workflow** in §39.11 — fetch through Arbitraitor → verify → inspect → release.
- Catches metadata-as-attack: an `integrity: sha512-X` field in a corrupted packument (real-world vector — the [eslint-config-eslint mirror attack (2018)](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes)).
- Honors `exact-byte-identity` and `single-retrieval` invariants naturally — every tarball flows through the CAS exactly once.
- **Pre-install hook is automatic** — no special tool argument required, just env / config.

**Cons.**

- **Token leakage.** `.npmrc` `_authToken`, `UV_INDEX_<NAME>_PASSWORD`, `CARGO_REGISTRY_TOKEN` all need to be available to the proxy. The proxy must NOT log them. This is a credential-piping surface that doesn't exist with the other patterns.
- **Phylum's cache caveat applies.** Once the user's local `~/.cargo/registry/cache/` is populated by an install that bypassed the proxy, the next install reads from cache. Arbitraitor needs to either (a) own the cache path, or (b) hash-verify cache contents on each install (uv supports this; cargo has [the open issue #16850](https://github.com/rust-lang/cargo/issues/16850) but no command yet).
- **Per-ecosystem protocol coverage.** npm/pnpm/yarn/bun all speak the npm registry API → one proxy. crates.io sparse + git → different proxy. PyPI PEP 503 → another. Three proxy implementations to maintain.
- **Doesn't help with git/path dependencies.** `cargo build` with a path dependency, or `uv add "pkg @ git+https://..."`, doesn't go through a registry at all. Arbitraitor needs a complementary mechanism (see D.2).
- **TLS / cert management.** The proxy needs a CA cert trusted by the tool. Tools that hardcode `CARGO_NET_GIT_FETCH_WITH_CLI=true` or use their own HTTP client (cargo's reqwest) need their trust store updated.

**Tool feasibility:**

| Tool | Proxy feasibility | Override surface |
|---|---|---|
| npm | High | `.npmrc` registry= |
| pnpm | High | `pnpm-workspace.yaml` registries |
| yarn classic | High | `.npmrc` registry= |
| yarn berry | High | `.yarnrc.yml` npmRegistryServer |
| bun | High | `bunfig.toml [install] registry` |
| cargo | Medium | `.cargo/config.toml [registries]` + `[source.crates-io]` replacement + `CARGO_REGISTRIES_CRATES_IO_PROTOCOL` |
| uv | High | `UV_INDEX_URL`, `UV_INDEX`, `UV_DEFAULT_INDEX`, `pyproject.toml [tool.uv.index]` |
| uvx | Medium | Inherits uv's config; ephemeral venvs complicate CAS reuse |

**Invariants preserved:**

- ✅ no-early-release (proxy holds bytes until verdict).
- ✅ exact-byte-identity (CAS hashes match upstream).
- ✅ single-retrieval (CAS-keyed, idempotent).
- ❌ Does not catch lifecycle-script execution *inside* the tool — script execution still happens after the tarball is released to the tool. (Mitigation: see D.4 post-install sandbox.)

### D.2 Lockfile pre-scan

**Mechanism.** Before invoking the tool, Arbitraitor reads `Cargo.lock` / `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` / `bun.lock` / `uv.lock`. For each entry, it pre-fetches the tarball, verifies the recorded hash matches, runs the detection pipeline, then allows the tool to run with `--frozen-lockfile` / `--frozen` / `--prefer-offline`. The tool then populates its cache from the *same* bytes (since hash matches, it's safe to copy from Arbitraitor's CAS to the tool's cache).

**Pros.**

- **No proxy credentials.** No `.npmrc` token interception, no `CARGO_REGISTRY_TOKEN` exposure. Arbitraitor fetches public tarballs directly.
- **Works with the existing tool path.** No `sfw npm install` — just `arbitraitor scan --lockfile package-lock.json && npm ci`.
- **Symmetric with the cargo-vet / osv-scanner model.** Audit before run.
- **Allows policy decisions on metadata before bytes flow.** "Is this version yanked? Is this dep allowed?"

**Cons.**

- **Doesn't help when the lockfile doesn't exist yet.** First-run / `npm install <new-package>` needs to *generate* the lockfile, which requires running the tool (which downloads bytes).
- **Two pass problem.** Generate-lockfile-run + verify-lockfile-run. Can be combined (`npm install --package-lock-only --ignore-scripts` then `arbitraitor scan --lockfile`) but that's two tool invocations.
- **Lockfile itself is untrusted.** A malicious `Cargo.toml` can include `[patch.crates-io]` entries that redirect. Arbitraitor must parse the *manifest* as well, not just the lockfile.
- **Doesn't cover git/path deps well.** Cargo's lockfile records git deps by commit SHA but the *content* of that commit isn't pinned at the manifest level — only at the registry/index level. To verify, Arbitraitor has to clone the repo.
- **Lifecycle scripts still execute after the lockfile scan passes.** Postinstall/build.rs/PEP 517 still run; this is "advisory with allow" rather than mediation.

**Tool feasibility:**

| Tool | Lockfile pre-scan | Notes |
|---|---|---|
| npm | `package-lock.json` v2/v3 | `npm ci` enforces |
| pnpm | `pnpm-lock.yaml` v5–v9 | `pnpm install --frozen-lockfile` enforces |
| yarn classic | `yarn.lock` (no checksums by default) | `--frozen-lockfile` available but checksum integrity is opt-in |
| yarn berry | `yarn.lock` v6+ | `enableImmutableInstalls: true` (CI default) enforces |
| bun | `bun.lock` (text) | `bun install --frozen-lockfile` enforces |
| cargo | `Cargo.lock` v3/v4 | `cargo build --locked --frozen` enforces |
| uv | `uv.lock` v1 | `uv sync --locked --frozen` enforces |

**Invariants preserved:**

- ✅ exact-byte-identity (lockfile hash == CAS hash).
- ❌ no-early-release — the tool downloads from upstream cache, not Arbitraitor's CAS, unless we actively seed the tool's cache.
- ❌ single-retrieval — the tool re-downloads (or fetches from cache) independently.
- ❌ Lifecycle script execution unmediated.

### D.3 Wrapper command (`arbitraitor wrap <tool> -- <args>`)

**Mechanism.** Mirrors §39.8's `arbitraitor wrap brew -- install example`. The wrapper invokes the tool but intercepts at the command-line level:

- Parses argv to discover the requested operation (`install`, `add`, `update`, etc.).
- Optionally pre-resolves the lockfile to enumerate targets.
- Spawns the tool under a controlled environment (`HTTPS_PROXY=arbitraitor-proxy`, `UV_INDEX_URL=…`).
- Captures tool's HTTP traffic via the proxy (or relies on registry config).

This is what Socket's `sfw` and Phylum's `phylum npm install` both do.

**Pros.**

- **Mirrors the existing homebrew adapter pattern** (spec §39.11). Low cognitive load for users already using `arbitraitor wrap brew`.
- **No environment tampering required.** User runs `arbitraitor wrap npm install lodash` explicitly; no shell aliases needed.
- **Combines naturally with proxy + lockfile scan + post-install scan.** The wrapper is the coordinator.

**Cons.**

- **Tool argv parsing is fragile.** `npm` accepts `npm install <pkg>`, `npm i <pkg>`, `npm add <pkg>`, `npx <pkg>` — different invocations of the same package install. `uv` has `uv add` / `uv pip install` / `uv tool install` / `uv sync` / `uv run --with` / `uvx` — each is a different installation path. Maintaining argv grammars per tool is high-touch.
- **Doesn't catch `npx <thing>` or `pnpm dlx <thing>`.** These resolve and execute packages without an explicit "install" step.
- **Doesn't catch transitive calls.** A `postinstall` script that does `npm install <other-pkg>` runs *outside* the wrapper.
- **Background process model.** The tool may detach (run lifecycle scripts as background children) and Arbitraitor loses visibility.

**Invariants preserved:**

- ✅ Same as proxy + lockfile scan (depending on which internal mechanism the wrapper uses).
- ❌ Wrapper cannot enforce if the user (or a malicious dep) bypasses by calling the real binary directly.

### D.4 Post-install scan

**Mechanism.** After `cargo build` / `npm install` / `uv sync`, Arbitraitor scans `node_modules/` / `~/.cargo/registry/src/` / `.venv/lib/python*/site-packages/` for malicious patterns: postinstall script remnants, suspicious binary blobs, unexpected file types, YARA matches, OSV/MAL hits against the lockfile.

**Pros.**

- **Trivial to retrofit.** No proxy, no env, no wrapper. Just a filesystem scan.
- **Catches missed cases** — if proxy was bypassed, if a malicious dep wrote additional files post-install.
- **Composes well with `osv-scanner` and `trivy fs`** as the underlying scanner.

**Cons.**

- **Too late.** If a `postinstall` script ran, it already executed. A post-install scan detects compromise *after the fact*. This violates *no-early-release* for the lifetime of the install.
- **Highest false-positive cost.** `node_modules/` has thousands of files; pattern-matching yields noise.
- **Tool-specific layout knowledge.** Each tool stores installed artifacts in a different shape (npm's nested `node_modules`, pnpm's symlink forest, uv's `.venv/lib/python*/site-packages`, cargo's `registry/src` + `target/`). Maintaining these is constant churn.
- **Doesn't see lifecycle script output.** A malicious `postinstall` that exfiltrates over the network and deletes itself is invisible.

**Invariants preserved:**

- ❌ no-early-release (already happened).
- ❌ exact-byte-identity (post-scan doesn't verify the *original* byte stream).
- ✅ single-retrieval (assumes the tool fetched once).
- ❌ Lifecycle script execution unmediated.

### D.5 Hybrid pattern (recommended)

Different tools warrant different patterns based on (a) how easy proxying is, (b) how risky lifecycle scripts are, (c) how reliable the lockfile is. Arbitraitor should ship a **per-tool recipe** that picks the best combination:

| Tool | Primary pattern | Secondary | Notes |
|---|---|---|---|
| **npm** | Registry proxy (`.npmrc` registry=) | Post-install scan | Bun's trustlist model is the gold standard; npm defaults to scripts-on. Arbitraitor can write `.npmrc` registry= and `--ignore-scripts=true` for the install then re-enable scripts post-verification per-dependency via `npm approve-scripts` (npm v11) — see [npm docs](https://docs.npmjs.com/cli/v11/commands/npm-approve-scripts). |
| **pnpm** | Registry proxy (`pnpm-workspace.yaml` registries) | Lockfile pre-scan + `pnpm fetch` to seed store | pnpm's `blockExoticSubdeps`, `minimumReleaseAge`, and `verifyStoreIntegrity` defaults reduce threat; Arbitraitor layers OSV + YARA + cargo-vet-style audits. |
| **yarn classic** | Registry proxy (`.npmrc`) | Lockfile pre-scan | Lockfile integrity is opt-in; proxy is the safer bet. |
| **yarn berry** | Registry proxy (`.yarnrc.yml` npmRegistryServer) | Lockfile pre-scan + `enableHardenedMode` | Berry defaults are already strong (`enableScripts: false`, `enableHardenedMode` on public PRs); Arbitraitor adds policy enforcement. |
| **bun** | Registry proxy (`bunfig.toml`) | Bun Security Scanner API | Bun's [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) is the native integration point; Arbitraitor can publish a scanner package that bun invokes pre-install. **This is the only tool with a first-party hook designed for security mediation.** |
| **cargo** | Lockfile pre-scan + post-install scan | (proxy is fragile because of `OUT_DIR` and `.crate` extraction) | **No first-party proxy support.** Build.rs executes outside any registry boundary. Arbitraitor should: (a) verify every `Cargo.lock` entry against CAS via `cargo fetch` + `cargo metadata --format-version=1`, (b) static-analyse `build.rs` source (Rust AST → heuristic for `Command::new`, `std::process::Command`, `std::fs::read_to_string`, network ops), (c) optional sandbox detonation of `build.rs` via OpenSSF Package Analysis-style gVisor. cargo-vet integration provides the audit-evidence layer. |
| **uv** | Registry proxy (`UV_DEFAULT_INDEX`) + lockfile pre-scan | `UV_MALWARE_CHECK=1` is already OSV-backed | uv has the strongest first-party foundation. Arbitraitor extends OSV with local intelligence, plus inspects sdists before they're built. uv's `--no-build` / `--no-build-isolation` give Arbitraitor a knob to defer build execution until after inspection. |
| **uvx / `uv tool run`** | Per-invocation: ephemeral venv inside Arbitraitor-managed path + OSV scan + sandboxed exec | (no proxy needed for one-shot tools; CAS-keyed tool dirs) | uvx creates temp venvs; Arbitraitor can mediate by intercepting `uv tool install` and using `--cache-dir` pointing at its CAS. |

**Why hybrid.** Each tool has different breaking points:

- npm/pnpm/yarn classic/bun → registry-protocol-based, **proxy is cheap and effective**.
- uv → registry-protocol-based **and has `UV_MALWARE_CHECK` built-in** → proxy + extend uv's own check.
- yarn berry → registry-protocol-based **and defaults deny scripts** → proxy + lockfile audit.
- cargo → **registry-protocol-based AND executes build.rs outside the registry boundary** → proxy is necessary but not sufficient; build.rs sandboxing is the binding constraint.

---

## Section E — Plugin classification recommendation

Per spec §39.3, plugins are classified into three tiers:

1. **Built-in** — small, security-critical, shipped in binary.
2. **First-party** — maintained by Arbitraitor org, signed by project keys, released independently.
3. **Community** — externally maintained, installed explicitly, stricter default capabilities.

### E.1 Recommendation table

| Tool | Class | Rationale |
|---|---|---|
| **cargo** | **First-party** | Cargo's `build.rs` is the most security-sensitive single vector outside Homebrew/AUR. The Rust ecosystem is high-maintenance (semver, MSRV, workspace metadata all change). Custom protocol (sparse vs git) + custom auth (`CARGO_REGISTRY_TOKEN`) need first-party maintenance. CVE-feed freshness matters more here than for npm/pnpm. The build.rs sandbox spec alone (modelled on OpenSSF Package Analysis) is enough work to justify first-party ownership. |
| **uv / uvx** | **First-party** | uv moves fast (multiple breaking changes per year, evidenced by the constant stream of preview features and the recent `UV_MALWARE_CHECK` addition). Astral's roadmap is security-positive — `UV_MALWARE_CHECK` is itself a competitor feature that Arbitraitor should interoperate with, not duplicate. uvx/uv run have unique ephemeral-env semantics that warrant close integration. The auth-cli + Bazel credential helper interface is a unique integration surface. |
| **npm** | **First-party** | npm's CLI + registry protocol changes frequently (`npm v11` introduced `approve-scripts`, `deny-scripts`, `trust`). npm is the **largest** ecosystem by package count and incident count. Registry signature changes + lifecycle script gates (which npm is actively evolving) need first-party tracking. |
| **pnpm** | **First-party** (or first-party + community partnership) | pnpm's unique supply-chain features (`minimumReleaseAge`, `trustPolicy`, `blockExoticSubdeps`, `frozenStore`, `pnpm fetch`, `pnpm audit`) are themselves a form of Arbitraitor-like enforcement. The plugin should *configure and extend* pnpm's built-ins, not duplicate. pnpm 11.5.3's CVE [GHSA-3qhv-2rgh-x77r](https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r) is a useful precedent for project-level `.npmrc` security policy that Arbitraitor can encode as default. |
| **yarn classic** | **Community** | Yarn 1 is in maintenance-only mode. Lockfile integrity is opt-in, ecosystem is shrinking. A community plugin covering the gap is sufficient. |
| **yarn berry** | **First-party** | Berry is the actively-developed Yarn. Its config surface is YAML-rich and security-positive by default; the plugin needs deep configuration authoring that benefits from first-party review. `enableHardenedMode` + `npmMinimalAgeGate` + `npmPreapprovedPackages` are policy primitives Arbitraitor can populate. |
| **bun** | **First-party** | Bun's [Security Scanner API](https://bun.com/docs/pm/security-scanner-api) is the only first-party security hook in any registry client. Publishing an Arbitraitor scanner as an npm package (consumed by bun's API) is a high-impact integration. The lifecycle-default-deny posture is best extended by a first-party plugin that decides *which* packages get on the trustedDependencies list. |

### E.2 Decision rationale

**Why "first-party" dominates over "built-in" for this batch:**

- **Spec §39.3 built-ins are "small, security-critical functionality."** These adapters are *not* small — each is several thousand LOC of tool-specific protocol handling, auth, lockfile parsing, lifecycle-script mediation.
- **Spec §39.4 runtime preference is "subprocess or WASM coordinator"** for package-manager adapters — i.e., they're not expected to be compiled into the binary.
- **First-party signing** lets the Arbitraitor org vouch for the adapter's correctness while keeping release cadence independent of the binary's.

**Why not "community" for most of these:**

- **Tool changes ship quickly.** npm, uv, pnpm, bun each release breaking config changes 2-4× per year. A community plugin can lag. uv 0.x → 1.x in under a year included `UV_MALWARE_CHECK`.
- **Security sensitivity is high.** A misconfigured plugin (e.g., one that silently allows `--ignore-scripts=false` when it shouldn't) is an attack surface. First-party status implies code review and signed releases.
- **Ecosystem-specific quirks matter.** pnpm's CVE-mitigating `${...}` env-expansion ban in project `.npmrc`, bun's per-source `trustedDependencies` semantics, yarn berry's `enableHardenedMode`-only-on-public-PRs behaviour — these require in-depth ecosystem knowledge that a casual community contributor may lack.

### E.3 Capability grants per class

Per spec §39.15, plugins declare required/optional capabilities. For these adapters:

| Capability | npm | pnpm | yarn berry | bun | cargo | uv |
|---|---|---|---|---|---|---|
| `parse_argv` | required | required | required | required | required | required |
| `read_env` | required (`.npmrc`) | required | required | required | required | required |
| `write_env` | required (`--ignore-scripts`) | required | required | required | required | required |
| `read_lockfile` | required | required | required | required | required | required |
| `write_lockfile` | optional | optional | optional | optional | optional | optional |
| `read_cache` | required (`.npm/_cacache`) | required (CAS) | required | required | required | required |
| `spawn_tool` | required (`npm` subprocess) | required | required | required | required | required |
| `sandbox_exec` | optional (sandbox postinstall) | optional | optional | required (Security Scanner API) | required (build.rs) | optional (PEP 517 build) |
| `network_egress` | **denied by default** | denied | denied | denied | denied | denied |
| `filesystem_write` | `~/.arbitraitor/staging/npm/` | `~/.arbitraitor/staging/pnpm/` | …/yarn/ | …/bun/ | …/cargo/ | …/uv/ |

Network egress from any plugin is denied by default — Arbitraitor mediates all network through the retriever (§39.9). Tools that legitimately need egress (e.g., proxying npm install) go through Arbitraitor's retriever, not the plugin's own network capability.

### E.4 Sandbox requirements

For cargo and uv, the plugin must run PEP 517 / `build.rs` execution inside the Arbitraitor sandbox (spec §39.6 / §6.6 / §39.11's clean-chroot requirement for AUR). This is the same enforcement mode that §39.12 requires for `makepkg` — building community recipes outside an isolated environment is **outside enforcement mode**.

Specifically:

- **cargo plugin**: must isolate `build.rs` execution. Recommended: OpenSSF Package Analysis-style gVisor sandbox per crate, with network deny-by-default + filesystem read-only for the consumer workspace + write-only for `OUT_DIR`.
- **uv plugin**: PEP 517 build isolation is already provided by uv (`UV_NO_BUILD_ISOLATION` opts out). Arbitraitor should leave isolation enabled by default and run the *output* wheel through the inspection pipeline before it's released.
- **npm / pnpm / yarn / bun plugins**: lifecycle script execution should be sandboxed via Arbitraitor's existing `arbitraitor-exec` (spec §1 / `arbitraitor-exec` crate per the README's architecture). With `--ignore-scripts` enforced by default and selective `trustedDependencies`-style approval per Arbitraitor policy.

---

## Section F — Open questions and follow-up

These are flagged for the spec draft but not answered in this research:

1. **Lockfile trust.** Should Arbitraitor accept a lockfile from the manifest repo (committed), require a separate signed lockfile, or generate its own (à la `cargo vendor`)? Cargo-vet's in-tree approach is the model to study.
2. **Audit publication.** Cargo-vet imports audits from other projects. Should Arbitraitor ship an "audits" repo that downstream consumers import? This depends on whether Arbitraitor is a developer tool or an enterprise platform.
3. **Build-time provenance.** uv publishes PyPI attestations (PEP 740) for projects built with `uv build`. npm publishes provenance for projects with `provenance: true` in CI. Crates.io has limited provenance. Should Arbitraitor enforce provenance-attested-only policy, or treat it as one signal among many?
4. **`UV_MALWARE_CHECK` interaction.** uv already OSV-checks every `uv sync`. Should Arbitraitor use uv's check (and add its own intelligence on top), or bypass uv's check and run its own? Bypassing is riskier (uv has a tighter feedback loop with OSV MAL) but composes more cleanly with Arbitraitor's own policy engine.
5. **Cargo `verify-sources` advocacy.** Issue [rust-lang/cargo#16850](https://github.com/rust-lang/cargo/issues/16850) is the missing primitive for "verify local cache against lockfile." Arbitraitor might benefit from either (a) funding that issue, (b) shipping an external verifier (`arbitraitor verify-sources`), or (c) integrating with the pre-RFC work.
6. **Multi-registry composition.** pnpm's namedRegistries + cargo's `[registries]` + uv's multi-index all support multiple registries in one resolution. The proxy pattern needs to handle multi-registry resolution without leaking credentials between registries.
7. **Workspace detection.** When `pnpm-workspace.yaml` / `Cargo.toml [workspace]` / `uv pyproject.toml [tool.uv.workspace]` exist, the plugin should treat the whole workspace as a unit. Otherwise per-package inspection produces confusing verdicts.

---

## Citations (consolidated)

## Cargo

- Cargo Book — [Registries](https://doc.rust-lang.org/cargo/reference/registries.html), [Registry Index](https://dev-doc.rust-lang.org/stable/cargo/reference/registry-index.html), [Cargo.toml vs Cargo.lock](https://doc.rust-lang.org/stable/cargo/guide/cargo-toml-vs-cargo-lock.html), [Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html).
- Cargo source — [core/resolver/encode](https://doc.rust-lang.org/nightly/nightly-rustc/cargo/core/resolver/encode/index.html), [core/resolver/resolve](https://docs.rs/cargo/latest/src/cargo/core/resolver/resolve.rs.html).
- Cargo issues/PRs — [sparse-registry stabilisation #11224](https://github.com/rust-lang/cargo/pull/11224), [verify-sources #16850](https://github.com/rust-lang/cargo/issues/16850), [Stack Exchange: cargo cryptographic auth](https://security.stackexchange.com/questions/257076/does-rusts-cargo-provide-cryptographic-authentication-and-integrity-validation).
- Cargo incidents — [onering@1.4.1 build.rs exfiltration (Corgea, 2026-06)](https://corgea.com/research/onering-crates-build-rs-sentry-source-exfiltration), [TrapDoor Rust crates (Socket, 2026-05)](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates), [GHSA-5PMP-JPCF-PWX6 tracing-check (CVE Reports, 2026-03)](https://cvereports.com/reports/GHSA-5PMP-JPCF-PWX6), [petgraph CI RCE via build.rs (2026-01)](https://github.com/petgraph/petgraph/issues/950).

## uv (Astral)

- uv docs — [Locking and syncing § Malware checks](https://docs.astral.sh/uv/concepts/projects/sync/), [Environment variables](https://docs.astral.sh/uv/reference/environment/), [HTTP credentials](https://docs.astral.sh/uv/concepts/authentication/http/), [The auth CLI](https://docs.astral.sh/uv/concepts/authentication/cli/), [Using workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/), [Build backend](https://docs.astral.sh/uv/concepts/build-backend/), [Configuration files](https://docs.astral.sh/uv/concepts/configuration-files/), [Storage](https://docs.astral.sh/uv/reference/storage/), [Cache](https://docs.astral.sh/uv/concepts/cache/), [Authentication](https://docs.astral.sh/uv/concepts/authentication/).

## npm

- npm docs — [package-lock.json](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json), [scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts), [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit), [About ECDSA registry signatures](https://docs.npmjs.com/about-registry-signatures), [Verifying ECDSA registry signatures](https://docs.npmjs.com/verifying-registry-signatures), [Registry](https://docs.npmjs.com/cli/v10/using-npm/registry).

## pnpm

- pnpm docs — [Settings (pnpm-workspace.yaml)](https://pnpm.io/settings), [Authentication (.npmrc)](https://pnpm.io/npmrc), [CLI install](https://pnpm.io/cli/install), [CLI fetch](https://pnpm.io/cli/fetch), [Supply-chain security](https://pnpm.io/supply-chain-security).
- pnpm advisory — [GHSA-3qhv-2rgh-x77r](https://github.com/pnpm/pnpm/security/advisories/GHSA-3qhv-2rgh-x77r).

## Yarn

- Yarn berry docs — [Settings (.yarnrc.yml)](https://yarnpkg.com/configuration/yarnrc), [API](https://yarnpkg.com/api).
- Yarn classic docs — [CLI install](https://classic.yarnpkg.com/en/docs/cli/install), [.yarnrc](https://classic.yarnpkg.com/en/docs/yarnrc).

## Bun

- Bun docs — [bunfig.toml](https://bun.com/docs/runtime/bunfig), [Lifecycle scripts](https://bun.com/docs/pm/lifecycle), [bun install](https://bun.com/docs/pm/cli/install), [Workspaces](https://bun.com/docs/pm/workspaces), [Security Scanner API](https://bun.com/docs/pm/security-scanner-api), [default-trusted-dependencies.txt](https://github.com/oven-sh/bun/blob/main/src/install/default-trusted-dependencies.txt).

## Prior art

- [Socket.dev](https://socket.dev/features/firewall) — [Wrapper Mode](https://docs.socket.dev/docs/socket-firewall-enterprise-wrapper-mode), [socket-npm](https://docs.socket.dev/docs/socket-npm-socket-npx), [socket-cli README](https://github.com/SocketDev/socket-cli/blob/main/packages/cli/README.md), [Introducing safe-npm](https://socket.dev/blog/introducing-safe-npm).
- [Phylum](https://docs.phylum.io/) — [phylum analyze](https://docs.phylum.io/cli/commands/phylum_analyze), [Package Firewalls](https://docs.phylum.io/package_firewall/about), [FAQ](https://docs.phylum.io/package_firewall/faq), [Lockfile Generation](https://docs.phylum.io/cli/lockfile_generation).
- [cargo-vet](https://mozilla.github.io/cargo-vet/) — [Introduction](https://mozilla.github.io/cargo-vet/), [Configuration](https://mozilla.github.io/cargo-vet/config.html), [Trusting Publishers](https://mozilla.github.io/cargo-vet/trusting-publishers.html), [How it Works](https://mozilla.github.io/cargo-vet/how-it-works.html), [Algorithm](https://mozilla.github.io/cargo-vet/algorithm.html).
- [OpenSSF Package Analysis](https://github.com/ossf/package-analysis).
- [osv-scanner](https://github.com/google/osv-scanner) — [docs](https://google.github.io/osv-scanner/).
- [Trivy](https://trivy.dev/) — [Vulnerability scanning](https://trivy.dev/docs/latest/scanner/vulnerability/).
- [pip-audit](https://github.com/pypa/pip-audit).
- [Verdaccio](https://verdaccio.org/docs/what-is-verdaccio).

## Arbitraitor spec (relevant sections)

- `.spec/arbitraitor-comprehensive-spec.md` — §39.1 design objective, §39.2 plugin classes, §39.2.3 package-manager wrapper plugins, §39.3 distribution classes, §39.5 normalized operation plan, §39.8 invocation and interception modes, §39.11 Homebrew adapter, §39.12 Arch community adapter, §39.13 lifecycle mediation coverage values.
