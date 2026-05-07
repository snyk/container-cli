# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, etc.) working in this repo.

## What this is

`container-cli` (`github.com/snyk/container-cli`) is a **Go library** that provides Snyk CLI
extension workflows for container image analysis. It is embedded in the Snyk CLI host process via
`github.com/snyk/go-application-framework` and is **not a standalone binary** — there is no `main`
package.

The sole public entry point is:

```go
// package github.com/snyk/container-cli/pkg/container
func Init(e workflow.Engine) error
```

`Init` registers two workflows with the host engine:

- **`container depgraph`** — invokes the legacy Snyk CLI to extract dependency-graph data from a
  container image (`container test --print-graph --json`).
- **`container sbom`** — orchestrates the DepGraph workflow, then converts its output into an SBOM
  document by calling the Snyk REST API (`POST /hidden/orgs/{orgID}/sbom`).

Everything outside `pkg/container` is `internal/` and not exported.

## Registered workflows / public surface

### Workflow identifiers

| Workflow | Identifier |
|---|---|
| Container DepGraph | `workflow://container depgraph` |
| Container SBOM | `workflow://container sbom` |

The SBOM workflow always invokes the DepGraph workflow as a sub-workflow; there is no SBOM path
that bypasses it.

### Flags

Both workflows share `CommonFlags` (defined in `internal/common/flags/flags.go`):

| Flag | Type | Description |
|---|---|---|
| `--platform` | string | Target platform for multi-arch images |
| `--exclude-app-vulns` | bool | Disable application vulnerability scanning |
| `--username` | string | Username for private registry authentication |
| `--password` | string | Password for private registry authentication |
| `--exclude-node-modules` | bool | Exclude node_modules from scanning |
| `--nested-jars-depth` | string | Maximum depth for nested JAR scanning |

The SBOM workflow adds one additional flag:

| Flag | Type | Description |
|---|---|---|
| `--format` | string | **Required.** SBOM output format (no default) |

### Valid `--format` values

`cyclonedx1.4+json`, `cyclonedx1.4+xml`, `cyclonedx1.5+json`, `cyclonedx1.5+xml`,
`cyclonedx1.6+json`, `cyclonedx1.6+xml`, `spdx2.3+json`

### Valid `--platform` values

`linux/amd64`, `linux/arm64`, `linux/riscv64`, `linux/ppc64le`, `linux/s390x`, `linux/386`,
`linux/arm/v7`, `linux/arm/v6`

An empty `--platform` is accepted (omits the flag from the legacy CLI invocation).

## Repo layout

```
pkg/
  container/
    container_cli.go        Only public entry point — exports Init(workflow.Engine) error

internal/
  common/
    constants/
      constants.go          Shared string constants (data types, HTTP headers)
    errors/
      error.go              ContainerExtensionError struct (internal + user-facing messages)
      error_factory.go      Base ErrorFactory (logs internal error, returns user message)
      errors.go             NewEmptyOrgError (generic error constructors)
    flags/
      flag.go               Flag interface
      flags.go              All concrete flag singletons + CommonFlags slice
      base_flag.go          BaseFlag (embeds pflag.FlagSet)
      bool_flag.go          BoolFlag
      string_flag.go        StringFlag
    workflows/
      base_workflow.go      BaseWorkflow (Name, Flags, Identifier, ConfigurationOptions)
  workflows/
    depgraph/
      depgraph.go           DepGraphWorkflow + singleton Workflow var
    sbom/
      sbom.go               Workflow struct, Init, entrypoint
      depgraph.go           depGraphMetadata, parseDepGraph helpers
      archive.go            Archive input detection and name extraction
      http_sbom_client.go   HTTPSbomClient (SbomClient implementation)
      interfaces.go         SbomClient interface (go:generate mockgen)
      interfaces_mocks.go   Generated GoMock mock (committed to source)
      types.go              Request/response structs
      constants/
        constants.go        SbomValidFormats, ValidPlatforms lists
      errors/
        errors.go           SbomErrorFactory (extends base ErrorFactory)
      testdata/             JSON fixtures for tests

scripts/
  coverage.sh               Ratchet-style coverage enforcement (gotestsum)
  license.py                Apache 2.0 header validator/inserter for .go/.rego/.tf/.yaml files

go.mod                      Module: github.com/snyk/container-cli (Go 1.24)
Makefile                    fmt, lint, tidy, test, coverage, build, license, release, all
.golangci.yaml              golangci-lint configuration
.circleci/config.yml        CI pipeline definition
coverage_threshold          Persisted coverage floor (currently 87.9%)
```

## Setup

- **Go 1.24** — match the `go` directive in `go.mod` and the CI image (`cimg/go:1.24`).
- Download dependencies: `go mod download` (or `make tidy` to tidy first).
- No external services or credentials are required to run unit tests.

## Commands

Use only these exact targets from the `Makefile` — do not invent scripts.

| Task | Command |
|---|---|
| Format | `make fmt` |
| Lint | `make lint` |
| Tidy modules | `make tidy` |
| Unit tests | `make test` (runs `go test ./...`) |
| Coverage (ratchet) | `make coverage` |
| Build | `make build` |
| License header check | `PARAM="--validate" make license` |
| All (fmt + lint + tidy + test + build) | `make all` |

`make coverage` uses `gotestsum` and enforces the `coverage_threshold` file (see **Testing rules**
below). `make lint` runs `golangci-lint run ./...` with the config in `.golangci.yaml`.

## Testing rules

- Tests use the standard `testing` package together with `github.com/stretchr/testify`
  (`assert`/`require`).
- Mocks are generated via `github.com/golang/mock` (`mockgen`). The `//go:generate` directive
  lives in `internal/workflows/sbom/interfaces.go`. Regenerate with:
  ```
  go generate ./...
  ```
  The generated file `internal/workflows/sbom/interfaces_mocks.go` is committed to source control —
  always regenerate rather than hand-editing it.
- Test setup follows the `gomock.Controller` pattern (`gomock.NewController(t)` with
  `ctrl.Finish()` or `t.Cleanup`). Existing `*_test.go` files demonstrate the pattern.
- JSON fixtures for SBOM tests live in `internal/workflows/sbom/testdata/`.
- **Coverage may not regress.** `scripts/coverage.sh` compares the current total coverage against
  the value stored in `coverage_threshold` (currently `87.9%`). It ratchets upward only — if
  coverage improves, the threshold file is updated automatically. CI will fail if coverage drops
  below the threshold.

## Debugging

- Logging uses `github.com/rs/zerolog`. The engine's logger is obtained via
  `ictx.GetEnhancedLogger()` (returns `*zerolog.Logger`).
  - Internal errors: logged at `Error` level via `ErrorFactory.NewError`.
  - Workflow lifecycle events: `Info`.
  - Intermediate steps: `Debug`.
- To trace the legacy CLI sub-invocation, inspect `internal/workflows/depgraph/depgraph.go`:
  - `buildCliCommand` — constructs `["container", "test", "--print-graph", "--json", <flags>, <image>]`.
  - `extractDepGraphsFromCLIOutput` — parses stdout with the regex
    `(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`.
  - `extractLegacyCLIError` — decodes `exec.ExitError` into the legacy JSON error envelope
    `{ok, error, path}`.
- HTTP calls to the Snyk REST API are made by `HTTPSbomClient`
  (`internal/workflows/sbom/http_sbom_client.go`). The client uses the `http.Client` returned by
  `engine.GetNetworkAccess().GetHttpClient()`, so proxy and TLS settings are inherited from the
  framework automatically.

## CI

CircleCI (`.circleci/config.yml`). There are two workflow definitions:

**Test** (all non-`main` branches):
1. Lint (`make lint`)
2. Security Scans
3. Unit Tests + Coverage (`make coverage`)
4. Secrets Scan
5. Commit Lint
6. License Check (`PARAM="--validate" make license`)

**Release** (`main` only):
1. Security Scans
2. Lint
3. Unit Tests + Coverage
4. Semantic Release (`make release`) — derives the version from conventional commits and publishes
   a GitHub tag/release via `npx semantic-release`.

Match Go `1.24` locally to match the CI image (`cimg/go:1.24`).

## Commit & PR conventions

- **Conventional commits** enforced by `commitlint` (`commitlint.config.js` extends
  `@commitlint/config-conventional`).
- Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `style`, `test`, `perf`, `build`,
  `ci`, `revert`.
- Semantic-release derives version bumps from commit messages:
  - `feat:` → minor bump
  - `fix:` → patch bump
  - `BREAKING CHANGE` in footer → major bump
- Example: `fix(sbom): handle empty org ID before API call`
- CODEOWNERS: `@snyk/infrasec_container @snyk/container_container` review everything by default.
- This repo accepts **internal (Snyk) contributions only** — see `CONTRIBUTING.md`.

## Things not to touch

- **`coverage_threshold`** — managed exclusively by `scripts/coverage.sh`. Do not hand-edit it
  downward; doing so defeats the ratchet and will cause misleading CI passes.
- **`internal/workflows/sbom/interfaces_mocks.go`** — generated file. Only update it by running
  `go generate ./...`; never hand-edit.
- **`internal/workflows/sbom/archive.go` archive prefix list** — the `archivePrefixes` slice
  (`docker-archive:`, `oci-archive:`, `kaniko-archive:`) and `.tar` suffix detection **must stay
  in sync with `snyk-docker-plugin/lib/image-type.ts`** (`getImageType`). The file documents this
  invariant explicitly.
- **Legacy CLI output regex** in `internal/workflows/depgraph/depgraph.go`
  (`(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`) — this is a structural contract
  with the legacy Snyk CLI's `container test --print-graph --json` output format. Changes here
  require coordinating with the CLI team.
- **Apache 2.0 header on every `.go` file** — enforced by `scripts/license.py`. Use
  `make license` (without `PARAM`) to add headers, or `PARAM="--validate" make license` to check.
  Do not remove or alter existing copyright headers.
- **`pkg/container/container_cli.go`** is the only exported entry point. Do not add new exported
  symbols under `pkg/`; all implementation must remain under `internal/`.

## Style

- Go source is formatted by `gofmt` / `goimports`. Run `make fmt` before committing.
- Linting uses `golangci-lint` with the config in `.golangci.yaml`. Line length cap: **120
  characters** (enforced by the `lll` linter). Active linters include: `errcheck`, `errorlint`,
  `gosec`, `govet`, `staticcheck`, `revive`, `stylecheck`, `gocritic`, `gocognit`, `gocyclo`,
  `dupl`, `goconst`, `misspell`, `whitespace`.
- **Error handling**: use the `ContainerExtensionError` / `ErrorFactory` pattern in
  `internal/common/errors`. This ensures internal error details are logged at `Error` level but
  are never surfaced directly to users — only the `userMsg` field is returned via `Error()`. Do not
  return raw `fmt.Errorf` strings from workflow entrypoints.

## When in doubt

- **Public entry point**: `pkg/container/container_cli.go`.
- **SBOM end-to-end flow**: start at `internal/workflows/sbom/sbom.go` (`entrypoint` function).
- **DepGraph extraction from legacy CLI**: `internal/workflows/depgraph/depgraph.go`.
- **HTTP contract with Snyk REST API**: `internal/workflows/sbom/http_sbom_client.go` — POSTs to
  `{API_URL}/hidden/orgs/{orgID}/sbom?version=2022-03-31~experimental&format=…[&platform=…]`.
- **Adding or changing a flag**: edit `internal/common/flags/flags.go`, then update the workflow
  registration(s) that use it (`internal/workflows/sbom/sbom.go` for SBOM-only flags;
  `CommonFlags` for flags shared by both workflows).
- **Adding a new SBOM format or platform**: update
  `internal/workflows/sbom/constants/constants.go`.
