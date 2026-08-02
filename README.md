# pkgscope

`pkgscope` is a CLI/TUI for auditing and safely uninstalling developer tools managed by Homebrew, npm, pnpm, pipx, uv, and Cargo on macOS.

## Important notice

This project was created with substantial assistance from generative AI. Although its behavior is reviewed and tested, AI-generated code can contain mistakes, unsafe assumptions, or unexpected behavior.

Use pkgscope entirely at your own risk. In particular, its uninstall feature executes package-manager commands and may remove software or related data. Review the displayed command and confirmation screen before proceeding. The authors, contributors, and AI service providers accept no responsibility or liability for loss, damage, interruption, or other consequences arising from use of this software, to the maximum extent permitted by law. No warranty is provided. The MIT License's “AS IS” terms also apply.

It answers three deliberately separate questions:

- What does each detected manager instance own?
- Which commands are active, hidden, shadowed, colliding, or broken in the current `PATH`?
- What exact manager-native action would remove one record, and how can it be executed only after explicit confirmation?

pkgscope does not claim that a tool is “safe to uninstall,” does not infer a numerical “unused score,” and does not read shell history or project files unless a future evidence feature explicitly asks for consent.

## Status

This repository contains the v0.2 pre-release implementation. Public release binaries are intentionally distributed without Apple Developer ID signing or notarization so the project can remain free to publish and maintain. See the installation warning below before using a downloaded binary.

## Highlights

- Manager-instance-aware inventory for Apple Silicon and Intel Homebrew prefixes, multiple npm roots, pnpm, pipx environments, persistent uv tools, and Cargo install roots.
- Field-level provenance and confidence for versions, dates, architecture, and sizes.
- Separate `duplicate_package`, `command_collision`, `shadowed_command`, `broken_command`, `broken_runtime`, and `partial_data` findings.
- Bounded, parallel manager scans with direct argv execution, timeouts, output limits, cancellation, and partial-success results.
- Stable schema-versioned JSON, JSONL, CSV, and terminal table output. Progress and diagnostics stay on stderr.
- SQLite snapshots with exact first/last-seen times, bounded retention, process-safe writes, health checking, and corruption recovery.
- Interactive TUI with a fresh scan on every launch, highlighted sort columns, explicit ascending/descending indicators, search, locally sourced package descriptions, one vertically scrollable all-details page, rescan, help, and typed-confirmation uninstall.
- No direct file deletion, automatic `sudo`, telemetry, network lookup, or implicit history/project scan. Confirmed uninstalls are delegated to the owning package manager.

## Build and run

Requirements: Rust 1.88 or newer. macOS 14+ on Apple Silicon is the primary target; Intel/Rosetta manager instances are detected separately.

Install the published npm package:

```console
npm install --global @pirasan023/pkgscope
pkgscope
```

Or build from source:

```console
cargo build --release
./target/release/pkgscope doctor
./target/release/pkgscope
```

Running `pkgscope` in an interactive terminal opens the TUI and always performs a fresh scan first. When stdout is piped, it prints a predictable table instead.

## Commands

```text
pkgscope                         TTY: TUI; non-TTY: list
pkgscope tui                     open the interactive interface
pkgscope list                    print the inventory
pkgscope doctor                  diagnose the local setup
```

The normal interface intentionally stays small. Use `--refresh` to force a new scan for non-TUI output and `--format table|json|jsonl|csv` with `list` when machine-readable output is needed. The TUI always starts with a fresh scan.

Examples:

```console
pkgscope
pkgscope list --refresh
pkgscope list --format json > snapshot.json
pkgscope doctor
```

Exit codes are stable for schema v1:

| Code | Meaning |
|---:|---|
| 0 | Requested operation succeeded |
| 1 | General error or cancellation |
| 2 | Invalid argument/configuration |
| 3 | Partial scan; successful manager results are still present |

## Output meaning

`Known since` is the first exact pkgscope observation, not a guessed installation time. Filesystem birth time is shown separately as an estimate. `owned_allocated_bytes` excludes symlink targets and deduplicates hard-linked inodes within a record. Shared pnpm/uv/Cargo stores are not attributed to individual records, and Homebrew cask reclaimable size remains ambiguous where artifacts live outside Caskroom.

JSON uses an envelope with `schema_version`, `generated_at`, `scan_id`, scope, partial status, manager instances, installations, commands, findings, and errors. See [schema-v1.json](docs/schema-v1.json) and [JSON compatibility](docs/json-compatibility.md).

## Privacy and state

State is stored locally at:

```text
~/.local/share/pkgscope/state.db
```

`XDG_DATA_HOME` overrides the base directory. The database contains normalized inventory and derived findings, not registry credentials, environment dumps, shell-history text, or project contents. A corrupt database is preserved before automatic recovery is attempted.

Optional defaults are read from `~/.config/pkgscope/config.toml` (or `XDG_CONFIG_HOME`). See [config.example.toml](docs/config.example.toml). Command-line options override the configuration file; snapshot count/age retention is configurable, and unsafe requests to enable telemetry or retain raw history are rejected.

`--history` and `--project-root` are accepted as explicit consent-shaped preview flags, but v0.2 intentionally reads neither source and reports that fact. There is no telemetry.

## Removal safety

The TUI can execute a manager-native uninstall only after the user opens package details with Enter, presses `u`, reviews the exact executable and arguments, types the full package name, and presses Enter. pkgscope then performs a fresh scan and revalidates the stable ID, owner, version, install root, executable and argument vector. It refuses to remove itself, the manager/runtime required for the action, or a package with reported managed dependents. Commands are invoked directly without a shell and the inventory is rescanned afterward. Homebrew `--zap` is never used; shared caches, configuration, logs, and rollback are not included or promised.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
node --test npm/test/launcher.test.js
```

The integration suite constructs isolated manager fixtures and verifies npm, pnpm, pipx, uv, and Cargo together. Homebrew parser behavior and real-manager behavior are also exercised on macOS CI. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Distribution and releases

The repository includes:

- a native macOS release workflow for `aarch64-apple-darwin` and `x86_64-apple-darwin`;
- checksum, SBOM, and GitHub build-provenance generation;
- explicitly unsigned and unnotarized binaries, with no paid Apple Developer Program requirement;
- an npm thin launcher with platform-specific optional dependencies and version matching;
- a generated Homebrew formula with architecture-specific checksums.

Because the binaries are unsigned, macOS may block or warn about a downloaded release. Do not bypass a security warning unless you trust this repository and have verified the downloaded file against `SHA256SUMS`. Release details are documented in [docs/releasing.md](docs/releasing.md). Package/repository/search/trademark availability must be rechecked immediately before the first public release because `pkgscope` remains a working title.

## License

MIT — see [LICENSE](LICENSE).
