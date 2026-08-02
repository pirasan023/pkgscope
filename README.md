# pkgscope

`pkgscope` is an offline-first CLI/TUI for auditing and safely uninstalling packages managed by Homebrew, npm, pnpm, pipx, uv, Cargo, apt, DNF, pacman, Snap, and Flatpak on macOS and Linux.

## Important notice

This project was created with substantial assistance from generative AI. Although its behavior is reviewed and tested, AI-generated code can contain mistakes, unsafe assumptions, or unexpected behavior.

Use pkgscope entirely at your own risk. Its uninstall feature runs package-manager commands and may remove software or related data. Always review the displayed command and confirmation screen. The authors, contributors, and AI service providers accept no responsibility or liability for loss, damage, interruption, or other consequences arising from use, to the maximum extent permitted by law. The MIT License's “AS IS” terms apply.

## What it does

- Inventories each detected manager instance from local metadata, without requiring a network connection.
- Shows which commands are active, hidden, shadowed, colliding, or broken in the current `PATH`.
- Separates explicitly installed apt, DNF, and pacman packages from automatically installed system libraries.
- Treats Snap applications as records while retaining bases, kernels, and content providers as dependency evidence.
- Separates Flatpak user, default-system, and named-system installations.
- Reports locally sourced descriptions, URLs, versions, CPU architectures, sizes, install times, dependencies, and owned commands. Unknown values remain unknown; pkgscope does not guess them.
- Builds one exact manager-native uninstall action, shows it, and requires typed confirmation before execution.

pkgscope does not calculate an “unused score,” read shell history or projects without explicit future consent, use telemetry, delete files directly, contact package registries for inventory, or invoke `sudo`.

## Install

The same command is used on supported macOS and Linux systems:

```console
npm install --global @pirasan023/pkgscope
pkgscope
```

Supported release targets are:

| OS | CPU | Native target |
|---|---|---|
| macOS 14+ | Apple Silicon | `aarch64-apple-darwin` |
| macOS 14+ | Intel | `x86_64-apple-darwin` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` |
| Linux | x64 | `x86_64-unknown-linux-musl` |

Linux releases are statically linked musl binaries and are tested on Ubuntu, Debian, Fedora, Arch, Alpine, and the standard Linuxbrew environment. The native archives and generated Homebrew Formula are also attached to each GitHub Release.

To build from source, install Rust 1.88 or newer:

```console
cargo build --release
./target/release/pkgscope doctor
./target/release/pkgscope
```

## Commands

```text
pkgscope                         TTY: TUI; non-TTY: list
pkgscope tui                     open the interactive interface
pkgscope list                    print the inventory
pkgscope doctor                  diagnose the local setup
```

The normal interface intentionally stays small. `--refresh` forces a new scan for non-TUI output. `--format table|json|jsonl|csv` selects output. The TUI always starts with a fresh scan and uses the same screen, keys, and meanings on macOS and Linux.

Examples:

```console
pkgscope
pkgscope list --refresh
pkgscope list --format json > snapshot.json
pkgscope doctor
```

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | Requested operation succeeded |
| 1 | General error or cancellation |
| 2 | Invalid argument or configuration |
| 3 | Partial scan; successful manager results remain available |
| 4 | Requested installation was not found |

## Output and JSON

`Known since` is the first exact pkgscope observation, not a guessed installation time. A filesystem timestamp is labeled as estimated. Package managers' local databases and receipts are authoritative for their own fields. Size methods and confidence are reported with the result.

JSON output uses schema v2 and includes Linux distribution information read from `os-release`, the eleven manager values, and the new source kinds. See [schema-v2.json](docs/schema-v2.json) and [JSON compatibility](docs/json-compatibility.md). Schema v1 snapshots still deserialize, but v0.3.0 never reuses them as a current cache: it automatically performs a fresh scan and writes v2.

## Local state and privacy

State is stored in `~/.local/share/pkgscope/state.db`; `XDG_DATA_HOME` overrides the base directory. The database contains normalized inventory and derived findings, not registry credentials, environment dumps, shell-history text, or project contents. Corrupt databases are preserved before recovery.

Optional defaults are read from `~/.config/pkgscope/config.toml` or `XDG_CONFIG_HOME`; see [config.example.toml](docs/config.example.toml). Command-line options override the file. Unsafe requests to enable telemetry or retain raw history are rejected. `--history` and `--project-root` remain consent-shaped preview flags and do not read those sources in v0.3.0.

## Removal safety

The TUI requires this sequence: open details with Enter, press `u`, review the exact executable and argument array, type the full package name, and press Enter. pkgscope then performs a fresh scan and revalidates the stable identity, owner, version, install root, executable, dependencies, and action. It refuses to remove itself, the package manager, its runtime, or a record with known managed dependents, and rescans after success.

For apt, DNF, and pacman, pkgscope additionally simulates or tests the removal transaction immediately before execution. If it cannot prove that exactly the selected package—and no replacement or dependent package—will change, it refuses the operation. System changes run only when pkgscope already has the required effective root privilege. Otherwise it displays the command and reason and stops; it never starts `sudo`.

Snap removal never adds `--purge`, so Snap data is retained. Flatpak removal never adds `--delete-data` and never uninstalls related refs automatically. Homebrew never uses `--zap`. Shared caches, rollback, and configuration removal are not promised.

## Development and verification

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo audit --deny warnings
npm test --prefix npm
```

Unit and isolated integration tests cover Mach-O/ELF inspection, all eleven managers, malformed and unknown input, control characters, bounded output, timeouts, safe removal planning, permissions, and direct argument execution. A pseudo-terminal test drives TUI navigation, both sort directions, search, detail scrolling, cancellation, wrong confirmation, and disposable-package removal. CI adds real or container-isolated checks on supported Linux families, Linuxbrew, Flatpak scopes, Snap, ARM64, and macOS regression.

## Distribution security

Every release contains four native archives, `SHA256SUMS`, a CycloneDX SBOM per target, GitHub build-provenance attestations, and a generated Homebrew Formula. Linux binaries are checked for CPU type, absence of dynamic dependencies, and real startup. Published npm and GitHub artifacts are re-downloaded into clean x64 and ARM64 Linux jobs and exercised again.

The binaries are not code-signed or notarized. macOS may block or warn about a downloaded binary; Linux distributions may also display provenance or trust warnings for manually downloaded executables. Verify the archive against `SHA256SUMS` and its GitHub attestation before use. See [SECURITY.md](SECURITY.md) and [the release procedure](docs/releasing.md).

## License

MIT — see [LICENSE](LICENSE).
