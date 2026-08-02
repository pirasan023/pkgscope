# Changelog

All notable changes are documented here. The project follows semantic versioning for the CLI and separately versions its JSON schema.

## [Unreleased]

## [0.3.0] - 2026-08-02

### Added

- Native Linux x64 and ARM64 support with statically linked musl releases, ELF CPU detection, `os-release` host metadata, Linuxbrew discovery, and Linux-aware filesystem measurements.
- Local, explicit-package inventory for apt, DNF4/DNF5, and pacman; application inventory for Snap; and separate user/default/named system Flatpak scopes.
- Manager-native Linux metadata for descriptions, URLs, versions, CPU, sizes, install times, dependencies, and commands without registry or repository lookups.
- Exact target-only apt, DNF, and pacman transaction verification; explicit root preconditions without automatic `sudo`; non-purging Snap and data-preserving Flatpak removal.
- JSON schema v2 and automatic fresh scanning when a readable schema-v1 snapshot is encountered.
- Linux ARM64/x64 npm packages, four-target release archives, SBOMs, checksums, provenance, a cross-platform Homebrew Formula, Linux distribution CI, and publication re-verification.
- Pseudo-terminal automation for the complete navigation, sorting, search, details, confirmation, cancellation, rejection, deletion, and rescan flow.

## [0.2.0] - 2026-08-02

### Added

- One vertically scrollable package page containing overview, commands, evidence, dependencies, and the exact uninstall action.
- Typed-confirmation TUI uninstall with fresh identity/action revalidation, direct argv execution, self/runtime/dependent protection, and post-action rescanning.
- Locally sourced package descriptions and explicit highlighted sort direction indicators.

## [0.1.0] - 2026-08-01

### Added

- Read-only v0.1 inventory core for Homebrew formulae/casks, npm global packages, pnpm global packages, pipx, persistent uv tools, and Cargo installs.
- Manager-instance discovery, partial-success scanning, field provenance, size/date semantics, PATH resolution, findings, SQLite snapshots, removal planning, TUI, and schema-v1 output.
- Isolated integration fixtures, security-focused unit tests, npm launcher, native packaging, and release automation.
