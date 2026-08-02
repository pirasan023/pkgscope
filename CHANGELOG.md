# Changelog

All notable changes are documented here. The project follows semantic versioning for the CLI and separately versions its JSON schema.

## [Unreleased]

## [0.2.0] - 2026-08-02

### Added

- One vertically scrollable package page containing overview, commands, evidence, dependencies, and the exact uninstall action.
- Typed-confirmation TUI uninstall with fresh identity/action revalidation, direct argv execution, self/runtime/dependent protection, and post-action rescanning.
- Locally sourced package descriptions and explicit highlighted sort direction indicators.

## [0.1.0] - 2026-08-01

### Added

- Read-only v0.1 inventory core for Homebrew formulae/casks, npm global packages, pnpm global packages, pipx, persistent uv tools, and Cargo installs.
- Manager-instance discovery, partial-success scanning, field provenance, size/date semantics, PATH resolution, findings, SQLite snapshots, removal planning, TUI, and schema-v1 output.
- Isolated integration fixtures, security-focused unit tests, npm launcher, native packaging, and signed release automation.
