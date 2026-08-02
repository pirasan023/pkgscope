# @pirasan023/pkgscope

This is the OS-independent npm launcher for pkgscope. It selects an exact-version native package for macOS or Linux and ARM64 or x64, verifies that the bundled binary reports the same version, and launches it with a direct argument array and `shell: false`.

```console
npm install --global @pirasan023/pkgscope
pkgscope
```

The native package is one of:

- `@pirasan023/pkgscope-darwin-arm64`
- `@pirasan023/pkgscope-darwin-x64`
- `@pirasan023/pkgscope-linux-arm64`
- `@pirasan023/pkgscope-linux-x64`

Linux packages contain statically linked musl binaries. Windows and other CPUs are rejected with an explicit unsupported-platform error.

pkgscope inventories Homebrew, npm, pnpm, pipx, uv, Cargo, apt, DNF, pacman, Snap, and Flatpak from local data. Uninstall is never automatic: the TUI shows the exact command, requires the full package name, revalidates the installation, and applies manager-specific dependency and privilege checks. pkgscope never invokes `sudo`, purges Snap data, or deletes Flatpak user data.

Release archives, SHA-256 checksums, SBOMs, provenance attestations, documentation, and source are available in the [GitHub repository](https://github.com/pirasan023/pkgscope).
