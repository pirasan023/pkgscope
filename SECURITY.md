# Security policy

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories for this repository. Do not include credentials, complete shell history, private registry output, or other secrets in a report. A minimal redacted reproducer is preferred.

## Security boundary

pkgscope treats manager executables, manager metadata, paths, and filenames as untrusted local inputs. Manager processes are invoked directly with an executable and argument array, never through a shell. Output is bounded and timed out, terminal controls are removed, and symlinks are not recursively followed for size scans. TUI uninstall requires exact-name confirmation and a fresh identity/owner/action revalidation; it refuses self, required manager/runtime, and reported managed-dependent removal before invoking the owning package manager.

Snapshot state intentionally excludes registry credentials, environment dumps, raw shell history, and project file contents. Telemetry is disabled and not implemented.

Signed public releases are expected to include SHA-256 checksums, an SBOM, GitHub build provenance, Developer ID signatures, and Apple notarization. If any mandatory signing/notarization secret is absent, the release workflow fails instead of publishing an unsigned substitute.
