# Contributing

pkgscope prioritizes false-positive avoidance, provenance, and explicit confirmation over feature count.

Before opening a change:

1. Keep manager output as untrusted input. Use structured output where available, tolerate unknown fields, sanitize terminal text, and never compose shell command strings.
2. Do not label an estimate as exact. New inferred fields require a source, confidence, observation time, fixture, and an explanation of failure modes.
3. Do not attribute shared stores or caches to an individual installation.
4. Preserve partial results when one manager fails. Never present an old failed-manager snapshot as current without a stale marker.
5. Any destructive workflow must use manager-native direct argv, typed confirmation, fresh identity/ownership revalidation, self/runtime/dependent protection, and a post-action scan.

Run the complete local gate:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
cargo audit --deny warnings
npm test --prefix npm
```

Parser changes should include a minimal fixture covering the relevant manager version and malformed/unknown-field cases. Security fixes should include a regression test where practical.
