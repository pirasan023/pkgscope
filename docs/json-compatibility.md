# JSON schema compatibility

pkgscope v0.3.0 writes `schema_version: 2`. Timestamps are RFC 3339 UTC strings, byte counts are unsigned integers, and missing knowledge is represented by `null` with provenance and confidence rather than a fabricated sentinel.

Schema v2 formalizes:

- `apt`, `dnf`, `pacman`, `snap`, and `flatpak` manager values in addition to the original six;
- `deb`, `rpm`, `pacman`, `snap`, and `flatpak` source kinds;
- optional `host.linux_distribution` fields sourced from `/etc/os-release` or `/usr/lib/os-release`;
- the existing manager-instance, installation, command, finding, error, scope, partial-result, and field-provenance model.

Within schema v2, new optional object fields and capability strings may be added. Existing meanings, enum strings, and numeric units do not change. Consumers must ignore unknown object fields and must not infer meaning from deterministic array ordering.

JSON is canonical. JSONL begins with a `type: "scan"` envelope and subsequent lines repeat `schema_version` and `scan_id`. CSV is a flattened installation view and cannot represent all provenance and relationships. stdout contains only the requested format; progress and diagnostics use stderr.

Schema v1 remains checked in at [schema-v1.json](schema-v1.json). v0.3.0 can deserialize a v1 snapshot for compatibility and migration safety, but it does not reuse that snapshot to answer a current request. A cache hit requires the current schema number, so v1 automatically triggers a fresh local scan and the next stored snapshot is v2. Consumers that need the new Linux or manager values must validate against [schema-v2.json](schema-v2.json).

A breaking removal, type change, semantic change, or enum reinterpretation requires another schema version. CLI and schema versions evolve independently.
