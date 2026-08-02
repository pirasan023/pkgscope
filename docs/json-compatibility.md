# JSON schema compatibility

pkgscope JSON uses `schema_version: 1`. Timestamps are RFC 3339 strings in UTC, byte counts are unsigned integers, and missing knowledge is represented by `null` plus confidence/provenance rather than fabricated sentinel values.

Within schema v1:

- New optional object fields and new manager capability strings may be added.
- Existing field meanings, enum strings, and numeric units do not change.
- Consumers must ignore unknown object fields.
- Arrays are deterministically ordered for human diffability, but consumers must not infer meaning from order.
- stdout contains only the requested format. Progress, warnings, partial failures, and diagnostics use stderr.
- JSONL starts with a `type: "scan"` envelope line. Following lines use `type` plus `data` and repeat `schema_version` and `scan_id`.
- CSV is a flattened installation view and cannot represent every provenance or finding relationship; JSON is canonical.

A breaking field removal, type change, semantic change, or enum reinterpretation requires a new major schema version. The CLI version and schema version evolve independently.

