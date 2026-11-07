# Test data

## osv-schema.json

A copy of the official OSV JSON schema, used by `tests/test_advisory.py` to validate the advisory pack's `osv-draft.json`.

- Source: <https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json>, from the repository <https://github.com/ossf/osv-schema>, at commit `cfe70141baa3cc24184333c4bdf393f3a6fe9b07` (committed 2026-10-14). The repository's latest tag at the time was `v1.9.2`, and its `docs/schema.md` gives version 1.9.2 (October 13, 2026).
- Fetched: 2026-11-07.
- Licence: Apache License 2.0, the licence of the ossf/osv-schema repository (<https://github.com/ossf/osv-schema/blob/main/LICENSE>, checked through GitHub's licence API on 2026-11-07). The file is unchanged.

The schema test needs the optional `jsonschema` package and skips with a message when it is not installed (CI installs jsonschema 4.26.0; local installations remain optional). A second test checks the required fields and their types without any package, so it always runs.
