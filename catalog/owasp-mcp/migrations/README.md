# OWASP MCP Top 10 risk ID migrations

No migration ships yet: as of 2026-10-07 the only published OWASP MCP Top 10 is the 2025 beta.

When OWASP publishes a new version:

1. Add its catalog file (IDs and titles only, original summaries) to `catalog/owasp-mcp/` and list it in
   `versions.yaml` with `crosswalk: null`.
2. Author `migrations/<from>__to__<to>.yaml` (schema: `schema/migration.schema.json`):

   ```yaml
   from_version: 2025-beta
   to_version: <new id>
   map:
     MCP01: {to: MCP01, note: Unchanged.}
     MCP07: {to: MCP11, note: Renumbered; scope unchanged.}
     MCP08: {to: null, note: Retired; folded into the new logging risk.}
   ```

   Every risk of `from_version` must be listed. `to: null` retires a risk. Two old risks may not map to
   the same new ID (merges are authored by hand).
3. Run `mcpxw crosswalk migrate --to <new id> --out <dir>`. It writes renumbered copies to `<dir>` (never in
   place), reports renamed and retired risks, and exits 1 while any new risk has no crosswalk file.
4. Author the missing files, review every migrated mapping, then run
   `mcpxw crosswalk validate --catalog-version <new id> --crosswalk-dir <dir>`.
5. Move the reviewed files into place and set `crosswalk:` for the version in `versions.yaml`.
