# Crosswalk methodology

This document explains how the OWASP MCP Top 10 to NIST crosswalk in `crosswalk/` was built, what the
relationship and confidence fields mean, and where the mappings stop being reliable.

> Findings are indicators relevant to the listed controls. They are not a compliance determination.
> Mappings are maintainer-reviewed and not endorsed by OWASP or NIST.

## Sources

| Source | Version | Use |
|---|---|---|
| OWASP MCP Top 10 | 2025, Phase 3 beta (retrieved 2026-10-07) | Risk IDs and titles only (CC BY-NC-SA 4.0). Summaries are original. |
| NIST SP 800-53 Rev 5 | OSCAL catalog 5.2.0 (`catalog/frameworks/`) | Control and enhancement IDs, titles, statement text |
| NIST CSF 2.0 | OSCAL catalog (`catalog/frameworks/`) | Subcategory IDs and statement text |
| NIST SP 800-53 Rev 5 baselines | LOW, MODERATE, HIGH, PRIVACY resolved-profile catalogs (`metadata.version` 5.2.0 in all four), as published on 2026-10-07 | Derived baseline membership only |
| NIST SP 800-171 Rev 3 | OSCAL catalog 1.1.0 | Derived requirement links only |

Catalog provenance (URL, retrieval time, SHA-256) is in `catalog/frameworks/SOURCES.md`. Each scan report
also records the SHA-256 of the 800-53 and CSF catalogs it used.

## Mapping unit

Each crosswalk file maps **one OWASP MCP risk** to controls. The thing being compared is the risk's
**mitigation need**: what an organization would have to do to reduce that risk for MCP deployments. The risk is
the focal element and the control is the reference element (see the relationship direction below). A control
is mapped when implementing it would materially contribute to that need. Unrelated controls are simply not
mapped; there is no "not related to" entry.

Valid targets:

- **SP 800-53 Rev 5:** base controls and control enhancements that are not withdrawn. Enhancements are preferred
  when one fits more precisely than its base control (for example `IA-5(7)` rather than only `IA-5`).
- **CSF 2.0:** subcategories only (for example `PR.AA-01`). Functions (`PR`) and categories (`PR.AA`) are not
  valid targets.

## Relationship direction (NIST OLIR convention, NIST IR 8278)

Relationships follow the NIST Online Informative References (OLIR) convention. Each one describes the **focal
document element**, the OWASP MCP risk, relative to the **reference document element**, the NIST control or
subcategory. Read every row as "the risk is ___ the control".

Here the risk means its mitigation need: what an organization would have to do to reduce that risk in MCP
deployments.

| Relationship | Meaning | Example |
|---|---|---|
| `subset_of` | The risk is a subset of the control. Everything the risk needs is within the control's scope, and the control also covers other things. | `SR-3` for MCP04: supply chain weaknesses in the registries, maintainers, and build pipelines behind MCP server packages fall entirely within supply chain controls and processes, which also cover all other suppliers. |
| `superset_of` | The risk is a superset of the control. The control covers part of what the risk needs and nothing outside it. | Not used. |
| `equal` | The risk and the control cover the same scope. | Not used. No control matches an MCP risk exactly. |
| `intersects_with` | The risk and the control overlap, and each also covers things the other does not. | `SI-7(1)` for MCP03: startup integrity checks detect a tool description changed after approval, but not poisoning present at approval, and the control also covers firmware and software unrelated to MCP. |

After the maintainer review, 76 of the 77 mappings are `intersects_with` and one is `subset_of`. That is
expected: general-purpose controls cover much more than MCP, and most MCP risks have exposure paths that any one
control misses.

## Confidence

| Confidence | Meaning |
|---|---|
| `high` | The control text directly addresses the MCP mechanism behind the risk. A practitioner would expect this mapping. |
| `medium` | The control clearly applies, but only to one aspect of the risk, or only once the control is tailored to MCP. |
| `low` | Plausible but indirect. Implementing the control helps, but it would not usually be cited as the mitigation. |

Confidence was not inflated: where a candidate control's text only loosely fits, it is marked `low` or dropped.

## Process

1. Started from the candidate list in the build specification.
2. For each candidate, read the control statement in the vendored OSCAL catalog (not from memory) and kept it only
   if the statement fits the MCP mechanism. Added better-fitting controls found while reading the catalog
   (for example `CM-7(6)` confined environments, `CM-8(3)` unauthorized component detection, `SI-7(1)` startup
   integrity checks, `SI-15` output filtering, `SC-8(1)` cryptographic transmission protection).
3. Dropped candidates whose control text did not fit (recorded in [`DECISIONS.md`](build-log/DECISIONS.md)), for
   example `SC-12` (cryptographic key management, not API tokens) and `CM-10` (software licensing and copyright, not
   shadow servers).
4. Wrote each rationale in original words, naming the MCP mechanism (config file, stdio command, tool description,
   remote transport) that connects the risk to the control.
5. Linked each mapping to the scanner checks (`check_ids`) whose findings are evidence relevant to that mapping.
   A mapping with no `check_ids` is still a valid mapping; it just cannot be evidenced by static config analysis.
6. `mcpxw crosswalk validate` enforces the structural rules (schema, one file per risk, IDs exist and are not
   withdrawn, minimum counts, no duplicates, check references consistent, rationale length).
7. The maintainer reviewed all 77 mappings against the control text on 2026-10-31, using the worksheet in
   [`review/crosswalk-review.csv`](review/crosswalk-review.csv), which records each decision and its reasoning.
   The review changed five relationship types, set the relationship direction to the OLIR convention above, and
   lowered the confidence of two MCP01 mappings (`SC-28`, `PR.DS-01`). No mapping was dropped.

## How findings use the crosswalk

A scanner finding carries the controls from the crosswalk for the finding's risks, **restricted to mappings whose
`check_ids` include that check**. A finding from `MCPXW-001` (literal secret in `env`) therefore lists `IA-5(7)`,
`IA-5`, `SC-28`, `PR.AA-01`, and `PR.DS-01`, but not `AC-3`, which is mapped to MCP01 without check evidence.

## Derived federal context (not authored mappings)

Two columns are computed from vendored NIST OSCAL files at run time. They are never stored in the crosswalk YAML,
never count toward mapping totals, and are always labeled as derived.

- **Baselines.** For each SP 800-53 control in the crosswalk, membership in the LOW, MODERATE, HIGH, and PRIVACY
  baselines is an **exact OSCAL ID match** (`ac-2`, `ac-2.1`) against the control IDs in NIST's resolved-profile
  baseline catalogs. `IA-5` and `IA-5(7)` are different IDs; each is looked up on its own. All four vendored
  baseline files report `metadata.version` 5.2.0 (the HIGH file's title still says "Revision 5.1.1"); membership is
  taken as published.
- **800-171r3 (derived via source 800-53 control).** Each SP 800-171 Rev 3 requirement (for example `03.05.07`
  Password Management) has `reference` links to back-matter resources; resources whose title is an SP 800-53
  control in zero-padded form (`IA-05(01)`) are its source controls. Inverting those links gives, for an 800-53
  control, the requirements that cite it. Rules: **exact ID match only** (a mapping to `IA-5` does not inherit
  `03.05.07`, which cites only `IA-5(1)`); references that are not 800-53 IDs (for example `SP 800-63-3`) are
  ignored; the 33 withdrawn requirements are excluded; `addressed_by` and `incorporated_into` links are ignored.
- **What this does not mean.** A derived link says "NIST lists this 800-53 control as a source of that 800-171r3
  requirement". It is not a mapping from the MCP risk to the requirement, and it is not reviewed. **It does not
  indicate CMMC alignment:** CMMC Level 2 assessments reference SP 800-171 Rev 2, not Rev 3.

## OWASP catalog versions and migration

`catalog/owasp-mcp/versions.yaml` lists the catalog versions (`id`, `file`, `status`, `retrieved`, and the
`crosswalk` directory authored for it). The default is `2025-beta`. Scanner checks declare risk IDs in the default
version's numbering; for another version they are translated through the migration file
`catalog/owasp-mcp/migrations/<from>__to__<to>.yaml`, which must list every old risk ID with its new ID or `null`
(retired) and a note. `mcpxw crosswalk migrate --to <version> --out <dir>` writes renumbered copies (never in
place), reports renamed and retired risks, and exits 1 while a risk that is new in the target version has no
crosswalk file. Migrated files stay `draft`: a renumbered risk may also have a changed scope, so every mapping must
be re-read against the new risk text. No migration ships yet, because no newer OWASP version is published.

## `mcpxw enrich`: ID assumptions

`enrich` reads OWASP MCP risk IDs (`MCP01` to `MCP10`, optionally with a `:20NN` year suffix, case-insensitive, as
whole tokens) from a SARIF result's `ruleId`, message text, and tags, and from the matching rule's `id`, `name`,
`shortDescription`, and tags. The matching rule is looked up only in the tool component that owns the result
(`rule.toolComponent`, otherwise the driver). In message text the match is stricter: an ID glued to a `.`, `/`, or
`-` word (`mcp05.internal.example.com`, `servers/mcp01/config.json`, `mcp-server-mcp03`, `MCP10.2`) is not read as
a risk ID, because free text often names hosts, paths, and packages. It then attaches **all** crosswalk mappings for those risks, because a foreign
scanner's checks are not linked to this project's `check_ids`. That makes enrichment broader than a native `scan`
finding, which lists only the mappings that cite its check. It assumes the input uses the **official OWASP
numbering** of the selected catalog version; some tools number MCP risks differently, and `enrich` cannot detect
that. IDs with no crosswalk file in the selected version are counted in the summary and not enriched.

## Limitations

- **Single reviewer.** The mappings were drafted by an automated build and then reviewed by the maintainer (step 7
  of the process). They have not been reviewed by OWASP, NIST, or an independent assessor. Treat them as one
  practitioner's informed judgment, not an authoritative mapping.
- **Static evidence only.** Three risks (MCP03 Tool Poisoning, MCP06 Prompt Injection, MCP08 Lack of Audit and
  Telemetry) cannot be assessed from config files. Their mappings are documentation only.
- **Indicators, not determinations.** A finding indicates a condition relevant to a control. It never shows that a
  control is or is not implemented; the control may be satisfied by a compensating mechanism the scanner cannot see.
- **Beta source.** The OWASP MCP Top 10 is in beta. Risk titles and scope may change; each crosswalk file records
  its `catalog_version`, and validation fails if it does not match the selected catalog.
- **Single reviewer judgment.** Relationship and confidence are judgments. Reasonable practitioners may differ,
  particularly between `subset_of` and `intersects_with`.
- **Baselines are context, not tailoring.** Baseline membership shows where NIST selected a control; it does not
  say which mappings apply to a given system, and it ignores tailoring and overlays.
