# Use case: an ISSO preparing for FedRAMP Moderate

This is an illustrative scenario. The company, people, and numbers are made up; the commands and control mappings are real.

## The situation

A 400-person SaaS company is working toward FedRAMP Moderate. Over six months, its engineers adopted Cursor and Claude Code and added MCP servers for GitHub, Postgres, Slack, and the local filesystem. Nobody approved them. They just got added.

During readiness, the 3PAO asks the ISSO: *"Your developers use AI agents with tool access. How is that covered in your SSP, and where are the findings?"*

Security has already run an MCP scanner on a few machines, but its results ("MCP04: unpinned package") don't map to anything in the ISSO's control set.

## What the ISSO does with mcp-crosswalk

### 1. Find out what is actually there (MCP09, shadow servers)

IT runs a read-only discovery scan on developer endpoints. It parses config files only and never starts, installs, or connects to a server.

```bash
mcpxw scan --discover --allowlist approved-servers.yaml --format json,md,poam --out mcpxw-report
```

Result: 140 MCP servers across 60 laptops, 31 not on the approved list. Those findings point to **CM-8(3)** and **CM-7(5)**, and the server inventory in the report is evidence for **CM-8**.

### 2. Translate the scanner results the team already has

The security team's existing scanner writes SARIF tagged with OWASP MCP IDs. `enrich` adds the mapped controls to every finding without changing tools.

```bash
mcpxw enrich their-scanner-results.sarif --format sarif,md --out enriched
```

A finding like *"Postgres MCP server launched via `npx -y` with no pinned version"* now carries **MCP04 → SI-7, SR-4, CM-7(5), CM-11, ID.RA-09**, with 800-53 baseline membership.

### 3. Turn findings into POA&M entries

The `poam` format writes one CSV row per finding with the control, severity, evidence, and remediation. Example rows:

| Finding | Control | Severity | Remediation |
|---|---|---|---|
| Plaintext GitHub tokens in MCP config on 12 laptops | IA-5(7) | High | Move tokens to the OS keychain or a secret manager; rotate |
| Filesystem servers rooted at the home directory on 4 laptops | AC-6 | High | Scope to project directories |
| Remote MCP servers over plain `http://` | SC-8(1) | High | Enforce TLS |

The ISSO imports the CSV into the POA&M tracker instead of writing each entry by hand.

### 4. Update the SSP

The crosswalk shows which control implementation statements need an MCP paragraph: CM-7(5) for the approved server list, IA-5(7) for no secrets in config files, AC-6 for scoped filesystem access, and so on. Each mapping's rationale is a starting point for the wording.

### 5. Document what a config scan cannot see

Every report lists MCP03, MCP06, and MCP08 (tool poisoning, prompt injection, audit logging) as **not assessed**, because they only appear at runtime. The ISSO records that as a known gap and plans a runtime control, such as an MCP gateway with logging, for AU-2 and AU-12.

### 6. Make it continuous monitoring

The scan runs monthly. New findings flow into the POA&M and closed ones drop off, which becomes continuous monitoring evidence for **CA-7**.

## What changed

- **Before:** MCP risk was invisible to the compliance program, and there was no answer for the assessor.
- **After:** MCP risk appears in the same inventory, POA&M, and SSP the assessor already reviews, with a clear statement of what the tool can and cannot see.

The tool does not decide what is acceptable risk, and its output is not a compliance determination. It puts engineering findings into the language the compliance program already uses.
