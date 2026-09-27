# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository:

https://github.com/fastrevmd-lab/rustunifimcp/security/advisories/new

Include what you'd include in a bug report — affected version, reproduction steps, and impact — but keep it in the private report, not a public issue, PR, or discussion.

## Scope

`rustunifimcp` is an MCP server that authenticates to one or more UniFi Network controllers and exposes a curated, scoped set of read and write tools over MCP, with authentication, transport, audit, and change-control behavior supplied by the shared [`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) crates. Vulnerability classes we especially want to hear about:

- Anything that lets a caller reach a write tool, or exceed the scope granted to its token, without going through the intended auth/scope checks
- Anything that lets a UniFi change set apply — or bypass its pre-image capture, local validation, or rollback steps — without the operator's explicit approval
- TLS or certificate-handling issues in the server's listener
- Injection or path-traversal issues via the controller inventory file, token store, or change-set state file
- Parsing issues where a malicious or malformed controller response could affect the server beyond the intended request

If the issue is actually in shared `mecmcp` code rather than something specific to this repo's UniFi integration, it's still fine to report it here — it will get routed to the right repository.

## Response

This is a community-maintained project. There's no guaranteed SLA, but reports are read and triaged by a human maintainer, not by any automated or model-based process.
