# Security Policy

Velstra is network infrastructure — a data-plane firewall, router, load balancer,
and overlay, plus a control plane. Security issues are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately, one of:

- **GitHub Security Advisories** — the "Report a vulnerability" button under the
  repository's *Security* tab (preferred).

Please include:

- affected component (crate / binary / eBPF program) and version or commit,
- a description and, if possible, a minimal reproduction,
- impact (what an attacker can do), and any suggested fix.

You will get an acknowledgement within **72 hours**. We aim to confirm or
dismiss a report within **7 days** and to ship a fix or mitigation as quickly as
the severity warrants, coordinating a disclosure date with you.

## Scope

In scope: the Velstra crates and binaries in this repository — the eBPF data
plane, the agent, the controller (incl. the gRPC, admin, and Raft channels), and
the orchestrator/IPAM logic.

Out of scope: vulnerabilities in third-party dependencies (report those upstream;
tell us so we can bump), and misconfigurations of a user's own deployment.

## Supported versions

Until a `1.0` release, only the latest `main` is supported with security fixes.
The supported-version matrix will be published here once tagged releases begin.
