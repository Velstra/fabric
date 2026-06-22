---
name: Bug report
about: Something doesn't work as expected
title: ""
labels: bug
assignees: ""
---

## What happened

A clear description of the bug.

## Expected

What you expected to happen instead.

## Reproduction

Steps to reproduce. A minimal config (`rules.toml` / `topology.toml`) and the
exact command line help a lot.

```toml
# minimal config that triggers it
```

```
# exact command(s)
```

## Environment

- Velstra version / commit:
- Component: <!-- agent / controller / orchestrator / eBPF / CNI -->
- Kernel (`uname -r`):
- Rust / toolchain (`rustc --version`):
- Attach mode (XDP `driver`/`skb`), NIC/driver if relevant:

## Logs / output

If it's an **eBPF load failure**, paste the verifier output (run the agent
directly so you see it). For data-plane issues, the per-CPU stats table and any
`RUST_LOG=debug` output help.

```
# logs
```
