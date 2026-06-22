<!--
Thanks for contributing to Velstra! By submitting this PR you agree to the
Contributor License Agreement (see CONTRIBUTING.md), which keeps dual-licensing
possible.
-->

## What & why

What does this change do, and why?

Closes #<!-- issue number, if any -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] CI / tooling

## Checklist

- [ ] `cargo fmt --all` is clean
- [ ] `cargo clippy --workspace --exclude velstra-ebpf` passes with no warnings
- [ ] `make test` passes (host crates)
- [ ] New logic has unit tests (in `velstra-common` if it's data-plane logic, so
      the kernel and the tests share one implementation)
- [ ] If this changes the **eBPF data plane**, I ran `make e2e` (or noted that a
      maintainer must, since loading needs root)
- [ ] Docs / comments updated for any new public API or behavior

## Notes for reviewers

Anything tricky, trade-offs, or follow-ups.
