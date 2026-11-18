# Combined Fabric contract check

**Targeted checks passed; release approval remains blocked.** The current
userspace changes, common models and conformance fixtures were compiled and
tested together on a remote Linux builder and a fresh KVM guest. This closes
the combined host-contract check, not the failed stateful traffic gate.

## Results

| Check | Result |
| --- | --- |
| Common unit / documentation tests | 263 / 14 passed |
| Agent unit tests in Linux 6.12.113 | 220 passed; 8 existing privileged tests ignored |
| Expiry / publication fixture unit tests | 7 / 4 passed; one privileged case in each not repeated |
| Publication / NAT writer source guards | 5 / 3 passed |
| Capacity / ICMP / TCP probe self-tests | 6 / 16 / 12 passed |
| Scoped common, agent and three fixture Clippy checks | Passed with warnings denied |
| Full workspace formatting on the frozen source | Passed with the pinned release toolchain |
| Explicit privileged compact-storage test | Passed |

The storage test retained every synthetic record through 32,768 two-policy
flows in a fixed 65,536-entry HASH. Overflow and duplicate admission preserved
existing owners. Four workers competed for 2,048 keys with a rendezvous before
and after each claim; each key had exactly one winner. During 20,000 whole-value
writes, 47,230 reads observed both versions and no mixed value.

These are **kernel storage operations, not TCP connections**. They do not prove
packet read/modify/write serialization or change the production firewall map.
The storage test's ordinarily ignored case was explicitly executed; it is not
counted as passed merely because the default test command skipped it.

The same frozen source also passed the CI host-workspace scope on Rust 1.95.0:
`cargo test --workspace --exclude velstra-ebpf --exclude velstra --locked`
and its all-target Clippy counterpart with warnings denied. Both ran in release
mode with offline dependencies. Results: CNI 16, common 263, configuration 81,
controller 50 plus five integration tests, orchestrator 59 and Raft 13; all
487 tests and 14 common doctests passed, with none ignored. The common checks
repeat the earlier run and are not additional unique coverage. The configuration
suite includes rejection of unauthenticated replication settings.

An initial host-workspace attempt reused the older packet-release compiler and
failed in `fs-err` before testing. The unchanged source passed with the stable
host toolchain; no dependency downgrade or test omission was used. That failed
log is retained. Final host-workspace log SHA-256:
`906a593d0db2000003f1cbeb05a0b15aa7de005235f86b28d6ef44dd1f2d2219`.

## Evidence and scope

The source plan SHA-256 is
`a065e42cd112f9292beeef879c35dd1e3e4e0261b08c459511233ef5eeea9e84`.
All 18 archived files, including test executables and raw receipts, were
individually hash-verified. Archive SHA-256:
`a7c2c3c84d7ccce16358001d4eefb4398f883bb0bbcd204d691dbdcc3ebfed15`.

The agent **unit-test executable**, not a release image, has SHA-256
`e5a63d47dc24ced57597ca061df134eec523a678a768c752788c66ef025f8106`.
The run reused unchanged packet object
`8b0d3f1b27ffd49c5d506b76376f818ff7a1d55076aaec4bf87e2ee1322d371b`;
it did not attach or newly qualify that object. Actual KVM descriptors were
observed during execution, and the guest exited after the tests.

The first attempt failed on two Clippy formatting diagnostics in the publication
fixture. Only those two error-message expressions changed; assertions and test
thresholds stayed unchanged. Failed build logs were retained before the complete
successful rerun.

The sequence-aware TCP model and compact representation remain prerequisites,
not live datapath or HA migrations. No pressure, packet-publication fault,
expiry live-traffic, HA, verifier, signed-image, SBOM or CVE gate was repeated
by this contract batch. Their earlier evidence and remaining failures keep
their original scope. No production dependency pin or release was changed.
