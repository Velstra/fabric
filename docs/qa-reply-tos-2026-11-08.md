# Synthesized IPv4 reply checksum correction

OSQA-169 was reproduced on the installed immutable QA2 image, using the real
Sentinel CLI and independent OpenStack client. TOS0 TCP SYN receives a usable
RST immediately. TOS184,40,252 instead time out. Independent Ethernet capture
shows that the TOS184 RST retains TOS184 under an IPv4 checksum calculated for
TOS0: checksum `c66c`, expected `c5b4`. Its TCP checksum is correct. No checksum,
GSO/GRO offload, sysctl, clock or guest service was changed to make it pass.

`reject_packet` now explicitly clears TOS to match `plan_tcp_rst`'s canonical
header. `write_synth`, used for SYN-proxy replies, has the same mismatch with
its canonical checksum planner and receives the same correction. The pure
checksum planners are unchanged. Ordinary TOS0 routed reject already works on
QA2; this does not close the older, distinct routed TCP-checksum failure.

The native temporary rule was deleted via verified CLI commit and save. The
original saved configuration, boot, machine, SSH and TLS-key identities were
independently verified unchanged. Protected raw evidence is retained in the
enterprise QA run under `tos-reject1123-private/`; it must not be published
with its private configuration backup.

Sentinel's `checks.x86_64-linux.reject` now tests all64DSCP classes using actual
native sockets and the receiving kernel's `Ip.InHdrErrors`. Its eBPF fixed-output
hash must change, and the VM must load and verify the new object. Passing pure
host tests alone is not dataplane proof or complete production certification.

The forced rebuild of Sentinel's public locked Fabric pin, with the exact
forward/reverse backport, reproduces the corrected object hash
`sha256-dpvGqzkkpxS8BlGtEHsgstx/zmWDX9HRk/MFLe33dFE=`. The KVM reject gate
passes all64native DSCP cases without additional receiver IPv4 header errors.
The SYN-proxy gate passes four real DSCP-marked HTTP sessions, bulk traffic and
its existing flood/recovery case. Host workspace Clippy/tests also pass, with
seven explicitly ignored host tests; those are not described as kernel passes.

Actual signed immutable QA4 on standalone cloud C independently repeats all64
native classes via a real CLI rule and via an actual GUI-created rule. The GUI
case observes exactly64XDP rejects, zero additional receiver header errors and
CLI/UI agreement, then deletes/confirms its rule and restores the original
configuration and identities. No checksum offload settings were changed.
QA4 image SHA256 is
`66d60a48348e256d779f35e2bccfd67576b83bf23ff822cecb7d0828fa61014f`.
The older pair's separate TCP-checksum failure remains unadjudicated.
