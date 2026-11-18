# RELATED ICMP: Linux parity correction

This is a targeted correction, not final-image or all-protocol certification.
The prior real differential receipt remains a failure: Linux6.12.113 forwarded
two variants that Sentinel rejected on SNAT, DNAT and hairpin paths. Both also
reached the real connected UDP socket with `IP_RECVERR` enabled:

| Variant | Linux raw delivery | Native UDP error |
| --- | --- | --- |
| Corrupt quoted IPv4 checksum, valid enclosing checksums | Yes; quoted residual stays invalid | `ECONNREFUSED`, type3/code3 |
| Time Exceeded with unassigned code2 | Yes | `EHOSTUNREACH`, type11/code2 |

## Compatibility decision

For the supported ICMP error types3/11/12, the code is opaque routing metadata
and is preserved unchanged. Redirect, Source Quench and unrelated ICMP types
remain outside this RELATED permission. A quoted IPv4 header is data inside
the ICMP message, not another independently received IPv4 packet. Its checksum
is adjusted incrementally during inverse NAT, preserving any existing corrupt
residual rather than silently repairing it.

This intentionally follows Linux conntrack interoperability instead of
[RFC5508§4.1 REQ-3a](https://www.rfc-editor.org/rfc/rfc5508.html#section-4.1),
which recommends dropping an invalid embedded IP checksum. It is not a claim
that such a quote is RFC-valid. The enclosing IPv4 header and **entire** ICMP
message still require valid checksums. Length/IHL/fragment/transport bounds,
the outer destination versus quoted sender, existing unexpired NAT and physical
firewall state, interface policy, epochs and explicit operator denies remain
mandatory. An ICMP error creates or refreshes no NAT state.

The exact tested Linux source supports this distinction:

- [conntrack error association](https://github.com/gregkh/linux/blob/v6.12.113/net/netfilter/nf_conntrack_proto_icmp.c)
  checks the ICMP checksum and existing matching tuple, without an embedded-IP
  checksum or per-code gate for error association.
- [NAT ICMP translation](https://github.com/gregkh/linux/blob/v6.12.113/net/netfilter/nf_nat_proto.c)
  inverse-translates the embedded tuple and recomputes the enclosing checksum.
- [ICMP endpoint dispatch](https://github.com/gregkh/linux/blob/v6.12.113/net/ipv4/icmp.c)
  does not deliver Destination Unreachable codes above15 to UDP, even when the
  router forwards them. The new type3/code16 control therefore requires raw
  delivery **and no socket error**, not invented application acceptance.
- [UDP error handling](https://github.com/gregkh/linux/blob/v6.12.113/net/ipv4/udp.c)
  exposes Time Exceeded as `EHOSTUNREACH` and Parameter Problem as `EPROTO`.

## Regression contract

The differential probe requires positive raw delivery and exact native error
queue identity for the two original variants. It also records the actual
quoted checksum residual for an exact reference/DUT comparison. New unassigned
code controls cover3/16,12/3 and11/255; the endpoint distinction above is
explicit. A new corrupt **outer** IPv4 checksum control must be dropped, as
must the existing corrupt ICMP checksum. All prior tuple, truncated quote,
fragment, physical-state deletion, wrong-interface, expiry, stateful-off and
explicit-policy controls remain. Reference and Sentinel reports must match;
an oracle failure is not success for the DUT.

Common host tests exhaust all65536 type/code pairs and independently recompute
Internet checksums after inverse translation. Every single-bit corruption of
the embedded checksum is exercised across TCP short/full quotes, UDP including
disabled checksums, ICMP echo and20/24/60-byte IP headers. They require the
original corrupt residual and a valid enclosing ICMP checksum after rewriting.

Host checks passed230 common unit tests,14 doctests and14 independent probe
selftests; common Clippy with `-D warnings`, no-default-features check, scoped
rustfmt and fixture parsing passed. Subsequent qualification uses real ELF
`8cbd1c27a458d26e17c7893ad43da566e0903fe7571485c47d14206b8e2a9d4d`:
all 21 programs load on Linux 6.6.159, 6.12.113 and 6.18.57. The real 6.12.113
differential VM passes in 168.55s with 145 observations across 19 reports and
no failures. Receipt is
`/nix/store/x93zlzy8ra5bbc48ajkv4fgkfzyrsdsh-vm-test-run-sentinel-related-icmp-netfilter/icmp-related-differential.json`.
An initial single residual discrepancy exposed a lane-dependent XOR corruption
in the test stimulus; one's-complement addition now generates the same corrupt
residual for every initial header checksum. All 16 probe selftests pass,
including all 65,536 checksum words. Exact packet/error-queue comparison was
not relaxed. The earlier red receipts are not overwritten. Scope remains
IPv4 UDP quotes on SNAT/DNAT/hairpin, physical-state and policy guards; fragment
NAT, general PMTU, TCP-error quotes and final-image certification remain open.
