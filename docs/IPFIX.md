# IPFIX export contract

The exporter sends IPv4 NAT flow tuples and measured byte/packet deltas over UDP.
The collector address can be IPv4 or IPv6. DNS resolution selects the resolver's
first result; its family determines the local socket family. There is no silent
IPv6-to-IPv4 fallback. The configured interval is at least one second.

Template 257 replaces template 256 and is included in every datagram. It contains
the IANA information element `observationPointId` (138, unsigned64), followed by
source/destination IPv4 addresses, transport ports, protocol and byte/packet deltas.
The observation point is the configured firewall policy ID, zero-extended to 64
bits: policy 0 is the top-level policy; named policies use their explicit numeric
IDs (tenant VXLAN policy IDs use the VNI). This is a logical observation point,
not an interface index. Collectors group by exporter, observation domain and
observation point before aggregating tuples. Identical private tuples belonging
to distinct policies must not be merged.

Policy numbers remain meaningful for the lifetime of that configuration. When
reassigning an ID to another tenant, rotate the observation domain or exporter
identity and retain the old configuration mapping with historical records. The
exporter does not claim a globally permanent tenant UUID or fabricate timestamps.
Element definitions: <https://www.iana.org/assignments/ipfix/ipfix.xhtml>.

Only successful local datagram submissions advance the export sequence. One
snapshot's unsent chunks are retained and retried before taking another snapshot;
already submitted chunks are not repeated. Memory is bounded by one conntrack
snapshot. A disappeared flow's pending record remains until submission. Local
send failures are logged with the number of retained records. UDP has no remote
acknowledgement: delivery loss beyond the local host remains possible and differs
from locally known unsent data. Restarting the exporter loses its in-memory
baseline/pending batch; this stream is diagnostic, not a durable billing ledger.
