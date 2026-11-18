# Export IPFIX records

Use IPFIX to measure **IPv4 NAT flows per firewall policy**. A collector may be reached over either IPv4 or IPv6. This is a diagnostic UDP stream; local submission cannot confirm delivery to the collector.

## Configure an exporter

Add a `flow_export` table to the local node policy. Replace the example collector with your collector's address:

```toml
[flow_export]
collector = "192.0.2.45:4739"
interval_secs = 30
observation_domain = 42
```

Validate the edited node policy with `velstra validate PATH`. After the agent sees traffic through a NAT service, inspect the records at your collector. An idle flow with no new packets produces no delta.

## Decode a record

| Field | What to do with it |
|---|---|
| Template ID `257` | Expect the template in each datagram. |
| `observationPointId` (IE 138) | Decode as unsigned 64-bit. It identifies the firewall policy. Policy 0 is the top-level policy. |
| IPv4 tuple, protocol, byte/packet counts | Count deltas for each tuple. Group by exporter, observation domain **and** observation point before aggregating. |

Two tenants can use identical private addresses. Keep their policy IDs distinct in the collector. If a policy ID is reassigned, rotate the exporter or observation domain and preserve the historical mapping.

Local send failures retain unsent records for retry in memory. An exporter restart loses that pending state and the previous baseline. See the [encoder and wire-format tests](https://github.com/Velstra/fabric/blob/main/velstra-app/src/ipfix.rs) and the [IANA information elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml).
