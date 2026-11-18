# IPv4 reply checksum correction

**Scope.** A generated IPv4 TCP reset could retain the incoming TOS value while its IPv4 checksum assumed TOS zero. Some receivers discarded the resulting reply. The correction aligns the TOS byte with the checksum calculation for reject and synthesized replies.

**Verification.** The recorded appliance checks covered all 64 DSCP classes for native rejects and actual proxied sessions for SYN-proxy behavior. An earlier, separate routed TCP-checksum observation remained open in that investigation.

For release selection, use the [Fabric release notes](https://github.com/Velstra/fabric/blob/main/CHANGELOG.md) and the qualification evidence for the appliance version you plan to run.
