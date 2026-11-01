//! Local, native-endian BPF control ABI. These records never cross an HA link.
//! A coherent local state copy must be exported to a relative-lifetime transfer
//! before network serialization. An incarnation identifies a slot lifetime;
//! revision additionally detects packet updates within that lifetime.

use crate::{FirewallFlow, FirewallFlowKey, FirewallFlowRef};

pub const FIREWALL_FLOW_CAPACITY: u32 = 65_536;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowVersion {
    pub entry: FirewallFlowRef,
    pub revision: u64,
}

pub struct FlowRecordKind;
impl FlowRecordKind {
    pub const EMPTY: u32 = 0;
    pub const PRIMARY: u32 = 1;
    pub const ALIAS: u32 = 2;
    pub const ORPHAN_ALIAS: u32 = 3;
}

/// Snapshot of a primary, or of an alias AND its primary under ordered locks.
/// An orphan names its original primary but has no valid primary state. For
/// aliases, state and primary_revision always belong to the target, not alias.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallFlowRecord {
    pub kind: u32,
    pub flip: u32,
    pub key: FirewallFlowKey,
    pub entry: FirewallFlowRef,
    pub revision: u64,
    pub primary_key: FirewallFlowKey,
    pub primary: FirewallFlowRef,
    pub primary_revision: u64,
    pub state: FirewallFlow,
    pub reserved: u64,
}
impl FirewallFlowRecord {
    pub const EMPTY: Self = Self {
        kind: 0,
        flip: 0,
        key: FirewallFlowKey::ZERO,
        entry: FirewallFlowRef {
            slot: 0,
            _pad: 0,
            incarnation: 0,
        },
        revision: 0,
        primary_key: FirewallFlowKey::ZERO,
        primary: FirewallFlowRef {
            slot: 0,
            _pad: 0,
            incarnation: 0,
        },
        primary_revision: 0,
        state: FirewallFlow::ZERO,
        reserved: 0,
    };
    pub const fn version(&self) -> FlowVersion {
        FlowVersion {
            entry: self.entry,
            revision: self.revision,
        }
    }
}

pub struct FlowControlOp;
impl FlowControlOp {
    pub const SNAPSHOT: u16 = 1;
    /// GC: compare alias and primary revisions before removing either grant.
    pub const REMOVE: u16 = 2;
    /// Explicit policy revocation: compare the local entry version only.
    pub const REVOKE: u16 = 3;
    pub const IMPORT_PRIMARY: u16 = 4;
    pub const IMPORT_ALIAS: u16 = 5;
    /// Reclaim only RETIRED slots; never expire an active slot by raw index.
    pub const RECLAIM: u16 = 6;
    /// Deterministic enumeration without a mutable hash iterator.
    pub const SNAPSHOT_SLOT: u16 = 7;
    /// Coherent allocator high-water mark, not a count of live entries.
    pub const ALLOCATED_SLOTS: u16 = 8;
}
pub struct FlowControlStatus;
impl FlowControlStatus {
    pub const PENDING: u32 = 0;
    pub const APPLIED: u32 = 1;
    pub const UNCHANGED: u32 = 2;
    pub const MISSING: u32 = 3;
    pub const BUSY: u32 = 4;
    pub const CONFLICT: u32 = 5;
    pub const FULL: u32 = 6;
    pub const INVALID: u32 = 7;
    pub const EXHAUSTED: u32 = 8;
    pub const STORAGE: u32 = 9;
    pub const CORRUPT: u32 = 10;
}

/// Syscall-only message following16 bytes of dummy Ethernet framing. The XDP
/// program is loaded but NEVER attached to a network interface. No output map
/// is shared between requests: response bytes return in the caller's packet.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowControlMessage {
    pub magic: u32,
    pub version: u16,
    pub operation: u16,
    pub request_id: u64,
    pub status: u32,
    pub reserved: u32,
    pub record: FirewallFlowRecord,
    /// IMPORT_ALIAS only: expected wire incarnation of the named primary.
    pub wire_incarnation: u64,
}
impl FlowControlMessage {
    pub const MAGIC: u32 = u32::from_ne_bytes(*b"VFC1");
    pub const VERSION: u16 = 1;
    pub const PREFIX_LEN: usize = 16;
    pub const fn new(operation: u16, request_id: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            operation,
            request_id,
            status: 0,
            reserved: 0,
            record: FirewallFlowRecord::EMPTY,
            wire_incarnation: 0,
        }
    }
    pub const fn valid_header(&self) -> bool {
        self.magic == Self::MAGIC
            && self.version == Self::VERSION
            && self.request_id != 0
            && self.status == 0
            && self.reserved == 0
            && self.record.reserved == 0
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallFlowRecord {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowControlMessage {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowVersion {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_control_layout_has_no_implicit_padding() {
        assert_eq!(core::mem::size_of::<FlowVersion>(), 24);
        assert_eq!(core::mem::size_of::<FirewallFlowRecord>(), 256);
        assert_eq!(core::mem::size_of::<FlowControlMessage>(), 288);
        assert_eq!(core::mem::offset_of!(FirewallFlowRecord, state), 168);
        assert_eq!(core::mem::offset_of!(FlowControlMessage, record), 24);
        assert_eq!(
            core::mem::offset_of!(FlowControlMessage, wire_incarnation),
            280
        );
        assert!(!FlowControlMessage::new(FlowControlOp::SNAPSHOT, 0).valid_header());
        let mut message = FlowControlMessage::new(FlowControlOp::SNAPSHOT, 1);
        assert!(message.valid_header());
        message.status = 1;
        assert!(!message.valid_header());
        assert!(
            !FirewallFlowRecord::EMPTY
                .state
                .valid_for(crate::ip_proto::TCP)
        );
    }
}
