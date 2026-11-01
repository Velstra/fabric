//! Derived policy lifecycle metadata. Routing ordinals are not flow identities.

pub const FLOW_POLICY_CAPACITY: u32 = 1024;
pub const FLOW_LABEL_MAX: usize = 128;

/// Local map key, never a wire representation. Kinds distinguish the global
/// policy, explicitly numbered native policies, and named appliance zones.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowScopeLabel {
    pub kind: u32,
    pub length: u32,
    pub bytes: [u8; FLOW_LABEL_MAX],
}
impl FlowScopeLabel {
    pub fn policy(id: u32, name: Option<&str>) -> Option<Self> {
        let mut label = Self {
            kind: 1,
            length: 0,
            bytes: [0; FLOW_LABEL_MAX],
        };
        if id == 0 {
            return Some(label);
        }
        if let Some(name) = name {
            if name.is_empty() || name.len() > FLOW_LABEL_MAX || name.chars().any(char::is_control)
            {
                return None;
            }
            label.kind = 3;
            label.length = name.len() as u32;
            label.bytes[..name.len()].copy_from_slice(name.as_bytes());
        } else {
            label.kind = 2;
            label.length = 4;
            label.bytes[..4].copy_from_slice(&id.to_ne_bytes());
        }
        Some(label)
    }
    pub fn valid(&self) -> bool {
        let length = self.length as usize;
        if length > FLOW_LABEL_MAX || self.bytes[length..].iter().any(|v| *v != 0) {
            return false;
        }
        match self.kind {
            1 => length == 0,
            2 => length == 4 && self.bytes[..4] != [0; 4],
            3 => {
                length > 0
                    && core::str::from_utf8(&self.bytes[..length])
                        .is_ok_and(|s| !s.chars().any(char::is_control))
            }
            _ => false,
        }
    }
}

/// The namespace and high watermark outlive agent processes with their pinned
/// flow maps. Reservations are never rolled back or reused after failed apply.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowScopeMetadata {
    pub version: u32,
    pub reserved: u32,
    pub namespace: u64,
    pub next_identity: u64,
}
impl FlowScopeMetadata {
    pub const VERSION: u32 = 1;
    pub const EMPTY: Self = Self {
        version: 0,
        reserved: 0,
        namespace: 0,
        next_identity: 0,
    };
    pub const fn valid(self) -> bool {
        self.version == Self::VERSION && self.reserved == 0 && self.namespace != 0
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for crate::FlowTimeouts {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowScopeLabel {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowScopeMetadata {}
