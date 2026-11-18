//! Canonical TCP identity. This is not yet a deployed map or HA record.

use core::cmp::Ordering;

/// One key for both directions; address bytes then numeric port order endpoints.
/// A policy is still an independent admission domain: a router/NAT key never
/// substitutes for the required physical policy identity.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSessionKey {
    pub policy: u32,
    pub family: u32,
    pub addr0: [u8; 16],
    pub addr1: [u8; 16],
    pub port0: u16,
    pub port1: u16,
}

impl TcpSessionKey {
    /// Returns canonical key and source side (0/1). On an admitted initial SYN,
    /// its source side becomes the immutable initiator_side of the map value.
    /// Thereafter direction = source_side XOR initiator_side.
    pub fn new(
        policy: u32,
        family: u32,
        source: [u8; 16],
        destination: [u8; 16],
        source_port: u16,
        destination_port: u16,
    ) -> Option<(Self, u32)> {
        let order = endpoint_cmp(&source, source_port, &destination, destination_port);
        let (addr0, port0, addr1, port1, source_side) = match order {
            Ordering::Less => (source, source_port, destination, destination_port, 0),
            Ordering::Greater => (destination, destination_port, source, source_port, 1),
            // A self-identical tuple has no observable direction. Do not invent
            // one. Any future caller must surface this unsupported identity.
            Ordering::Equal => return None,
        };
        let key = Self {
            policy,
            family,
            addr0,
            addr1,
            port0,
            port1,
        };
        key.valid().then_some((key, source_side))
    }

    pub fn valid(&self) -> bool {
        matches!(self.family, 4 | 6)
            && (self.family != 4
                || (self.addr0[4..].iter().all(|b| *b == 0)
                    && self.addr1[4..].iter().all(|b| *b == 0)))
            && endpoint_cmp(&self.addr0, self.port0, &self.addr1, self.port1) == Ordering::Less
    }

    /// Find fixed model direction only for an exact tuple match. No address
    /// family, policy, NAT alias or initiator orientation is inferred here.
    pub fn direction(
        &self,
        source: &[u8; 16],
        destination: &[u8; 16],
        source_port: u16,
        destination_port: u16,
        initiator_side: u32,
    ) -> Option<u32> {
        if !self.valid() || initiator_side > 1 {
            return None;
        }
        let source_side = if (source, destination, source_port, destination_port)
            == (&self.addr0, &self.addr1, self.port0, self.port1)
        {
            0
        } else if (source, destination, source_port, destination_port)
            == (&self.addr1, &self.addr0, self.port1, self.port0)
        {
            1
        } else {
            return None;
        };
        Some(source_side ^ initiator_side)
    }
}

fn endpoint_cmp(a: &[u8; 16], ap: u16, b: &[u8; 16], bp: u16) -> Ordering {
    a.cmp(b).then(ap.cmp(&bp))
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpSessionKey {}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> [u8; 16] {
        let mut a = [0; 16];
        a[..4].copy_from_slice(&[198, 18, 0, last]);
        a
    }

    #[test]
    fn exact_layout_and_reverse_identity() {
        assert_eq!(core::mem::size_of::<TcpSessionKey>(), 44);
        assert_eq!(core::mem::offset_of!(TcpSessionKey, family), 4);
        assert_eq!(core::mem::offset_of!(TcpSessionKey, addr0), 8);
        assert_eq!(core::mem::offset_of!(TcpSessionKey, port0), 40);
        // ABI shape only. A real BPF definition MUST use the kernel's named
        // bpf_spin_lock type here, not this u32 host layout witness. No map or
        // claim of helper/BTF/verifier compatibility is produced by this test.
        #[repr(C)]
        struct LockedValueLayout {
            lock: u32,
            initiator_side: u32,
            local_epoch: u64,
            session: crate::TcpSession,
        }
        assert_eq!(core::mem::size_of::<LockedValueLayout>(), 152);
        assert_eq!(core::mem::offset_of!(LockedValueLayout, initiator_side), 4);
        assert_eq!(core::mem::offset_of!(LockedValueLayout, local_epoch), 8);
        assert_eq!(core::mem::offset_of!(LockedValueLayout, session), 16);
        for family in [4, 6] {
            for ports in [(0, 65535), (443, 42000), (42000, 443), (0, 0)] {
                let (key, side) =
                    TcpSessionKey::new(17, family, addr(2), addr(1), ports.0, ports.1).unwrap();
                let (reverse, reverse_side) =
                    TcpSessionKey::new(17, family, addr(1), addr(2), ports.1, ports.0).unwrap();
                assert_eq!(key, reverse);
                assert_eq!(side ^ reverse_side, 1);
                assert_eq!(
                    key.direction(&addr(2), &addr(1), ports.0, ports.1, side),
                    Some(0)
                );
                assert_eq!(
                    key.direction(&addr(1), &addr(2), ports.1, ports.0, side),
                    Some(1)
                );
            }
        }
    }

    #[test]
    fn port_order_matters_only_after_equal_address() {
        let (key, side) = TcpSessionKey::new(1, 4, addr(1), addr(1), 256, 255).unwrap();
        assert_eq!((key.port0, key.port1, side), (255, 256, 1));
        assert!(TcpSessionKey::new(1, 4, addr(1), addr(1), 443, 443).is_none());
    }

    #[test]
    fn invalid_family_v4_tail_unsorted_key_and_foreign_tuple_are_refused() {
        let (key, _) = TcpSessionKey::new(1, 4, addr(1), addr(2), 0, 0).unwrap();
        for family in [0, 1, 5, u32::MAX] {
            assert!(!TcpSessionKey { family, ..key }.valid());
        }
        let mut invalid = key;
        invalid.addr1[15] = 1;
        assert!(!invalid.valid());
        let mut invalid = key;
        core::mem::swap(&mut invalid.addr0, &mut invalid.addr1);
        assert!(!invalid.valid());
        assert_eq!(key.direction(&addr(1), &addr(3), 0, 0, 0), None);
        assert_eq!(key.direction(&addr(1), &addr(2), 1, 0, 0), None);
        assert_eq!(key.direction(&addr(1), &addr(2), 0, 0, 2), None);
    }
}
