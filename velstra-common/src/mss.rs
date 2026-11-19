//! MSS clamping: the checksum operands for rewriting a SYN's MSS option.
//!
//! `bpf_l4_csum_replace(skb, off, from, to, 2)` hands `from`/`to` to the
//! kernel's `inet_proto_csum_replace2`, which takes them as `__be16`: the two
//! bytes **as they sit in the packet**, read in the machine's own byte order.
//! Passing the MSS as a host-order number instead — 1460 rather than the bytes
//! `05 b4` — adjusts the checksum by the wrong amount, and every clamped SYN
//! leaves with a TCP checksum the receiver discards (audit DP-09). A VM test
//! does not see it when the skb is `CHECKSUM_PARTIAL`, because the kernel then
//! ignores the adjustment and the NIC (or virtio) fills the checksum in later;
//! a forwarded SYN from a host with checksum offload off is not PARTIAL.

/// The `(from, to)` operands for `bpf_l4_csum_replace` when an MSS option's
/// value changes from `current` to `limit` (both host-order MSS numbers).
#[inline(always)]
pub const fn mss_clamp_csum_operands(current: u16, limit: u16) -> (u64, u64) {
    (
        u16::from_ne_bytes(current.to_be_bytes()) as u64,
        u16::from_ne_bytes(limit.to_be_bytes()) as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `csum16_add` from the kernel (`include/net/checksum.h`): a 16-bit
    /// one's-complement add with end-around carry.
    fn csum16_add(a: u16, b: u16) -> u16 {
        let (res, carry) = a.overflowing_add(b);
        res.wrapping_add(carry as u16)
    }

    /// A model of what `bpf_l4_csum_replace(.., from, to, 2)` does to the checksum
    /// field of a non-`CHECKSUM_PARTIAL` skb: `csum_replace2` on the field's
    /// in-memory value, with `from`/`to` truncated to `__be16`.
    fn kernel_l4_csum_replace2(field: [u8; 2], from: u64, to: u64) -> [u8; 2] {
        let sum = u16::from_ne_bytes(field);
        let old = from as u16;
        let new = to as u16;
        // *sum = ~csum16_add(csum16_sub(~(*sum), old), new)
        let sub = csum16_add(!sum, !old);
        (!csum16_add(sub, new)).to_ne_bytes()
    }

    /// The Internet checksum of a TCP segment with its IPv4 pseudo-header.
    fn tcp_checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut add = |hi: u8, lo: u8| sum += u16::from_be_bytes([hi, lo]) as u32;
        add(src[0], src[1]);
        add(src[2], src[3]);
        add(dst[0], dst[1]);
        add(dst[2], dst[3]);
        add(0, 6);
        let len = segment.len() as u16;
        add((len >> 8) as u8, len as u8);
        for pair in segment.chunks(2) {
            add(pair[0], *pair.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A SYN with `MSS 1460, SACK-permitted, NOP, window scale 7` and a valid
    /// checksum, as a Linux client sends it.
    fn syn() -> ([u8; 4], [u8; 4], Vec<u8>) {
        let (src, dst) = ([198, 18, 20, 50], [198, 18, 10, 254]);
        let mut seg = vec![
            0x9c, 0x40, 0x46, 0xa0, // ports 40000 -> 18080
            0x12, 0x34, 0x56, 0x78, // seq
            0, 0, 0, 0, // ack
            0x80, 0x02, 0xfa, 0xf0, // doff 8, SYN, window 64240
            0, 0, 0, 0, // checksum, urgent
            2, 4, 0x05, 0xb4, // MSS 1460
            4, 2, 1, 3, 3, 7, 1, 1, // SACK-permitted, NOP, wscale 7, pad
        ];
        seg.truncate(32);
        let csum = tcp_checksum(src, dst, &seg);
        seg[16..18].copy_from_slice(&csum.to_be_bytes());
        (src, dst, seg)
    }

    fn clamp(seg: &mut [u8], from: u64, to: u64, limit: u16) {
        seg[22..24].copy_from_slice(&limit.to_be_bytes());
        let field = [seg[16], seg[17]];
        let out = kernel_l4_csum_replace2(field, from, to);
        seg[16..18].copy_from_slice(&out);
    }

    #[test]
    fn clamped_syn_keeps_a_valid_checksum() {
        for (current, limit) in [(1460u16, 1452u16), (1460, 1400), (65495, 1360), (536, 500)] {
            let (src, dst, mut seg) = syn();
            seg[22..24].copy_from_slice(&current.to_be_bytes());
            seg[16..18].copy_from_slice(&[0, 0]);
            let csum = tcp_checksum(src, dst, &seg);
            seg[16..18].copy_from_slice(&csum.to_be_bytes());

            let (from, to) = mss_clamp_csum_operands(current, limit);
            clamp(&mut seg, from, to, limit);
            // A valid segment checksums to zero over itself.
            assert_eq!(
                tcp_checksum(src, dst, &seg),
                0,
                "{current} -> {limit}: checksum invalid after clamp"
            );
        }
    }

    /// The defect this module exists for: host-order operands — what the data
    /// plane passed before — leave a checksum the receiver rejects. On a
    /// big-endian host the two forms coincide, so the assertion is guarded.
    #[test]
    fn host_order_operands_corrupt_the_checksum() {
        if cfg!(target_endian = "big") {
            return;
        }
        let (src, dst, mut seg) = syn();
        clamp(&mut seg, 1460, 1452, 1452);
        assert_ne!(tcp_checksum(src, dst, &seg), 0);
    }
}
