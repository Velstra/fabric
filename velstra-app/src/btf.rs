//! Normalize Rust identifiers in BTF without changing ELF offsets or types.
//! Native cargo builds need the same kernel-compatible names as the appliance
//! build: generic Rust names such as `MaybeUninit<u8>` are not BTF identifiers.

use std::borrow::Cow;

use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection};

pub fn kernel_object(bytes: &[u8]) -> Result<Cow<'_, [u8]>> {
    let file = object::File::parse(bytes).context("reading eBPF ELF")?;
    let Some(section) = file.section_by_name(".BTF") else {
        return Ok(Cow::Borrowed(bytes));
    };
    let (offset, length) = section.file_range().context("BTF has no file range")?;
    let start = usize::try_from(offset)?;
    let end = start
        .checked_add(usize::try_from(length)?)
        .context("BTF range overflow")?;
    let raw = bytes.get(start..end).context("BTF outside ELF")?;
    let fixed = normalize(raw)?;
    if fixed == raw {
        return Ok(Cow::Borrowed(bytes));
    }
    let mut result = bytes.to_vec();
    result[start..end].copy_from_slice(&fixed);
    Ok(Cow::Owned(result))
}

fn word(bytes: &[u8], offset: usize) -> Result<usize> {
    let raw = bytes
        .get(offset..offset + 4)
        .context("truncated BTF word")?;
    Ok(u32::from_le_bytes(raw.try_into()?) as usize)
}

fn identifier(result: &mut [u8], strings: usize, length: usize, offset: usize) -> Result<()> {
    if offset == 0 {
        return Ok(());
    }
    ensure!(offset < length, "BTF name outside string table");
    let start = strings + offset;
    let count = result[start..strings + length]
        .iter()
        .position(|b| *b == 0)
        .context("unterminated BTF name")?;
    for (index, byte) in result[start..start + count].iter_mut().enumerate() {
        if !byte.is_ascii_alphabetic() && *byte != b'_' && !(index > 0 && byte.is_ascii_digit()) {
            *byte = b'_';
        }
    }
    Ok(())
}

fn normalize(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(raw.len() >= 24, "truncated BTF header");
    ensure!(raw[..4] == [0x9f, 0xeb, 1, 0], "unsupported BTF header");
    let header = word(raw, 4)?;
    ensure!(header >= 24, "invalid BTF header size");
    let start = header
        .checked_add(word(raw, 8)?)
        .context("BTF type offset overflow")?;
    let end = start
        .checked_add(word(raw, 12)?)
        .context("BTF type size overflow")?;
    let strings = header
        .checked_add(word(raw, 16)?)
        .context("BTF string offset overflow")?;
    let length = word(raw, 20)?;
    let string_end = strings
        .checked_add(length)
        .context("BTF string size overflow")?;
    ensure!(
        end <= raw.len() && strings >= end && string_end <= raw.len(),
        "invalid BTF bounds"
    );
    let mut result = raw.to_vec();
    let mut cursor = start;
    while cursor < end {
        ensure!(cursor + 12 <= end, "truncated BTF type");
        let name = word(raw, cursor)?;
        let info = word(raw, cursor + 4)?;
        let kind = (info >> 24) & 31;
        let count = info & 0xffff;
        let payload = match kind {
            1 | 14 | 17 => 4,
            2 | 7..=12 | 16 | 18 => 0,
            3 => 12,
            4 | 5 | 15 | 19 => count * 12,
            6 | 13 => count * 8,
            _ => bail!("invalid BTF kind {kind}"),
        };
        ensure!(cursor + 12 + payload <= end, "truncated BTF payload");
        if kind != 15 {
            identifier(&mut result, strings, length, name)?;
        }
        if matches!(kind, 4 | 5 | 6 | 13 | 19) {
            let stride = if matches!(kind, 4 | 5 | 19) { 12 } else { 8 };
            for member in 0..count {
                identifier(
                    &mut result,
                    strings,
                    length,
                    word(raw, cursor + 12 + member * stride)?,
                )?;
            }
        }
        cursor += 12 + payload;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalized_without_changing_layout_sections_or_offsets() {
        let strings = b"\0MaybeUninit<u8>\0.data\0member::value\0";
        let section = strings.windows(5).position(|s| s == b".data").unwrap() as u32;
        let member = strings.windows(8).position(|s| s == b"member::").unwrap() as u32;
        let mut types = Vec::new();
        for word in [1u32, (5 << 24) | 1, 1, member, 1, 0, section, 15 << 24, 0] {
            types.extend_from_slice(&word.to_le_bytes());
        }
        let mut raw = vec![0x9f, 0xeb, 1, 0];
        for word in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            raw.extend_from_slice(&word.to_le_bytes());
        }
        raw.extend_from_slice(&types);
        raw.extend_from_slice(strings);
        let fixed = normalize(&raw).unwrap();
        assert_eq!(&fixed[..24 + types.len()], &raw[..24 + types.len()]);
        assert_eq!(fixed.len(), raw.len());
        assert_eq!(
            &fixed[24 + types.len()..],
            b"\0MaybeUninit_u8_\0.data\0member__value\0"
        );
        assert_eq!(normalize(&fixed).unwrap(), fixed);
        for truncated in [&raw[..23], &raw[..raw.len() - 1]] {
            assert!(normalize(truncated).is_err());
        }
        let mut malformed = raw;
        malformed[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(normalize(&malformed).is_err());
    }

    #[test]
    fn embedded_object_normalization_is_idempotent() {
        let object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/velstra"));
        let fixed = kernel_object(object).unwrap();
        assert!(matches!(kernel_object(&fixed).unwrap(), Cow::Borrowed(_)));
    }
}
