//! Bounded, read-only rtnetlink observations. No subprocess or cached grants.
//!
//! Separate dumps are not an atomic kernel-wide snapshot. A second link dump
//! rejects changed owning identities; callers still revalidate before opening
//! their datapath. Interrupted, incomplete or ambiguous dumps are errors.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};

const LIMIT: usize = 8 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);
const HEADER: usize = 16;
const NEWLINK: u16 = 16;
const GETLINK: u16 = 18;
const NEWADDR: u16 = 20;
const GETADDR: u16 = 22;
const NOOP: u16 = 1;
const ERROR: u16 = 2;
const DONE: u16 = 3;
const OVERRUN: u16 = 4;
const MULTI: u16 = 2;
const DUMP_INTR: u16 = 0x10;

pub(crate) type Prefix = ([u8; 4], [u8; 4]);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    name: String,
    mac: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Interface {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) mac: Option<Vec<u8>>,
    /// Preserve kernel order: the first address is implicit masquerade's source.
    pub(crate) addresses: Vec<Prefix>,
    /// The link's IPv6 addresses, in kernel order. Only "is this one of the
    /// host's own addresses" is asked of them (`dst = "local"` rules), so no
    /// prefix length is kept.
    pub(crate) addresses6: Vec<[u8; 16]>,
}

/// What one address dump said about one link, per family.
#[derive(Debug, Default)]
pub(crate) struct Addresses {
    v4: Vec<Prefix>,
    v6: Vec<[u8; 16]>,
}

/// Existing libc is sufficient; no subprocess or fixed polling sleep. Kernel
/// syscalls and scheduling are still subject to the overall observer deadline.
pub(crate) fn read() -> Result<Vec<Interface>> {
    let mut socket = Socket::open()?;
    let mut first = BTreeMap::new();
    socket.dump(GETLINK, NEWLINK, 16, |payload| {
        add_link(&mut first, payload)
    })?;
    let mut addresses = BTreeMap::new();
    socket.dump(GETADDR, NEWADDR, 8, |payload| {
        add_address(&mut addresses, &first, payload)
    })?;
    let mut second = BTreeMap::new();
    socket.dump(GETLINK, NEWLINK, 16, |payload| {
        add_link(&mut second, payload)
    })?;
    let interfaces = finish(first, second, addresses)?;
    socket.budget.check()?;
    Ok(interfaces)
}

fn finish(
    first: BTreeMap<u32, Link>,
    second: BTreeMap<u32, Link>,
    mut addresses: BTreeMap<u32, Addresses>,
) -> Result<Vec<Interface>> {
    ensure!(
        first == second,
        "link identities changed during address observation"
    );
    Ok(first
        .into_iter()
        .map(|(index, link)| {
            let observed = addresses.remove(&index).unwrap_or_default();
            Interface {
                name: link.name,
                index,
                mac: link.mac,
                addresses: observed.v4,
                addresses6: observed.v6,
            }
        })
        .collect())
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn aligned(length: usize) -> Result<usize> {
    Ok(length.checked_add(3).context("netlink length overflow")? & !3)
}

/// Structural validation includes unknown attributes, which remain extensible.
fn attributes(mut bytes: &[u8], mut visit: impl FnMut(u16, &[u8]) -> Result<()>) -> Result<()> {
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "truncated netlink attribute header");
        let length = usize::from(u16_at(bytes, 0));
        ensure!(
            length >= 4 && length <= bytes.len(),
            "invalid netlink attribute length"
        );
        visit(u16_at(bytes, 2), &bytes[4..length])?;
        let step = aligned(length)?;
        // A final unpadded attribute is valid; padding is not payload.
        if length == bytes.len() {
            break;
        }
        ensure!(step <= bytes.len(), "truncated netlink attribute padding");
        bytes = &bytes[step..];
    }
    Ok(())
}

fn add_link(links: &mut BTreeMap<u32, Link>, payload: &[u8]) -> Result<()> {
    ensure!(payload.len() >= 16, "truncated link message");
    let index = u32_at(payload, 4);
    ensure!(index > 0 && index <= i32::MAX as u32, "invalid link index");
    let mut name = None;
    let mut mac = None;
    attributes(&payload[16..], |kind, value| {
        match kind & 0x3fff {
            3 => {
                ensure!(kind == 3 && name.is_none(), "ambiguous link name attribute");
                ensure!(
                    value.len() >= 2 && value.len() <= libc::IFNAMSIZ && value.last() == Some(&0),
                    "invalid link name"
                );
                let text =
                    std::str::from_utf8(&value[..value.len() - 1]).context("non-UTF8 link name")?;
                ensure!(!text.as_bytes().contains(&0), "embedded NUL in link name");
                name = Some(text.to_owned());
            }
            1 => {
                ensure!(kind == 1 && mac.is_none(), "ambiguous link MAC attribute");
                mac = Some(value.to_vec());
            }
            _ => {}
        }
        Ok(())
    })?;
    let name = name.context("link has no name")?;
    ensure!(
        !links.contains_key(&index) && !links.values().any(|link| link.name == name),
        "duplicate observed link identity"
    );
    links.insert(index, Link { name, mac });
    Ok(())
}

fn add_address(
    addresses: &mut BTreeMap<u32, Addresses>,
    links: &BTreeMap<u32, Link>,
    payload: &[u8],
) -> Result<()> {
    ensure!(payload.len() >= 8, "truncated address message");
    let family = i32::from(payload[0]);
    ensure!(
        family == libc::AF_INET || family == libc::AF_INET6,
        "unknown address family"
    );
    let index = u32_at(payload, 4);
    ensure!(
        links.contains_key(&index),
        "address has unknown owning link"
    );
    let size = if family == libc::AF_INET { 4 } else { 16 };
    ensure!(
        usize::from(payload[1]) <= size * 8,
        "invalid address prefix length"
    );
    let mut local = None;
    let mut address = None;
    let mut singleton = BTreeSet::new();
    attributes(&payload[8..], |kind, value| {
        let base = kind & 0x3fff;
        match base {
            1 | 2 => {
                ensure!(
                    kind == base && singleton.insert(base) && value.len() == size,
                    "ambiguous or malformed address attribute"
                );
                if base == 2 {
                    local = Some(value.to_vec());
                } else {
                    address = Some(value.to_vec());
                }
            }
            // Flags and lifetimes do not filter authorization in the existing
            // observer. Validate their shape but keep all returned addresses.
            6 | 8 => {
                ensure!(
                    kind == base
                        && singleton.insert(base)
                        && value.len() == if base == 6 { 16 } else { 4 },
                    "malformed address metadata"
                );
            }
            _ => {}
        }
        Ok(())
    })?;
    let local = local.or(address).context("address has no local value")?;
    let observed = addresses.entry(index).or_default();
    if family == libc::AF_INET {
        let mask = u32::MAX
            .checked_shl(u32::from(32 - payload[1]))
            .unwrap_or(0);
        let local: [u8; 4] = local
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed IPv4 address"))?;
        observed.v4.push((local, mask.to_be_bytes()));
    } else {
        let local: [u8; 16] = local
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed IPv6 address"))?;
        observed.v6.push(local);
    }
    Ok(())
}

struct Dump {
    sequence: u32,
    port: u32,
    expected: u16,
    done: bool,
}

impl Dump {
    fn datagram(
        &mut self,
        mut bytes: &[u8],
        mut visit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.done && !bytes.is_empty(),
            "data outside active netlink dump"
        );
        while !bytes.is_empty() {
            ensure!(bytes.len() >= HEADER, "truncated netlink header");
            let length = u32_at(bytes, 0) as usize;
            ensure!(
                length >= HEADER && length <= bytes.len(),
                "invalid netlink message length"
            );
            ensure!(
                u32_at(bytes, 8) == self.sequence && u32_at(bytes, 12) == self.port,
                "unexpected netlink sequence or port"
            );
            let kind = u16_at(bytes, 4);
            let flags = u16_at(bytes, 6);
            ensure!(flags & DUMP_INTR == 0, "interrupted netlink dump");
            let payload = &bytes[HEADER..length];
            ensure!(!self.done, "data after netlink completion");
            match kind {
                DONE => {
                    ensure!(
                        payload.len() >= 4 && u32_at(payload, 0) == 0,
                        "failed or malformed netlink completion"
                    );
                    // Any optional extended ACK attributes must themselves
                    // be well framed; never accept arbitrary trailing bytes.
                    attributes(&payload[4..], |_, _| Ok(()))?;
                    self.done = true;
                }
                ERROR => {
                    ensure!(
                        payload.len() >= 20 && u32_at(payload, 0) == 0,
                        "netlink request failed or malformed ACK"
                    );
                    attributes(&payload[20..], |_, _| Ok(()))?;
                    // A successful ACK alone does not complete a dump.
                }
                NOOP => {}
                OVERRUN => bail!("netlink dump overrun"),
                _ => {
                    ensure!(
                        kind == self.expected && flags & MULTI != 0,
                        "unexpected netlink dump message"
                    );
                    visit(payload)?;
                }
            }
            let step = aligned(length)?;
            if length == bytes.len() {
                break;
            }
            ensure!(step <= bytes.len(), "truncated netlink message padding");
            bytes = &bytes[step..];
        }
        Ok(())
    }
}

struct Budget {
    deadline: Instant,
    bytes: usize,
}

impl Budget {
    fn check(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "interface observer timed out after 2 seconds"
        );
        Ok(())
    }

    fn charge(&mut self, length: usize) -> Result<()> {
        self.check()?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .context("interface inventory size overflow")?;
        ensure!(self.bytes <= LIMIT, "interface inventory exceeds 8 MiB");
        Ok(())
    }
}

struct Socket {
    fd: OwnedFd,
    port: u32,
    sequence: u32,
    budget: Budget,
}

impl Socket {
    fn open() -> Result<Self> {
        let budget = Budget {
            deadline: Instant::now() + TIMEOUT,
            bytes: 0,
        };
        // SAFETY: socket has no pointer arguments; ownership transferred once.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        ensure!(
            raw >= 0,
            "opening interface netlink socket: {}",
            io::Error::last_os_error()
        );
        // SAFETY: raw is a newly created owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is valid before filling family; port zero
        // requests an assigned local port, with no multicast subscriptions.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let size = std::mem::size_of_val(&address) as libc::socklen_t;
        // SAFETY: address and its length are valid throughout both syscalls.
        ensure!(
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    size,
                )
            } == 0,
            "binding interface netlink socket: {}",
            io::Error::last_os_error()
        );
        // Connecting to kernel port zero rejects userspace unicast senders.
        // SAFETY: address remains a valid kernel address.
        ensure!(
            unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    size,
                )
            } == 0,
            "connecting interface netlink socket: {}",
            io::Error::last_os_error()
        );
        let mut actual_size = size;
        // SAFETY: output pointers refer to correctly sized writable objects.
        ensure!(
            unsafe {
                libc::getsockname(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_nl).cast(),
                    &mut actual_size,
                )
            } == 0,
            "reading local netlink identity: {}",
            io::Error::last_os_error()
        );
        ensure!(
            actual_size == size
                && i32::from(address.nl_family) == libc::AF_NETLINK
                && address.nl_pid != 0,
            "invalid local netlink identity"
        );
        budget.check()?;
        Ok(Self {
            fd,
            port: address.nl_pid,
            sequence: 0,
            budget,
        })
    }

    fn wait(&self, events: i16) -> Result<()> {
        loop {
            self.budget.check()?;
            let remaining = self
                .budget
                .deadline
                .saturating_duration_since(Instant::now());
            let timeout = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: poll points to one valid pollfd and cannot outlive it.
            let status = unsafe { libc::poll(&mut poll, 1, timeout) };
            let error = (status < 0).then(io::Error::last_os_error);
            self.budget.check()?;
            if let Some(error) = error {
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("waiting for interface netlink observation");
            }
            if status == 0 {
                continue;
            }
            ensure!(
                poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                "interface netlink socket failed"
            );
            if poll.revents & events != 0 {
                return Ok(());
            }
        }
    }

    fn io(&self, events: i16, mut call: impl FnMut() -> isize) -> Result<usize> {
        loop {
            self.budget.check()?;
            let result = call();
            let error = (result < 0).then(io::Error::last_os_error);
            self.budget.check()?;
            if result >= 0 {
                return Ok(result as usize);
            }
            let error = error.expect("negative syscall result has an errno");
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => self.wait(events)?,
                _ => return Err(error).context("interface netlink transport"),
            }
        }
    }

    fn dump(
        &mut self,
        request: u16,
        expected: u16,
        payload_size: usize,
        mut visit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.sequence += 1;
        let mut bytes = vec![0u8; HEADER + payload_size];
        let length = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&request.to_ne_bytes());
        bytes[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
        bytes[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.port.to_ne_bytes());
        // AF_UNSPEC includes addressless and IPv6-only links and both IP families.
        let sent = self.io(libc::POLLOUT, || {
            // SAFETY: buffer lives across this nonblocking datagram send.
            unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) }
        })?;
        ensure!(sent == bytes.len(), "short interface netlink request");
        let mut dump = Dump {
            sequence: self.sequence,
            port: self.port,
            expected,
            done: false,
        };
        while !dump.done {
            let mut byte = 0u8;
            let length = self.io(libc::POLLIN, || {
                // SAFETY: MSG_TRUNC returns the full datagram size; only one
                // byte is writable. This exclusively owned socket has no other reader.
                unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        (&mut byte as *mut u8).cast(),
                        1,
                        libc::MSG_PEEK | libc::MSG_TRUNC,
                    )
                }
            })?;
            ensure!(length > 0, "empty interface netlink datagram");
            self.budget.charge(length)?;
            let mut data = vec![0u8; length];
            // SAFETY: zeroed address/message are valid before all pointers and
            // lengths are assigned to the live owned buffers below.
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut vector = libc::iovec {
                iov_base: data.as_mut_ptr().cast(),
                iov_len: data.len(),
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = std::mem::size_of_val(&sender) as libc::socklen_t;
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let received = self.io(libc::POLLIN, || {
                // SAFETY: all message output buffers and pointers remain live.
                unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut message, 0) }
            })?;
            validate_datagram(
                received,
                length,
                message.msg_flags,
                &sender,
                message.msg_namelen,
            )?;
            dump.datagram(&data, |payload| {
                self.budget.check()?;
                visit(payload)
            })?;
            self.budget.check()?;
        }
        Ok(())
    }
}

fn validate_datagram(
    received: usize,
    expected: usize,
    flags: i32,
    sender: &libc::sockaddr_nl,
    size: libc::socklen_t,
) -> Result<()> {
    ensure!(
        received == expected && flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0,
        "truncated interface netlink datagram"
    );
    ensure!(
        size as usize == std::mem::size_of::<libc::sockaddr_nl>()
            && i32::from(sender.nl_family) == libc::AF_NETLINK
            && sender.nl_pid == 0
            && sender.nl_groups == 0,
        "unexpected interface netlink sender"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(aligned(bytes.len()).unwrap(), 0);
        bytes
    }

    fn link(index: u32, name: &str) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[4..8].copy_from_slice(&index.to_ne_bytes());
        bytes.extend(attr(3, format!("{name}\0").as_bytes()));
        bytes.extend(attr(1, &[2, 0, 0, 0, 0, 1]));
        bytes
    }

    fn address(index: u32, local: [u8; 4], prefix: u8) -> Vec<u8> {
        let mut bytes = vec![libc::AF_INET as u8, prefix, 0, 0];
        bytes.extend_from_slice(&index.to_ne_bytes());
        bytes.extend(attr(2, &local));
        bytes
    }

    fn message(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&((HEADER + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&7u32.to_ne_bytes());
        bytes.extend_from_slice(&42u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(aligned(bytes.len()).unwrap(), 0);
        bytes
    }

    fn dump() -> Dump {
        Dump {
            sequence: 7,
            port: 42,
            expected: NEWLINK,
            done: false,
        }
    }

    #[test]
    fn native_parser_preserves_identity_primary_and_all_address_flags() {
        let mut links = BTreeMap::new();
        add_link(&mut links, &link(9, "lan0")).unwrap();
        add_link(&mut links, &link(10, "empty0")).unwrap();
        let mut addresses = BTreeMap::new();
        let mut first = address(9, [192, 0, 2, 1], 24);
        // Peer address, forged alias and deprecated/secondary flags do not
        // substitute the local address or change its actual owning ifindex.
        first.extend(attr(1, &[203, 0, 113, 99]));
        first.extend(attr(3, b"empty0:forged\0"));
        first.extend(attr(8, &0x21u32.to_ne_bytes()));
        let mut lifetime = vec![];
        for value in [0u32, 30, 100, 100] {
            lifetime.extend(value.to_ne_bytes());
        }
        first.extend(attr(6, &lifetime));
        add_address(&mut addresses, &links, &first).unwrap();
        add_address(&mut addresses, &links, &address(9, [192, 0, 2, 2], 32)).unwrap();
        add_address(&mut addresses, &links, &address(9, [10, 1, 2, 3], 0)).unwrap();
        let observed = finish(links.clone(), links, addresses).unwrap();
        assert_eq!(observed[0].name, "lan0");
        assert_eq!(observed[0].index, 9);
        assert_eq!(
            observed[0].addresses,
            vec![
                ([192, 0, 2, 1], [255, 255, 255, 0]),
                ([192, 0, 2, 2], [255, 255, 255, 255]),
                ([10, 1, 2, 3], [0; 4]),
            ]
        );
        assert!(observed[1].addresses.is_empty());
    }

    #[test]
    fn native_parser_keeps_ipv6_only_link_and_local_fallback() {
        let mut links = BTreeMap::new();
        add_link(&mut links, &link(9, "v6only")).unwrap();
        add_link(&mut links, &link(10, "fallback")).unwrap();
        let mut addresses = BTreeMap::new();
        let mut ipv6 = vec![libc::AF_INET6 as u8, 64, 0, 0];
        ipv6.extend(9u32.to_ne_bytes());
        ipv6.extend(attr(1, &[0; 16]));
        add_address(&mut addresses, &links, &ipv6).unwrap();
        let mut fallback = vec![libc::AF_INET as u8, 24, 0, 0];
        fallback.extend(10u32.to_ne_bytes());
        fallback.extend(attr(1, &[192, 0, 2, 4]));
        add_address(&mut addresses, &links, &fallback).unwrap();
        let observed = finish(links.clone(), links, addresses).unwrap();
        assert!(observed[0].addresses.is_empty());
        assert_eq!(observed[1].addresses[0].0, [192, 0, 2, 4]);
    }

    #[test]
    fn native_parser_rejects_changed_link_identity_and_orphaned_addresses() {
        let mut links = BTreeMap::new();
        add_link(&mut links, &link(9, "lan0")).unwrap();
        for altered in [
            BTreeMap::new(),
            BTreeMap::from([(10, links[&9].clone())]),
            BTreeMap::from([(
                9,
                Link {
                    name: "renamed".into(),
                    ..links[&9].clone()
                },
            )]),
            BTreeMap::from([(
                9,
                Link {
                    mac: Some(vec![7; 6]),
                    ..links[&9].clone()
                },
            )]),
        ] {
            assert!(finish(links.clone(), altered, BTreeMap::new()).is_err());
        }
        assert!(add_address(&mut BTreeMap::new(), &links, &address(10, [1, 2, 3, 4], 24)).is_err());
        assert!(add_link(&mut links.clone(), &link(10, "lan0")).is_err());
        assert!(add_link(&mut links, &link(9, "other0")).is_err());
    }

    #[test]
    fn native_parser_rejects_malformed_or_ambiguous_attributes() {
        let mut links = BTreeMap::new();
        add_link(&mut links, &link(9, "lan0")).unwrap();
        let mut duplicate = address(9, [1, 2, 3, 4], 24);
        duplicate.extend(attr(2, &[4, 3, 2, 1]));
        let mut malformed = address(9, [1, 2, 3, 4], 24);
        malformed.extend([3, 0, 2, 0]);
        let mut flags = address(9, [1, 2, 3, 4], 24);
        flags.extend(attr(8, &[1]));
        for bad in [
            vec![],
            vec![0; 7],
            address(9, [1, 2, 3, 4], 33),
            duplicate,
            malformed,
            flags,
        ] {
            assert!(add_address(&mut BTreeMap::new(), &links, &bad).is_err());
        }
        let mut unknown = address(9, [1, 2, 3, 4], 24);
        unknown.extend(attr(0x3fff, &[1, 2, 3]));
        add_address(&mut BTreeMap::new(), &links, &unknown).unwrap();
        let mut duplicate = link(9, "lan0");
        duplicate.extend(attr(3, b"other0\0"));
        for bad in [vec![], vec![0; 15], link(0, "lan0"), duplicate] {
            assert!(add_link(&mut BTreeMap::new(), &bad).is_err());
        }
        for bad in [
            vec![0],
            vec![3, 0, 0, 0],
            vec![9, 0, 0, 0],
            vec![5, 0, 0, 0, 1, 0],
        ] {
            assert!(attributes(&bad, |_, _| Ok(())).is_err());
        }
    }

    #[test]
    fn dump_requires_complete_matching_success_and_keeps_ack_distinct() {
        let mut state = dump();
        let mut count = 0;
        state
            .datagram(&message(NEWLINK, MULTI, &link(9, "lan0")), |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        state
            .datagram(&message(ERROR, 0, &[0; 20]), |_| Ok(()))
            .unwrap();
        assert!(!state.done);
        state
            .datagram(&message(DONE, MULTI, &[0; 4]), |_| Ok(()))
            .unwrap();
        assert_eq!(count, 1);
        assert!(state.done);
        assert!(
            state
                .datagram(&message(DONE, MULTI, &[0; 4]), |_| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn dump_rejects_wrong_identity_interruption_errors_and_bad_frames() {
        let valid = message(NEWLINK, MULTI, &link(9, "lan0"));
        let mut sequence = valid.clone();
        sequence[8] = 8;
        let mut port = valid.clone();
        port[12] = 0;
        let mut length = valid.clone();
        length[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        for bad in [
            sequence,
            port,
            length,
            vec![],
            vec![0; 15],
            message(NEWLINK, MULTI | DUMP_INTR, &link(9, "lan0")),
            message(DONE, MULTI | DUMP_INTR, &[0; 4]),
            message(DONE, MULTI, &(-4i32).to_ne_bytes()),
            message(DONE, MULTI, &[]),
            message(DONE, MULTI, &[0, 0, 0, 0, 1]),
            message(ERROR, 0, &[0; 4]),
            message(ERROR, 0, &[1; 20]),
            message(OVERRUN, 0, &[]),
            message(NEWADDR, MULTI, &[]),
            message(NEWLINK, 0, &link(9, "lan0")),
        ] {
            assert!(
                dump().datagram(&bad, |_| Ok(())).is_err(),
                "accepted {bad:?}"
            );
        }
        let mut after = message(DONE, MULTI, &[0; 4]);
        after.extend(valid);
        assert!(dump().datagram(&after, |_| Ok(())).is_err());
    }

    #[test]
    fn datagram_rejects_wrong_sender_and_all_truncation() {
        // SAFETY: zeroed sockaddr_nl is valid; set the required family below.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sender.nl_family = libc::AF_NETLINK as u16;
        let size = std::mem::size_of_val(&sender) as libc::socklen_t;
        validate_datagram(64, 64, 0, &sender, size).unwrap();
        for (received, expected, flags, length) in [
            (63, 64, 0, size),
            (64, 64, libc::MSG_TRUNC, size),
            (64, 64, libc::MSG_CTRUNC, size),
            (64, 64, 0, size - 1),
        ] {
            assert!(validate_datagram(received, expected, flags, &sender, length).is_err());
        }
        sender.nl_pid = 42;
        assert!(validate_datagram(64, 64, 0, &sender, size).is_err());
        sender.nl_pid = 0;
        sender.nl_groups = 1;
        assert!(validate_datagram(64, 64, 0, &sender, size).is_err());
    }

    #[test]
    fn one_budget_bounds_all_dumps_including_incomplete_and_interrupted_io() {
        let mut budget = Budget {
            deadline: Instant::now() + TIMEOUT,
            bytes: 0,
        };
        budget.charge(LIMIT / 2).unwrap();
        budget.charge(LIMIT / 2).unwrap();
        assert!(budget.charge(1).is_err());
        let mut socket = Socket::open().unwrap();
        socket.budget.deadline = Instant::now() + Duration::from_millis(20);
        let start = Instant::now();
        // No request means there can be no completion. poll must time out.
        assert!(socket.wait(libc::POLLIN).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        socket.budget.deadline = Instant::now() + Duration::from_millis(20);
        let start = Instant::now();
        let mut calls = 0;
        assert!(
            socket
                .io(libc::POLLIN, || {
                    calls += 1;
                    // SAFETY: errno is thread-local and immediately consumed by io().
                    unsafe {
                        *libc::__errno_location() = libc::EINTR;
                    }
                    -1
                })
                .is_err()
        );
        assert!(calls > 1 && start.elapsed() < Duration::from_secs(1));
        socket.budget.deadline = Instant::now() + TIMEOUT;
        let error = socket
            .io(libc::POLLIN, || {
                // SAFETY: same thread-local errno contract as above.
                unsafe {
                    *libc::__errno_location() = libc::ENOBUFS;
                }
                -1
            })
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::ENOBUFS)
        );
    }

    #[test]
    fn live_read_only_inventory_contains_loopback() {
        let interfaces = read().unwrap();
        let lo = interfaces.iter().find(|link| link.name == "lo").unwrap();
        assert!(lo.index > 0);
        assert!(lo.addresses.contains(&([127, 0, 0, 1], [255, 0, 0, 0])));
    }
}
