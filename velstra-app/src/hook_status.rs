//! Read the kernel's actual XDP attachment, including an explicitly detached
//! but still pinned link. An open descriptor or a remembered name is not proof
//! that a newly created interface is protected.

use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

use anyhow::{Context, Result, ensure};

// Stable Linux UAPI: BPF_OBJ_GET, BPF_OBJ_GET_INFO_BY_FD, BPF_LINK_TYPE_XDP.
const OBJ_GET: u32 = 7;
const OBJ_INFO: u32 = 15;
const LINK_XDP: u32 = 6;

#[repr(C)]
struct ObjectRequest {
    path: u64,
    fd: u32,
    flags: u32,
}

#[repr(C)]
struct InfoRequest {
    fd: u32,
    len: u32,
    info: u64,
}

/// The common header and XDP prefix of bpf_link_info. The union begins at
/// offset 16 because its UAPI members include aligned 64-bit fields. Request
/// only this prefix; newer kernels may append fields without changing it.
#[repr(C, align(8))]
#[derive(Default)]
struct XdpInfo {
    kind: u32,
    id: u32,
    program: u32,
    padding: u32,
    ifindex: u32,
    reserved: u32,
}

impl XdpInfo {
    fn verify(&self, len: u32, index: u32, program: u32) -> Result<()> {
        ensure!(len >= 20, "kernel returned incomplete XDP link information");
        ensure!(
            self.kind == LINK_XDP && self.id != 0,
            "pin is not an XDP link"
        );
        ensure!(
            index != 0 && self.ifindex == index,
            "XDP link is detached or belongs to a different interface"
        );
        ensure!(
            program != 0 && self.program == program,
            "XDP link does not run the current firewall program"
        );
        Ok(())
    }
}

pub fn verify_xdp(path: &Path, index: u32, program: u32) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).context("invalid XDP pin path")?;
    let request = ObjectRequest {
        path: path.as_ptr() as u64,
        fd: 0,
        flags: 0,
    };
    // SAFETY: request and its NUL-terminated path remain live for the syscall;
    // BPF_OBJ_GET only reads this UAPI structure and returns an owned FD.
    let fd = unsafe { libc::syscall(libc::SYS_bpf, OBJ_GET, &request, size_of::<ObjectRequest>()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("opening the actual XDP link");
    }
    // SAFETY: a successful BPF_OBJ_GET returned a new descriptor owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // OBJ_GET accepts maps and programs too. Their info prefixes overlap with
    // bpf_link_info, so a numeric type alone cannot establish the object class.
    let object = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .context("checking the kernel object class")?;
    ensure!(
        object == Path::new("anon_inode:bpf-link"),
        "pin does not refer to a kernel BPF link"
    );
    let mut info = XdpInfo::default();
    let mut request = InfoRequest {
        fd: fd.as_raw_fd() as u32,
        len: size_of::<XdpInfo>() as u32,
        info: (&mut info as *mut XdpInfo) as u64,
    };
    // SAFETY: request names a live descriptor and a writable, aligned buffer of
    // the advertised length. The kernel updates len to the returned size.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            OBJ_INFO,
            &mut request,
            size_of::<InfoRequest>(),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("reading the actual XDP attachment");
    }
    info.verify(request.len, index, program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_requested_prefix_matches_the_linux_uapi_alignment() {
        assert_eq!(size_of::<ObjectRequest>(), 16);
        assert_eq!(size_of::<InfoRequest>(), 16);
        assert_eq!(size_of::<XdpInfo>(), 24);
        assert_eq!(std::mem::offset_of!(XdpInfo, ifindex), 16);
    }

    #[test]
    fn detached_stale_foreign_and_incomplete_hooks_are_never_ready() {
        let good = XdpInfo {
            kind: LINK_XDP,
            id: 1,
            program: 3,
            ifindex: 7,
            ..Default::default()
        };
        good.verify(24, 7, 3).unwrap();
        for (len, index, program) in [(19, 7, 3), (24, 8, 3), (24, 7, 4), (24, 0, 3), (24, 7, 0)] {
            assert!(good.verify(len, index, program).is_err());
        }
        assert!(XdpInfo { ifindex: 0, ..good }.verify(24, 7, 3).is_err());
        assert!(XdpInfo { kind: 11, ..good }.verify(24, 7, 3).is_err());
        assert!(XdpInfo { id: 0, ..good }.verify(24, 7, 3).is_err());
    }
}
