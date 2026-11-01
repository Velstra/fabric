//! Syscall-only coherent state control. Never attach this program to a NIC.
//! Requests and responses use caller-owned test-run packet buffers; no global
//! response map can be overwritten by another control caller on another CPU.
use core::sync::atomic::{AtomicU32, Ordering};

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_xdp_get_buff_len, bpf_xdp_load_bytes, bpf_xdp_store_bytes},
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use velstra_common::{
    FlowControlMessage as Message, FlowControlOp as Op, FlowControlStatus as Status,
    FlowRecordKind as Kind, FlowTableError, FlowVersion,
};

use crate::flow_table::{FLOW_CAPACITY, table};

#[repr(C)]
struct Scratch {
    busy: u32,
    _pad: u32,
    input: Message,
    output: Message,
}
#[map]
static FW_CTL_BUF: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

#[xdp]
pub fn fw_flow_control(ctx: XdpContext) -> u32 {
    let size = core::mem::size_of::<Message>() as u32;
    if unsafe { bpf_xdp_get_buff_len(ctx.ctx) } != (size + Message::PREFIX_LEN as u32) as u64 {
        return 1;
    }
    let Some(ptr) = FW_CTL_BUF.get_ptr_mut(0) else {
        return 1;
    };
    let lock = unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() };
    if lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return unavailable(&ctx, Status::BUSY);
    }
    let result = unsafe { execute(&ctx, &mut (*ptr).input, &mut (*ptr).output, size) };
    lock.swap(0, Ordering::Release);
    result
}
// A nested/preempted invocation may not touch the occupied per-CPU buffer.
// Return a correlated BUSY header in its own packet without copying map data.
#[repr(C)]
struct Header {
    magic: u32,
    version: u16,
    operation: u16,
    request_id: u64,
    status: u32,
    reserved: u32,
}
#[inline(always)]
fn unavailable(ctx: &XdpContext, status: u32) -> u32 {
    let mut header = Header {
        magic: 0,
        version: 0,
        operation: 0,
        request_id: 0,
        status: 0,
        reserved: 0,
    };
    if unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            Message::PREFIX_LEN as u32,
            (&mut header as *mut Header).cast(),
            24,
        )
    } != 0
        || header.magic != Message::MAGIC
        || header.version != Message::VERSION
        || header.request_id == 0
        || header.status != 0
        || header.reserved != 0
    {
        return 1;
    }
    header.status = status;
    if unsafe {
        bpf_xdp_store_bytes(
            ctx.ctx,
            Message::PREFIX_LEN as u32,
            (&mut header as *mut Header).cast(),
            24,
        )
    } != 0
    {
        return 1;
    }
    2
}
#[inline(always)]
fn execute(ctx: &XdpContext, input: &mut Message, output: &mut Message, size: u32) -> u32 {
    if unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            Message::PREFIX_LEN as u32,
            (input as *mut Message).cast(),
            size,
        )
    } != 0
    {
        return 1;
    }
    if !input.valid_header() {
        return 1;
    }
    *output = Message::new(input.operation, input.request_id);
    output.status = dispatch(input, output);
    // Never return an input's stale status if serialization failed.
    if unsafe {
        bpf_xdp_store_bytes(
            ctx.ctx,
            Message::PREFIX_LEN as u32,
            (output as *mut Message).cast(),
            size,
        )
    } != 0
    {
        return 1;
    }
    2
}
#[inline(always)]
fn error(value: FlowTableError) -> u32 {
    match value {
        FlowTableError::Busy => Status::BUSY,
        FlowTableError::Full => Status::FULL,
        FlowTableError::Exhausted => Status::EXHAUSTED,
        FlowTableError::Corrupt => Status::CORRUPT,
        FlowTableError::Storage => Status::STORAGE,
        FlowTableError::Conflict => Status::CONFLICT,
        FlowTableError::Missing => Status::MISSING,
        FlowTableError::Invalid => Status::INVALID,
    }
}
#[inline(never)]
fn dispatch(input: &Message, output: &mut Message) -> u32 {
    if input.operation != Op::IMPORT_ALIAS && input.wire_incarnation != 0 {
        return Status::INVALID;
    }
    if input.operation != Op::RECLAIM
        && input.operation != Op::SNAPSHOT_SLOT
        && input.operation != Op::ALLOCATED_SLOTS
        && !input.record.key.valid()
    {
        return Status::INVALID;
    }
    match input.operation {
        Op::ALLOCATED_SLOTS => match table().allocated_slots() {
            Ok(count) => {
                output.record.entry.slot = count;
                Status::APPLIED
            }
            Err(e) => error(e),
        },
        Op::SNAPSHOT => snapshot(input, output, false),
        Op::SNAPSHOT_SLOT => snapshot(input, output, true),
        Op::REMOVE => remove(input, false),
        Op::REVOKE => remove(input, true),
        Op::IMPORT_PRIMARY => import_primary(input, output),
        Op::IMPORT_ALIAS => import_alias(input, output),
        Op::RECLAIM => {
            if input.record.entry.slot >= FLOW_CAPACITY
                || input.record.entry.incarnation != 0
                || input.record.revision != 0
            {
                return Status::INVALID;
            }
            match table().reclaim_retired(input.record.entry.slot) {
                Ok(true) => Status::APPLIED,
                Ok(false) => Status::UNCHANGED,
                Err(e) => error(e),
            }
        }
        _ => Status::INVALID,
    }
}
#[inline(never)]
fn snapshot(input: &Message, output: &mut Message, by_slot: bool) -> u32 {
    let result = if by_slot {
        if input.record.entry.slot >= FLOW_CAPACITY {
            return Status::INVALID;
        }
        table().snapshot_slot_into(input.record.entry.slot, &mut output.record)
    } else {
        table().snapshot_into(&input.record.key, &mut output.record)
    };
    match result {
        Ok(()) => Status::APPLIED,
        Err(e) => error(e),
    }
}
#[inline(never)]
fn remove(input: &Message, explicit: bool) -> u32 {
    if !matches!(
        input.record.kind,
        Kind::PRIMARY | Kind::ALIAS | Kind::ORPHAN_ALIAS
    ) {
        return Status::INVALID;
    }
    match table().remove_snapshot(&input.record, explicit) {
        Ok(()) => Status::APPLIED,
        Err(e) => error(e),
    }
}
#[inline(never)]
fn import_primary(input: &Message, output: &mut Message) -> u32 {
    if input.record.kind != Kind::PRIMARY || input.record.entry._pad != 0 {
        return Status::INVALID;
    }
    let expected = if input.record.entry.incarnation == 0 {
        if input.record.entry.slot != 0 || input.record.revision != 0 {
            return Status::INVALID;
        }
        None
    } else {
        Some(FlowVersion {
            entry: input.record.entry,
            revision: input.record.revision,
        })
    };
    let now = unsafe { bpf_ktime_get_ns() } / 1_000_000;
    match table().import_primary(&input.record.key, &input.record.state, expected, now) {
        Ok(version) => {
            output.record.kind = Kind::PRIMARY;
            output.record.key = input.record.key;
            output.record.entry = version.entry;
            output.record.revision = version.revision;
            Status::APPLIED
        }
        Err(e) => error(e),
    }
}
#[inline(never)]
fn import_alias(input: &Message, output: &mut Message) -> u32 {
    if input.record.kind != Kind::ALIAS
        || input.record.entry._pad != 0
        || input.record.entry.incarnation == 0 && input.record.entry.slot != 0
    {
        return Status::INVALID;
    }
    let now = unsafe { bpf_ktime_get_ns() } / 1_000_000;
    match table().import_alias(&input.record, input.wire_incarnation, now) {
        Ok(version) => {
            output.record.kind = Kind::ALIAS;
            output.record.key = input.record.key;
            output.record.entry = version.entry;
            output.record.revision = version.revision;
            Status::APPLIED
        }
        Err(e) => error(e),
    }
}
