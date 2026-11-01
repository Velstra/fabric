//! Stable firewall-state Array storage; the hash map is an index only.
use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use velstra_common::{
    FirewallFlowAllocator, FirewallFlowKey, FirewallFlowRef, FirewallFlowSlot, FirewallFlowStorage,
    FirewallFlowTable, FlowTableError,
};

pub const FLOW_CAPACITY: u32 = velstra_common::firewall_control::FIREWALL_FLOW_CAPACITY;

// The catalogue maps are operational lifecycle metadata, owned by the single
// guarded userspace writer. Keep them in the ELF even before a packet accesses
// one, so the loader can create/reuse and validate the complete storage schema.
#[map]
static FW_SCOPE_META: Array<velstra_common::FlowScopeMetadata> = Array::with_max_entries(1, 0);
#[map]
static FW_LABELS: HashMap<velstra_common::FlowScopeLabel, velstra_common::FlowScope> =
    HashMap::with_max_entries(velstra_common::FLOW_POLICY_CAPACITY, 0);
#[map]
pub static FW_POLICY: HashMap<u32, velstra_common::FlowScope> =
    HashMap::with_max_entries(velstra_common::FLOW_POLICY_CAPACITY, 0);
#[map]
pub static FW_TIMEOUT: HashMap<velstra_common::FlowScope, velstra_common::FlowTimeouts> =
    HashMap::with_max_entries(velstra_common::FLOW_POLICY_CAPACITY, 0);
#[map]
static FW_SLOT: Array<FirewallFlowSlot> = Array::with_max_entries(FLOW_CAPACITY, 0);
#[map]
static FW_ALLOC: Array<FirewallFlowAllocator> = Array::with_max_entries(1, 0);
#[map]
static FW_INDEX: HashMap<FirewallFlowKey, FirewallFlowRef> =
    HashMap::with_max_entries(FLOW_CAPACITY, 0);

pub struct BpfFlowStorage;
// All maps live for the loaded program's lifetime. Only the common table may
// mutate slots/allocator/index. Arrays begin in their specified zero state;
// callers must never reset or raw-update these maps while hooks execute.
unsafe impl FirewallFlowStorage for BpfFlowStorage {
    #[inline(always)]
    fn capacity(&self) -> u32 {
        FLOW_CAPACITY
    }
    #[inline(always)]
    fn allocator(&self) -> Option<&FirewallFlowAllocator> {
        FW_ALLOC.get_ptr(0).map(|ptr| unsafe { &*ptr })
    }
    #[inline(always)]
    fn slot(&self, index: u32) -> Option<&FirewallFlowSlot> {
        FW_SLOT.get_ptr(index).map(|ptr| unsafe { &*ptr })
    }
    #[inline(always)]
    fn index(&self, key: &FirewallFlowKey) -> Option<FirewallFlowRef> {
        // A concurrent map replacement/reuse may produce an old or mixed index.
        // It cannot authorize: full key + unique incarnation are checked while
        // holding the addressed stable slot lock, before any protocol read.
        unsafe {
            FW_INDEX
                .get_ptr(key)
                .map(|ptr| core::ptr::read_volatile(ptr))
        }
    }
    #[inline(always)]
    fn insert(
        &self,
        key: &FirewallFlowKey,
        value: FirewallFlowRef,
    ) -> Result<bool, FlowTableError> {
        match FW_INDEX.insert(key, &value, 1 /* BPF_NOEXIST */) {
            Ok(()) => Ok(true),
            Err(-17) => Ok(false),
            Err(_) => Err(FlowTableError::Storage),
        }
    }
    #[inline(always)]
    fn remove(&self, key: &FirewallFlowKey) -> Result<(), FlowTableError> {
        FW_INDEX.remove(key).map_err(|_| FlowTableError::Storage)
    }
}
pub const fn table() -> FirewallFlowTable<'static, BpfFlowStorage> {
    FirewallFlowTable::new(&BpfFlowStorage)
}
