//! Operational identity derived from desired policies, retained with their
//! kernel state. All methods run under the agent's single-writer ownership;
//! installing views/committing labels additionally requires drained packet
//! readers and the shared state-controller lock. No second desired config.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap, Map, MapData, MapType},
};
use velstra_common::{
    ConfigFlags, FLOW_POLICY_CAPACITY, FlowRecordKind, FlowScope, FlowScopeLabel,
    FlowScopeMetadata, FlowTimeouts,
};
use velstra_config::PolicyConfig;

use crate::flow_store::{FlowStore, status};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopePlan {
    pub labels: BTreeMap<FlowScopeLabel, FlowScope>,
    pub bindings: BTreeMap<u32, FlowScope>,
    pub timeouts: BTreeMap<FlowScope, FlowTimeouts>,
}
impl ScopePlan {
    pub fn scope(&self, policy: u32) -> Option<FlowScope> {
        self.bindings.get(&policy).copied()
    }
}

pub struct ScopeCatalogue {
    labels: HashMap<MapData, FlowScopeLabel, FlowScope>,
    metadata: Array<MapData, FlowScopeMetadata>,
    active: BTreeMap<FlowScopeLabel, FlowScope>,
    state: FlowScopeMetadata,
}
impl ScopeCatalogue {
    pub fn open(ebpf: &mut Ebpf) -> Result<Self> {
        validate_scope_maps(ebpf)?;
        let labels: HashMap<MapData, FlowScopeLabel, FlowScope> =
            HashMap::try_from(ebpf.take_map("FW_LABELS").context("missing scope labels")?)?;
        let mut metadata: Array<MapData, FlowScopeMetadata> = Array::try_from(
            ebpf.take_map("FW_SCOPE_META")
                .context("missing scope metadata")?,
        )?;
        let mut active = BTreeMap::new();
        for item in labels.iter() {
            let (label, scope) = item?;
            ensure!(
                active.insert(label, scope).is_none(),
                "duplicate scope label"
            );
        }
        let mut state = metadata.get(&0, 0)?;
        if state == FlowScopeMetadata::EMPTY {
            ensure!(
                active.is_empty(),
                "uninitialized scope namespace contains active labels"
            );
            let mut random = [0u8; 8];
            loop {
                std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
                let namespace = u64::from_ne_bytes(random);
                if namespace != 0 {
                    state = FlowScopeMetadata {
                        version: FlowScopeMetadata::VERSION,
                        reserved: 0,
                        namespace,
                        next_identity: 0,
                    };
                    break;
                }
            }
            metadata.set(0, state, 0)?;
        }
        validate_catalogue(state, &active)?;
        Ok(Self {
            labels,
            metadata,
            active,
            state,
        })
    }

    /// Reserve fresh identities before map publication. Holes after failure
    /// are intentional: no retry, rollback or restart may reuse a reserved ID.
    pub fn prepare(&mut self, policies: &[PolicyConfig]) -> Result<ScopePlan> {
        let (plan, state) = plan(self.state, &self.active, policies)?;
        if state != self.state {
            self.metadata
                .set(0, state, 0)
                .context("reserving policy scope identities")?;
            self.state = state;
        }
        Ok(plan)
    }

    /// The caller retains old views for rollback. If this fails, restore() is
    /// required before reopening; a failed restore leaves enforcement closed.
    pub fn commit(&mut self, next: &ScopePlan) -> Result<()> {
        replace(&mut self.labels, &next.labels)?;
        self.active = next.labels.clone();
        Ok(())
    }
    pub fn restore(&mut self, previous: &ScopePlan) -> Result<()> {
        replace(&mut self.labels, &previous.labels)?;
        self.active = previous.labels.clone();
        Ok(())
    }
}

fn validate_catalogue(
    state: FlowScopeMetadata,
    active: &BTreeMap<FlowScopeLabel, FlowScope>,
) -> Result<()> {
    ensure!(
        state.valid(),
        "invalid or incompatible policy scope namespace"
    );
    let mut used = BTreeSet::new();
    for (label, scope) in active {
        ensure!(
            label.valid()
                && scope.generation == state.namespace
                && scope.identity != 0
                && scope.identity <= state.next_identity
                && used.insert(*scope),
            "corrupt policy scope catalogue"
        );
    }
    Ok(())
}

fn plan(
    mut state: FlowScopeMetadata,
    active: &BTreeMap<FlowScopeLabel, FlowScope>,
    policies: &[PolicyConfig],
) -> Result<(ScopePlan, FlowScopeMetadata)> {
    validate_catalogue(state, active)?;
    ensure!(
        policies.len() <= FLOW_POLICY_CAPACITY as usize,
        "too many policies for the stateful scope catalogue"
    );
    let mut desired = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for policy in policies {
        ensure!(ids.insert(policy.id), "duplicate policy id {}", policy.id);
        if !policy.global.has_flag(ConfigFlags::STATEFUL) {
            continue;
        }
        let label = FlowScopeLabel::policy(policy.id, policy.state_scope.as_deref())
            .with_context(||format!("policy {} needs a nonempty state_scope of at most 128 UTF-8 bytes without control characters",policy.id))?;
        ensure!(
            desired.insert(label, policy.id).is_none(),
            "stateful semantic scopes must be unique"
        );
    }
    let mut next = ScopePlan {
        labels: BTreeMap::new(),
        bindings: BTreeMap::new(),
        timeouts: BTreeMap::new(),
    };
    for (label, id) in desired {
        let scope = match active.get(&label) {
            Some(scope) => *scope,
            None => {
                state.next_identity = state
                    .next_identity
                    .checked_add(1)
                    .context("policy scope identity space exhausted")?;
                FlowScope {
                    identity: state.next_identity,
                    generation: state.namespace,
                }
            }
        };
        next.labels.insert(label, scope);
        next.bindings.insert(id, scope);
        next.timeouts.insert(scope, FlowTimeouts::DEFAULT);
    }
    Ok((next, state))
}

/// Views are derived from the complete candidate, replaced only while the
/// packet gate is closed. Removed scopes no longer have a timeout/authority.
pub fn install_views(ebpf: &mut Ebpf, next: &ScopePlan) -> Result<()> {
    let mut policies = HashMap::try_from(
        ebpf.map_mut("FW_POLICY")
            .context("scope bindings missing")?,
    )?;
    replace(&mut policies, &next.bindings)?;
    let mut timeouts = HashMap::try_from(
        ebpf.map_mut("FW_TIMEOUT")
            .context("scope timeouts missing")?,
    )?;
    replace(&mut timeouts, &next.timeouts)?;
    Ok(())
}

fn replace<T, K, V>(map: &mut HashMap<T, K, V>, wanted: &BTreeMap<K, V>) -> Result<()>
where
    T: std::borrow::BorrowMut<MapData>,
    K: Pod + Ord,
    V: Pod,
{
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    // No successful apply may hide enumeration/deletion errors.
    for key in keys {
        if !wanted.contains_key(&key) {
            map.remove(&key)?;
        }
    }
    for (key, value) in wanted {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

/// Primary records first, then reload aliases after our own primary updates.
/// Configuration reconciliation must hold the shared control lock throughout.
pub fn reconcile_store(store: &mut FlowStore, next: &ScopePlan) -> Result<()> {
    let scan = store.scan()?;
    ensure!(
        scan.retry_slots.is_empty(),
        "stateful scope reconciliation encountered busy/changed slots; retry before reopening"
    );
    for record in scan
        .records
        .iter()
        .filter(|r| r.kind == FlowRecordKind::PRIMARY)
    {
        if let Some(timeouts) = next.timeouts.get(&record.key.scope) {
            store.constrain_timeout(record, *timeouts)?;
        } else {
            store.revoke_if_unchanged(record)?;
        }
    }
    for old in scan
        .records
        .iter()
        .filter(|r| r.kind != FlowRecordKind::PRIMARY)
    {
        let record = match store.snapshot(&old.key) {
            Ok(record) => record,
            Err(error) if status(&error) == Some(velstra_common::FlowControlStatus::MISSING) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if record.kind == FlowRecordKind::ORPHAN_ALIAS
            || !next.timeouts.contains_key(&record.key.scope)
            || !next.timeouts.contains_key(&record.primary_key.scope)
        {
            store.revoke_if_unchanged(&record)?;
        }
    }
    Ok(())
}

pub fn validate_scope_maps(ebpf: &Ebpf) -> Result<()> {
    for (name, kind, key, value, capacity) in scope_map_specs() {
        let data = match (name, ebpf.map(name)) {
            ("FW_SCOPE_META", Some(Map::Array(data)))
            | ("FW_LABELS" | "FW_POLICY" | "FW_TIMEOUT", Some(Map::HashMap(data))) => data,
            _ => anyhow::bail!("{name} scope map missing or has an incompatible type"),
        };
        let info = data.info()?;
        ensure!(
            info.map_type()? == kind
                && info.key_size() == key
                && info.value_size() == value
                && info.max_entries() == capacity
                && info.map_flags() == 0,
            "incompatible scope map ABI: {name}"
        );
    }
    Ok(())
}

pub fn scope_map_specs() -> [(&'static str, MapType, u32, u32, u32); 4] {
    [
        (
            "FW_SCOPE_META",
            MapType::Array,
            4,
            core::mem::size_of::<FlowScopeMetadata>() as u32,
            1,
        ),
        (
            "FW_LABELS",
            MapType::Hash,
            core::mem::size_of::<FlowScopeLabel>() as u32,
            16,
            FLOW_POLICY_CAPACITY,
        ),
        ("FW_POLICY", MapType::Hash, 4, 16, FLOW_POLICY_CAPACITY),
        ("FW_TIMEOUT", MapType::Hash, 16, 24, FLOW_POLICY_CAPACITY),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> FlowScopeMetadata {
        FlowScopeMetadata {
            version: 1,
            reserved: 0,
            namespace: 991,
            next_identity: 0,
        }
    }
    fn policy(id: u32, name: Option<&str>, enabled: bool) -> PolicyConfig {
        let mut policy = velstra_config::RuntimeConfig::passthrough()
            .policies
            .remove(0);
        policy.id = id;
        policy.state_scope = name.map(str::to_owned);
        policy.global = velstra_common::GlobalConfig::new(
            velstra_common::Action::Drop,
            if enabled { ConfigFlags::STATEFUL } else { 0 },
        );
        policy
    }
    #[test]
    fn named_scope_survives_routing_ordinal_movement() {
        let (old, state) =
            plan(initial(), &BTreeMap::new(), &[policy(1, Some("wan"), true)]).unwrap();
        let (new, _) = plan(
            state,
            &old.labels,
            &[policy(1, Some("dmz"), true), policy(2, Some("wan"), true)],
        )
        .unwrap();
        assert_eq!(old.scope(1), new.scope(2));
        assert_ne!(new.scope(1), old.scope(1));
    }
    #[test]
    fn delete_recreate_and_confirm_rollback_allocate_fresh_identity() {
        let desired = [policy(1, Some("wan"), true)];
        let (old, state) = plan(initial(), &BTreeMap::new(), &desired).unwrap();
        let (deleted, state) = plan(state, &old.labels, &[]).unwrap();
        let (restored, _) = plan(state, &deleted.labels, &desired).unwrap();
        assert_ne!(old.scope(1), restored.scope(1));
        assert!(restored.scope(1).unwrap().identity > old.scope(1).unwrap().identity);
    }
    #[test]
    fn failed_reservations_do_not_reuse_ids_and_unchanged_plans_are_idempotent() {
        let desired = [policy(1, Some("wan"), true)];
        let (failed, reserved) = plan(initial(), &BTreeMap::new(), &desired).unwrap();
        let (retried, state) = plan(reserved, &BTreeMap::new(), &desired).unwrap();
        assert_ne!(failed.scope(1), retried.scope(1));
        let (same, unchanged) = plan(state, &retried.labels, &desired).unwrap();
        assert_eq!(same, retried);
        assert_eq!(state, unchanged);
    }
    #[test]
    fn disable_then_enable_is_a_new_scope_lifetime() {
        let (old, state) = plan(initial(), &BTreeMap::new(), &[policy(1, None, true)]).unwrap();
        let (disabled, state) = plan(state, &old.labels, &[policy(1, None, false)]).unwrap();
        assert!(disabled.bindings.is_empty());
        let (enabled, _) = plan(state, &disabled.labels, &[policy(1, None, true)]).unwrap();
        assert_ne!(old.scope(1), enabled.scope(1));
    }
    #[test]
    fn duplicate_names_ids_and_invalid_labels_are_refused() {
        for desired in [
            vec![policy(1, Some("a"), true), policy(2, Some("a"), true)],
            vec![policy(1, None, true), policy(1, None, true)],
            vec![policy(1, Some(""), true)],
            vec![policy(1, Some("bad\nname"), true)],
            vec![policy(1, Some(&"a".repeat(129)), true)],
        ] {
            assert!(plan(initial(), &BTreeMap::new(), &desired).is_err());
        }
    }
    #[test]
    fn label_kinds_are_disjoint_and_full_names_are_validated() {
        let global = FlowScopeLabel::policy(0, None).unwrap();
        let native = FlowScopeLabel::policy(1, None).unwrap();
        let named = FlowScopeLabel::policy(1, Some("1")).unwrap();
        assert!(global.valid() && native.valid() && named.valid());
        assert_ne!(global, native);
        assert_ne!(native, named);
        let mut corrupted = named;
        corrupted.bytes[127] = 1;
        assert!(!corrupted.valid());
        assert!(FlowScopeLabel::policy(1, Some(&"é".repeat(65))).is_none());
        assert_eq!(core::mem::size_of::<FlowScopeLabel>(), 136);
        assert_eq!(core::mem::size_of::<FlowScopeMetadata>(), 24);
    }
    #[test]
    fn corrupt_namespace_and_duplicate_scope_bindings_fail_closed() {
        let (old, state) =
            plan(initial(), &BTreeMap::new(), &[policy(1, Some("a"), true)]).unwrap();
        let mut bad = old.labels.clone();
        bad.insert(
            FlowScopeLabel::policy(2, Some("b")).unwrap(),
            old.scope(1).unwrap(),
        );
        assert!(validate_catalogue(state, &bad).is_err());
        assert!(plan(FlowScopeMetadata::EMPTY, &BTreeMap::new(), &[]).is_err());
    }
    #[test]
    fn allocator_exhaustion_never_wraps_into_a_previous_lifetime() {
        let state = FlowScopeMetadata {
            next_identity: u64::MAX,
            ..initial()
        };
        assert!(plan(state, &BTreeMap::new(), &[policy(1, None, true)]).is_err());
    }
}
