//! Real kernel storage contract. No packet attachment or production-map access.
//! Each map is created here, unpinned, and released when its last FD closes.
use std::{
    env, fs,
    mem::size_of,
    os::fd::{AsFd, FromRawFd, OwnedFd},
    sync::{Arc, Barrier},
    thread,
};

use anyhow::{Context, Result, ensure};
use aya::maps::{HashMap, IterableMap, Map, MapData};
use serde_json::json;
use velstra_common::{FirewallKey, FirewallSession, FirewallSessionKey, FirewallState, FlowKey};

type Sessions = HashMap<MapData, FirewallSessionKey, FirewallSession>;
const CAPACITY: u32 = 65_536;
const NOEXIST: u64 = 1;
const EXIST: u64 = 2;

#[repr(C)]
struct Create {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
}

fn create(capacity: u32) -> Result<Sessions> {
    let attr = Create {
        map_type: 1, // BPF_MAP_TYPE_HASH, not LRU.
        key_size: size_of::<FirewallSessionKey>() as u32,
        value_size: size_of::<FirewallSession>() as u32,
        max_entries: capacity,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: *b"qa_fw_sessions\0\0",
        map_ifindex: 0,
    };
    // SAFETY: fully initialized repr(C) prefix of Linux bpf_attr for
    // BPF_MAP_CREATE; the kernel reads exactly this valid 48-byte allocation.
    let raw = unsafe { libc::syscall(libc::SYS_bpf, 0, &attr, size_of::<Create>()) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_MAP_CREATE HASH");
    }
    // SAFETY: successful BPF_MAP_CREATE returned a new owned descriptor.
    let data = MapData::from_fd(unsafe { OwnedFd::from_raw_fd(raw as i32) })?;
    let info = data.info()?;
    ensure!(info.key_size() == 44 && info.value_size() == 48);
    ensure!(info.max_entries() == capacity && info.map_flags() == 0);
    Ok(Sessions::try_from(Map::HashMap(data))?)
}

fn duplicate(map: &Sessions) -> Result<Sessions> {
    let data = MapData::from_fd(map.map().fd().as_fd().try_clone_to_owned()?)?;
    Ok(Sessions::try_from(Map::HashMap(data))?)
}

fn record(index: u32, policy: u32, generation: u64) -> (FirewallSessionKey, FirewallSession) {
    let key = FirewallKey::ipv4(FlowKey::new(
        policy,
        [192, 0, (index >> 8) as u8, index as u8],
        [198, 51, 100, 9],
        41000,
        9000,
        6,
    ));
    let state = FirewallState {
        last_seen_ns: generation,
        age_ns: 0,
        phase: FirewallState::ESTABLISHED,
        reply: 0,
        ..FirewallState::UNTRACKED
    };
    // Asymmetric age must survive storage; it must not be replaced with a
    // shared newest timestamp or broaden the older direction's permission.
    let reverse = FirewallState {
        age_ns: generation,
        ..state.reverse()
    };
    FirewallSession::from_rows((key, state), (key.reverse(), reverse)).unwrap()
}

fn require_records(map: &Sessions, count: u32, generation: u64) -> Result<()> {
    for index in 0..count {
        for policy in [2, 3] {
            let (key, expected) = record(index, policy, generation);
            ensure!(
                map.get(&key, 0)? == expected,
                "lost/changed {index}/{policy}"
            );
            // Validate both logical rows, not just physical occupancy.
            let rows = map.get(&key, 0)?.rows(key);
            ensure!(rows[0].0.reverse() == rows[1].0);
            ensure!(rows == expected.rows(key));
        }
    }
    Ok(())
}

fn capacity_contract() -> Result<serde_json::Value> {
    let mut map = create(CAPACITY)?;
    let id = map.map().info()?.id();
    let mut rows = Vec::new();
    let mut previous = 0;
    for count in [1, 64, 12_000, 15_000, 16_000, 17_000, 20_000, CAPACITY / 2] {
        for index in previous..count {
            for policy in [2, 3] {
                let (key, value) = record(index, policy, 100);
                map.insert(key, value, NOEXIST)?;
            }
        }
        require_records(&map, count, 100)?;
        let actual = map.keys().collect::<Result<Vec<_>, _>>()?.len();
        ensure!(actual == count as usize * 2);
        rows.push(json!({"logical_flows":count,"physical_records":actual,
            "directional_rows_verified":count * 4,"all_values_retained":true}));
        previous = count;
    }
    let (new_key, new_state) = record(CAPACITY / 2, 2, 100);
    let exhausted = map.insert(new_key, new_state, NOEXIST).unwrap_err();
    ensure!(map.get(&new_key, 0).is_err());
    require_records(&map, CAPACITY / 2, 100)?;
    let (existing_key, changed) = record(0, 2, 101);
    ensure!(map.insert(existing_key, changed, NOEXIST).is_err());
    ensure!(map.get(&existing_key, 0)? == record(0, 2, 100).1);
    // Updating an already-owned record in a full HASH does not need to evict
    // another live session. EXIST cannot silently create an absent session.
    map.insert(existing_key, changed, EXIST)?;
    ensure!(map.get(&existing_key, 0)? == changed);
    ensure!(map.insert(new_key, new_state, EXIST).is_err());
    map.insert(existing_key, record(0, 2, 100).1, EXIST)?;
    require_records(&map, CAPACITY / 2, 100)?;
    ensure!(map.map().info()?.id() == id);
    Ok(
        json!({"phases":rows,"map_id":id,"map_type":"HASH","capacity":CAPACITY,
        "overflow_refused":true,"overflow_error":exhausted.to_string(),
        "existing_update_at_capacity":true,"noexist_preserved_owner":true}),
    )
}

fn concurrent_claims() -> Result<serde_json::Value> {
    const WORKERS: usize = 4;
    const KEYS: u32 = 2048;
    let map = create(KEYS)?;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut jobs = Vec::new();
    for writer in 0..WORKERS {
        let mut handle = duplicate(&map)?;
        let barrier = barrier.clone();
        jobs.push(thread::spawn(move || -> Result<u32> {
            let mut won = 0;
            let mut first_error = None;
            for index in 0..KEYS {
                // Rendezvous for EVERY key: no worker can fill the whole map
                // before the others have attempted the first claim.
                barrier.wait();
                let outcome = (|| -> Result<bool> {
                    let (key, value) = record(index, 2, writer as u64 + 1);
                    if handle.insert(key, value, NOEXIST).is_ok() {
                        return Ok(true);
                    }
                    // A rejected claim must observe one complete winner.
                    let observed = handle.get(&key, 0)?;
                    ensure!((1..=WORKERS).any(|w| observed == record(index, 2, w as u64).1));
                    Ok(false)
                })();
                match outcome {
                    Ok(true) => won += 1,
                    Ok(false) => (),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
                // Finish the rendezvous even after an assertion failure, so
                // one error cannot strand other workers at their next barrier.
                barrier.wait();
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            Ok(won)
        }));
    }
    let mut wins = Vec::new();
    for job in jobs {
        wins.push(job.join().expect("claim worker panic")?);
    }
    ensure!(wins.iter().sum::<u32>() == KEYS);
    ensure!(map.keys().collect::<Result<Vec<_>, _>>()?.len() == KEYS as usize);
    for index in 0..KEYS {
        let (key, _) = record(index, 2, 1);
        let value = map.get(&key, 0)?;
        ensure!((1..=WORKERS).any(|writer| value == record(index, 2, writer as u64).1));
    }
    Ok(json!({"workers":WORKERS,"keys":KEYS,"wins":wins,
        "synchronized_claim_rounds":KEYS,"exactly_one_winner_per_key":true}))
}

fn whole_value_observation() -> Result<serde_json::Value> {
    let mut map = create(1)?;
    let (key, a) = record(0, 2, 0xaaaa_aaaa_aaaa_aaaa);
    let (_, b) = record(0, 2, 0x5555_5555_5555_5555);
    map.insert(key, a, NOEXIST)?;
    let mut writer = duplicate(&map)?;
    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = barrier.clone();
    let job = thread::spawn(move || -> Result<()> {
        writer_barrier.wait();
        for iteration in 0..20_000 {
            writer.insert(key, if iteration % 2 == 0 { b } else { a }, EXIST)?;
        }
        Ok(())
    });
    barrier.wait();
    let mut reads = 0;
    let mut versions = [0u32; 2];
    let mut active_reads = 0;
    let result = (|| -> Result<()> {
        while reads < 20_000 || !job.is_finished() {
            let writer_active = !job.is_finished();
            let observed = map.get(&key, 0)?;
            ensure!(
                observed == a || observed == b,
                "torn whole-session observation"
            );
            versions[usize::from(observed == b)] += 1;
            active_reads += u32::from(writer_active);
            reads += 1;
        }
        Ok(())
    })();
    job.join().expect("writer panic")?;
    result?;
    ensure!(
        versions.iter().all(|count| *count > 0) && active_reads > 0,
        "test did not observe both versions and an active writer"
    );
    Ok(json!({"writes":20_000,"reads":reads,"torn_observations":0,
        "version_reads":versions,"reads_while_writer_active":active_reads,
        "scope":"syscall HASH whole-value replacement; not BPF in-place writes or read-modify-write serialization"}))
}

#[test]
#[ignore = "requires disposable root VM with BPF; creates only private unpinned maps"]
fn kernel_session_storage() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root VM required");
    let report = json!({
        "capacity":capacity_contract()?,
        "claims":concurrent_claims()?,
        "whole_value":whole_value_observation()?,
        "scope":"storage contract only; no production map, packet program, HA or release qualification",
    });
    fs::write(
        env::var("VELSTRA_SESSION_RECEIPT")?,
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
