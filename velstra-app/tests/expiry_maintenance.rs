//! Real small HASH-map expiry checks. Not a packet/HA/retention qualification.
use std::{env, fs, os::fd::AsFd};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, HashMap, Map, MapData},
};
use velstra_common::{CONFIG_READY, ConntrackTimeouts, FirewallKey, FirewallState, FlowKey};

#[path = "../src/btf.rs"]
mod btf;
#[path = "../src/expiry.rs"]
mod expiry;

fn drain() -> Result<()> {
    // SAFETY: membarrier accepts integer arguments, with no pointers.
    ensure!(
        unsafe { libc::syscall(libc::SYS_membarrier, libc::MEMBARRIER_CMD_GLOBAL, 0, 0) } == 0,
        "kernel reader barrier failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[test]
#[ignore = "requires root, BPF, and an explicitly supplied HASH4 instrumented object"]
fn kernel_expiry_maintenance() -> Result<()> {
    let path = env::var("VELSTRA_EXPIRY_OBJECT")?;
    let bytes = fs::read(path)?;
    let mut ebpf = Ebpf::load(&btf::kernel_object(&bytes)?)?;
    let Map::HashMap(data) = ebpf.map("FW_FLOWS").context("FW_FLOWS missing")? else {
        anyhow::bail!(
            "test requires non-LRU HASH4, never silently substitute a production LRU map"
        );
    };
    ensure!(data.info()?.max_entries() == 4);
    let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
    let mut map = HashMap::<_, FirewallKey, FirewallState>::try_from(Map::HashMap(duplicate))?;
    Array::<_, u32>::try_from(ebpf.map_mut("APPLY_STATE").unwrap())?.set(0, CONFIG_READY, 0)?;
    Array::<_, u64>::try_from(ebpf.map_mut("CONFIG_EPOCH").unwrap())?.set(0, 2, 0)?;
    let eligibility = expiry::Eligibility {
        ha: false,
        replication: false,
        current_intent: true,
    };
    let keys: Vec<_> = (0..5)
        .map(|i| {
            FirewallKey::ipv4(FlowKey::new(
                2,
                [192, 0, 2, 7],
                [198, 51, 100, 8],
                41000 + i,
                9000,
                6,
            ))
        })
        .collect();
    // Future timestamps conservatively represent current activity. This test
    // needs no sleeps and never expires a live record because its clock is ahead.
    let live = FirewallState {
        last_seen_ns: u64::MAX,
        age_ns: 0,
        phase: FirewallState::ESTABLISHED,
        reply: 0,
        ..FirewallState::UNTRACKED
    };
    let expired = FirewallState {
        last_seen_ns: 0,
        age_ns: u64::MAX,
        phase: FirewallState::NEW,
        reply: 1,
        ..FirewallState::UNTRACKED
    };
    let mut rows = Vec::new();
    for cycle in 0..16 {
        for key in map.keys().collect::<Result<Vec<_>, _>>()? {
            map.remove(&key)?;
        }
        for key in &keys[..4] {
            map.insert(key, live, 0)?;
        }
        ensure!(
            map.insert(keys[4], live, 1).is_err(),
            "full HASH must refuse a new owner"
        );
        let full = expiry::collect(
            &mut ebpf,
            &mut map,
            eligibility,
            4,
            |k, v, now| v.expired(k.proto, now, ConntrackTimeouts::DEFAULT),
            drain,
        )?;
        ensure!(full.removed == 0 && full.examined == 4 && full.scan_complete);
        for key in &keys[..4] {
            ensure!(map.get(key, 0)? == live);
        }
        map.insert(keys[0], expired, 0)?;
        // Reverse key need not be present in the candidate set. Its live state
        // is independent and must never be deleted by pair-shaped cleanup.
        map.remove(&keys[1])?;
        map.insert(keys[0].reverse(), live, 0)?;
        let reclaimed = expiry::collect(
            &mut ebpf,
            &mut map,
            eligibility,
            4,
            |k, v, now| v.expired(k.proto, now, ConntrackTimeouts::DEFAULT),
            drain,
        )?;
        ensure!(reclaimed.removed == 1 && reclaimed.scan_complete);
        ensure!(map.get(&keys[0], 0).is_err());
        ensure!(map.get(&keys[0].reverse(), 0)? == live);
        ensure!(map.get(&keys[2], 0)? == live && map.get(&keys[3], 0)? == live);
        map.insert(keys[4], live, 1)?;
        let limited = expiry::collect(
            &mut ebpf,
            &mut map,
            eligibility,
            1,
            |k, v, now| v.expired(k.proto, now, ConntrackTimeouts::DEFAULT),
            drain,
        )?;
        ensure!(limited.examined == 1 && !limited.scan_complete && limited.removed == 0);
        rows.push(
            serde_json::json!({"cycle":cycle,"full":full,"reclaimed":reclaimed,"limited":limited}),
        );
    }
    let gate = Array::<_, u32>::try_from(ebpf.map("APPLY_STATE").unwrap())?.get(&0, 0)?;
    ensure!(gate == CONFIG_READY);
    let receipt = serde_json::json!({"cycles":rows,"map_type":"HASH","map_capacity":4,
        "scope":"real kernel map and reader-barrier operations; no packet attachment or HA claim"});
    fs::write(
        env::var("VELSTRA_EXPIRY_RECEIPT")?,
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(())
}
