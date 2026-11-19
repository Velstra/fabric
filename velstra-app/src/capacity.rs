//! Connection-state table capacity and occupancy (DP-06).
//!
//! Sizes come from the load-time sizing (`state_tables`); occupancy comes from
//! the background collector's last complete walk of each table (`reclaim`),
//! which reads every entry anyway. An occupancy is an observation over a walk,
//! not an atomic snapshot, and it counts expired entries until they are
//! reclaimed. A table that has not been walked recently is `unknown`, never
//! reported healthy.

use std::{sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{
    firewall::Firewall,
    reclaim::{self, TableObservation},
    state_tables::{self, HIGH_WATER_PERCENT},
};

/// The capacity report the `capacity` query answers with.
pub async fn query(firewall: Arc<Mutex<Firewall>>) -> Value {
    let (sizing, adopted) = firewall.lock().await.state_tables();
    report(sizing, adopted, reclaim::snapshot())
}

fn report(
    sizing: state_tables::Sizing,
    adopted: bool,
    tables: Vec<(TableObservation, Option<Duration>)>,
) -> Value {
    let maps: Vec<Value> = sizing
        .maps()
        .iter()
        .map(|(name, max)| {
            let observed = tables.iter().find(|(t, _)| t.name == *name);
            row(name, *max, observed)
        })
        .collect();
    let status = if maps.iter().any(|m| m["status"] == "unknown") {
        "unknown"
    } else if maps.iter().any(|m| m["status"] == "warning") {
        "warning"
    } else {
        "observed-below-threshold"
    };
    json!({
        "version": 2,
        "threshold_percent": HIGH_WATER_PERCENT,
        "measurement": "background walk of each table; entries include expired state until reclaimed",
        "atomic_snapshot": false,
        "connections_sized_for": sizing.connections,
        "committed_bytes": sizing.committed_bytes(),
        "state_adopted_from_previous_agent": adopted,
        "status": status,
        "maps": maps,
    })
}

fn row(name: &str, max: u32, observed: Option<&(TableObservation, Option<Duration>)>) -> Value {
    let mut row = json!({
        "name": name,
        "max_entries": max,
        "observed_entries": null,
        "utilization_percent": null,
        "reclaimed_expired": null,
        "age_ms": null,
        "status": "unknown",
        "error": "not yet walked",
    });
    let Some((table, age)) = observed else {
        return row;
    };
    row["reclaimed_expired"] = json!(table.reclaimed_expired);
    row["age_ms"] = age.map_or(Value::Null, |age| json!(age.as_millis() as u64));
    row["error"] = json!(table.last_error);
    let Some(entries) = table.observed_entries else {
        return row;
    };
    if reclaim::is_stale(*age) {
        row["error"] = json!("occupancy observation is stale");
        return row;
    }
    row["observed_entries"] = json!(entries);
    row["utilization_percent"] = json!(entries as f64 * 100.0 / f64::from(max.max(1)));
    row["status"] = json!(if state_tables::past_high_water(entries, u64::from(max)) {
        "warning"
    } else {
        "observed-below-threshold"
    });
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(
        name: &'static str,
        max: u32,
        entries: Option<u64>,
        age: u64,
    ) -> (TableObservation, Option<Duration>) {
        let table = TableObservation {
            name,
            max_entries: max,
            observed_entries: entries,
            reclaimed_expired: 0,
            passes: u64::from(entries.is_some()),
            completed_at: None,
            last_error: None,
        };
        (table, Some(Duration::from_secs(age)))
    }

    #[test]
    fn the_report_names_the_resized_capacity_and_the_high_water_mark() {
        let sizing = state_tables::Sizing::for_connections(100_000);
        let tables = vec![
            observed("FW_FLOWS", sizing.fw_flows, Some(480_000), 1),
            observed("CONNTRACK", sizing.conntrack, Some(10), 1),
            observed("SYN_FLOWS", sizing.syn_flows, Some(0), 1),
        ];
        let value = report(sizing, true, tables);
        assert_eq!(value["connections_sized_for"], 100_000);
        assert_eq!(value["state_adopted_from_previous_agent"], true);
        assert_eq!(value["maps"][0]["max_entries"], 600_000);
        assert_eq!(value["maps"][0]["status"], "warning");
        assert_eq!(value["maps"][1]["status"], "observed-below-threshold");
        assert_eq!(value["status"], "warning");
    }

    #[test]
    fn an_unwalked_or_stale_table_is_unknown_never_healthy() {
        let sizing = state_tables::Sizing::for_connections(16_384);
        let tables = vec![
            observed("FW_FLOWS", sizing.fw_flows, None, 1),
            observed("CONNTRACK", sizing.conntrack, Some(1), 3600),
        ];
        let value = report(sizing, false, tables);
        for map in value["maps"].as_array().unwrap() {
            assert_eq!(map["status"], "unknown", "{map}");
        }
        assert_eq!(value["status"], "unknown");
    }
}
