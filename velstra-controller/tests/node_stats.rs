//! A node's counters survive being reported.
//!
//! They used to reach `info!` and stop there: agents report on a timer over
//! `ReportStats`, the controller formatted the non-zero ones into a log line,
//! and nothing kept them. So there was a whole reporting channel, exercised on
//! every node every few seconds, and no way to *ask* a running fabric anything
//! at all — which is what the observability item on the roadmap actually was.
//!
//! This test reports as a node would and then asks, over the two surfaces a
//! reader has: the admin gRPC API and the REST gateway.

use std::{
    process::{Child, Command},
    time::Duration,
};

use serde_json::Value;
use velstra_proto::{Counter, GetStatsRequest, StatsReport};

struct Controller(Child);
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const NODE: &str = "edge-7";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nodes_counters_can_be_asked_for_after_it_reports_them() {
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velstra-stats-test-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let topology = dir.join("topology.toml");
    std::fs::write(&topology, "").unwrap();

    // Its own band, clear of the other integration tests in this crate.
    let base = 32000 + (pid % 6000) as u16;
    let (agent_port, admin_port, rest_port) = (base, base + 1, base + 2);
    let rest = format!("http://127.0.0.1:{rest_port}");

    let _controller = Controller(
        Command::new(env!("CARGO_BIN_EXE_velstra-controller"))
            .args([
                "serve",
                "--listen",
                &format!("127.0.0.1:{agent_port}"),
                "--admin-listen",
                &format!("127.0.0.1:{admin_port}"),
                "--topology",
                topology.to_str().unwrap(),
                "--rest-listen",
                &format!("127.0.0.1:{rest_port}"),
            ])
            .spawn()
            .expect("spawn controller"),
    );

    let http = reqwest::Client::new();
    let mut up = false;
    for _ in 0..50 {
        if let Ok(resp) = http.get(format!("{rest}/healthz")).send().await
            && resp.status().is_success()
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "the gateway never came up");

    // Nothing has reported, so there is nothing to see. Asserted first, so the
    // assertions below cannot pass on state that was already there.
    let empty: Value = http
        .get(format!("{rest}/v1/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty.as_array().map(|a| a.len()), Some(0), "{empty}");

    // Report as the node would.
    let mut agent = velstra_proto::velstra_control_client::VelstraControlClient::connect(format!(
        "http://127.0.0.1:{agent_port}"
    ))
    .await
    .expect("the agent-facing channel");
    agent
        .report_stats(StatsReport {
            node_id: NODE.into(),
            counters: vec![
                Counter {
                    name: "xdp_pass".into(),
                    value: 4210,
                },
                Counter {
                    name: "xdp_drop".into(),
                    value: 17,
                },
                // Zero is reported and must be *kept*: "this counter exists and
                // has not fired" is a different answer from "this counter is not
                // there", and only the first one tells a reader the data plane
                // is loaded.
                Counter {
                    name: "conntrack_evict".into(),
                    value: 0,
                },
            ],
        })
        .await
        .expect("reporting stats");

    // Ask over REST.
    let seen: Value = http
        .get(format!("{rest}/v1/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = seen.as_array().expect("an array");
    assert_eq!(rows.len(), 1, "{seen}");
    assert_eq!(rows[0]["node_id"], NODE);
    assert_eq!(rows[0]["counters"]["xdp_pass"], 4210);
    assert_eq!(rows[0]["counters"]["xdp_drop"], 17);
    assert_eq!(
        rows[0]["counters"]["conntrack_evict"], 0,
        "a zero counter was dropped, so a loaded data plane reads as an absent one"
    );
    assert!(
        rows[0]["reported_at_ms"].as_u64().unwrap_or(0) > 0,
        "no timestamp, so a quiet node cannot be told from a dead one: {seen}"
    );

    // And one node by name.
    let one: Value = http
        .get(format!("{rest}/v1/stats/{NODE}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one["counters"]["xdp_pass"], 4210);

    // A node nobody has heard from is a 404 that says which question it
    // answered, not an empty object that reads like a healthy silent node.
    let missing = http
        .get(format!("{rest}/v1/stats/never-seen"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let body: Value = missing.json().await.unwrap();
    assert!(
        body["message"].as_str().unwrap_or("").contains("reported"),
        "{body}"
    );

    // Ask over the admin gRPC API, which is the surface the cloud would use.
    let mut admin = velstra_proto::velstra_admin_client::VelstraAdminClient::connect(format!(
        "http://127.0.0.1:{admin_port}"
    ))
    .await
    .expect("the admin channel");
    let all = admin
        .get_stats(GetStatsRequest {
            node_id: String::new(),
        })
        .await
        .expect("asking for every node's stats")
        .into_inner();
    assert_eq!(all.nodes.len(), 1);
    assert_eq!(all.nodes[0].node_id, NODE);
    assert_eq!(all.nodes[0].counters.len(), 3);

    // A node replaces its own entry rather than appending: this is "what is it
    // doing now", and a controller that accumulated a history in memory is a
    // controller that eventually stops.
    agent
        .report_stats(StatsReport {
            node_id: NODE.into(),
            counters: vec![Counter {
                name: "xdp_pass".into(),
                value: 9999,
            }],
        })
        .await
        .expect("reporting again");
    let again = admin
        .get_stats(GetStatsRequest {
            node_id: NODE.into(),
        })
        .await
        .expect("asking again")
        .into_inner();
    assert_eq!(again.nodes.len(), 1, "a second report made a second node");
    assert_eq!(
        again.nodes[0].counters.len(),
        1,
        "the previous report's counters outlived it"
    );
    assert_eq!(again.nodes[0].counters[0].value, 9999);
}
