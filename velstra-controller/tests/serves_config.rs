//! End-to-end test of the controller over a real gRPC connection (no root, no
//! eBPF): spawn the controller binary pointed at a temp config dir, connect with
//! the generated client, and check it serves the right config — including a live
//! update when the file changes.

use std::{
    process::{Child, Command},
    time::Duration,
};

use velstra_proto::{
    ListNodesRequest, NodeConfig, NodeRequest, Proto, Service, SetConfigRequest,
    velstra_admin_client::VelstraAdminClient, velstra_control_client::VelstraControlClient,
};

/// Kills the spawned controller when the test ends (even on panic).
struct Controller(Child);
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_serves_and_updates_config() {
    // A unique temp dir + port so parallel test runs don't collide.
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velstra-ctl-test-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = 49152 + (pid % 8000) as u16;
    let admin_port = port + 1;
    let endpoint = format!("http://127.0.0.1:{port}");
    let admin_endpoint = format!("http://127.0.0.1:{admin_port}");

    std::fs::write(
        dir.join("node-a.toml"),
        r#"
            default_action = "drop"
            [[policy]]
            id = 5
            name = "tenant"
            default_action = "pass"
            [[interface]]
            name = "lo"
            policy = 5
            [[service]]
            vip = "10.0.0.100"
            port = 80
            proto = "tcp"
            backends = [{ ip = "10.0.1.2", port = 8080 }]
        "#,
    )
    .unwrap();

    let _controller = Controller(
        Command::new(env!("CARGO_BIN_EXE_velstra-controller"))
            .args([
                "serve",
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--admin-listen",
                &format!("127.0.0.1:{admin_port}"),
                "--config-dir",
                dir.to_str().unwrap(),
                "--poll-interval",
                "1",
            ])
            .spawn()
            .expect("spawn controller"),
    );

    // The server takes a moment to bind; retry the initial connect.
    let mut client = None;
    for _ in 0..50 {
        if let Ok(c) = VelstraControlClient::connect(endpoint.clone()).await {
            client = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut client = client.expect("controller never came up");

    // GetConfig returns the node's served policy.
    let cfg = client
        .get_config(NodeRequest {
            node_id: "node-a".into(),
        })
        .await
        .expect("GetConfig")
        .into_inner();
    assert_eq!(cfg.default_action(), velstra_proto::Action::Drop);
    // The controller distributes the tenant policy + interface assignment.
    assert_eq!(cfg.policies.len(), 1);
    assert_eq!(cfg.policies[0].id, 5);
    assert_eq!(
        cfg.policies[0].default_action(),
        velstra_proto::Action::Pass
    );
    assert_eq!(cfg.interfaces.len(), 1);
    assert_eq!(cfg.interfaces[0].name, "lo");
    assert_eq!(cfg.interfaces[0].policy, 5);
    assert_eq!(cfg.services.len(), 1);
    assert_eq!(cfg.services[0].port, 80);
    assert_eq!(cfg.services[0].proto(), Proto::Tcp);
    assert_eq!(cfg.services[0].backends[0].ip, "10.0.1.2");
    let first_version = cfg.version;

    // An unknown node gets the fail-open default (empty config).
    let unknown = client
        .get_config(NodeRequest {
            node_id: "nope".into(),
        })
        .await
        .expect("GetConfig")
        .into_inner();
    assert_eq!(unknown.default_action(), velstra_proto::Action::Pass);
    assert!(unknown.services.is_empty());

    // Change the file; WatchConfig must push a new version.
    std::fs::write(
        dir.join("node-a.toml"),
        r#"
            default_action = "pass"
            blocklist = ["10.0.0.0/8"]
        "#,
    )
    .unwrap();

    let mut stream = client
        .watch_config(NodeRequest {
            node_id: "node-a".into(),
        })
        .await
        .expect("WatchConfig")
        .into_inner();

    // Drain until we observe the updated config (version bumped, new content).
    let mut saw_update = false;
    for _ in 0..50 {
        if let Ok(Ok(Some(msg))) =
            tokio::time::timeout(Duration::from_millis(500), stream.message()).await
            && msg.version > first_version
            && msg.blocklist == ["10.0.0.0/8"]
        {
            assert_eq!(msg.default_action(), velstra_proto::Action::Pass);
            saw_update = true;
            break;
        }
    }
    assert!(saw_update, "controller never pushed the updated config");

    // --- Admin API: push a runtime override for a brand-new node ------------
    let mut admin = VelstraAdminClient::connect(admin_endpoint)
        .await
        .expect("connect admin");

    let pushed = NodeConfig {
        default_action: velstra_proto::Action::Drop as i32,
        services: vec![Service {
            vip: "192.0.2.1".into(),
            port: 443,
            proto: Proto::Tcp as i32,
            backends: vec![velstra_proto::Backend {
                ip: "10.9.9.9".into(),
                port: 8443,
            }],
            policy: 0,
        }],
        ..Default::default()
    };
    let ack = admin
        .set_config(SetConfigRequest {
            node_id: "node-b".into(),
            config: Some(pushed),
        })
        .await
        .expect("SetConfig")
        .into_inner();
    assert!(ack.ok);

    // The agent-facing GetConfig now serves the admin-pushed config.
    let served = client
        .get_config(NodeRequest {
            node_id: "node-b".into(),
        })
        .await
        .expect("GetConfig")
        .into_inner();
    assert_eq!(served.default_action(), velstra_proto::Action::Drop);
    assert_eq!(served.services[0].vip, "192.0.2.1");
    assert!(served.version > 0);

    // ListNodes marks node-b as admin-sourced.
    let list = admin
        .list_nodes(ListNodesRequest {})
        .await
        .expect("ListNodes")
        .into_inner();
    let summary = list.nodes.iter().find(|n| n.node_id == "node-b").unwrap();
    assert!(summary.from_admin);

    // Deleting the override reverts node-b to the fail-open default.
    admin
        .delete_config(NodeRequest {
            node_id: "node-b".into(),
        })
        .await
        .expect("DeleteConfig");
    let reverted = client
        .get_config(NodeRequest {
            node_id: "node-b".into(),
        })
        .await
        .expect("GetConfig")
        .into_inner();
    assert_eq!(reverted.default_action(), velstra_proto::Action::Pass);
    assert!(reverted.services.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
