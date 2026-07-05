//! HTTP integration test of the REST/JSON northbound gateway (roadmap D1). Spawns
//! the controller binary in single-mode (a temp topology file) with the gateway
//! enabled and a bearer-token authz policy, then drives it over real HTTP with
//! reqwest: create → list → get → delete for networks, subnets, a security group
//! and a floating IP; the consistent error envelope; an authz rejection for a
//! non-admin mutation; and that mutations land in the audit log. No root, no eBPF.

use std::{
    process::{Child, Command},
    time::Duration,
};

use serde_json::{Value, json};

/// Kills the spawned controller when the test ends (even on panic).
struct Controller(Child);
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const ADMIN_TOKEN: &str = "admin-secret-token";
const NODE_TOKEN: &str = "node-secret-token";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_gateway_crud_authz_and_audit() {
    // Unique temp paths + ports so parallel runs don't collide.
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velstra-rest-test-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let topology = dir.join("topology.toml");
    std::fs::write(&topology, "").unwrap();

    // Spread the three listen ports well apart from the other integration test.
    let base = 40000 + (pid % 8000) as u16;
    let agent_port = base;
    let admin_port = base + 1;
    let rest_port = base + 2;
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
                "--rest-token",
                &format!("ops-admin={ADMIN_TOKEN}"),
                "--rest-token",
                &format!("web-1={NODE_TOKEN}"),
                "--admin-cn",
                "ops-admin",
            ])
            .spawn()
            .expect("spawn controller"),
    );

    let http = reqwest::Client::new();

    // Wait for the gateway to bind (retry /healthz).
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
    assert!(up, "REST gateway never came up");

    // --- /version is unversioned and open -----------------------------------
    let version: Value = http
        .get(format!("{rest}/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(version["api"], "v1");
    assert_eq!(version["name"], "velstra-controller");

    let admin = |req: reqwest::RequestBuilder| req.bearer_auth(ADMIN_TOKEN);
    let node = |req: reqwest::RequestBuilder| req.bearer_auth(NODE_TOKEN);

    // --- Networks: create → list → get → delete -----------------------------
    let resp = admin(http.post(format!("{rest}/v1/networks")))
        .json(
            &json!({ "vni": 100, "name": "tenant-a", "subnet": "10.50.0.0/24", "drop_icmp": true }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "network create should be 201");
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["vni"], 100);
    assert_eq!(created["name"], "tenant-a");
    assert_eq!(created["subnet"], "10.50.0.0/24");
    assert_eq!(created["drop_icmp"], true);

    let list: Vec<Value> = http
        .get(format!("{rest}/v1/networks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["vni"], 100);

    let got: Value = http
        .get(format!("{rest}/v1/networks/100"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got["name"], "tenant-a");

    // A missing network returns the consistent error envelope with 404.
    let missing = http
        .get(format!("{rest}/v1/networks/999"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let env: Value = missing.json().await.unwrap();
    assert_eq!(env["status"], 404);
    assert!(
        env["message"].as_str().unwrap().contains("999"),
        "error envelope carries a message: {env}"
    );

    // --- AuthZ: a non-admin (node) token may NOT define a network -----------
    let denied = node(http.post(format!("{rest}/v1/networks")))
        .json(&json!({ "vni": 200, "name": "nope", "subnet": "10.60.0.0/24" }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403, "node token must be forbidden");
    let denied_env: Value = denied.json().await.unwrap();
    assert_eq!(denied_env["status"], 403);

    // An anonymous (no token) mutation is likewise rejected.
    let anon = http
        .post(format!("{rest}/v1/networks"))
        .json(&json!({ "vni": 201, "name": "nope", "subnet": "10.61.0.0/24" }))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 403, "anonymous mutation must be forbidden");

    // …a node token CAN register its own host (host-scoped authz)…
    let host = node(http.post(format!("{rest}/v1/hosts")))
        .json(&json!({
            "id": "web-1",
            "vtep": "192.168.1.10",
            "underlay_iface": "eth0",
            "underlay_mac": "02:00:00:00:00:01"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(host.status(), 201, "node registers its own host");
    let host: Value = host.json().await.unwrap();
    assert_eq!(host["id"], "web-1");
    assert_eq!(host["vtep"], "192.168.1.10");
    assert_eq!(host["encap"], "vxlan");

    // …but NOT a different host (host-scoped authz).
    let other_host = node(http.post(format!("{rest}/v1/hosts")))
        .json(&json!({
            "id": "db-9",
            "vtep": "192.168.1.20",
            "underlay_iface": "eth0",
            "underlay_mac": "02:00:00:00:00:02"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_host.status(),
        403,
        "node cannot register another host"
    );

    // …and CAN create a port on its own host (host-scoped authz).
    let port: Value = node(http.post(format!("{rest}/v1/ports")))
        .json(&json!({ "network": 100, "host": "web-1", "tap": "tap0" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let port_id = port["id"].as_str().unwrap().to_string();
    assert_eq!(port["vni"], 100);
    assert_eq!(port["host"], "web-1");
    assert!(!port["ip"].as_str().unwrap().is_empty(), "port got an IP");

    // A node token creating a port on ANOTHER host is forbidden.
    let cross = node(http.post(format!("{rest}/v1/ports")))
        .json(&json!({ "network": 100, "host": "db-9", "tap": "tap1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cross.status(),
        403,
        "cross-host port create must be forbidden"
    );

    // --- Subnets: create → get → delete -------------------------------------
    let subnet = admin(http.post(format!("{rest}/v1/subnets")))
        .json(&json!({ "id": "sub-a", "vni": 100, "cidr": "10.50.0.0/24" }))
        .send()
        .await
        .unwrap();
    assert_eq!(subnet.status(), 201);
    let subnet: Value = subnet.json().await.unwrap();
    assert_eq!(subnet["id"], "sub-a");
    assert_eq!(subnet["cidr"], "10.50.0.0/24");

    let got_subnet: Value = http
        .get(format!("{rest}/v1/subnets/sub-a"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got_subnet["vni"], 100);

    // --- Security group: create → get ---------------------------------------
    let sg = admin(http.post(format!("{rest}/v1/security-groups")))
        .json(&json!({
            "name": "web",
            "default_action": "drop",
            "stateful": true,
            "rules": [ { "proto": "tcp", "port": 443, "action": "pass" } ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(sg.status(), 201);
    let sg: Value = sg.json().await.unwrap();
    assert_eq!(sg["name"], "web");
    assert_eq!(sg["default_action"], "drop");
    assert_eq!(sg["stateful"], true);
    assert_eq!(sg["rules"][0]["proto"], "tcp");
    assert_eq!(sg["rules"][0]["port"], 443);

    let sgs: Vec<Value> = http
        .get(format!("{rest}/v1/security-groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(sgs.iter().any(|g| g["name"] == "web"));

    // --- Floating IP: allocate (from a floating subnet) → get → release ------
    admin(http.post(format!("{rest}/v1/subnets")))
        .json(&json!({ "id": "fip-pool", "vni": 100, "cidr": "192.0.2.0/24" }))
        .send()
        .await
        .unwrap();
    let fip = admin(http.post(format!("{rest}/v1/floating-ips")))
        .json(&json!({ "subnet_id": "fip-pool" }))
        .send()
        .await
        .unwrap();
    assert_eq!(fip.status(), 201);
    let fip: Value = fip.json().await.unwrap();
    let fip_id = fip["id"].as_str().unwrap().to_string();
    assert_eq!(fip["subnet_id"], "fip-pool");
    assert!(!fip["addr"].as_str().unwrap().is_empty());

    let fips: Vec<Value> = http
        .get(format!("{rest}/v1/floating-ips"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(fips.iter().any(|f| f["id"] == fip_id.as_str()));

    let released = admin(http.delete(format!("{rest}/v1/floating-ips/{fip_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), 200);
    assert_eq!(released.json::<Value>().await.unwrap()["deleted"], true);

    // --- Delete network (still referenced by the port) → 409 conflict -------
    let busy = admin(http.delete(format!("{rest}/v1/networks/100")))
        .send()
        .await
        .unwrap();
    assert_eq!(busy.status(), 409, "network in use should conflict");
    assert_eq!(busy.json::<Value>().await.unwrap()["status"], 409);

    // Remove the port (admin-only), then the network deletes cleanly.
    let del_port = admin(http.delete(format!("{rest}/v1/ports/{port_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(del_port.status(), 200);
    assert_eq!(del_port.json::<Value>().await.unwrap()["deleted"], true);

    // The subnet must go before the network it belongs to.
    admin(http.delete(format!("{rest}/v1/subnets/sub-a")))
        .send()
        .await
        .unwrap();
    admin(http.delete(format!("{rest}/v1/subnets/fip-pool")))
        .send()
        .await
        .unwrap();
    let del_net = admin(http.delete(format!("{rest}/v1/networks/100")))
        .send()
        .await
        .unwrap();
    assert_eq!(del_net.status(), 200);
    assert_eq!(del_net.json::<Value>().await.unwrap()["deleted"], true);

    let empty: Vec<Value> = http
        .get(format!("{rest}/v1/networks"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(empty.is_empty(), "network list empty after delete");

    // A node can deregister its own host (host-scoped delete).
    let del_host = node(http.delete(format!("{rest}/v1/hosts/web-1")))
        .send()
        .await
        .unwrap();
    assert_eq!(del_host.status(), 200);
    assert_eq!(del_host.json::<Value>().await.unwrap()["deleted"], true);
    let hosts: Vec<Value> = http
        .get(format!("{rest}/v1/hosts"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(hosts.is_empty(), "host list empty after delete");

    // --- Audit log: mutations were recorded with actor + operation ----------
    let audit: Vec<Value> = http
        .get(format!("{rest}/v1/audit"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!audit.is_empty(), "audit log recorded mutations");

    // The successful network create is present, attributed to the admin CN.
    let net_create = audit
        .iter()
        .find(|e| e["operation"] == "network.create" && e["result"] == "ok")
        .expect("network.create audited");
    assert_eq!(net_create["actor"], "ops-admin");
    assert!(net_create["target"].as_str().unwrap().contains("100"));
    assert!(net_create["ts_millis"].as_u64().unwrap() > 0);

    // The denied node mutation is audited as a denial.
    assert!(
        audit
            .iter()
            .any(|e| e["operation"] == "network.create" && e["result"] == "denied"),
        "denied mutation audited"
    );

    // The port created by the node token is attributed to that CN.
    assert!(
        audit
            .iter()
            .any(|e| e["operation"] == "port.create" && e["actor"] == "web-1"),
        "node-created port audited to its CN"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
