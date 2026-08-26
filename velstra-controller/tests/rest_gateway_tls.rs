//! HTTPS integration test of the REST/JSON northbound gateway. The controller
//! serves the gateway over TLS — reusing the agent-channel `--tls-cert`/
//! `--tls-key` — and a client that trusts the test CA completes a *real*
//! handshake (not accept-invalid) and drives the API; a plaintext client against
//! the same port is refused. This is the proof the northbound wire is no longer
//! plaintext when certs are configured. No root, no eBPF.

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

/// Absolute path to a bundled test PEM fixture (CA + server cert/key).
fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_gateway_serves_https() {
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("velstra-rest-tls-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let topology = dir.join("topology.toml");
    std::fs::write(&topology, "").unwrap();

    // A port band distinct from the plaintext gateway test so the two can run in
    // parallel without colliding.
    let base = 41000 + (pid % 8000) as u16;
    let agent_port = base;
    let admin_port = base + 1;
    let rest_port = base + 2;
    // The server cert's SANs cover `localhost` and 127.0.0.1, so dial by name.
    let rest = format!("https://localhost:{rest_port}");

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
                "ops-admin=admin-secret-token",
                "--admin-cn",
                "ops-admin",
                // Reusing the agent-channel certs turns the gateway to HTTPS.
                "--tls-cert",
                &fixture("server.pem"),
                "--tls-key",
                &fixture("server.key"),
            ])
            .spawn()
            .expect("spawn controller"),
    );

    // A client that trusts the test CA — a genuine handshake, so a broken TLS
    // path fails the test rather than being waved through.
    let ca = reqwest::Certificate::from_pem(&std::fs::read(fixture("ca.pem")).unwrap())
        .expect("parse test CA");
    let http = reqwest::Client::builder()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Wait for the gateway to bind (retry the HTTPS probe).
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
    assert!(up, "HTTPS REST gateway never came up");

    // A create over TLS proves the JSON + authz path works end to end on the
    // secure wire, not just the health probe.
    let resp = http
        .post(format!("{rest}/v1/networks"))
        .bearer_auth("admin-secret-token")
        .json(&json!({ "vni": 100, "name": "tls-tenant", "subnet": "10.70.0.0/24" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "network create over https should be 201"
    );
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["vni"], 100);
    assert_eq!(created["name"], "tls-tenant");

    // A plaintext HTTP client against the TLS port must NOT get through — the
    // handshake it never performs is exactly the confidentiality guarantee.
    let plain = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let plain_res = plain
        .get(format!("http://localhost:{rest_port}/healthz"))
        .send()
        .await;
    assert!(
        plain_res.is_err(),
        "plaintext http against the TLS port must fail, got {plain_res:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
