//! A real three-controller Raft cluster exposes the current write leader.

use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use tonic::transport::Endpoint;
use velstra_proto::{
    Action, LeaderRequest, NetworkSpec, velstra_orchestrator_client::VelstraOrchestratorClient,
};

struct Controller(Child);
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_ports() -> [u16; 9] {
    let sockets: Vec<_> = (0..9)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports = std::array::from_fn(|i| sockets[i].local_addr().unwrap().port());
    drop(sockets);
    ports
}

async fn client(port: u16) -> Option<VelstraOrchestratorClient<tonic::transport::Channel>> {
    Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(1))
        .connect()
        .await
        .ok()
        .map(VelstraOrchestratorClient::new)
}

async fn leader(admin: &[u16; 3], excluded: Option<usize>) -> usize {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let mut leaders = Vec::new();
        for (i, port) in admin.iter().enumerate() {
            if excluded == Some(i) {
                continue;
            }
            if let Some(mut client) = client(*port).await
                && let Ok(answer) = client.get_leader(LeaderRequest {}).await
                && answer.get_ref().leader
            {
                leaders.push(i);
            }
        }
        if leaders.len() == 1 {
            return leaders[0];
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the fabric cluster did not elect exactly one reachable write leader");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_probe_tracks_election_and_failover() {
    let ports = free_ports();
    let raft = [ports[0], ports[1], ports[2]];
    let agent = [ports[3], ports[4], ports[5]];
    let admin = [ports[6], ports[7], ports[8]];
    let mut children = Vec::new();
    // Start followers before the bootstrap node so all peer listeners exist.
    for i in [1, 2, 0] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_velstra-controller"));
        command
            .args([
                "serve",
                "--node-id",
                &(i + 1).to_string(),
                "--raft-listen",
                &format!("127.0.0.1:{}", raft[i]),
                "--listen",
                &format!("127.0.0.1:{}", agent[i]),
                "--admin-listen",
                &format!("127.0.0.1:{}", admin[i]),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if i == 0 {
            command.arg("--bootstrap");
            for (n, port) in raft.iter().enumerate() {
                command.args(["--peer", &format!("{}=127.0.0.1:{port}", n + 1)]);
            }
        }
        children.push((
            i,
            Controller(command.spawn().expect("spawn fabric controller")),
        ));
    }

    let first = leader(&admin, None).await;
    let follower = (0..3).find(|i| *i != first).unwrap();
    let mut follower_client = client(admin[follower]).await.unwrap();
    let refusal = follower_client
        .add_network(NetworkSpec {
            vni: 3001,
            name: "before-failover".into(),
            subnet: "10.31.0.0/24".into(),
            default_action: Action::Drop as i32,
            drop_icmp: false,
        })
        .await
        .unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::FailedPrecondition);

    let (_, mut failed) = children.remove(children.iter().position(|(i, _)| *i == first).unwrap());
    failed.0.kill().unwrap();
    failed.0.wait().unwrap();
    let next = leader(&admin, Some(first)).await;
    assert_ne!(next, first);
    let mut leader_client = client(admin[next]).await.unwrap();
    leader_client
        .add_network(NetworkSpec {
            vni: 3002,
            name: "after-failover".into(),
            subnet: "10.32.0.0/24".into(),
            default_action: Action::Drop as i32,
            drop_icmp: false,
        })
        .await
        .expect("new leader accepts a write");
}
