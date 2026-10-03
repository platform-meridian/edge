use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use edge_cni::netlink::Net;

mod common;

const PODS: usize = 8;
const TRIALS: usize = 5;
const CONF: &str = r#"{"cniVersion":"1.0.0","name":"edge","podCIDR":"10.244.0.0/24"}"#;

fn spawn_sandbox() -> Child {
    let child = Command::new("unshare")
        .args(["-n", "sleep", "30"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let own = std::fs::read_link("/proc/self/ns/net").unwrap();
    let theirs = format!("/proc/{}/ns/net", child.id());
    let start = Instant::now();
    while std::fs::read_link(&theirs).is_ok_and(|ns| ns == own) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sandbox never unshared"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child
}

fn start_add(pin_base: &Path, container_id: &str, sandbox: &Child) -> Child {
    let mut add = Command::new(env!("CARGO_BIN_EXE_edge-cni"))
        .env("CNI_COMMAND", "ADD")
        .env("CNI_CONTAINERID", container_id)
        .env("CNI_NETNS", format!("/proc/{}/ns/net", sandbox.id()))
        .env("CNI_IFNAME", "eth0")
        .env("CNI_PATH", "/nonexistent")
        .env("EDGE_CNI_PIN_BASE", pin_base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    add.stdin
        .take()
        .unwrap()
        .write_all(CONF.as_bytes())
        .unwrap();
    add
}

fn race() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { Net::open().unwrap().set_up("lo").await.unwrap() });

    // ADD waits for a synced dataplane in bpffs; a marker directory stands in.
    let tmp = tempfile::tempdir().unwrap();
    let pin_base = tmp.path();
    std::fs::create_dir_all(pin_base.join("test/synced")).unwrap();

    for trial in 0..TRIALS {
        let mut sandboxes: Vec<Child> = (0..PODS).map(|_| spawn_sandbox()).collect();
        let adds: Vec<Child> = sandboxes
            .iter()
            .enumerate()
            .map(|(i, sandbox)| start_add(pin_base, &format!("t{trial}c{i}xxxxxxxxxxxx"), sandbox))
            .collect();

        let mut addresses = HashSet::new();
        for add in adds {
            let out = add.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "trial {trial}: ADD failed: {stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            let address = result["ips"][0]["address"].as_str().unwrap().to_string();
            assert!(
                addresses.insert(address.clone()),
                "trial {trial}: {address} handed out twice"
            );
        }

        // The kernel removes each veth, and so its route, with its netns.
        for sandbox in &mut sandboxes {
            sandbox.kill().unwrap();
            sandbox.wait().unwrap();
        }
    }
}

#[test]
fn concurrent_adds_get_distinct_addresses() {
    let Some((passed, text)) =
        common::in_user_netns("concurrent_adds_get_distinct_addresses", race)
    else {
        return;
    };
    assert!(passed, "namespace child failed:\n{text}");
}
