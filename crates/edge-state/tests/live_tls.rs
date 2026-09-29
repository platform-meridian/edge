//! Probes a live edge-state: set EDGE_STATE_ENDPOINT and EDGE_STATE_PKI, run with --ignored.

use edge_state::pb::etcdserverpb::{
    MemberListRequest, RangeRequest, cluster_client::ClusterClient, kv_client::KvClient,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

async fn connect() -> Channel {
    let ep = std::env::var("EDGE_STATE_ENDPOINT").expect("set EDGE_STATE_ENDPOINT");
    let pki = std::env::var("EDGE_STATE_PKI").expect("set EDGE_STATE_PKI");
    let read = |f: &str| std::fs::read(format!("{pki}/{f}")).expect(f);
    let tls = ClientTlsConfig::new()
        // The certificate names the node, not the address dialled.
        .domain_name("node-1")
        .ca_certificate(Certificate::from_pem(read("etcd-client-ca.crt")))
        .identity(Identity::from_pem(
            read("etcd-client.crt"),
            read("etcd-client.key"),
        ));
    Endpoint::from_shared(ep)
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("connect over TLS")
}

#[tokio::test]
#[ignore = "needs a live edge-state and the node's PKI"]
async fn member_list_over_talos_tls() {
    let mut c = ClusterClient::new(connect().await);
    let r = c
        .member_list(MemberListRequest {
            linearizable: false,
        })
        .await
        .expect("MemberList over TLS")
        .into_inner();

    println!("members: {:?}", r.members);
    assert_eq!(r.members.len(), 1);
    assert_eq!(r.members[0].name, "node-1", "the --name Talos passed");
    assert!(r.header.is_some());
}

#[tokio::test]
#[ignore = "needs a live edge-state serving a cluster"]
async fn cluster_objects_read_back() {
    let mut kv = KvClient::new(connect().await);
    let r = kv
        .range(RangeRequest {
            key: b"/registry/".to_vec(),
            range_end: b"/registry0".to_vec(),
            ..Default::default()
        })
        .await
        .expect("range over /registry/")
        .into_inner();

    println!("keys under /registry/: {}", r.kvs.len());
    assert!(
        r.kvs.len() > 100,
        "a cluster should have hundreds of objects"
    );

    let keys: Vec<String> = r
        .kvs
        .iter()
        .map(|k| String::from_utf8_lossy(&k.key).into_owned())
        .collect();
    for want in [
        "/registry/namespaces/",
        "/registry/pods/",
        "/registry/secrets/",
    ] {
        assert!(
            keys.iter().any(|k| k.starts_with(want)),
            "no {want} in the store"
        );
    }
    // Kubernetes objects are protobuf beginning with "k8s\0".
    let ns = r
        .kvs
        .iter()
        .find(|k| k.key.starts_with(b"/registry/namespaces/"))
        .unwrap();
    assert!(
        ns.value.starts_with(b"k8s\x00"),
        "namespace value is not a k8s protobuf"
    );
    println!(
        "sample: {} ({} bytes)",
        String::from_utf8_lossy(&ns.key),
        ns.value.len()
    );
}
