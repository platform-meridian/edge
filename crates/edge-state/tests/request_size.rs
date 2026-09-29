mod common;

use edge_state::pb::etcdserverpb::{
    PutRequest, RangeRequest, RequestOp, TxnRequest, kv_client::KvClient, request_op,
};
use edge_state::server::EtcdServer;
use edge_state::store::Store;
use prost::Message;
use tonic::Code;

const TOO_LARGE: &str = "etcdserver: request is too large";

async fn spawn(dir: &std::path::Path) -> KvClient<tonic::transport::Channel> {
    let store = Store::open(dir.join("state.log")).unwrap();
    let url = common::serve(EtcdServer::new(store)).await;
    KvClient::connect(url).await.unwrap()
}

fn put(value_len: usize) -> PutRequest {
    PutRequest {
        key: b"/big".to_vec(),
        value: vec![b'v'; value_len],
        ..Default::default()
    }
}

fn assert_too_large(r: Result<impl std::fmt::Debug, tonic::Status>) {
    let e = r.expect_err("accepted an oversized request");
    assert_eq!((e.code(), e.message()), (Code::InvalidArgument, TOO_LARGE));
}

#[tokio::test]
async fn put_limit_is_raft_entry() {
    let dir = common::tempdir();
    let mut kv = spawn(dir.path()).await;
    // The raft entry is the value plus 25 bytes: 11 of header with a 7-byte request ID,
    // 1 + 3 of field tag and length, 6 of key, 1 + 3 of value tag and length.
    kv.put(put(1_572_864 - 25)).await.unwrap();
    assert_too_large(kv.put(put(1_572_864 - 24)).await);
}

#[tokio::test]
async fn write_txn_checked_read_only_not() {
    let dir = common::tempdir();
    let mut kv = spawn(dir.path()).await;
    let op = |request| RequestOp {
        request: Some(request),
    };
    let write = TxnRequest {
        success: vec![op(request_op::Request::RequestPut(put(1_572_864)))],
        ..Default::default()
    };
    assert_too_large(kv.txn(write).await);

    let read = TxnRequest {
        success: vec![op(request_op::Request::RequestRange(RangeRequest {
            key: vec![b'k'; 1_572_864],
            ..Default::default()
        }))],
        ..Default::default()
    };
    kv.txn(read).await.unwrap();
}

#[tokio::test]
async fn grpc_limit_as_grpc_go() {
    let dir = common::tempdir();
    let mut kv = spawn(dir.path()).await;
    let limit = 1_572_864 + 512 * 1024;
    let at_limit = put(limit - 10);
    assert_eq!(at_limit.encoded_len(), limit);
    assert_too_large(kv.put(at_limit).await);

    let over = put(limit - 9);
    assert_eq!(over.encoded_len(), limit + 1);
    let e = kv.put(over).await.unwrap_err();
    assert_eq!(
        (e.code(), e.message()),
        (
            Code::ResourceExhausted,
            format!(
                "grpc: received message larger than max ({} vs. {limit})",
                limit + 1
            )
            .as_str()
        )
    );
}

#[tokio::test]
async fn flag_sets_limit() {
    let dir = common::tempdir();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _child = Kill(
        std::process::Command::new(env!("CARGO_BIN_EXE_edge-state"))
            .arg(format!("--data-dir={}", dir.path().display()))
            .arg(format!("--listen-client-urls=http://127.0.0.1:{port}"))
            .arg("--max-request-bytes=4096")
            .env_remove("RUST_LOG")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut kv = loop {
        if let Ok(c) = KvClient::connect(format!("http://127.0.0.1:{port}")).await {
            break c;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never started serving"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    // n + 23 bytes: the value's length takes 2 bytes, as does the put's.
    kv.put(put(4096 - 23)).await.unwrap();
    assert_too_large(kv.put(put(4096 - 22)).await);
}
