#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use edge_dns::forward::{ForwardCfg, Forwarder};
use edge_dns::handler::EdgeDns;
use edge_dns::watch::ZoneState;
use edge_kube::ServiceView;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::net::NetError;
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use libfuzzer_sys::fuzz_target;

struct World {
    rt: tokio::runtime::Runtime,
    dns: EdgeDns,
}

static WORLD: LazyLock<World> = LazyLock::new(|| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut view = ServiceView::default();
    for (ns, name, ip) in [
        ("default", "kubernetes", "10.96.0.1"),
        ("default", "v6", "fd00::1"),
        ("db", "headless", "None"),
    ] {
        let mut s = Service::default();
        s.metadata.name = Some(name.into());
        s.metadata.namespace = Some(ns.into());
        s.spec = Some(ServiceSpec {
            cluster_ip: Some(ip.into()),
            ports: Some(vec![ServicePort {
                port: 80,
                name: Some("http".into()),
                ..Default::default()
            }]),
            ..Default::default()
        });
        view.apply_service(s);
    }
    let state = ZoneState::new("cluster.local");
    state.on_synced(&view);
    // No name servers: every forward fails at once.
    let resolver = rt.block_on(async {
        edge_dns::upstream::build(
            std::path::Path::new("/nonexistent"),
            Duration::from_millis(1),
            0,
        )
    });
    let dns = EdgeDns::new(state, Forwarder::new(resolver, ForwardCfg::default()));
    World { rt, dns }
});

#[derive(Clone, Default)]
struct Wire(Arc<Mutex<Option<Vec<u8>>>>);

#[async_trait::async_trait]
impl ResponseHandler for Wire {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        // What hickory's UDP send allows.
        encoder.set_max_size(response.edns().map_or(512, |e| e.max_payload()));
        let info = response.destructive_emit(&mut encoder)?;
        *self.0.lock().unwrap() = Some(bytes);
        Ok(info)
    }
}

/// The wire response, or None where hickory's server answers before the handler.
fn answer(payload: Vec<u8>) -> Option<Message> {
    let src: SocketAddr = "10.244.0.9:5353".parse().unwrap();
    let request = Request::from_bytes(payload, src, Protocol::Udp).ok()?;
    if request.metadata.message_type == MessageType::Response {
        return None;
    }
    let wire = Wire::default();
    let world = &*WORLD;
    world.rt.block_on(
        world
            .dns
            .handle_request::<_, TokioTime>(&request, wire.clone()),
    );
    let bytes = wire
        .0
        .lock()
        .unwrap()
        .take()
        .expect("every request is answered");
    let response = Message::from_vec(&bytes).expect("the response decodes");
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    Some(response)
}

const SUFFIXES: &[&str] = &[
    ".",
    "cluster.local.",
    "default.svc.cluster.local.",
    "kubernetes.default.svc.cluster.local.",
    "_http._tcp.kubernetes.default.svc.cluster.local.",
    "_http._tcp.headless.db.svc.cluster.local.",
    "1.0.96.10.in-addr.arpa.",
    "in-addr.arpa.",
    "ip6.arpa.",
];

fuzz_target!(|data: &[u8]| {
    answer(data.to_vec());

    let [a, b, c, d, e, rest @ ..] = data else {
        return;
    };
    let suffix = Name::from_ascii(SUFFIXES[*e as usize % SUFFIXES.len()]).unwrap();
    let Ok(name) = Name::from_labels(rest.split(|x| *x == b'.').filter(|l| !l.is_empty()))
        .and_then(|n| n.append_domain(&suffix))
    else {
        return;
    };
    let mut query = Message::new(
        u16::from_be_bytes([*a, *b]),
        MessageType::Query,
        OpCode::Query,
    );
    query.add_query(Query::query(
        name,
        RecordType::from(u16::from_be_bytes([*c, *d])),
    ));
    let Ok(payload) = query.to_vec() else {
        return;
    };
    let response = answer(payload).expect("a query reaches the handler");
    assert_eq!(response.queries.len(), 1);
    let (sent, got) = (&query.queries[0], &response.queries[0]);
    assert_eq!(got.name().to_string(), sent.name().to_string());
    assert_eq!(
        (got.query_type(), got.query_class()),
        (sent.query_type(), sent.query_class())
    );
});
