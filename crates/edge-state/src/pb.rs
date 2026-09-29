//! etcd v3.5 protos with the Go-only gogoproto/google.api options stripped; the wire format is unchanged.
#![allow(clippy::all)]
pub mod authpb {
    tonic::include_proto!("authpb");
}
pub mod mvccpb {
    tonic::include_proto!("mvccpb");
}
pub mod etcdserverpb {
    tonic::include_proto!("etcdserverpb");
}
