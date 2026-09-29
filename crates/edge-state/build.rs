fn main() {
    let protos = protox::compile(["proto/rpc.proto"], ["proto"]).expect("parse etcd protos");
    tonic_prost_build::configure()
        .build_client(true) // for the integration tests
        .compile_fds(protos)
        .expect("compile etcd protos");
    println!("cargo:rerun-if-changed=proto");
}
