fn main() {
    let protos = protox::compile(["proto/cri.proto"], ["proto"]).expect("parse the CRI subset");
    tonic_prost_build::configure()
        .compile_fds(protos)
        .expect("compile the CRI subset");
    println!("cargo:rerun-if-changed=proto");
}
