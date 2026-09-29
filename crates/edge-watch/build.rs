fn main() {
    let protos =
        protox::compile(["proto/machine.proto"], ["proto"]).expect("parse the machine API subset");
    tonic_prost_build::configure()
        .compile_fds(protos)
        .expect("compile the machine API subset");
    println!("cargo:rerun-if-changed=proto");
}
