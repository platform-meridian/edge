fn main() {
    let protos = protox::compile(["proto/cri.proto", "proto/machine.proto"], ["proto"])
        .expect("parse the API subsets");
    tonic_prost_build::configure()
        .compile_fds(protos)
        .expect("compile the API subsets");
    println!("cargo:rerun-if-changed=proto");
}
