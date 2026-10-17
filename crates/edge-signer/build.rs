fn main() {
    let talos =
        protox::compile(["talos/machine.proto"], ["proto"]).expect("parse the machine API subset");
    tonic_prost_build::configure()
        .compile_fds(talos)
        .expect("compile the machine API subset");

    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut api = protox::Compiler::new(["proto"]).expect("proto root");
    api.include_imports(true).include_source_info(true);
    api.open_files(["edge/signer/v1/access.proto"])
        .expect("parse the access API");
    std::fs::write(out.join("access.fds"), api.encode_file_descriptor_set())
        .expect("write the descriptor set");
    connectrpc_build::Config::new()
        .descriptor_set(out.join("access.fds"))
        .files(&["edge/signer/v1/access.proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("generate the access API");
    println!("cargo:rerun-if-changed=proto");
}
