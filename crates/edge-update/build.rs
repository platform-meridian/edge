fn main() {
    let talos = protox::compile(["talos/talos.proto", "talos/cosi.proto"], ["proto"])
        .expect("parse the Talos API subset");
    tonic_prost_build::configure()
        .compile_fds(talos)
        .expect("compile the Talos API subset");

    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut api = protox::Compiler::new(["proto"]).expect("proto root");
    api.include_imports(true).include_source_info(true);
    api.open_files(["edge/update/v1/update.proto"])
        .expect("parse the update API");
    std::fs::write(out.join("update.fds"), api.encode_file_descriptor_set())
        .expect("write the descriptor set");
    connectrpc_build::Config::new()
        .descriptor_set(out.join("update.fds"))
        .files(&["edge/update/v1/update.proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("generate the update API");
    println!("cargo:rerun-if-changed=proto");
}
