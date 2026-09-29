use std::path::PathBuf;
use std::process::Command;

fn main() {
    let ebpf = PathBuf::from("../ebpf");
    for path in [
        "src",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        "../common",
    ] {
        println!("cargo::rerun-if-changed={}", ebpf.join(path).display());
    }
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("ebpf");

    // A clean environment, so rustup reads the BPF crate's own toolchain file
    // instead of inheriting this build's stable toolchain and flags.
    let mut cargo = Command::new("cargo");
    cargo.env_clear().current_dir(&ebpf);
    for var in ["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME"] {
        if let Some(value) = std::env::var_os(var) {
            cargo.env(var, value);
        }
    }
    let status = cargo
        .args(["build", "--release", "--target-dir"])
        .arg(&out)
        .status()
        .expect("run cargo for the BPF programs");
    assert!(status.success(), "building the BPF programs failed");
}
