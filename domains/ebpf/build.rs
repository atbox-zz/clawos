use aya_build::{build_bpf, BindingsBuilder, Compiler};

fn main() {
    build_bpf(
        CARGO_MANIFEST_DIR.as_str(),
        "src/bpf/main.bpf.rs",
        &["-Wall", "-Werror"],
    )
    .unwrap();

    let mut bindings = BindingsBuilder::default()
        .generate("src/bpf/main.bpf.rs")
        .unwrap();

    bindings
        .write_to_file("src/bpf/main.skel.rs")
        .unwrap();
}
