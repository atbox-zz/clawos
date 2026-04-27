cargo +nightly build -p clawos-ebpf --target bpfel-unknown-none --release -Zbuild-std=core
cargo build -p clawos-ebpf-userspace --features ebpf-embed
