#!/bin/bash
set -e  

cargo +nightly build -p clawos-ebpf --target bpfel-unknown-none --release -Zbuild-std=core
echo "    # 1. cargo eBPF Done!"

cargo build --workspace --exclude clawos-ebpf --release
echo "    # 2. cargo build Done!"
