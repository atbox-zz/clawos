# ClawOS Makefile
# Orchestrates multi-target build, test, and ISO assembly.
# Run: make help

SHELL   := /bin/bash
VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2 || echo "0.1.0")
TARGET  := x86_64-unknown-linux-musl
eBPF_TARGET := bpfel-unknown-none

.PHONY: help build build-release build-ebpf test lint check \
        setup-dev setup-system preflight \
        calibrate security-report benchmark qemu-test \
        iso install clean

help:
	@echo "ClawOS v$(VERSION) Build System"
	@echo ""
	@echo "Development:"
	@echo "  make build          — cargo build (native, debug)"
	@echo "  make test           — cargo test --workspace"
	@echo "  make lint           — cargo clippy -D warnings"
	@echo "  make check          — cargo check --workspace"
	@echo ""
	@echo "Production:"
	@echo "  make build-release  — static x86_64 musl binary"
	@echo "  make build-ebpf     — eBPF kernel programs"
	@echo "  make build-tools    — all WASM tools"
	@echo "  make iso            — full ISO image (<128MB)"
	@echo ""
	@echo "System setup (run as root):"
	@echo "  make setup-system   — cgroups + netns + AppArmor"
	@echo "  make preflight      — pre-flight validation"
	@echo ""
	@echo "Validation:"
	@echo "  make calibrate      — P4 resource calibration"
	@echo "  make security-report — P4 security audit"
	@echo "  make benchmark      — P4 performance vs IronClaw"
	@echo "  make qemu-test      — QEMU boot + integration test"

# ── Development ───────────────────────────────────────────────

build:
	cargo build --workspace

check:
	cargo check --workspace --all-targets

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all -- --check

test:
	cargo test --workspace

test-security:
	cargo test -p clawos-seccomp -p clawfs -- --test-threads=1

test-integration:
	cargo test --test integration_agent -- --include-ignored

# ── Production ────────────────────────────────────────────────

build-release:
	cargo build -p clawos-agent -p clawos-ebpf-userspace \
		--target $(TARGET) --release
	@ls -lh target/$(TARGET)/release/clawos-agent
	@ls -lh target/$(TARGET)/release/clawos-ebpf-userspace

build-ebpf:
	cargo build -p clawos-ebpf \
		--target $(eBPF_TARGET) --release

build-tools:
	@for tool in web-search file-read summarise; do \
		echo "Building $$tool..."; \
		(cd tools/$$tool && cargo build --target wasm32-wasi --release && \
		 cp ../../target/wasm32-wasi/release/$${tool//-/_}.wasm tool.wasm && \
		 echo "  ✅ $$tool (tool.wasm $(du -sh tool.wasm | cut -f1))"); \
	done

# ── System Setup ──────────────────────────────────────────────

setup-dev:
	@mkdir -p /var/lib/clawos/{tools,workspace,logs,secrets,vault}
	@mkdir -p /var/run/clawos/ipc
	@mkdir -p /etc/clawos
	@cp config/config.toml /etc/clawos/config.toml
	@echo "Dev directories created"

setup-system:
	@[ "$$EUID" -eq 0 ] || (echo "Run as root" && exit 1)
	bash scripts/setup-cgroups.sh
	bash scripts/setup-netns.sh
	apparmor_parser -r apparmor/clawos-agent
	aa-enforce /etc/apparmor.d/clawos-agent

preflight:
	bash scripts/preflight.sh

# ── Validation ────────────────────────────────────────────────

calibrate:
	bash scripts/calibrate.sh

security-report:
	bash scripts/security-report.sh

benchmark:
	bash scripts/benchmark.sh

qemu-test: iso
	bash scripts/qemu-test.sh image/clawos-v$(VERSION).iso

# ── ISO ───────────────────────────────────────────────────────

iso: build-release build-ebpf build-tools
	@echo "Building ClawOS $(VERSION) ISO..."
	@mkdir -p buildroot-2024.11
	@cd buildroot-2024.11 && \
		[ -f Makefile ] || \
		(echo "Download buildroot: wget https://buildroot.org/downloads/buildroot-2024.11.tar.gz" && exit 1)
	cd buildroot-2024.11 && \
		make BR2_DEFCONFIG=../image/buildroot.config defconfig && \
		make -j$$(nproc)
	@ls -lh image/clawos-v$(VERSION).iso

# ── Installation ──────────────────────────────────────────────

install: build-release
	install -m 755 target/$(TARGET)/release/clawos-agent /usr/local/bin/
	install -m 755 target/$(TARGET)/release/clawos-ebpf-userspace /usr/local/bin/
	install -m 755 scripts/preflight.sh /usr/local/bin/clawos-preflight
	install -m 755 scripts/setup-netns.sh /usr/local/bin/clawos-setup-netns
	install -m 644 scripts/clawos-agent.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Installed clawos-agent $(VERSION)"

# ── Utility ───────────────────────────────────────────────────

clean:
	cargo clean
	@rm -rf image/clawos-*.iso image/clawos-*.sha256
	@rm -f /var/run/clawos/agent.heartbeat /var/run/clawos/ebpf.pid
	@echo "Clean complete"

# ── Gate shortcuts ────────────────────────────────────────────

gate-p1: preflight
	@echo "Run: /gate P1→P2 in clawsh to verify specs"

gate-p2: lint test
	@echo "P2 lint+test gate: PASS"

gate-p3: test-security build-tools
	@echo "P3 gate: tools built + security tests pass"

gate-p4: benchmark security-report
	@echo "P4 gate: check reports above for PASS/FAIL"
