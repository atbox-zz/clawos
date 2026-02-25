#!/bin/bash
# ClawOS Build Environment Check & Helper Script
# Usage: ./scripts/build.sh [debug|release|check|clean]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RUST_MIN_VERSION="1.85.0"
REQUIRED_LINUX_KERNEL="6.6.0"

# Functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if command -v $1 &> /dev/null; then
        return 0
    else
        return 1
    fi
}

check_rust() {
    print_info "Checking Rust installation..."

    if ! check_command rustc; then
        print_error "Rust not installed. Install from https://rustup.rs/"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        return 1
    fi

    RUST_VERSION=$(rustc --version | awk '{print $2}')
    print_success "Rust version: $RUST_VERSION"

    # Parse version and compare
    if [ "$RUST_VERSION" != "$RUST_MIN_VERSION" ] && [ "$(printf '%s\n' "$RUST_MIN_VERSION" "$RUST_VERSION" | sort -V | head -n1)" = "$RUST_MIN_VERSION" ]; then
        print_success "Rust version >= $RUST_MIN_VERSION"
    else
        print_warning "Rust version may be lower than recommended ($RUST_MIN_VERSION)"
    fi

    return 0
}

check_cargo() {
    print_info "Checking Cargo..."

    if ! check_command cargo; then
        print_error "Cargo not found (should be installed with Rust)"
        return 1
    fi

    print_success "Cargo found: $(cargo --version)"
    return 0
}

check_linux_kernel() {
    print_info "Checking Linux kernel version..."

    if [ -z "$(uname -s | grep Linux)" ]; then
        print_error "This script requires Linux kernel. Current: $(uname -s)"
        print_warning "ClawOS requires Linux 6.6 LTS kernel features"
        return 1
    fi

    KERNEL_VERSION=$(uname -r | cut -d- -f1)
    print_success "Kernel version: $KERNEL_VERSION"

    if [ "$(printf '%s\n' "$REQUIRED_LINUX_KERNEL" "$KERNEL_VERSION" | sort -V | head -n1)" = "$REQUIRED_LINUX_KERNEL" ]; then
        print_success "Kernel >= $REQUIRED_LINUX_KERNEL"
    else
        print_warning "Kernel may be older than recommended ($REQUIRED_LINUX_KERNEL)"
        print_warning "Some eBPF features may not work correctly"
    fi

    return 0
}

check_system_deps() {
    print_info "Checking system dependencies..."

    MISSING_DEPS=()

    # Check for required libraries
    local deps=(
        "libseccomp:libseccomp-dev"
        "clang:clang"
        "llvm:llvm"
        "libelf:libelf-dev"
        "libssl:libssl-dev"
        "pkg-config:pkg-config"
    )

    for dep in "${deps[@]}"; do
        local cmd=$(echo $dep | cut -d: -f1)
        local pkg=$(echo $dp | cut -d: -f2)

        if dpkg -l | grep -q "^ii  $pkg"; then
            print_success "$pkg installed"
        else
            print_warning "$pkg not installed"
            MISSING_DEPS+=("$pkg")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        print_error "Missing dependencies: ${MISSING_DEPS[*]}"
        echo ""
        print_info "Install with:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install -y ${MISSING_DEPS[*]}"
        return 1
    fi

    return 0
}

check_aya_toolchain() {
    print_info "Checking Aya eBPF toolchain..."

    if check_command aya; then
        AYA_VERSION=$(aya --version 2>/dev/null || echo "unknown")
        print_success "Aya installed: $AYA_VERSION"
    else
        print_warning "Aya not installed (required for eBPF domain)"
        print_info "Install with: cargo install aya --version 0.13.0"
    fi

    return 0
}

run_build() {
    local build_type=$1

    print_info "Starting $build_type build..."

    case $build_type in
        debug)
            cargo build --verbose
            ;;
        release)
            cargo build --release --verbose
            ;;
        check)
            cargo check --all --verbose
            ;;
        clean)
            cargo clean
            print_success "Build artifacts cleaned"
            return 0
            ;;
        *)
            print_error "Unknown build type: $build_type"
            print_info "Usage: $0 [debug|release|check|clean]"
            return 1
            ;;
    esac

    print_success "Build completed successfully"

    # Show output files
    local target_dir="target/$build_type"
    if [ "$build_type" = "release" ]; then
        target_dir="target/release"

        print_info "Output files:"
        find target/release -name "*.rlib" -o -name "*.so" | head -n 10
    fi
}

run_tests() {
    print_info "Running tests..."

    cargo test --verbose

    print_success "All tests passed"
}

run_clippy() {
    print_info "Running clippy linter..."

    cargo clippy --all -- -D warnings

    print_success "Clippy checks passed (zero warnings)"
}

show_help() {
    echo "ClawOS Build Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  check    - Run pre-build checks (recommended first)"
    echo "  debug    - Build debug version"
    echo "  release  - Build optimized release version"
    echo "  test     - Run unit tests"
    echo "  clippy   - Run clippy linter"
    echo "  clean    - Clean build artifacts"
    echo "  help     - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 check     # Check environment before building"
    echo "  $0 debug     # Quick development build"
    echo "  $0 release   # Optimized production build"
    echo "  $0 test      # Run all tests"
}

# Main
main() {
    local command=${1:-help}

    print_info "ClawOS Build Environment"
    echo ""

    case $command in
        check)
            check_rust || exit 1
            check_cargo || exit 1
            check_linux_kernel || exit 1
            check_system_deps || exit 1
            check_aya_toolchain
            print_success "All checks passed!"
            ;;
        debug)
            run_build debug
            ;;
        release)
            run_build release
            ;;
        test)
            run_tests
            ;;
        clippy)
            run_clippy
            ;;
        clean)
            run_build clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
