#!/bin/bash
# Quick build helper - assumes prerequisites are already installed
# Usage: ./scripts/quick-build.sh [debug|release]

BUILD_TYPE=${1:-release}
set -e

echo "🔨 Building ClawOS ($BUILD_TYPE)..."

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release
    echo "✅ Release build complete"
    echo "📦 Artifacts in: target/release/"
else
    cargo build
    echo "✅ Debug build complete"
    echo "📦 Artifacts in: target/debug/"
fi
