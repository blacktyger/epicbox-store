#!/usr/bin/env bash
# Reproducible build of the epicbox-store canister. Linux, from any directory: the paths of this
# checkout and of the cargo home are rewritten to fixed names, so the bytes do not depend on where
# it is built. The toolchain is pinned by rust-toolchain.toml and the dependencies by Cargo.lock.
#
#   ./build.sh            prints the sha256 of the Wasm, which is the canister's module hash
set -euo pipefail
cd "$(dirname "$0")"
here="$(pwd -P)"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
export RUSTFLAGS="--remap-path-prefix=$here=/epicbox-store --remap-path-prefix=$cargo_home=/cargo"
export CARGO_TARGET_DIR="$here/target"
cargo build --release --locked --target wasm32-unknown-unknown
sha256sum target/wasm32-unknown-unknown/release/epicbox_store.wasm
