#!/bin/sh
# Run in the pinned Linux build environment with the adjacent components and
# their locked guest-components source available. Does not alter Kata binaries.
set -eu
cd "$(dirname "$0")/../confidential-storage-service"
cargo test --locked --offline --features trustee-rcar
cargo build --release --locked --offline --features trustee-rcar
