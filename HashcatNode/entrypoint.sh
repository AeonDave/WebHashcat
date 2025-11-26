#!/usr/bin/env bash
set -euo pipefail

cd /hashcatnode

if [ "${HASHCATNODE_DEVICE_TYPE:-}" = "2" ]; then
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        echo "CUDA device type requested but nvidia-smi not found; ensure NVIDIA drivers/runtime are available."
        exit 1
    fi
    if ! nvidia-smi >/dev/null 2>&1; then
        echo "CUDA device type requested but GPU is not available."
        exit 1
    fi
fi

DB_PATH="${HASHCATNODE_DB_PATH:-/hashcatnode/data/hashcatnode.db}"
DB_DIR="$(dirname "$DB_PATH")"
export HASHCATNODE_DB_PATH="$DB_PATH"
mkdir -p "$DB_DIR"

# Always ensure database schema exists (create_table is safe)
echo "Ensuring sqlite database at $DB_PATH"
HASHCATNODE_DB_PATH="$DB_PATH" python3 ./create_database.py

exec "$@"
