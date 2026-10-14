#!/bin/sh
# Stop the regtest network and delete its volumes and exported files.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
docker compose -f "$here/compose.yml" down -v --remove-orphans
rm -rf "$here/.state"
