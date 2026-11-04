#!/bin/bash
set -euo pipefail

# Automatically capture the absolute folder path where this script resides
export PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Initializing shipper pipeline targeting workspace: $PROJECT_DIR"

if [ -f "$PROJECT_DIR/.env" ]; then
  set -a
  . "$PROJECT_DIR/.env"
  set +a
else
  echo "Error: .env file not found in $PROJECT_DIR" >&2
  exit 1
fi

# Boot filebeat using the dynamic variable string
sudo -E filebeat -e -c "$PROJECT_DIR/filebeat.yml" --strict.perms=false
