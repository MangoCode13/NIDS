#!/bin/bash
# Automatically capture the absolute folder path where this script resides
export PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Initializing shipper pipeline targeting workspace: $PROJECT_DIR"

# Boot filebeat using the dynamic variable string
sudo -E filebeat -e -c "$PROJECT_DIR/filebeat.yml"
