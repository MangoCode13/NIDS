#!/bin/sh
set -eu

if [ -z "${ELASTIC_PASSWORD:-}" ] || [ -z "${KIBANA_SYSTEM_PASSWORD:-}" ]; then
  echo "ELASTIC_PASSWORD and KIBANA_SYSTEM_PASSWORD must both be set." >&2
  exit 1
fi

while :; do
  result=$(curl -sS -o /dev/null -w "%{http_code}" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    http://elasticsearch:9200/_cluster/health || true)
  case "$result" in
    200) break ;;
    401|403)
      echo "Elasticsearch rejected ELASTIC_PASSWORD (HTTP $result)." >&2
      exit 1
      ;;
  esac
  echo "Waiting for Elasticsearch to become ready (HTTP ${result:-000})..."
  sleep 5
done

escaped_password=$(printf '%s' "$KIBANA_SYSTEM_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
while :; do
  result=$(curl -sS -o /dev/null -w "%{http_code}" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -X POST \
    http://elasticsearch:9200/_security/user/kibana_system/_password \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${escaped_password}\"}" || true)
  case "$result" in
    200) break ;;
    401|403)
      echo "Elasticsearch rejected credentials while setting kibana_system (HTTP $result)." >&2
      exit 1
      ;;
  esac
  echo "Waiting for Elasticsearch security API (HTTP ${result:-000})..."
  sleep 5
done

echo "kibana_system password set successfully"