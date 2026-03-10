#!/bin/sh

set -eu

INDEXER_URL="${INDEXER_URL:-https://wazuh.indexer:9200}"
INDEXER_USER="${INDEXER_USER:-${WAZUH_INDEXER_USERNAME:-admin}}"
INDEXER_PASSWORD="${INDEXER_PASSWORD:-${WAZUH_INDEXER_PASSWORD:-}}"
CA_CERT="${CA_CERT:-/certs/root-ca.pem}"

RETENTION_POLICY_ID="${RETENTION_POLICY_ID:-wazuh-retention-90d}"
RETENTION_MIN_INDEX_AGE="${RETENTION_MIN_INDEX_AGE:-90d}"
RETENTION_MIN_INDEX_SIZE="${RETENTION_MIN_INDEX_SIZE:-}"
RETENTION_INDEX_PATTERNS="${RETENTION_INDEX_PATTERNS:-wazuh*,.ds-wazuh*}"
RETENTION_RECHECK_SECONDS="${RETENTION_RECHECK_SECONDS:-1800}"
RETENTION_RUN_ONCE="${RETENTION_RUN_ONCE:-false}"

TMP_RESPONSE_FILE="/tmp/wazuh-retention-response.json"
ISM_PREFIX=""

if [ -z "$INDEXER_PASSWORD" ]; then
  echo "ERROR: INDEXER_PASSWORD/WAZUH_INDEXER_PASSWORD is empty" >&2
  exit 1
fi

http_code() {
  method="$1"
  url="$2"
  data="${3:-}"

  if [ -n "$data" ]; then
    curl \
      --silent \
      --show-error \
      --output "$TMP_RESPONSE_FILE" \
      --write-out "%{http_code}" \
      --cacert "$CA_CERT" \
      -u "$INDEXER_USER:$INDEXER_PASSWORD" \
      -H "Content-Type: application/json" \
      -X "$method" \
      --data "$data" \
      "$url"
    return
  fi

  curl \
    --silent \
    --show-error \
    --output "$TMP_RESPONSE_FILE" \
    --write-out "%{http_code}" \
    --cacert "$CA_CERT" \
    -u "$INDEXER_USER:$INDEXER_PASSWORD" \
    -X "$method" \
    "$url"
}

size_to_bytes() {
  value="$1"
  awk -v s="$value" '
    function tolower_ascii(str,    i, c, out) {
      out = ""
      for (i = 1; i <= length(str); i++) {
        c = substr(str, i, 1)
        if (c >= "A" && c <= "Z") {
          out = out sprintf("%c", ord(c) + 32)
        } else {
          out = out c
        }
      }
      return out
    }
    function ord(ch) { return index("\0\1\2\3\4\5\6\7\8\9\n\11\12\13\14\15\16\17\20\21\22\23\24\25\26\27\30\31 !\"#$%&'\''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", ch) - 1 }
    BEGIN {
      gsub(/[[:space:]]/, "", s)
      s = tolower(s)
      if (match(s, /^[0-9]+([.][0-9]+)?/)) {
        n = substr(s, RSTART, RLENGTH) + 0
        u = substr(s, RLENGTH + 1)
      } else {
        n = 0
        u = "b"
      }
      if (u == "" || u == "b")      m = 1
      else if (u == "kb" || u == "k") m = 1024
      else if (u == "mb" || u == "m") m = 1024 * 1024
      else if (u == "gb" || u == "g") m = 1024 * 1024 * 1024
      else if (u == "tb" || u == "t") m = 1024 * 1024 * 1024 * 1024
      else m = 1
      printf "%.0f", n * m
    }
  '
}

wait_for_indexer() {
  echo "Waiting for Wazuh indexer at $INDEXER_URL..."

  while :; do
    code="$(http_code GET "$INDEXER_URL/_cluster/health" || true)"
    if [ "$code" = "200" ]; then
      echo "Indexer is reachable."
      return
    fi
    sleep 5
  done
}

detect_ism_prefix() {
  code="$(http_code GET "$INDEXER_URL/_plugins/_ism/policies" || true)"
  if [ "$code" = "200" ]; then
    ISM_PREFIX="_plugins/_ism"
    return
  fi

  code="$(http_code GET "$INDEXER_URL/_opendistro/_ism/policies" || true)"
  if [ "$code" = "200" ]; then
    ISM_PREFIX="_opendistro/_ism"
    return
  fi

  echo "ERROR: ISM API endpoint not found (_plugins/_ism or _opendistro/_ism)." >&2
  exit 1
}

ensure_policy() {
  code="$(http_code GET "$INDEXER_URL/$ISM_PREFIX/policies/$RETENTION_POLICY_ID" || true)"
  case "$code" in
    200)
      echo "Policy '$RETENTION_POLICY_ID' already exists."
      return
      ;;
    404)
      ;;
    *)
      echo "ERROR: Cannot check policy '$RETENTION_POLICY_ID', HTTP $code" >&2
      cat "$TMP_RESPONSE_FILE" >&2 || true
      exit 1
      ;;
  esac

  payload="$(cat <<EOF
{
  "policy": {
    "description": "Wazuh index retention policy managed by sidecar",
    "default_state": "hot",
    "schema_version": 1,
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "$RETENTION_MIN_INDEX_AGE"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ]
  }
}
EOF
)"

  code="$(http_code PUT "$INDEXER_URL/$ISM_PREFIX/policies/$RETENTION_POLICY_ID" "$payload" || true)"
  case "$code" in
    2??)
      echo "Policy '$RETENTION_POLICY_ID' created."
      ;;
    *)
      echo "ERROR: Failed to create policy '$RETENTION_POLICY_ID', HTTP $code" >&2
      cat "$TMP_RESPONSE_FILE" >&2 || true
      exit 1
      ;;
  esac
}

attach_policy_to_existing_indexes() {
  code="$(http_code GET "$INDEXER_URL/_cat/indices/$RETENTION_INDEX_PATTERNS?h=index,store.size&s=index&format=txt&expand_wildcards=all&ignore_unavailable=true" || true)"

  case "$code" in
    200)
      ;;
    404)
      echo "No indexes matched patterns: $RETENTION_INDEX_PATTERNS"
      return
      ;;
    *)
      echo "ERROR: Failed to list indexes, HTTP $code" >&2
      cat "$TMP_RESPONSE_FILE" >&2 || true
      return
      ;;
  esac

  index_lines="$(tr -d '\r' < "$TMP_RESPONSE_FILE" | awk 'NF' | sort -u)"

  if [ -z "$index_lines" ]; then
    echo "No indexes matched patterns: $RETENTION_INDEX_PATTERNS"
    return
  fi

  min_index_bytes=0
  if [ -n "$RETENTION_MIN_INDEX_SIZE" ]; then
    min_index_bytes="$(size_to_bytes "$RETENTION_MIN_INDEX_SIZE")"
  fi

  echo "$index_lines" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    index_name="$(printf '%s\n' "$line" | awk '{print $1}')"
    index_size="$(printf '%s\n' "$line" | awk '{print $2}')"
    [ -n "$index_name" ] || continue

    code="$(http_code GET "$INDEXER_URL/$ISM_PREFIX/explain/$index_name" || true)"
    case "$code" in
      200)
        current_policy="$(
          tr -d '\n\r ' < "$TMP_RESPONSE_FILE" \
          | sed -n 's/.*"policy_id":"\([^"]*\)".*/\1/p'
        )"
        ;;
      404)
        current_policy=""
        ;;
      *)
        echo "WARN: Failed to read ISM state for '$index_name', HTTP $code"
        continue
        ;;
    esac

    if [ "$min_index_bytes" -gt 0 ]; then
      index_size_bytes="$(size_to_bytes "$index_size")"
      if [ "$index_size_bytes" -lt "$min_index_bytes" ]; then
        if [ "$current_policy" = "$RETENTION_POLICY_ID" ]; then
          code="$(http_code POST "$INDEXER_URL/$ISM_PREFIX/remove/$index_name" || true)"
          if [ "$code" -ge 200 ] && [ "$code" -lt 300 ]; then
            echo "Removed '$RETENTION_POLICY_ID' from '$index_name': size $index_size is below $RETENTION_MIN_INDEX_SIZE."
          else
            echo "WARN: Failed to remove policy from '$index_name', HTTP $code"
            cat "$TMP_RESPONSE_FILE" || true
          fi
        else
          echo "Skipping '$index_name': size $index_size is below $RETENTION_MIN_INDEX_SIZE."
        fi
        continue
      fi
    fi

    if [ "$current_policy" = "$RETENTION_POLICY_ID" ]; then
      continue
    fi

    if [ -n "$current_policy" ] && [ "$current_policy" != "$RETENTION_POLICY_ID" ]; then
      echo "Skipping '$index_name': already has policy '$current_policy'."
      continue
    fi

    payload="{\"policy_id\":\"$RETENTION_POLICY_ID\"}"
    code="$(http_code POST "$INDEXER_URL/$ISM_PREFIX/add/$index_name" "$payload" || true)"
    case "$code" in
      2??)
        echo "Attached '$RETENTION_POLICY_ID' to '$index_name'."
        ;;
      *)
        echo "WARN: Failed to attach policy to '$index_name', HTTP $code"
        cat "$TMP_RESPONSE_FILE" || true
        ;;
    esac
  done
}

reconcile() {
  detect_ism_prefix
  ensure_policy
  attach_policy_to_existing_indexes
}

wait_for_indexer

while :; do
  reconcile

  if [ "$RETENTION_RUN_ONCE" = "true" ]; then
    echo "Run-once mode enabled. Exiting."
    exit 0
  fi

  sleep "$RETENTION_RECHECK_SECONDS"
done
