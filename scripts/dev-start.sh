#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check-only)
      CHECK_ONLY=1
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: scripts/dev-start.sh [--check-only]"
      exit 1
      ;;
  esac
done

sanitize_sqlite_url() {
  local url="$1"
  if [[ "$url" != sqlite://* && "$url" != sqlite:* ]]; then
    printf "%s" "$url"
    return
  fi

  local base="$url"
  local query=""
  if [[ "$url" == *"?"* ]]; then
    base="${url%%\?*}"
    query="${url#*\?}"
  fi

  if [[ -z "$query" ]]; then
    printf "%s" "$base"
    return
  fi

  local -a filtered=()
  IFS="&" read -r -a pairs <<<"$query"
  for pair in "${pairs[@]}"; do
    [[ -z "$pair" ]] && continue
    local key="${pair%%=*}"
    local key_lc
    key_lc="$(printf "%s" "$key" | tr "[:upper:]" "[:lower:]")"
    if [[ "$key_lc" == "foreign_keys" ]]; then
      continue
    fi
    filtered+=("$pair")
  done

  if [[ ${#filtered[@]} -eq 0 ]]; then
    printf "%s" "$base"
  else
    printf "%s?%s" "$base" "$(IFS="&"; echo "${filtered[*]}")"
  fi
}

extract_sqlite_path() {
  local url="$1"
  if [[ "$url" == sqlite::memory:* || "$url" == sqlite://:memory:* ]]; then
    return
  fi
  local trimmed="${url#sqlite://}"
  trimmed="${trimmed#sqlite:}"
  trimmed="${trimmed%%\?*}"
  [[ -z "$trimmed" ]] && return
  printf "%s" "$trimmed"
}

echo "[1/5] Checking cargo toolchain..."
command -v cargo >/dev/null

raw_database_url="${DATABASE_URL:-sqlite://snippets.db?mode=rwc}"
database_url="$(sanitize_sqlite_url "$raw_database_url")"
export DATABASE_URL="$database_url"

echo "[2/5] DATABASE_URL: $DATABASE_URL"
if [[ "$raw_database_url" != "$database_url" ]]; then
  echo "      Removed unsupported sqlite query parameter(s) from DATABASE_URL."
fi

if [[ "$DATABASE_URL" == sqlite://* || "$DATABASE_URL" == sqlite:* ]]; then
  sqlite_path="$(extract_sqlite_path "$DATABASE_URL" || true)"
  if [[ -n "${sqlite_path:-}" && "$sqlite_path" != :memory: ]]; then
    if [[ "$sqlite_path" == /* ]]; then
      db_file="$sqlite_path"
    else
      db_file="$ROOT_DIR/$sqlite_path"
    fi
    db_parent="$(dirname "$db_file")"
    mkdir -p "$db_parent"
    echo "[3/5] SQLite file path: $db_file"
  else
    echo "[3/5] SQLite in-memory database detected."
  fi
else
  echo "[3/5] Non-sqlite database URL detected."
fi

echo "[4/5] Applying migrations..."
(
  cd "$ROOT_DIR"
  cargo run -p migration -- -u "$DATABASE_URL" up
)

if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[5/5] Port 3000 is already in use. Stop the existing process first."
    exit 1
  fi
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  echo "[5/5] Health checks passed (check-only mode)."
  exit 0
fi

echo "[5/5] Starting backend server..."
cd "$ROOT_DIR"
exec cargo run --package some-snippets --bin some-snippets --profile dev
