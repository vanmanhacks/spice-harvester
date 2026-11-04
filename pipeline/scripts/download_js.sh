#!/usr/bin/env bash
# Download JS files from a URL list through the Warden proxy
# Usage: download_js.sh <url_list> <output_dir>

set -euo pipefail
URL_LIST="$1"
OUT_DIR="$2"
mkdir -p "$OUT_DIR"

while IFS= read -r url; do
    fname=$(echo "$url" | md5sum | cut -d" " -f1).js
    curl -s --max-time 10 "$url" -o "$OUT_DIR/$fname" 2>/dev/null || true
done < "$URL_LIST"
