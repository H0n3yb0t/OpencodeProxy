#!/bin/sh
set -eu

SERVER="${1:-}"
TICKET="${2:-}"
if [ -z "$SERVER" ] || [ -z "$TICKET" ]; then
  echo "Usage: install.sh <server> <one-time-ticket>" >&2
  exit 1
fi
SERVER="${SERVER%/}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
JSON_PATH="$CONFIG_DIR/opencode.json"
JSONC_PATH="$CONFIG_DIR/opencode.jsonc"

if [ -f "$JSON_PATH" ] && [ -f "$JSONC_PATH" ]; then
  echo "Both opencode.json and opencode.jsonc exist. Keep only the active global config, then retry." >&2
  exit 1
fi
if [ -f "$JSON_PATH" ]; then
  CONFIG_PATH="$JSON_PATH"
elif [ -f "$JSONC_PATH" ]; then
  CONFIG_PATH="$JSONC_PATH"
else
  CONFIG_PATH="$JSON_PATH"
fi

PYTHON=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
fi
if [ -z "$PYTHON" ]; then
  echo "Python 3 is required for safe JSON/JSONC merging on macOS/Linux." >&2
  echo "Install Python 3, then run the same one-time command again." >&2
  exit 1
fi

mkdir -p "$CONFIG_DIR"
umask 077
"$PYTHON" - "$CONFIG_PATH" "$CONFIG_DIR/opencodeproxy.token" "$SERVER" "$TICKET" <<'PY'
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from datetime import datetime

config_path, token_path, server, ticket = sys.argv[1:]

def strip_jsonc(text):
    out = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif c == "/" and n == "/":
            i += 2
            while i < len(text) and text[i] != "\n":
                i += 1
        elif c == "/" and n == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(c)
            i += 1
    text = "".join(out)
    out = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        c = text[i]
        if in_string:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif c == ",":
            j = i + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in "}]":
                i += 1
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)

if os.path.exists(config_path):
    with open(config_path, "r", encoding="utf-8-sig") as handle:
        raw = handle.read()
    config = json.loads(strip_jsonc(raw)) if raw.strip() else {}
else:
    config = {}
if not isinstance(config, dict):
    raise SystemExit("The OpenCode global config must be a JSON object.")
if config.get("provider") is not None and not isinstance(config["provider"], dict):
    raise SystemExit("The provider field in the OpenCode global config must be a JSON object.")

payload = json.dumps({"ticket": ticket, "base_url": server}).encode("utf-8")
request = urllib.request.Request(
    server.rstrip("/") + "/api/client/enroll",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=30) as response:
    enrollment = json.load(response)

if config.get("provider") is None:
    config["provider"] = {}
config["provider"].update(enrollment["providers"])
if not config.get("model"):
    config["model"] = enrollment["default_model"]

with open(token_path, "w", encoding="utf-8", newline="") as handle:
    handle.write(enrollment["proxy_token"])
os.chmod(token_path, 0o600)

if os.path.exists(config_path):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(config_path, config_path + ".bak-" + stamp)
directory = os.path.dirname(config_path)
fd, temp_path = tempfile.mkstemp(prefix=".opencode-", suffix=".tmp", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, config_path)
finally:
    if os.path.exists(temp_path):
        os.unlink(temp_path)
PY

echo "OpencodeProxy configured successfully."
echo "Config: $CONFIG_PATH"
echo "Token:  $CONFIG_DIR/opencodeproxy.token"
echo "Restart OpenCode, then run /models and select OpencodeProxy."
