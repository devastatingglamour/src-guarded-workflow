#!/usr/bin/env bash
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="${BUNDLE_ROOT}/src-workflow"
PYTHON="${PYTHON:-python3}"

if [[ ! -f "${PLUGIN_ROOT}/plugin.json" ]]; then
  echo "Migration bundle is incomplete: ${PLUGIN_ROOT}" >&2
  exit 1
fi
if ! command -v codex >/dev/null 2>&1; then
  echo "Codex CLI is not installed or not in PATH." >&2
  exit 1
fi
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
  echo "Python 3 is required." >&2
  exit 1
fi

"${PYTHON}" - "${BUNDLE_ROOT}/.agents/plugins/marketplace.json" "${PLUGIN_ROOT}" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
plugin_root = sys.argv[2]
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
    for plugin in data.get("plugins", []):
        if plugin.get("name") == "src-guarded-workflow":
            plugin.setdefault("source", {})["path"] = "./src-workflow"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

"${PYTHON}" - "${PLUGIN_ROOT}/mcp.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["mcpServers"]["srcGuardedWorkflow"]["command"] = sys.executable
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

"${PYTHON}" -m pip install -r "${PLUGIN_ROOT}/requirements.txt"

codex plugin marketplace add "${BUNDLE_ROOT}" --json || true
codex plugin add 'src-guarded-workflow@codex-local' --json

echo "Migration complete."
echo "Restart Codex desktop, then start a new chat and provide the SRC program, authorized asset, and authorization confirmation."
