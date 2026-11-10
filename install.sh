#!/usr/bin/env bash
set -euo pipefail

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_ROOT="${INSTALL_ROOT:-$HOME}"
SKILL_TARGET="${HOME_ROOT}/.agents/skills/src-bug-bounty"
PLUGIN_TARGET="${HOME_ROOT}/.agents/plugins/src-guarded-workflow"
MARKETPLACE_ROOT="${HOME_ROOT}/.agents/plugins"
MARKETPLACE_PATH="${MARKETPLACE_ROOT}/marketplace.json"

if [[ -e "${SKILL_TARGET}" || -e "${PLUGIN_TARGET}" ]]; then
  echo "Target already exists. Remove it or update the existing install before retrying." >&2
  exit 1
fi

mkdir -p "${SKILL_TARGET}" "${PLUGIN_TARGET}" "${MARKETPLACE_ROOT}"
cp "${SOURCE}/skills/src-bug-bounty/SKILL.md" "${SKILL_TARGET}/"
cp -R "${SOURCE}/skills/src-bug-bounty/references" "${SKILL_TARGET}/"
for item in plugin.json mcp.json .codex-plugin skills scripts server schemas templates config knowledge requirements.txt README.md CHANGELOG.md AGENTS.md LICENSE THIRD_PARTY_NOTICES.md; do
  if [[ -e "${SOURCE}/${item}" ]]; then
    cp -R "${SOURCE}/${item}" "${PLUGIN_TARGET}/"
  fi
done

python - "${MARKETPLACE_PATH}" "${PLUGIN_TARGET}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
plugin_target = sys.argv[2]
entry = {
    "name": "src-guarded-workflow",
    "source": {"source": "local", "path": "./.agents/plugins/src-guarded-workflow"},
    "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
    "category": "Security",
}
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
else:
    data = {"name": "codex-local", "plugins": []}
data["plugins"] = [item for item in data.get("plugins", []) if item.get("name") != entry["name"]]
data["plugins"].append(entry)
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

python -m pip install -r "${PLUGIN_TARGET}/requirements.txt"
echo "Installed skill: ${SKILL_TARGET}"
echo "Installed plugin: ${PLUGIN_TARGET}"
echo "Restart Codex desktop, then enable src-guarded-workflow from the local marketplace."


