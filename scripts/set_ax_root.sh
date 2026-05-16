#/bin/bash

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <AX_ROOT>"
    exit 1
fi

AX_ROOT=$1
PROJECT_ROOT=$(pwd)
CONFIG_DIR="$PROJECT_ROOT/.cargo"
AX_ROOT_REL=$(python3 - "$PROJECT_ROOT" "$AX_ROOT" <<'PY'
import os
import sys

project_root = os.path.realpath(sys.argv[1])
ax_root = os.path.realpath(sys.argv[2])
print(os.path.relpath(ax_root, project_root))
PY
)
VENDOR_REL=$(python3 - "$PROJECT_ROOT" "$PROJECT_ROOT/vendor" <<'PY'
import os
import sys

project_root = os.path.realpath(sys.argv[1])
vendor_dir = os.path.realpath(sys.argv[2])
print(os.path.relpath(vendor_dir, project_root))
PY
)

mkdir -p "$CONFIG_DIR"
sed \
    -e "s|%AX_ROOT%|$AX_ROOT_REL|g" \
    -e "s|%VENDOR_DIR%|$VENDOR_REL|g" \
    scripts/config.toml.temp > "$CONFIG_DIR/config.toml"

echo "Set AX_ROOT (ArceOS directory) to $AX_ROOT"
