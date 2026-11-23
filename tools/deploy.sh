#!/usr/bin/env bash
# Install the committed tip of a branch (default main) into a dedicated virtual environment, so
# the deployed CLI and MCP server never run uncommitted or feature-branch code from the checkout.
#
#   tools/deploy.sh                 install or update the deployment
#   tools/deploy.sh --hooks         also install git hooks that redeploy when the branch moves
#   tools/deploy.sh --mcp           also register `retrore mcp` with Claude Code (user scope)
#
# Environment: RETRORE_DEPLOY_DIR (default ~/.local/share/retrore), RETRORE_DEPLOY_BRANCH (main),
# RETRORE_BIN_DIR (default ~/.local/bin), GHIDRA_HOME (default /snap/ghidra/current/ghidra).
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
branch=${RETRORE_DEPLOY_BRANCH:-main}
deploy=${RETRORE_DEPLOY_DIR:-$HOME/.local/share/retrore}
bin_dir=${RETRORE_BIN_DIR:-$HOME/.local/bin}
ghidra=${GHIDRA_HOME:-/snap/ghidra/current/ghidra}
python=${PYTHON:-python3}

install_hooks=0
register_mcp=0
for arg in "$@"; do
    case $arg in
        --hooks) install_hooks=1 ;;
        --mcp) register_mcp=1 ;;
        *) echo "usage: $0 [--hooks] [--mcp]" >&2; exit 2 ;;
    esac
done

commit=$(git -C "$repo" rev-parse --verify "$branch^{commit}")
mkdir -p "$deploy" "$bin_dir"
if [ ! -x "$deploy/venv/bin/python" ]; then
    "$python" -m venv "$deploy/venv"
fi

# pip clones the commit itself, so uncommitted changes never reach the deployment.
"$deploy/venv/bin/python" -m pip install --quiet --force-reinstall --upgrade-strategy only-if-needed \
    "retrore @ git+file://$repo@$commit"
echo "$commit" > "$deploy/COMMIT"

# A wrapper that supplies GHIDRA_HOME when the caller has not set it.
cat > "$bin_dir/retrore" <<EOF
#!/bin/sh
: "\${GHIDRA_HOME:=$ghidra}"
export GHIDRA_HOME
exec "$deploy/venv/bin/retrore" "\$@"
EOF
chmod +x "$bin_dir/retrore"

if [ "$install_hooks" = 1 ]; then
    hooks=$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)/hooks
    for hook in post-commit post-merge post-rewrite; do
        cat > "$hooks/$hook" <<EOF
#!/bin/sh
# Installed by tools/deploy.sh: redeploy retrore when $branch moves in the main checkout.
[ "\$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" = "$branch" ] || exit 0
[ "\$(git rev-parse $branch)" = "\$(cat "$deploy/COMMIT" 2>/dev/null)" ] && exit 0
nohup "$repo/tools/deploy.sh" > "$deploy/deploy.log" 2>&1 &
EOF
        chmod +x "$hooks/$hook"
    done
fi

if [ "$register_mcp" = 1 ]; then
    if claude mcp get retrore > /dev/null 2>&1; then
        echo "Claude Code already has an MCP server named retrore; leaving it unchanged"
    else
        claude mcp add --scope user retrore -e "GHIDRA_HOME=$ghidra" -- "$bin_dir/retrore" mcp
    fi
fi

echo "retrore $(git -C "$repo" log -1 --format='%h %s' "$commit") deployed to $deploy"
