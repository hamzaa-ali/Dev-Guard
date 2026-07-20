#!/bin/sh
# ═══════════════════════════════════════════════════════════
# DevGuard Git Hook Setup Script (Mac/Linux)
#
# Run this script once to install the pre-push hook.
# After installation, every git push will be scanned.
#
# Usage:
#   sh git_hooks/setup-hooks.sh
# ═══════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   DevGuard Hook Setup (Mac/Linux)        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check if .git folder exists
if [ ! -d ".git" ]; then
    echo "ERROR: Run this script from the root of your git repository."
    echo "       You must be in the folder that contains the .git folder."
    echo ""
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Copy the pre-push hook
echo "Installing pre-push hook..."
cp git_hooks/pre-push .git/hooks/pre-push

# Make it executable (required on Mac/Linux)
chmod +x .git/hooks/pre-push

echo ""
echo "✅ Pre-push hook installed successfully!"
echo ""
echo "   From now on, every git push will be scanned"
echo "   for hardcoded secrets before leaving your machine."
echo ""
echo "   To test: try pushing a file with a fake API key."
echo "   The push will be blocked automatically."
echo ""