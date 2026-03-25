#!/bin/bash
# ============================================
# github_setup.sh
# Run this ONCE to initialize git and push
# to GitHub for the first time.
# ============================================

set -e

echo ""
echo "================================================"
echo "  OSINT Recon Tool — GitHub Setup Script"
echo "================================================"
echo ""

# --- Check git is installed ---
if ! command -v git &> /dev/null; then
    echo "❌  git is not installed. Please install it first."
    exit 1
fi

# --- Prompt for GitHub username and repo name ---
read -p "Enter your GitHub username: " GH_USER
read -p "Enter your new repo name (e.g. osint-recon-tool): " REPO_NAME
read -p "Make repo private? (y/n): " PRIVATE

VISIBILITY="public"
if [[ "$PRIVATE" == "y" || "$PRIVATE" == "Y" ]]; then
    VISIBILITY="private"
fi

echo ""
echo "→ GitHub User : $GH_USER"
echo "→ Repo Name   : $REPO_NAME"
echo "→ Visibility  : $VISIBILITY"
echo ""

# --- Initialize git ---
git init
git add .
git commit -m "🚀 Initial commit — OSINT Recon Tool v1.0.0"

# --- Create repo on GitHub using gh CLI (if available) ---
if command -v gh &> /dev/null; then
    echo "→ Creating GitHub repository using gh CLI..."
    gh repo create "$REPO_NAME" --$VISIBILITY --source=. --remote=origin --push
    echo ""
    echo "✅  Done! Repository created and pushed."
    echo "🔗  https://github.com/$GH_USER/$REPO_NAME"
else
    echo "⚠️  GitHub CLI (gh) not found. Doing manual setup..."
    echo ""
    echo "Please:"
    echo "  1. Go to https://github.com/new"
    echo "  2. Create a new repo named: $REPO_NAME"
    echo "  3. Run the following commands:"
    echo ""
    echo "     git remote add origin https://github.com/$GH_USER/$REPO_NAME.git"
    echo "     git branch -M main"
    echo "     git push -u origin main"
    echo ""
fi

echo ""
echo "================================================"
echo "  Daily Git Workflow (after initial setup):"
echo "================================================"
echo ""
echo "  git add ."
echo "  git commit -m 'your message here'"
echo "  git push"
echo ""
echo "================================================"
echo "  Install GitHub CLI (optional, makes it easier):"
echo "================================================"
echo ""
echo "  macOS:  brew install gh"
echo "  Linux:  https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
echo "  Then:   gh auth login"
echo ""
