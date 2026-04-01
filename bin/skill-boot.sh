#!/bin/bash

# skill-boot.sh - Bootstraps a security analysis workspace with skills from sec-skillz

# Exit immediately if a command exits with a non-zero status
set -e

echo "🚀 Bootstrapping security analysis workspace..."

# 1. Add or Initialize submodule if missing
# If sec-skillz isn't here, or is empty, try to set it up.
if [ ! -d "sec-skillz" ] || [ -z "$(ls -A sec-skillz 2>/dev/null)" ]; then
    # Check if we are in a git repository
    if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        # Check if we are at the top-level of the git repository
        GIT_ROOT=$(git rev-parse --show-toplevel)
        CURRENT_DIR=$(pwd)
        
        if [ "$GIT_ROOT" != "$CURRENT_DIR" ]; then
            echo "❌ Error: You must run this script from the root of your git repository."
            echo "Root detected at: $GIT_ROOT"
            exit 1
        fi

        # Check if sec-skillz is already tracked by git (in the index)
        if git ls-files --stage sec-skillz | grep -q "^160000"; then
            echo "📦 sec-skillz detected in git index. Initializing..."
            if ! git submodule update --init --recursive; then
                echo "❌ Error: 'git submodule update --init' failed."
                exit 1
            fi
        else
            echo "📦 Adding sec-skillz as a git submodule..."
            # Use --force to handle cases where local git metadata exists but the directory is gone
            if ! git submodule add --force git@github.com:mdfranz/sec-skillz.git sec-skillz; then
                echo "❌ Error: 'git submodule add' failed."
                echo "   If issues persist, try: git rm -r --cached sec-skillz && rm -rf .git/modules/sec-skillz"
                exit 1
            fi
        fi
    elif [ ! -d "skills" ]; then
        echo "❌ Error: Not a git repository and 'sec-skillz' directory not found."
        echo "Please run this script from the root of a git-managed workspace."
        exit 1
    fi
fi

# 2. Identify the location of sec-skillz
if [ -d "sec-skillz/skills" ]; then
    SEC_SKILLZ_PATH="sec-skillz"
elif [ -d "skills" ] && [ -f "README.md" ] && grep -q "Security Skillz" README.md; then
    # If running from within the sec-skillz repo itself
    echo "ℹ️ Detected running from within sec-skillz repository."
    SEC_SKILLZ_PATH="."
else
    echo "❌ Error: Could not find 'sec-skillz/skills' directory even after attempt."
    exit 1
fi

# 3. Create CLI configuration directories
echo "📁 Creating CLI configuration directories..."
mkdir -p .gemini .claude .codex

# 4. Create symlinks to skills
# The symlinks use relative paths so they remain valid across different environments.
echo "🔗 Creating symlinks to skills..."

create_skill_link() {
    local cli_dir=$1
    local target="../$SEC_SKILLZ_PATH/skills"
    local link="$cli_dir/skills"

    if [ -L "$link" ]; then
        echo "   (Skipping) Symlink already exists: $link"
    elif [ -e "$link" ]; then
        echo "   ⚠️ Warning: File already exists at $link and is not a symlink."
    else
        ln -s "$target" "$link"
        echo "   ✅ Created: $link -> $target"
    fi
}

create_skill_link ".gemini"
create_skill_link ".claude"
create_skill_link ".codex"

echo "✨ Workspace bootstrap complete!"
echo "You can now use skills in Gemini CLI, Claude Code, and Codex."
