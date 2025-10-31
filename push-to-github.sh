#!/bin/bash

# Script to push project to GitHub
# Usage: ./push-to-github.sh YOUR-GITHUB-USERNAME

if [ -z "$1" ]; then
    echo "Usage: ./push-to-github.sh YOUR-GITHUB-USERNAME"
    echo "Example: ./push-to-github.sh john-doe"
    exit 1
fi

USERNAME=$1
REPO_NAME="phishing-automation-tool"

echo "🚀 Pushing to GitHub..."
echo "Repository: https://github.com/$USERNAME/$REPO_NAME"
echo ""

# Add remote
git remote add origin "https://github.com/$USERNAME/$REPO_NAME.git" 2>/dev/null || \
git remote set-url origin "https://github.com/$USERNAME/$REPO_NAME.git"

# Rename branch to main
git branch -M main

# Push to GitHub
echo "Pushing to GitHub..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Success! Your project is now on GitHub!"
    echo "View it at: https://github.com/$USERNAME/$REPO_NAME"
else
    echo ""
    echo "❌ Push failed. Make sure:"
    echo "  1. The repository exists on GitHub"
    echo "  2. You have a Personal Access Token (not password)"
    echo "  3. Your username is correct"
fi
