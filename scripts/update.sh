#!/bin/bash
# Update Script for Omni-Hack Terminal

echo "🔄 Updating Omni-Hack Terminal..."

# Pull latest changes from git
git pull origin main

# Update permissions
chmod +x omni_terminal.py
chmod +x scripts/*.sh

echo "✅ Update complete!"
