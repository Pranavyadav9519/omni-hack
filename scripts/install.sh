#!/bin/bash
# Omni-Hack Terminal Installation Script

echo "🚀 Installing Omni-Hack Terminal..."

# Check Python
python3 --version >/dev/null 2>&1 || { echo "❌ Python3 required"; exit 1; }

# Make executable
chmod +x omni_terminal.py

# Install system-wide
sudo cp omni_terminal.py /usr/local/bin/omni-hack 2>/dev/null

echo "✅ Installation complete!"
echo "🎉 Run 'omni-hack' to start!"
