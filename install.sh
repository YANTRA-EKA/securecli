#!/bin/bash

echo "🔐 Installing SecureCLI..."

# Clone the repo if not already
if [ ! -d "securecli" ]; then
  git clone https://github.com/YOUR_USERNAME/securecli.git
fi

cd securecli

# Make the script executable
chmod +x securecli.py

# Rename (optional)
mv securecli.py securecli

# Move to /usr/local/bin
sudo mv securecli /usr/local/bin/

echo "✅ SecureCLI installed! Try running: securecli -h"
