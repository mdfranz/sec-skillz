#!/bin/bash
# Run AgentOS locally without Docker

# Ensure we are executing from the agno directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for .env file to load keys locally
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
    echo "Loaded environment variables from .env"
fi

echo "Starting AgentOS locally on http://localhost:8000 ..."

# Use uv run if available, otherwise fallback to standard execution
if command -v uv > /dev/null; then
    uv run uvicorn agent_os:app --host 0.0.0.0 --port 8000 --reload
else
    uvicorn agent_os:app --host 0.0.0.0 --port 8000 --reload
fi
