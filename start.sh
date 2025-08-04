#!/bin/bash

source /opt/venv/bin/activate

#exec uvicorn main:app --host 0.0.0.0 --port 3000

# Start the MCP server in debug mode for development or production mode
if [ "$DEBUG" = "true" ]; then
  echo "Starting MCP server in debug mode..."
  exec /opt/venv/bin/uvicorn main:app --host 0.0.0.0 --port 3000 --reload
else
  echo "Starting MCP server in production mode..."
  # Create logs directory if it doesn't exist
  mkdir -p /var/log/mcp-server

  # Start the server with error logging
  #exec uvicorn main:app --host 0.0.0.0 --port 3000 --log-level info
  exec /opt/venv/bin/uvicorn main:app --host 0.0.0.0 --port 3001
fi
