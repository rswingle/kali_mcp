#!/bin/bash
# Wrapper script to debug what arguments LM Studio passes to docker

echo "[$(date -Iseconds)] Docker MCP Wrapper" >> /tmp/mcp_debug.log
echo "  Args: $@" >> /tmp/mcp_debug.log
echo "  Arg count: $#"

# Log all arguments
i=1
for arg in "$@"; do
    echo "  Arg $i: '$arg'" >> /tmp/mcp_debug.log
    i=$((i + 1))
done

# Pass through to docker
echo "  Running: docker $@" >> /tmp/mcp_debug.log
docker "$@"
