#!/bin/bash
# Debug script to see what arguments LM Studio passes

echo "Args received: $@" > /tmp/mcp_debug.log
echo "Arg count: $#"
for i, arg in enumerate($@):
    echo "Arg $i: $arg" >> /tmp/mcp_debug.log
