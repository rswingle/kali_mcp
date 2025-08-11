from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# List of allowed directories
allowed_directories = ['/opt/kali_mcp']

@app.route('/tool/<string:tool>', methods=['POST'])
def execute_tool(tool):
    # TODO: Implement tool execution logic here
    pass

# Endpoint for listing allowed directories
@app.route('/allowed')
def list_allowed():
    # TODO: Implement directory listing logic here
    pass

if __name__ == '__main__':
    app.run(port=3001)
