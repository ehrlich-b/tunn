#!/usr/bin/env python3
"""Read-only stdio MCP example: no files, network, credentials or dependencies."""
import json
import sys


def respond(request):
    if "id" not in request:  # Notifications have no response.
        return None
    method = request.get("method")
    params = request.get("params") or {}
    if method == "initialize":
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-03-26"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tunn-echo-demo", "version": "1.0.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{
            "name": "echo", "description": "Return your message without any side effects.",
            "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"], "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        }]}
    elif method == "tools/call" and params.get("name") == "echo":
        message = (params.get("arguments") or {}).get("message")
        if not isinstance(message, str) or len(message) > 10000:
            return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32602, "message": "message must be a string of at most 10000 characters"}}
        result = {"content": [{"type": "text", "text": message}], "isError": False}
    else:
        return {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32601, "message": "Method or tool not found"}}
    return {"jsonrpc": "2.0", "id": request["id"], "result": result}


if __name__ == "__main__":
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Expected an object")
            response = respond(request)
        except (ValueError, TypeError, AttributeError):
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON-RPC request"}}
        if response is not None:
            print(json.dumps(response), flush=True)
