#!/usr/bin/env python3
"""Small newline-delimited stdio MCP server for local end-to-end tests."""

import json
import sys


def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)


for line in sys.stdin:
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue

    request_id = request.get("id")
    method = request.get("method")
    if method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "tunn-e2e", "version": "1"},
                },
            }
        )
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echo text through tunn",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                            },
                        },
                        {
                            "name": "dangerous",
                            "description": "Must be removed by the local policy",
                            "inputSchema": {"type": "object"},
                        },
                    ]
                },
            }
        )
    elif method == "tools/call":
        params = request.get("params", {})
        name = params.get("name")
        if name == "echo":
            arguments = params.get("arguments", {})
            # Fault injection is confined to this synthetic, read-only fixture.
            if arguments.get("stall"):
                continue
            if arguments.get("exit"):
                sys.exit(0)
            text = arguments.get("text", "")
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "tunn-e2e:" + text}]
                    },
                }
            )
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "unknown tool"},
                }
            )
    elif request_id is not None:
        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        )
