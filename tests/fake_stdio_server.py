#!/usr/bin/env python3
"""Minimal fake MCP stdio server for emcp integration tests.

Modes:
  modern  - stateless 2026-07-28 era: answers server/discover, requires
            _meta on every request.
  legacy  - initialize-era: errors on server/discover, expects the
            initialize handshake.
"""
import json
import sys


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "modern"
    initialized = False
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}
        if msg_id is None:
            continue  # notification (e.g. notifications/initialized)
        if mode == "modern":
            meta = params.get("_meta") or {}
            if meta.get("io.modelcontextprotocol/protocolVersion") != "2026-07-28":
                reply(msg_id, error={"code": -32022,
                                     "message": "Unsupported protocol version",
                                     "data": {"supported": ["2026-07-28"]}})
                continue
            if method == "server/discover":
                reply(msg_id, {"resultType": "complete",
                               "serverInfo": {"name": "fake-stdio",
                                              "version": "1.0"},
                               "protocolVersions": ["2026-07-28"],
                               "capabilities": {}})
            elif method == "tools/list":
                reply(msg_id, {"resultType": "complete",
                               "tools": [{"name": "echo",
                                          "inputSchema": {"type": "object"}}]})
            elif method == "tools/call":
                reply(msg_id, {"resultType": "complete",
                               "echoed": params.get("arguments")})
            else:
                reply(msg_id, error={"code": -32601,
                                     "message": "Method not found"})
        else:  # legacy
            if method == "initialize":
                initialized = True
                reply(msg_id, {"protocolVersion":
                               params.get("protocolVersion", "2025-06-18"),
                               "serverInfo": {"name": "fake-stdio-legacy",
                                              "version": "0.9"},
                               "capabilities": {}})
            elif not initialized:
                reply(msg_id, error={"code": -32601,
                                     "message": "Method not found"})
            elif method == "tools/list":
                reply(msg_id, {"tools": [{"name": "old_echo",
                                          "inputSchema": {"type": "object"}}]})
            else:
                reply(msg_id, error={"code": -32601,
                                     "message": "Method not found"})


if __name__ == "__main__":
    main()
