import socket
import uvicorn
from mcp.server.fastmcp import FastMCP
sdk = FastMCP("independent-review")
@sdk.tool()
def echo(text: str) -> str:
    return text
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(f"http://127.0.0.1:{sock.getsockname()[1]}", flush=True)
uvicorn.Server(uvicorn.Config(sdk.streamable_http_app(), log_level="warning")).run(sockets=[sock])
