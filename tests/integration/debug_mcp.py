import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
    server_params = StdioServerParameters(
        command=sys.executable, args=[server_script], env=None
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            result = await session.initialize()
            print("Initialize result:", result)

            info = getattr(session, "server_info", getattr(session, "serverInfo", None))
            print("session.server_info =", info)

            tools = await session.list_tools()
            print("session.list_tools =", tools)
            print("dir(session) =", dir(session))


asyncio.run(main())
