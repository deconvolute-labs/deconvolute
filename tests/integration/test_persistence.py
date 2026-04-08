import sqlite3

from deconvolute.core.firewall import MCPFirewall
from deconvolute.core.types import ToolInterface
from deconvolute.models.policy import PolicyAction, SecurityPolicy, ServerPolicy


def test_agent_id_written_to_db(isolated_cache_dir):
    """
    End-to-end: agent_id passed to mcp_guard flows into both SQLite tables.

    Constructs MCPFirewall directly (the same object mcp_guard creates) with
    agent_id="my-agent", triggers tool discovery, and asserts the value is
    present in both pinned_tools and audit_queue.
    """
    policy = SecurityPolicy(
        version="2.0",
        default_action=PolicyAction.ALLOW,
        servers={"test-server": ServerPolicy(tools=[])},
    )

    firewall = MCPFirewall(policy, agent_id="my-agent")
    assert firewall.registry.agent_id == "my-agent"

    firewall.set_server("test-server", "1.0.0")
    tool_def: ToolInterface = {
        "name": "demo_tool",
        "description": "A demo tool",
        "input_schema": {},
    }
    firewall.check_tool_list([tool_def])

    store = firewall.registry.store
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT agent_id FROM pinned_tools WHERE tool_name='demo_tool'")
        row = cursor.fetchone()
        assert row is not None, "demo_tool should be pinned"
        assert row["agent_id"] == "my-agent"

        cursor.execute(
            "SELECT agent_id FROM audit_queue WHERE event_type='TOOL_PINNED'"
        )
        row = cursor.fetchone()
        assert row is not None, "TOOL_PINNED event should be logged"
        assert row["agent_id"] == "my-agent"
        assert row["agent_id"] == "my-agent"
