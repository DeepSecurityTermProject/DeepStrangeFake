import json
import sys
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.mcp_client import CveMcpClient, MCPClient
from audit_agent.memory import LexicalMemoryStore, MemoryIndexer
from audit_agent.message_bus import MessageBus, replay_messages
from audit_agent.repository import analyze_target

from tests.test_repository_analysis import create_vulnerable_fixture


FAKE_MCP_SERVER = r"""
import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {"serverInfo": {"name": "fake-cve-mcp"}, "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": [
            {"name": "lookup_cve", "description": "Lookup CVE", "inputSchema": {"type": "object"}},
            {"name": "get_epss_score", "description": "EPSS", "inputSchema": {"type": "object"}}
        ]}
    elif method == "tools/call":
        name = request["params"]["name"]
        if name == "lookup_cve":
            result = {"content": [{"type": "text", "text": "{\"cve_id\":\"CVE-2099-0001\",\"cvss\":9.1,\"cwe_ids\":[\"CWE-89\"]}"}]}
        else:
            result = {"content": [{"type": "text", "text": "{\"epss\":0.73}"}]}
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}) + "\n")
    sys.stdout.flush()
"""


class McpMemoryBusRuntimeTests(unittest.TestCase):
    def test_stdio_mcp_client_discovers_and_calls_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp) / "fake_mcp.py"
            server.write_text(FAKE_MCP_SERVER, encoding="utf-8")
            client = MCPClient(command=[sys.executable, str(server)], timeout_seconds=5)

            with client:
                tools = client.list_tools()
                result = client.call_tool("lookup_cve", {"cve_id": "CVE-2099-0001"})

            self.assertIn("lookup_cve", {tool.name for tool in tools})
            self.assertTrue(result.success)
            self.assertEqual(result.tool_name, "lookup_cve")
            self.assertEqual(result.response["cve_id"], "CVE-2099-0001")

    def test_cve_mcp_client_degrades_when_server_missing(self):
        client = CveMcpClient(command=["definitely-missing-mcp"])

        intel = client.lookup_cve("CVE-2099-0001")

        self.assertTrue(intel.raw["degraded"])
        self.assertFalse(intel.validation_evidence)

    def test_memory_indexer_retrieves_cited_chunks_and_invalidates_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            store = LexicalMemoryStore(Path(tmp) / "memory")
            indexer = MemoryIndexer(store)

            records = indexer.index_repository(metadata)
            results = store.retrieve("os.system request args", limit=3)
            first_id = results[0].record.id

            app = project / "app.py"
            app.write_text(app.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
            stale = store.stale_records(analyze_target(str(project)))

            self.assertTrue(records)
            self.assertEqual(results[0].record.source_path, "app.py")
            self.assertTrue(results[0].citation)
            self.assertIn(first_id, {record.id for record in stale})

    def test_message_bus_persists_and_replays_envelopes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bus = MessageBus(run_id="run-1", log_path=Path(tmp) / "messages.jsonl")
            observed = []
            bus.subscribe("tool.result", lambda envelope: observed.append(envelope.message_id))

            sent = bus.publish(
                sender="tool-protocol",
                recipient="analysis",
                message_type="tool.result",
                payload={"tool": "source-context"},
                correlation_id="corr-1",
            )
            replayed = replay_messages(Path(tmp) / "messages.jsonl")

            self.assertEqual(observed, [sent.message_id])
            self.assertEqual(replayed[0].message_id, sent.message_id)
            self.assertEqual(replayed[0].correlation_id, "corr-1")


if __name__ == "__main__":
    unittest.main()
