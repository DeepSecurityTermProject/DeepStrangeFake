import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from audit_agent.config import AuditConfig, DependencyIntelligenceConfig
from audit_agent.dependency_intelligence import (
    CommandMcpBatchProvider,
    DependencyBatchResponse,
    DependencyIntelligenceService,
    RuntimeMcpBatchProvider,
    dependency_key,
    normalize_dependency_batch_response,
    serialize_dependency_list,
)
from audit_agent.models import Dependency, ToolObservation, VulnerabilityIntelligence
from audit_agent.pipeline import run_audit


def dependency(name: str, version: str, manifest: str = "requirements.txt") -> Dependency:
    return Dependency(
        ecosystem="pypi",
        name=name,
        version=version,
        manifest_path=manifest,
        identifiers={"purl": f"pkg:pypi/{name}@{version}"},
    )


class RecordingProvider:
    def __init__(self, vulnerable: set[str] | None = None):
        self.vulnerable = vulnerable or set()
        self.calls: list[list[str]] = []

    def query(self, dependencies: list[Dependency]) -> DependencyBatchResponse:
        self.calls.append([dependency_key(item) for item in dependencies])
        records = {}
        for item in dependencies:
            key = dependency_key(item)
            records[key] = []
            if item.name in self.vulnerable:
                records[key].append(
                    VulnerabilityIntelligence(
                        tool_name="fake-cve-mcp",
                        query={"dependency_key": key},
                        cve_id=f"CVE-2099-{len(self.calls):04d}",
                        cwe_ids=["CWE-1104"],
                        cvss=8.1,
                        references=["https://example.invalid/advisory"],
                    )
                )
        return DependencyBatchResponse(True, records)


class GroupingProvider(RecordingProvider):
    @staticmethod
    def batch_key(item: Dependency) -> str:
        return "maven" if item.ecosystem.lower() == "maven" else "generic"


class FakeRuntimeMcpClient:
    def __init__(self, response_text: str):
        self.response_text = response_text
        self.session = SimpleNamespace(initialized=True, message="")
        self.arguments: list[dict] = []

    def start(self) -> None:
        return None

    def close(self) -> None:
        return None

    def list_tools(self):
        return [
            SimpleNamespace(
                name="scan_dependencies",
                input_schema={
                    "type": "object",
                    "properties": {"dependency_list": {"type": "string"}},
                    "required": ["dependency_list"],
                },
            )
        ]

    def call_tool(self, name: str, arguments: dict):
        self.arguments.append(arguments)
        return SimpleNamespace(
            success=True,
            response={"text": self.response_text},
            message="",
        )


class FakeCommandAdapter:
    tool_name = "fake-command-mcp"

    def __init__(self, response_text: str):
        self.response_text = response_text
        self.calls: list[tuple[str, dict]] = []

    def query(self, tool: str, payload: dict) -> ToolObservation:
        self.calls.append((tool, payload))
        return ToolObservation(
            tool_name=self.tool_name,
            kind="vulnerability-intelligence",
            message=self.response_text,
            success=True,
        )


class DependencyIntelligenceTests(unittest.TestCase):
    def test_dependency_list_normalizes_manifest_ranges_and_osv_ecosystems(self):
        dependencies = [
            Dependency("npm", "react", "^19.2.3", "package.json", {}),
            Dependency("cargo", "serde", "~1.0.228", "Cargo.toml", {}),
            Dependency("pypi", "requests", ">=2.19.0,<3", "requirements.txt", {}),
        ]

        self.assertEqual(
            serialize_dependency_list(dependencies),
            "react:npm:19.2.3\nserde:crates.io:1.0.228\nrequests:PyPI:2.19.0",
        )

    def test_runtime_provider_uses_real_dependency_list_schema_and_parses_text(self):
        dependencies = [dependency("alpha", "1.0"), dependency("bravo", "2.0")]
        text = """
Dependency Scan Results  (1 vulnerable out of 2 packages)

  PyPI/alpha@1.0  -> 1 vulnerability/vulnerabilities
    [HIGH] GHSA-AAAA-BBBB-CCCC  (CVE-2099-0042): example advisory
""".strip()
        provider = RuntimeMcpBatchProvider([], 15, 10, ["scan_dependencies"], None, {})
        fake_client = FakeRuntimeMcpClient(text)
        provider.client = fake_client
        provider._started = True

        response = provider.query(dependencies)

        self.assertTrue(response.success, response.message)
        self.assertEqual(
            fake_client.arguments,
            [{"dependency_list": "alpha:PyPI:1.0\nbravo:PyPI:2.0"}],
        )
        record = response.records_by_dependency["pypi:alpha@1.0"][0]
        self.assertEqual(record.cve_id, "CVE-2099-0042")
        self.assertEqual(record.raw["id"], "GHSA-AAAA-BBBB-CCCC")
        self.assertEqual(record.raw["severity"], "HIGH")
        self.assertEqual(response.records_by_dependency["pypi:bravo@2.0"], [])

    def test_command_provider_uses_real_contract_and_accepts_negative_text_result(self):
        dependencies = [dependency("alpha", "1.0"), dependency("bravo", "2.0")]
        adapter = FakeCommandAdapter(
            "No known vulnerabilities found in 2 scanned packages. (via OSV.dev)"
        )

        response = CommandMcpBatchProvider(adapter).query(dependencies)

        self.assertTrue(response.success, response.message)
        self.assertEqual(
            adapter.calls,
            [
                (
                    "scan_dependencies",
                    {"dependency_list": "alpha:PyPI:1.0\nbravo:PyPI:2.0"},
                )
            ],
        )
        self.assertTrue(all(not records for records in response.records_by_dependency.values()))

    def test_real_text_contract_fails_closed_on_errors_or_identity_mismatch(self):
        dependencies = [dependency("alpha", "1.0"), dependency("bravo", "2.0")]
        error = normalize_dependency_batch_response(
            {"text": "Dependency scan error: OSV unavailable"},
            dependencies,
            "fake-cve-mcp",
        )
        self.assertFalse(error.success)
        mismatch = normalize_dependency_batch_response(
            {
                "text": (
                    "Dependency Scan Results  (1 vulnerable out of 2 packages)\n\n"
                    "  PyPI/unknown@9.9  -> 1 vulnerability/vulnerabilities\n"
                    "    [HIGH] GHSA-AAAA-BBBB-CCCC: unknown package"
                )
            },
            dependencies,
            "fake-cve-mcp",
        )
        self.assertFalse(mismatch.success)
        self.assertIn("unambiguous dependency identity", mismatch.message)

    def test_provider_batch_key_partitions_maven_from_generic_dependencies(self):
        dependencies = [
            dependency("alpha", "1.0"),
            Dependency(
                ecosystem="maven",
                name="org.example:demo",
                version="2.0",
                manifest_path="pom.xml",
                identifiers={},
            ),
            dependency("bravo", "3.0"),
        ]
        provider = GroupingProvider()

        result = DependencyIntelligenceService(
            provider,
            batch_size=20,
            query_budget=10,
            cache_path=None,
            cache_ttl_seconds=0,
        ).scan(dependencies)

        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(result.summary["queries_used"], 2)
        self.assertEqual(
            provider.calls,
            [
                ["pypi:alpha@1.0", "pypi:bravo@3.0"],
                ["maven:org.example:demo@2.0"],
            ],
        )

    def test_disabled_provider_is_explicitly_incomplete_not_successful_zero_findings(self):
        result = DependencyIntelligenceService(
            None,
            batch_size=20,
            query_budget=10,
            cache_path=None,
            cache_ttl_seconds=0,
        ).scan([dependency("alpha", "1.0"), dependency("bravo", "2.0")])

        self.assertFalse(result.tool_result.success)
        self.assertFalse(result.summary["complete"])
        self.assertEqual(result.summary["disabled_count"], 2)
        self.assertEqual(result.summary["unqueried_dependency_count"], 2)

    def test_all_unique_dependencies_are_batched_and_duplicates_keep_manifest_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            dependencies = [
                dependency("alpha", "1.0", "requirements.txt"),
                dependency("bravo", "2.0", "requirements.txt"),
                dependency("alpha", "1.0", "services/api/requirements.txt"),
                dependency("charlie", "3.0", "services/api/requirements.txt"),
            ]
            provider = RecordingProvider({"alpha", "charlie"})
            service = DependencyIntelligenceService(
                provider,
                batch_size=2,
                query_budget=10,
                cache_path=Path(tmp) / "cache.json",
                cache_ttl_seconds=3600,
            )

            result = service.scan(dependencies)

            self.assertEqual(len(provider.calls), 2)
            self.assertEqual(result.summary["input_dependency_count"], 4)
            self.assertEqual(result.summary["unique_dependency_count"], 3)
            self.assertEqual(result.summary["queries_used"], 2)
            alpha = next(
                item for item in result.summary["items"]
                if item["dependency_key"] == "pypi:alpha@1.0"
            )
            self.assertEqual(
                alpha["manifest_paths"],
                ["requirements.txt", "services/api/requirements.txt"],
            )
            self.assertEqual(len(result.tool_result.observations), 2)

    def test_positive_and_negative_cache_hits_do_not_consume_query_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "cache.json"
            dependencies = [dependency("alpha", "1.0"), dependency("bravo", "2.0")]
            first_provider = RecordingProvider({"alpha"})
            first = DependencyIntelligenceService(
                first_provider,
                batch_size=20,
                query_budget=1,
                cache_path=cache_path,
                cache_ttl_seconds=3600,
            ).scan(dependencies)
            self.assertEqual(first.summary["queries_used"], 1)
            self.assertTrue(cache_path.exists())

            second_provider = RecordingProvider({"bravo"})
            second = DependencyIntelligenceService(
                second_provider,
                batch_size=1,
                query_budget=0,
                cache_path=cache_path,
                cache_ttl_seconds=3600,
            ).scan(dependencies)

            self.assertEqual(second_provider.calls, [])
            self.assertEqual(second.summary["cache_hits"], 2)
            self.assertEqual(second.summary["queries_used"], 0)
            self.assertEqual(second.summary["budget_exhausted_count"], 0)
            self.assertEqual(len(second.intelligence), 1)

    def test_query_budget_is_counted_per_batch_and_unqueried_dependencies_are_explicit(self):
        dependencies = [dependency(f"package-{index}", "1.0") for index in range(5)]
        provider = RecordingProvider()
        service = DependencyIntelligenceService(
            provider,
            batch_size=2,
            query_budget=2,
            cache_path=None,
            cache_ttl_seconds=0,
        )

        result = service.scan(dependencies)

        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(result.summary["queries_used"], 2)
        self.assertEqual(result.summary["queried_dependency_count"], 4)
        self.assertEqual(result.summary["budget_exhausted_count"], 1)
        self.assertFalse(result.tool_result.success)
        statuses = [item["status"] for item in result.summary["items"]]
        self.assertEqual(statuses, ["queried", "queried", "queried", "queried", "budget-exhausted"])

    def test_batch_response_requires_unambiguous_dependency_identity(self):
        dependencies = [dependency("alpha", "1.0"), dependency("bravo", "2.0")]
        response = normalize_dependency_batch_response(
            {
                "results": [
                    {
                        "dependency": {"ecosystem": "pypi", "name": "alpha", "version": "1.0"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-AAAA-BBBB-CCCC",
                                "aliases": ["CVE-2099-0042"],
                                "cwe_ids": ["CWE-1104"],
                                "cvss": 7.5,
                            }
                        ],
                    }
                ]
            },
            dependencies,
            "fake-cve-mcp",
        )
        self.assertTrue(response.success)
        self.assertEqual(
            response.records_by_dependency["pypi:alpha@1.0"][0].cve_id,
            "CVE-2099-0042",
        )
        ambiguous = normalize_dependency_batch_response(
            {"vulnerabilities": [{"cve_id": "CVE-2099-9999"}]},
            dependencies,
            "fake-cve-mcp",
        )
        self.assertFalse(ambiguous.success)
        self.assertIn("unambiguous dependency identity", ambiguous.message)

    def test_environment_configuration_validates_batch_cache_and_budget(self):
        config = DependencyIntelligenceConfig.from_environment(
            {
                "AUDIT_DEPENDENCY_INTELLIGENCE_ENABLED": "true",
                "AUDIT_DEPENDENCY_BATCH_SIZE": "7",
                "AUDIT_DEPENDENCY_QUERY_BUDGET": "3",
                "AUDIT_DEPENDENCY_CACHE_POLICY": "per-run",
                "AUDIT_DEPENDENCY_CACHE_PATH": "custom-cache.json",
                "AUDIT_DEPENDENCY_CACHE_TTL_SECONDS": "60",
            }
        )
        self.assertEqual(config.batch_size, 7)
        self.assertEqual(config.query_budget, 3)
        self.assertEqual(config.cache_policy, "per-run")
        self.assertEqual(config.cache_path, "custom-cache.json")
        self.assertEqual(config.cache_ttl_seconds, 60)
        with self.assertRaisesRegex(ValueError, "at most 1000"):
            DependencyIntelligenceConfig(batch_size=1001)

    def test_legacy_and_graph_runtime_convert_all_dependency_results_to_report_evidence(self):
        for graph_mode in ("legacy", "deterministic-graph"):
            with self.subTest(graph_mode=graph_mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                project = root / "project"
                project.mkdir()
                (project / "requirements.txt").write_text(
                    "alpha==1.0\nbravo==2.0\ncharlie==3.0\n",
                    encoding="utf-8",
                )
                fake_server = root / "fake_cve_batch.py"
                fake_server.write_text(
                    """
import json
import sys

payload = json.loads(sys.argv[-1])
lines = [line for line in payload["dependency_list"].splitlines() if line.strip()]
print(f"Dependency Scan Results  ({len(lines)} vulnerable out of {len(lines)} packages)")
for index, line in enumerate(lines, start=1):
    name, ecosystem, version = line.split(":", 2)
    count = 2 if index == 1 else 1
    print(f"  {ecosystem}/{name}@{version}  -> {count} vulnerability/vulnerabilities")
    print(f"    [HIGH] GHSA-2099-0000-{index:04d}  (CVE-2099-{index:04d}): test advisory")
    if index == 1:
        print("    [MEDIUM] GHSA-2099-9999-0001  (CVE-2099-9001): second advisory")
""".strip(),
                    encoding="utf-8",
                )
                config = AuditConfig.default()
                config.graph.mode = graph_mode
                config.runtime_enabled = False
                config.cve_mcp.enabled = True
                config.cve_mcp.command = [sys.executable, str(fake_server)]
                config.cve_mcp.query_budget = 10
                config.dependency_intelligence.batch_size = 2
                config.dependency_intelligence.query_budget = 10
                config.dependency_intelligence.cache_policy = "per-run"
                config.audit_scope.cve_query_budget = 10

                summary = run_audit(str(project), config, root / "runs")
                run_dir = Path(summary["run_dir"])
                report = json.loads(
                    (run_dir / "reports" / "report.json").read_text(encoding="utf-8")
                )
                dependency_summary = report["runtime"]["dependency_intelligence"]

                self.assertEqual(dependency_summary["input_dependency_count"], 3)
                self.assertEqual(dependency_summary["unique_dependency_count"], 3)
                self.assertEqual(dependency_summary["queries_used"], 2)
                self.assertEqual(dependency_summary["budget_exhausted_count"], 0)
                dependency_findings = [
                    item for item in report["findings"]
                    if item["vulnerability_class"] == "dependency-vulnerability"
                ]
                self.assertEqual(len(dependency_findings), 5)
                self.assertTrue(all(item["cve_ids"] for item in dependency_findings))
                self.assertEqual(len(report["evidence_chains"]), 5)
                for chain in report["evidence_chains"]:
                    tool_names = {
                        ref["payload"]["tool_name"]
                        for ref in chain["tool_refs"]
                    }
                    self.assertIn("dependency-intelligence", tool_names)
                self.assertTrue(
                    (run_dir / "intelligence" / "dependency-intelligence-summary.v1.json").exists()
                )
                self.assertTrue(
                    (run_dir / "tool_outputs" / "dependency-intelligence.json").exists()
                )


if __name__ == "__main__":
    unittest.main()
