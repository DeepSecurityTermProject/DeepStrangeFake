import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig, AuditScope
from audit_agent.pipeline import run_audit
from audit_agent.repository import analyze_target


def create_scope_fixture(root: Path) -> Path:
    project = root / "scope-app"
    project.mkdir()
    (project / ".gitignore").write_text("ignored_by_gitignore.py\nignored_dir/\n", encoding="utf-8")
    (project / "app.py").write_text("API_KEY = 'sk_live_product_123456'\n", encoding="utf-8")
    (project / "ignored_by_gitignore.py").write_text("API_KEY = 'sk_live_ignored_123456'\n", encoding="utf-8")
    (project / "ignored_dir").mkdir()
    (project / "ignored_dir" / "hidden.py").write_text("API_KEY = 'sk_live_hidden_123456'\n", encoding="utf-8")
    for dirname in ("tests", "fixtures", "external", "openspec", ".codex"):
        (project / dirname).mkdir()
        (project / dirname / "finding.py").write_text(
            "API_KEY = 'sk_live_local_dev_123456'\n",
            encoding="utf-8",
        )
    return project


class ScopeFilteringTests(unittest.TestCase):
    def test_repository_analysis_obeys_default_scope_and_root_gitignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_scope_fixture(Path(tmp))

            metadata = analyze_target(str(project), audit_scope=AuditScope())

            self.assertIn("app.py", metadata.file_tree)
            self.assertNotIn("ignored_by_gitignore.py", metadata.file_tree)
            self.assertNotIn("ignored_dir/hidden.py", metadata.file_tree)
            self.assertNotIn("tests/finding.py", metadata.file_tree)
            self.assertNotIn("fixtures/finding.py", metadata.file_tree)
            self.assertNotIn("external/finding.py", metadata.file_tree)
            self.assertNotIn("openspec/finding.py", metadata.file_tree)
            self.assertNotIn(".codex/finding.py", metadata.file_tree)
            self.assertEqual("product-code", metadata.file_categories["app.py"])

    def test_include_patterns_can_scan_default_excluded_fixture_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_scope_fixture(Path(tmp))

            metadata = analyze_target(
                str(project),
                audit_scope=AuditScope(include_patterns=["fixtures/**"]),
            )

            self.assertEqual(["fixtures/finding.py"], [item for item in metadata.file_tree if item.endswith(".py")])
            self.assertEqual("fixture", metadata.file_categories["fixtures/finding.py"])

    def test_report_marks_finding_source_category(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_scope_fixture(Path(tmp))
            config = AuditConfig.default()
            config.audit_scope.include_patterns = ["tests/**"]

            result = run_audit(str(project), config=config, output_dir=Path(tmp) / "runs")
            report = json.loads((Path(result["run_dir"]) / "reports" / "report.json").read_text(encoding="utf-8"))
            markdown = (Path(result["run_dir"]) / "reports" / "report.md").read_text(encoding="utf-8")

            self.assertEqual(1, report["executive_summary"]["source_category_distribution"]["test"])
            self.assertEqual("test", report["findings"][0]["source_category"])
            self.assertIn("- Source category: test", markdown)


if __name__ == "__main__":
    unittest.main()
