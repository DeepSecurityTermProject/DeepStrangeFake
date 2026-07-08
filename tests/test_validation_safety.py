import sys
import tempfile
import unittest
from pathlib import Path

from audit_agent.config import AuditConfig
from audit_agent.models import Finding, SourceLocation
from audit_agent.repository import analyze_target
from audit_agent.validation import Validator

from tests.test_repository_analysis import create_vulnerable_fixture


class ValidationSafetyTests(unittest.TestCase):
    def test_sandbox_runs_only_configured_local_safe_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))
            metadata = analyze_target(str(project))
            config = AuditConfig.default()
            config.sandbox.enabled = True
            config.sandbox.safe_commands = [f"{sys.executable} -c \"print('sandbox-ok')\""]
            finding = Finding(
                vulnerability_class="sql-injection",
                severity="high",
                confidence=0.8,
                location=SourceLocation(path="app.py", start_line=8, end_line=8),
                title="Potential SQL injection",
                evidence=["query uses request input"],
            )

            result = Validator(config).validate(finding, metadata, level="sandbox")

            self.assertEqual(result.status, "passed")
            self.assertEqual(result.level, "sandbox")
            self.assertTrue(result.artifacts)

    def test_sandbox_blocks_remote_targets(self):
        config = AuditConfig.default()
        config.sandbox.enabled = True
        config.sandbox.safe_commands = [f"{sys.executable} -c \"print('sandbox-ok')\""]
        metadata = analyze_target("https://github.com/OpenVPN/openvpn.git")
        finding = Finding(
            vulnerability_class="sql-injection",
            severity="high",
            confidence=0.8,
            location=SourceLocation(path="app.py", start_line=1, end_line=1),
            title="Remote target candidate",
            evidence=["synthetic local evidence"],
        )

        result = Validator(config).validate(finding, metadata, level="sandbox")

        self.assertEqual(result.status, "blocked")
        self.assertIn("No-live-target", result.message)


if __name__ == "__main__":
    unittest.main()
