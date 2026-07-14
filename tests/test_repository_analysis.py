import json
import tempfile
import unittest
from pathlib import Path

from audit_agent.repository import analyze_target, parse_target


def create_vulnerable_fixture(root: Path) -> Path:
    project = root / "fixture-app"
    project.mkdir()
    (project / "node_modules").mkdir()
    (project / "node_modules" / "ignored.js").write_text("eval('ignored')", encoding="utf-8")
    (project / "requirements.txt").write_text(
        "Flask==2.2.0\nrequests>=2.31.0\n",
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'dependencies = ["fastapi>=0.111,<1.0", "uvicorn[standard]>=0.30; python_version >= \'3.12\'"]',
                "",
                "[project.optional-dependencies]",
                'js-ast = ["tree-sitter>=0.22,<1.0"]',
            ]
        ),
        encoding="utf-8",
    )
    (project / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0", "lodash": "4.17.21"}}),
        encoding="utf-8",
    )
    (project / "app.py").write_text(
        "\n".join(
            [
                "import os",
                "from flask import Flask, request",
                "app = Flask(__name__)",
                "API_KEY = 'sk_live_1234567890abcdef'",
                "@app.route('/user/<name>')",
                "def user(name):",
                "    user_name = request.args.get('name')",
                "    query = \"select * from users where name='%s'\" % user_name",
                "    os.system('ls ' + request.args.get('cmd', ''))",
                "    return open('../' + request.args.get('file', '')).read()",
            ]
        ),
        encoding="utf-8",
    )
    return project


class RepositoryAnalysisTests(unittest.TestCase):
    def test_parse_github_and_gitlab_targets_without_checkout(self):
        github = parse_target("https://github.com/OpenVPN/openvpn.git")
        gitlab = parse_target("https://gitlab.com/gitlab-org/gitlab.git")

        self.assertEqual(github.kind, "github")
        self.assertEqual(github.owner, "OpenVPN")
        self.assertEqual(github.repo, "openvpn")
        self.assertEqual(gitlab.kind, "gitlab")
        self.assertEqual(gitlab.owner, "gitlab-org")
        self.assertEqual(gitlab.repo, "gitlab")

    def test_local_analysis_detects_languages_dependencies_and_attack_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = create_vulnerable_fixture(Path(tmp))

            metadata = analyze_target(str(project))

            self.assertEqual(metadata.target.kind, "local")
            self.assertEqual(metadata.dominant_language, "Python")
            self.assertIn("JavaScript", metadata.languages)
            self.assertNotIn("node_modules/ignored.js", metadata.file_tree)

            package_names = {dep.name for dep in metadata.dependencies}
            self.assertTrue(
                {
                    "Flask",
                    "requests",
                    "fastapi",
                    "uvicorn",
                    "tree-sitter",
                    "express",
                    "lodash",
                }.issubset(package_names)
            )
            self.assertTrue(all(dep.identifiers for dep in metadata.dependencies))
            pyproject_dependencies = {
                dependency.name: dependency
                for dependency in metadata.dependencies
                if dependency.manifest_path == "pyproject.toml"
            }
            self.assertEqual(pyproject_dependencies["fastapi"].version, "0.111,<1.0")
            self.assertEqual(pyproject_dependencies["uvicorn"].version, "0.30")

            surface_types = {surface.kind for surface in metadata.attack_surfaces}
            self.assertIn("route", surface_types)
            self.assertIn("command-execution", surface_types)
            self.assertIn("database-access", surface_types)
            self.assertIn("path-traversal-sink", surface_types)
            self.assertIn("hardcoded-secret", surface_types)


if __name__ == "__main__":
    unittest.main()
