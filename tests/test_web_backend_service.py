import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import anyio
import httpx

from audit_agent.message_bus import MessageBus


class ASGITestClient:
    def __init__(self, app):
        self.app = app

    def get(self, url: str):
        return anyio.run(self._request, "GET", url, None)

    def post(self, url: str, json: dict | None = None):
        return anyio.run(self._request, "POST", url, json)

    async def _request(self, method: str, url: str, payload: dict | None):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, json=payload)


def make_client(app):
    return ASGITestClient(app)


class RecordingRunner:
    def __init__(self):
        self.submitted = []

    def submit(self, job_id, request):
        self.submitted.append((job_id, request.target))


class ImmediateRunningRunner:
    def __init__(self, store):
        self.store = store

    def submit(self, job_id, request):
        self.store.mark_running(job_id)


class WebBackendApiTests(unittest.TestCase):
    def test_health_endpoint_returns_non_secret_service_metadata(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            client = make_client(
                create_app(job_store=JobStore(Path(tmp) / "jobs.json"), runner=RecordingRunner())
            )

            response = client.get("/api/health")
            payload = response.json()

            self.assertEqual(response.status_code, 200)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["service"], "agentic-security-audit-api")
            self.assertIn("api_version", payload)
            self.assertNotIn("key", json.dumps(payload).lower())
            self.assertNotIn("token", json.dumps(payload).lower())

    def test_options_endpoint_returns_values_accepted_by_create_run(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            runner = RecordingRunner()
            store = JobStore(Path(tmp) / "jobs.json")
            client = make_client(create_app(job_store=store, runner=runner))

            options_response = client.get("/api/options")
            options = options_response.json()

            self.assertEqual(options_response.status_code, 200)
            self.assertIn("mock", options["provider_modes"])
            self.assertEqual(
                options["graph_modes"],
                ["legacy", "deterministic-graph", "adaptive-graph"],
            )
            self.assertIn(options["default_graph_mode"], options["graph_modes"])
            self.assertIn("lexical", options["memory_modes"])
            self.assertIn("off", options["mcp_modes"])
            self.assertIn("static-only", options["validation_levels"])
            self.assertIn("analysis", options["llm_decision_roles"])
            self.assertIn("tests/**", options["default_exclude_patterns"])
            self.assertIn("docker", options["sandbox_runners"])
            self.assertEqual("python:3.12-slim", options["default_docker_image"])
            self.assertIn("default_docker_context", options)
            self.assertIn("default_docker_host", options)
            self.assertFalse(options["llm_poc_repair_default"])
            self.assertEqual(1, options["max_repair_attempts_default"])
            self.assertEqual([0, 2], options["max_repair_attempts_range"])
            self.assertTrue(options["poc_repair_requires_docker"])
            self.assertNotIn("api_key", json.dumps(options).lower())

            create_response = client.post(
                "/api/runs",
                json={
                    "target": "fixtures/integration_smoke",
                    "runtime": True,
                    "llm_provider": options["provider_modes"][0],
                    "llm_decisions": True,
                    "llm_decision_roles": options["llm_decision_roles"][:2],
                    "memory_mode": "lexical",
                    "mcp_mode": "off",
                    "validation_level": "static-only",
                    "sandbox_enabled": True,
                    "sandbox_runner": "docker",
                    "sandbox_docker_image": options["default_docker_image"],
                    "sandbox_docker_context": "desktop-linux",
                    "sandbox_docker_host": "npipe:////./pipe/dockerDesktopLinuxEngine",
                    "include_patterns": ["src/**"],
                    "exclude_patterns": options["default_exclude_patterns"],
                },
            )

            self.assertEqual(create_response.status_code, 202)

    def test_create_run_validates_payload_stores_job_and_submits_runner(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            runner = RecordingRunner()
            store = JobStore(Path(tmp) / "jobs.json")
            client = make_client(create_app(job_store=store, runner=runner, output_dir=Path(tmp) / "runs"))

            response = client.post(
                "/api/runs",
                json={
                    "target": "fixtures/integration_smoke",
                    "runtime": True,
                    "llm_provider": "mock",
                    "llm_decisions": True,
                    "llm_decision_roles": ["analysis", "verification"],
                    "memory_mode": "lexical",
                    "mcp_mode": "off",
                    "validation_level": "static-only",
                },
            )

            self.assertEqual(response.status_code, 202)
            payload = response.json()
            self.assertTrue(payload["job_id"].startswith("JOB-"))
            self.assertEqual(payload["status"], "queued")
            self.assertEqual(payload["status_url"], f"/api/runs/{payload['job_id']}")
            self.assertEqual(runner.submitted, [(payload["job_id"], "fixtures/integration_smoke")])

            status = client.get(payload["status_url"]).json()
            self.assertEqual(status["status"], "queued")
            self.assertEqual(status["target"], "fixtures/integration_smoke")

            listed = client.get("/api/runs").json()
            self.assertEqual([item["job_id"] for item in listed["jobs"]], [payload["job_id"]])

    def test_create_run_response_remains_queued_even_if_runner_starts_immediately(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            store = JobStore(Path(tmp) / "jobs.json")
            client = make_client(
                create_app(
                    job_store=store,
                    runner=ImmediateRunningRunner(store),
                    output_dir=Path(tmp) / "runs",
                )
            )

            response = client.post("/api/runs", json={"target": "fixtures/integration_smoke"})

            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["status"], "queued")
            self.assertEqual(store.get(response.json()["job_id"]).status, "running")

    def test_create_run_rejects_missing_target_invalid_enum_and_secret_fields(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            client = make_client(
                create_app(job_store=JobStore(Path(tmp) / "jobs.json"), runner=RecordingRunner())
            )

            self.assertEqual(client.post("/api/runs", json={}).status_code, 422)
            self.assertEqual(
                client.post("/api/runs", json={"target": ".", "memory_mode": "vector"}).status_code,
                422,
            )
            self.assertEqual(
                client.post("/api/runs", json={"target": ".", "api_key": "secret"}).status_code,
                422,
            )
            invalid_repair_payloads = [
                {"target": ".", "llm_poc_repair": True},
                {"target": ".", "runtime": True, "validation_level": "sandbox", "sandbox_enabled": True, "sandbox_runner": "local", "llm_poc_repair": True},
                {"target": ".", "runtime": True, "validation_level": "sandbox", "sandbox_enabled": True, "sandbox_runner": "docker", "llm_poc_repair": True, "max_repair_attempts": 3},
            ]
            for payload in invalid_repair_payloads:
                with self.subTest(payload=payload):
                    self.assertEqual(client.post("/api/runs", json=payload).status_code, 422)

            valid_repair = client.post(
                "/api/runs",
                json={
                    "target": ".",
                    "runtime": True,
                    "llm_provider": "mock",
                    "validation_level": "sandbox",
                    "sandbox_enabled": True,
                    "sandbox_runner": "docker",
                    "llm_poc_repair": True,
                    "max_repair_attempts": 2,
                },
            )
            self.assertEqual(valid_repair.status_code, 202)

    def test_unknown_job_returns_structured_404(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            client = make_client(
                create_app(job_store=JobStore(Path(tmp) / "jobs.json"), runner=RecordingRunner())
            )

            response = client.get("/api/runs/JOB-missing")

            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["detail"]["error"], "job-not-found")


class WebBackendJobStoreTests(unittest.TestCase):
    def test_job_store_records_transitions_and_persists_metadata(self):
        from audit_agent.server.job_store import JobStatus, JobStore

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "jobs.json"
            store = JobStore(path)
            job = store.create_job("fixtures/integration_smoke", output_dir=Path(tmp) / "runs")

            self.assertEqual(job.status, JobStatus.QUEUED.value)
            self.assertTrue(job.job_id.startswith("JOB-"))
            store.mark_running(job.job_id)
            store.mark_succeeded(
                job.job_id,
                {"run_dir": str(Path(tmp) / "runs" / "run-1"), "validated_count": 1},
            )

            reloaded = JobStore(path)
            saved = reloaded.get(job.job_id)

            self.assertEqual(saved.status, JobStatus.SUCCEEDED.value)
            self.assertEqual(saved.summary["validated_count"], 1)
            self.assertTrue(saved.finished_at)
            self.assertEqual(saved.run_dir, str(Path(tmp) / "runs" / "run-1"))

    def test_job_store_sanitizes_failure_messages(self):
        from audit_agent.server.job_store import JobStatus, JobStore

        with tempfile.TemporaryDirectory() as tmp:
            store = JobStore(Path(tmp) / "jobs.json")
            job = store.create_job("target", output_dir=Path(tmp) / "runs")

            store.mark_failed(job.job_id, "API_KEY=abc123 failed")

            failed = store.get(job.job_id)
            self.assertEqual(failed.status, JobStatus.FAILED.value)
            self.assertNotIn("abc123", failed.error)


class WebBackendRunnerTests(unittest.TestCase):
    def test_request_loads_llm_aliases_from_dotenv(self):
        from audit_agent.server.runner import build_audit_config
        from audit_agent.server.schemas import ScanRunRequest

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "\n".join(
                    [
                        "LLM_API_KEY=alias-secret-value",
                        "LLM_API_BASE_URL=https://alias.example/v1",
                        "LLM_MODEL=alias-model",
                    ]
                ),
                encoding="utf-8",
            )
            request = ScanRunRequest(
                target="fixtures/integration_smoke",
                runtime=True,
                llm_provider="openai-compatible",
            )

            with patch.dict("os.environ", {}, clear=True):
                config = build_audit_config(request, cwd=root)

        self.assertEqual(config.llm.provider, "openai-compatible")
        self.assertEqual(config.llm.api_key_env, "LLM_API_KEY")
        self.assertEqual(config.llm.base_url, "https://alias.example/v1")
        self.assertEqual(config.llm.model, "alias-model")

    def test_request_maps_to_audit_config(self):
        from audit_agent.server.runner import build_audit_config
        from audit_agent.server.schemas import ScanRunRequest

        request = ScanRunRequest(
            target="fixtures/integration_smoke",
            runtime=True,
            graph_mode="adaptive-graph",
            llm_provider="mock",
            model="deterministic-local",
            llm_decisions=True,
            llm_decision_roles=["analysis", "verification"],
            memory_mode="off",
            mcp_mode="degraded",
            validation_level="poc-generate",
            sandbox_enabled=True,
            sandbox_runner="docker",
            sandbox_docker_image="python:3.12-slim",
            sandbox_docker_context="desktop-linux",
            sandbox_docker_host="npipe:////./pipe/dockerDesktopLinuxEngine",
            include_patterns=["src/**"],
            exclude_patterns=["tests/**", "fixtures/**"],
        )

        config = build_audit_config(request)

        self.assertTrue(config.runtime_enabled)
        self.assertEqual(config.graph.mode, "adaptive-graph")
        self.assertEqual(config.llm.provider, "mock")
        self.assertEqual(config.llm.model, "deterministic-local")
        self.assertTrue(config.llm_decisions.enabled)
        self.assertEqual(config.llm_decisions.roles, ["analysis", "verification"])
        self.assertFalse(config.memory.enabled)
        self.assertTrue(config.mcp.enabled)
        self.assertTrue(config.mcp.degraded_mode)
        self.assertEqual(config.default_validation_level, "poc-generate")
        self.assertTrue(config.sandbox.enabled)
        self.assertEqual(config.sandbox.runner, "docker")
        self.assertEqual(config.sandbox.docker_image, "python:3.12-slim")
        self.assertEqual(config.sandbox.docker_context, "desktop-linux")
        self.assertEqual(config.sandbox.docker_host, "npipe:////./pipe/dockerDesktopLinuxEngine")
        self.assertEqual(config.audit_scope.include_patterns, ["src/**"])
        self.assertEqual(config.audit_scope.exclude_patterns, ["tests/**", "fixtures/**"])

    def test_explicit_repair_request_maps_to_disabled_by_default_config(self):
        from audit_agent.server.runner import build_audit_config
        from audit_agent.server.schemas import ScanRunRequest

        default = build_audit_config(ScanRunRequest(target="fixtures/integration_smoke"))
        self.assertFalse(default.poc_repair.enabled)

        request = ScanRunRequest(
            target="fixtures/integration_smoke",
            runtime=True,
            llm_provider="mock",
            validation_level="sandbox",
            sandbox_enabled=True,
            sandbox_runner="docker",
            llm_poc_repair=True,
            max_repair_attempts=2,
        )
        config = build_audit_config(request)
        self.assertTrue(config.poc_repair.enabled)
        self.assertEqual(2, config.poc_repair.max_repair_attempts)
        self.assertEqual("explicit", config.poc_repair.effective_source)

    def test_runner_updates_job_from_run_audit_result(self):
        from audit_agent.server.job_store import JobStatus, JobStore
        from audit_agent.server.runner import ScanJobRunner
        from audit_agent.server.schemas import ScanRunRequest

        with tempfile.TemporaryDirectory() as tmp:
            store = JobStore(Path(tmp) / "jobs.json")
            job = store.create_job("target", output_dir=Path(tmp) / "runs")

            def fake_run_audit(target, config, output_dir):
                self.assertEqual(target, "target")
                self.assertEqual(Path(output_dir), Path(tmp) / "runs")
                return {"run_dir": str(Path(tmp) / "runs" / "run-1"), "validated_count": 2}

            runner = ScanJobRunner(store, run_audit_func=fake_run_audit)
            runner.run_job(job.job_id, ScanRunRequest(target="target", output=str(Path(tmp) / "runs")))

            updated = store.get(job.job_id)
            self.assertEqual(updated.status, JobStatus.SUCCEEDED.value)
            self.assertEqual(updated.summary["validated_count"], 2)
            self.assertEqual(updated.run_dir, str(Path(tmp) / "runs" / "run-1"))


class WebBackendArtifactTests(unittest.TestCase):
    def test_runtime_replay_and_report_endpoints_read_only_known_job_files(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "runs" / "run-1"
            (run_dir / "runtime_state").mkdir(parents=True)
            (run_dir / "messages").mkdir()
            (run_dir / "reports").mkdir()
            (run_dir / "runtime_state" / "state.json").write_text(
                json.dumps({"status": "succeeded", "tasks": [{"role": "analysis"}]}),
                encoding="utf-8",
            )
            bus = MessageBus("run-1", run_dir / "messages" / "messages.jsonl")
            bus.publish("runtime", "analysis", "runtime.task", {"role": "analysis", "status": "succeeded"})
            (run_dir / "reports" / "report.json").write_text(
                json.dumps({"executive_summary": {"validated_count": 1}}),
                encoding="utf-8",
            )
            (run_dir / "reports" / "report.md").write_text("# Report\n", encoding="utf-8")

            store = JobStore(root / "jobs.json")
            job = store.create_job("target", output_dir=root / "runs")
            store.mark_succeeded(job.job_id, {"run_dir": str(run_dir), "validated_count": 1})
            client = make_client(create_app(job_store=store, runner=RecordingRunner()))

            self.assertEqual(client.get(f"/api/runs/{job.job_id}/runtime-state").json()["status"], "succeeded")
            replay = client.get(f"/api/runs/{job.job_id}/replay-summary").json()
            self.assertIn("runtime_lifecycle", replay)
            self.assertEqual(
                client.get(f"/api/runs/{job.job_id}/reports/report.json").json()["executive_summary"]["validated_count"],
                1,
            )
            markdown = client.get(f"/api/runs/{job.job_id}/reports/report.md")
            self.assertEqual(markdown.status_code, 200)
            self.assertIn("# Report", markdown.text)
            self.assertEqual(
                client.get(f"/api/runs/{job.job_id}/reports/%2e%2e%2fruntime_state%2fstate.json").status_code,
                404,
            )

    def test_artifact_endpoints_return_404_before_files_exist(self):
        from audit_agent.server.app import create_app
        from audit_agent.server.job_store import JobStore

        with tempfile.TemporaryDirectory() as tmp:
            store = JobStore(Path(tmp) / "jobs.json")
            job = store.create_job("target", output_dir=Path(tmp) / "runs")
            client = make_client(create_app(job_store=store, runner=RecordingRunner()))

            self.assertEqual(client.get(f"/api/runs/{job.job_id}/runtime-state").status_code, 404)
            self.assertEqual(client.get(f"/api/runs/{job.job_id}/replay-summary").status_code, 404)
            self.assertEqual(client.get(f"/api/runs/{job.job_id}/reports/report.json").status_code, 404)


if __name__ == "__main__":
    unittest.main()
