from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from audit_agent.agent_led_runtime import AgentLedInvestigationCoordinator, InvestigationCheckpointStore
from audit_agent.config import AuditConfig
from audit_agent.evidence_gate import EvidenceGate
from audit_agent.investigation_models import (
    EvidenceItem,
    InvestigationCheckpoint,
    InvestigationHypothesis,
    InvestigationStep,
    SecuritySignal,
    VerificationEvidencePackage,
    VerificationPlan,
    VerificationPrimitiveCall,
)
from audit_agent.investigation_tools import (
    FixedSastAdapter,
    InvestigationActionRegistry,
    InvestigationToolError,
    RepositoryCallGraphBuilder,
    RepositoryView,
)
from audit_agent.llm import LLMCancelled, LLMValidationError, MockLLMClient, validate_json_schema
from audit_agent.benchmark_runtime import ProcessTreeRunner
from audit_agent.models import AuditTarget, Finding, LLMResponse, RepositoryMetadata, SourceLocation
from audit_agent.pipeline import run_audit
from audit_agent.prompts import INVESTIGATION_RESPONSE_SCHEMA, VERIFICATION_PLAN_RESPONSE_SCHEMA
from audit_agent.runtime import CancellationToken
from audit_agent.verification import LocalSandboxRunner, VerificationStatus
from audit_agent.verification_plans import TrustedVerificationCompiler, plan_from_payload


def metadata_for(root: Path, files: list[str]) -> RepositoryMetadata:
    return RepositoryMetadata(
        target=AuditTarget(source=str(root), kind="local", path=str(root)),
        root_path=str(root),
        dominant_language="python",
        languages={"Python": len(files)},
        file_tree=files,
        file_categories={item: "product-code" for item in files},
    )


class ContractTests(unittest.TestCase):
    def test_contracts_reject_unknown_fields_authority_and_invalid_transitions(self):
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            SecuritySignal.from_dict(
                {
                    "run_id": "run",
                    "vulnerability_class": "sql-injection",
                    "path": "app.py",
                    "line": 1,
                    "excerpt": "1: x",
                    "content_hash": "a" * 64,
                    "unexpected": "authority",
                }
            )
        with self.assertRaisesRegex(ValueError, "authority"):
            InvestigationStep(
                run_id="run",
                hypothesis_id="HYP-1",
                round_index=1,
                action="search",
                arguments={"query": "x", "nested": {"command": "whoami"}},
                action_key="ACT-1",
                status="accepted",
            )
        hypothesis = InvestigationHypothesis(
            run_id="run",
            vulnerability_class="sql-injection",
            claim="query reaches execute",
            target_paths=["app.py"],
            rationale="repository source",
            confidence=0.7,
        )
        with self.assertRaisesRegex(ValueError, "invalid hypothesis transition"):
            hypothesis.transition("promoted")

    def test_verification_plan_rejects_wrong_class_and_model_authority(self):
        call = VerificationPrimitiveCall(
            primitive_id="command.argv-marker",
            parameters={"path": "app.py", "line": 1, "sink": "os.system"},
            expected_observations=["marker"],
            evidence_refs=["EVI-1"],
        )
        with self.assertRaisesRegex(ValueError, "incompatible"):
            VerificationPlan(
                run_id="run",
                candidate_id="F-1",
                vulnerability_class="sql-injection",
                evidence_package_ref="package.json",
                primitives=[call],
                confidence=0.8,
                rationale="wrong primitive",
            )
        with self.assertRaisesRegex(ValueError, "forbidden authority"):
            plan_from_payload(
                {
                    "confidence": 0.8,
                    "rationale": "unsafe",
                    "primitives": [],
                    "command": "python exploit.py",
                },
                run_id="run",
                candidate_id="F-1",
                vulnerability_class="sql-injection",
                evidence_package_ref="package.json",
            )

    def test_phase_one_verification_plan_requires_exactly_one_primitive(self):
        call = VerificationPrimitiveCall(
            primitive_id="sql.sqlite-parameter-binding",
            parameters={"path": "app.py", "line": 1, "mode": "vulnerable"},
            expected_observations=["parameter binding"],
            evidence_refs=["EVI-1"],
        )
        common = {
            "run_id": "run",
            "candidate_id": "F-1",
            "vulnerability_class": "sql-injection",
            "evidence_package_ref": "package.json",
            "confidence": 0.8,
            "rationale": "bounded phase-one plan",
        }
        with self.assertRaisesRegex(ValueError, "exactly one primitive"):
            VerificationPlan(primitives=[], **common)
        with self.assertRaisesRegex(ValueError, "exactly one primitive"):
            VerificationPlan(primitives=[call, call], **common)
        primitive_schema = VERIFICATION_PLAN_RESPONSE_SCHEMA["properties"]["primitives"]
        self.assertEqual((primitive_schema["minItems"], primitive_schema["maxItems"]), (1, 1))

    def test_investigation_schema_uses_runtime_vulnerability_and_action_enums(self):
        invalid = {
            "hypotheses": [
                {
                    "vulnerability_class": "SQL injection",
                    "claim": "unsafe query",
                    "target_paths": ["app.py"],
                    "confidence": 0.8,
                    "rationale": "inspect source",
                    "signal_refs": [],
                    "next_action": {
                        "action": "run_shell",
                        "arguments": {},
                    },
                }
            ],
            "updates": [],
            "rationale": "bounded investigation",
        }
        with self.assertRaises(LLMValidationError):
            validate_json_schema(invalid, INVESTIGATION_RESPONSE_SCHEMA)


class InvestigationToolTests(unittest.TestCase):
    def test_process_tree_and_default_sast_runner_are_actively_cancelled(self):
        token = CancellationToken()
        timer = threading.Timer(0.25, token.cancel)
        timer.start()
        started = time.monotonic()
        result = ProcessTreeRunner().run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            env=dict(),
            cwd=None,
            timeout_seconds=20,
            cancelled=lambda: token.cancelled,
        )
        timer.join()
        self.assertTrue(result.cancelled)
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(result.cleanup["attempted"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('x')\n", encoding="utf-8")
            second = CancellationToken()
            adapter = FixedSastAdapter("semgrep", timeout_seconds=20, cancelled=lambda: second.cancelled)
            adapter.command = (sys.executable, "-c", "import time; time.sleep(30)")
            timer = threading.Timer(0.25, second.cancel)
            timer.start()
            observation = adapter.run(RepositoryView(metadata_for(root, ["app.py"])))
            timer.join()
            self.assertEqual(observation.status, "cancelled")

            sleeper = root / "sleep.py"
            sleeper.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
            third = CancellationToken()
            sandbox_config = AuditConfig.default()
            timer = threading.Timer(0.25, third.cancel)
            timer.start()
            sandbox_result = LocalSandboxRunner(
                sandbox_config, root / "sandbox", third
            ).run(
                {
                    "id": "POC-1",
                    "finding_id": "F-1",
                    "command_argv": [sys.executable, str(sleeper)],
                }
            )
            timer.join()
            self.assertEqual(sandbox_result.status, "cancelled")

    def test_repository_scope_search_context_lexical_and_call_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text(
                "import os\ndef helper(value):\n    return os.system(value)\ndef caller(x):\n    return helper(x)\n",
                encoding="utf-8",
            )
            (root / "b.ts").write_text(
                "function run(x: string) { return x; }\nexport function sink(x: string) { return run(x); }\nconst dyn = handlers[name](value);\n",
                encoding="utf-8",
            )
            metadata = metadata_for(root, ["a.py", "b.ts"])
            view = RepositoryView(metadata)
            evidence = view.source_evidence("a.py", 3, context=1)
            self.assertEqual(evidence.path, "a.py")
            self.assertEqual(len(evidence.content_hash), 64)
            self.assertTrue(view.search("os.system"))
            self.assertTrue(view.lexical("helper system"))
            with self.assertRaises(InvestigationToolError):
                view.read("../outside.txt")
            graph = RepositoryCallGraphBuilder().build(view)
            self.assertTrue(graph.callers("helper"))
            self.assertTrue(any(not edge["unresolved"] for edge in graph.callers("run")))
            self.assertTrue(any(edge.unresolved for edge in graph.edges))

    def test_action_registry_rejects_unknown_arguments_and_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("value = input()\n", encoding="utf-8")
            registry = InvestigationActionRegistry(metadata_for(root, ["app.py"]), run_dir=root / "run")
            with self.assertRaisesRegex(InvestigationToolError, "unknown"):
                registry.dispatch("search", {"query": "value", "shell": "cmd.exe"})
            with self.assertRaisesRegex(InvestigationToolError, "unregistered"):
                registry.dispatch("execute", {})

    def test_sast_adapters_normalize_three_tools_and_cap_or_reject_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("password = 'Ab9$supersecret'\nos.system(request.args['x'])\n", encoding="utf-8")
            view = RepositoryView(metadata_for(root, ["app.py"]))

            payloads = {
                "semgrep": {"results": [{"check_id": "python.lang.security.audit.command-injection", "path": "app.py", "start": {"line": 2}, "extra": {"message": "os.system command injection"}}]},
                "bandit": {"results": [{"test_id": "B605 CWE-78", "filename": "app.py", "line_number": 2, "issue_text": "shell command"}]},
                "gitleaks": [{"RuleID": "generic-api-key", "File": "app.py", "StartLine": 1, "Description": "hardcoded secret"}],
            }
            for tool, payload in payloads.items():
                runner = lambda *args, payload=payload, **kwargs: subprocess.CompletedProcess(
                    args[0], 0, json.dumps(payload).encode(), b""
                )
                result = FixedSastAdapter(tool, runner=runner).run(view)
                self.assertEqual(result.status, "ok")
                self.assertEqual(len(result.observations), 1)
                self.assertEqual(result.observations[0].origin, tool)

            malformed = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"not-json", b"")
            self.assertEqual(FixedSastAdapter("semgrep", runner=malformed).run(view).status, "malformed")
            huge = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"[]" * 100, b"")
            self.assertEqual(FixedSastAdapter("gitleaks", runner=huge, output_limit=10).run(view).status, "output-capped")
            timeout = lambda *args, **kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 1))
            )
            self.assertEqual(FixedSastAdapter("bandit", runner=timeout).run(view).status, "timeout")
            with patch("audit_agent.investigation_tools.shutil.which", return_value=None):
                self.assertEqual(FixedSastAdapter("semgrep").run(view).status, "unavailable")
            varied = lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0],
                0,
                json.dumps(
                    {
                        "version": "different-tool-version",
                        "results": [
                            {
                                "check_id": "cwe-78",
                                "path": "app.py",
                                "start": {"line": 2, "column": 1},
                                "extra": {"message": "command execution", "metavars": {}},
                            }
                        ],
                    }
                ).encode(),
                b"",
            )
            self.assertEqual(len(FixedSastAdapter("semgrep", runner=varied).run(view).observations), 1)


class EvidenceGateTests(unittest.TestCase):
    def _fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
        (root / "app.py").write_text("from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n", encoding="utf-8")
        metadata = metadata_for(root, ["settings.py", "app.py"])
        return temporary, RepositoryView(metadata)

    def test_dual_evidence_promotes_and_replays_deterministically(self):
        temporary, view = self._fixture()
        self.addCleanup(temporary.cleanup)
        local = view.source_evidence("settings.py", 1, origin="source", vulnerability_class="hardcoded-secret")
        corroboration = view.source_evidence("app.py", 3, origin="call-graph", vulnerability_class="hardcoded-secret")
        corroboration.raw["edge"] = {"caller_id": "auth", "callee_name": "use", "path": "app.py", "line": 3}
        hypothesis = InvestigationHypothesis(
            run_id="run",
            vulnerability_class="hardcoded-secret",
            claim="credential literal is consumed by auth",
            target_paths=["settings.py"],
            rationale="local source and use path",
            confidence=0.85,
            state="evidence-gate",
            evidence=[local, corroboration],
            round_count=2,
        )
        first = EvidenceGate(view).evaluate(hypothesis)
        second = EvidenceGate(view).evaluate(hypothesis)
        self.assertEqual(first.decision.state, "promoted")
        self.assertEqual(first.decision.to_dict(), second.decision.to_dict())
        self.assertIsNotNone(first.evidence_package)

    def test_same_source_nonlocal_counterevidence_and_drift_do_not_promote(self):
        temporary, view = self._fixture()
        self.addCleanup(temporary.cleanup)
        local = view.source_evidence("settings.py", 1, origin="source", vulnerability_class="hardcoded-secret")
        same = EvidenceItem.from_dict({**local.to_dict(), "evidence_id": "EVI-same", "origin": "independent-source"})
        hypothesis = InvestigationHypothesis(
            run_id="run",
            vulnerability_class="hardcoded-secret",
            claim="secret",
            target_paths=["settings.py"],
            rationale="test gate",
            confidence=0.7,
            state="evidence-gate",
            evidence=[local, same],
            round_count=1,
        )
        self.assertNotEqual(EvidenceGate(view).evaluate(hypothesis).decision.state, "promoted")
        model = EvidenceItem("EVI-model", "model", message="LLM says vulnerable")
        hypothesis.evidence = [local, model]
        self.assertNotEqual(EvidenceGate(view).evaluate(hypothesis).decision.state, "promoted")
        counter = view.source_evidence("app.py", 3, origin="call-graph", vulnerability_class="hardcoded-secret")
        counter.counterevidence = True
        hypothesis.evidence = [local, counter]
        self.assertEqual(EvidenceGate(view).evaluate(hypothesis).decision.state, "rejected")
        (view.root / "settings.py").write_text("CREDENTIAL = os.environ['CREDENTIAL']\n", encoding="utf-8")
        hypothesis.evidence = [local, counter]
        self.assertEqual(EvidenceGate(view).evaluate(hypothesis).decision.state, "rejected")

    def test_sql_parameterization_counterevidence_does_not_match_across_source_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "def run_query(name, cursor):\n"
                "    query = \"SELECT id FROM users WHERE name = '\" + name + \"'\"\n"
                "    return cursor.execute(query)\n"
                "def handler(user_name, cursor):\n"
                "    return run_query(user_name, cursor)\n",
                encoding="utf-8",
            )
            view = RepositoryView(metadata_for(root, ["app.py"]))
            local = view.source_evidence(
                "app.py", 1, 3, context=2, origin="source", vulnerability_class="sql-injection"
            )
            corroboration = view.source_evidence(
                "app.py", 5, origin="call-graph", vulnerability_class="sql-injection"
            )
            corroboration.raw["edge"] = {
                "caller_id": "handler",
                "callee_name": "run_query",
                "path": "app.py",
                "line": 5,
            }
            hypothesis = InvestigationHypothesis(
                run_id="run",
                vulnerability_class="sql-injection",
                claim="user input reaches a dynamically concatenated query",
                target_paths=["app.py"],
                rationale="exact source and an independent call edge",
                confidence=0.9,
                state="evidence-gate",
                evidence=[local, corroboration],
                round_count=2,
            )
            result = EvidenceGate(view).evaluate(hypothesis)
            self.assertEqual(result.decision.state, "promoted", result.decision.reasons)
            self.assertEqual(result.decision.counterevidence_refs, [])

            (root / "app.py").write_text(
                "def run_query(name, cursor):\n"
                "    return cursor.execute(\"SELECT id FROM users WHERE name = ?\", (name,))\n",
                encoding="utf-8",
            )
            safe_view = RepositoryView(metadata_for(root, ["app.py"]))
            safe_local = safe_view.source_evidence(
                "app.py", 1, 2, origin="source", vulnerability_class="sql-injection"
            )
            safe_hypothesis = InvestigationHypothesis(
                run_id="safe-run",
                vulnerability_class="sql-injection",
                claim="query may be injectable",
                target_paths=["app.py"],
                rationale="negative control",
                confidence=0.7,
                state="evidence-gate",
                evidence=[safe_local],
                round_count=1,
            )
            safe_result = EvidenceGate(safe_view).evaluate(safe_hypothesis)
            self.assertEqual(safe_result.decision.state, "rejected")
            self.assertTrue(safe_result.decision.counterevidence_refs)


class VerificationPlanTests(unittest.TestCase):
    def test_secret_static_semantic_confirms_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text("def auth():\n    return use(CREDENTIAL)\n", encoding="utf-8")
            metadata = metadata_for(root, ["settings.py", "app.py"])
            view = RepositoryView(metadata)
            local = view.source_evidence("settings.py", 1, vulnerability_class="hardcoded-secret")
            corroboration = view.source_evidence("app.py", 2, origin="call-graph", vulnerability_class="hardcoded-secret")
            package = VerificationEvidencePackage(
                run_id="run",
                hypothesis_id="HYP-1",
                candidate_id="F-1",
                vulnerability_class="hardcoded-secret",
                claim="credential literal",
                severity="medium",
                local_evidence=[local],
                corroborating_evidence=[corroboration],
            )
            finding = Finding(
                id="F-1",
                vulnerability_class="hardcoded-secret",
                severity="medium",
                confidence=0.8,
                location=SourceLocation("settings.py", 1, 1),
                title="secret",
                metadata={"evidence_package_ref": "package.json"},
            )
            compiler = TrustedVerificationCompiler(AuditConfig.default(), view, root / "run")
            plan = compiler.default_plan(package, "package.json")
            compiled = compiler.compile(plan, package, finding)
            result = compiler.execute(compiled, package, metadata)
            self.assertEqual(result.verification_status, VerificationStatus.CONFIRMED)
            self.assertEqual(result.level, "static-semantic")
            judge = json.loads(Path(result.artifacts[-1]).read_text(encoding="utf-8"))
            self.assertEqual(judge["network_attempts"], 0)
            self.assertNotIn("Aa9$supersecret", json.dumps(judge))

    def test_registered_dynamic_primitives_compile_to_manual_without_sandbox(self):
        cases = [
            ("sql-injection", "sql.sqlite-parameter-binding", {"mode": "vulnerable"}, "cursor.execute(query)\n"),
            ("command-injection", "command.argv-marker", {"sink": "os.system"}, "os.system(request.args.get('cmd'))\n"),
            ("path-traversal", "path.safe-root-boundary", {"transform": "open"}, "open('/srv/files/' + filename)\n"),
        ]
        for vulnerability_class, primitive_id, extra, source_text in cases:
            with self.subTest(vulnerability_class=vulnerability_class), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "app.py").write_text(source_text, encoding="utf-8")
                metadata = metadata_for(root, ["app.py"])
                view = RepositoryView(metadata)
                local = view.source_evidence("app.py", 1, vulnerability_class=vulnerability_class)
                corroboration = view.source_evidence("app.py", 1, origin="dataflow", vulnerability_class=vulnerability_class)
                corroboration.raw["dataflow_status"] = "complete-flow"
                package = VerificationEvidencePackage(
                    run_id="run",
                    hypothesis_id="HYP-1",
                    candidate_id="F-1",
                    vulnerability_class=vulnerability_class,
                    claim="dangerous flow",
                    severity="high",
                    local_evidence=[local],
                    corroborating_evidence=[corroboration],
                )
                finding = Finding(
                    id="F-1",
                    vulnerability_class=vulnerability_class,
                    severity="high",
                    confidence=0.8,
                    location=SourceLocation("app.py", 1, 1),
                    title="candidate",
                    metadata={"evidence_package_ref": "package.json"},
                )
                call = VerificationPrimitiveCall(
                    primitive_id=primitive_id,
                    parameters={"path": "app.py", "line": 1, **extra},
                    expected_observations=["bounded observation"],
                    evidence_refs=[local.evidence_id, corroboration.evidence_id],
                )
                plan = VerificationPlan(
                    run_id="run",
                    candidate_id="F-1",
                    vulnerability_class=vulnerability_class,
                    evidence_package_ref="package.json",
                    primitives=[call],
                    confidence=0.8,
                    rationale="registered primitive",
                )
                compiler = TrustedVerificationCompiler(AuditConfig.default(), view, root / "run")
                compiled = compiler.compile(plan, package, finding)
                result = compiler.execute(compiled, package, metadata)
                self.assertEqual(result.verification_status, VerificationStatus.MANUAL_REQUIRED)

    def test_dynamic_primitive_parameters_must_match_evidence_and_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("os.system(request.args.get('cmd'))\n", encoding="utf-8")
            metadata = metadata_for(root, ["app.py"])
            view = RepositoryView(metadata)
            local = view.source_evidence("app.py", 1, vulnerability_class="command-injection")
            flow = view.source_evidence("app.py", 1, origin="dataflow", vulnerability_class="command-injection")
            flow.raw["dataflow_status"] = "complete-flow"
            package = VerificationEvidencePackage(
                run_id="run",
                hypothesis_id="HYP-1",
                candidate_id="F-1",
                vulnerability_class="command-injection",
                claim="dynamic shell sink",
                severity="high",
                local_evidence=[local],
                corroborating_evidence=[flow],
            )
            finding = Finding(
                id="F-1",
                vulnerability_class="command-injection",
                severity="high",
                confidence=0.8,
                location=SourceLocation("app.py", 1, 1),
                title="command candidate",
                metadata={"evidence_package_ref": "package.json"},
            )
            compiler = TrustedVerificationCompiler(AuditConfig.default(), view, root / "run")
            correct = compiler.default_plan(package, "package.json")
            compiled = compiler.compile(correct, package, finding)
            artifact = json.loads(Path(compiled.artifact_ref).read_text(encoding="utf-8"))
            self.assertEqual(artifact["primitive_calls"][0]["parameters"]["sink"], "os.system")
            self.assertEqual(
                finding.metadata["trusted_verification_primitive"]["parameters"]["sink"],
                "os.system",
            )
            wrong = VerificationPlan.from_dict(correct.to_dict())
            wrong.primitives[0].parameters["sink"] = "subprocess"
            wrong_finding = Finding(
                id="F-1",
                vulnerability_class="command-injection",
                severity="high",
                confidence=0.8,
                location=SourceLocation("app.py", 1, 1),
                title="command candidate",
                metadata={"evidence_package_ref": "package.json"},
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                compiler.compile(wrong, package, wrong_finding)


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_load_skips_corrupt_latest_and_preserves_action_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = InvestigationCheckpointStore(tmp)
            checkpoint = InvestigationCheckpoint(
                run_id="run",
                sequence=1,
                hypothesis_states={"HYP-1": "investigating"},
                hypothesis_refs=["h.json"],
                completed_action_keys=["ACT-1"],
                step_refs=["s.json"],
                evidence_gate_refs=[],
                verification_plan_refs=[],
                remaining_budget={"requests": 39},
            )
            store.write(checkpoint)
            (store.root / "9999-corrupt.json").write_text("{", encoding="utf-8")
            loaded, errors = store.load_latest("run")
            self.assertEqual(loaded.completed_action_keys, ["ACT-1"])
            self.assertTrue(errors)

    def test_restore_validates_refs_and_prevents_completed_tool_redispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "app.py").write_text("needle = 1\n", encoding="utf-8")
            metadata = metadata_for(target, ["app.py"])
            run_dir = root / "run"
            hypothesis_dir = run_dir / "investigations" / "hypotheses"
            step_dir = run_dir / "investigations" / "steps"
            hypothesis_dir.mkdir(parents=True)
            step_dir.mkdir(parents=True)
            hypothesis = InvestigationHypothesis(
                run_id="run",
                vulnerability_class="sql-injection",
                claim="review search result",
                target_paths=["app.py"],
                rationale="checkpoint test",
                confidence=0.7,
                state="investigating",
            )
            arguments = {"query": "needle"}
            action_key = InvestigationActionRegistry.action_key("search", arguments)
            step = InvestigationStep(
                run_id="run",
                hypothesis_id=hypothesis.hypothesis_id or "",
                round_index=1,
                action="search",
                arguments=arguments,
                action_key=action_key,
                status="completed",
            )
            hypothesis_ref = hypothesis_dir / "hypothesis.json"
            step_ref = step_dir / "step.json"
            hypothesis_ref.write_text(json.dumps(hypothesis.to_dict()), encoding="utf-8")
            step_ref.write_text(json.dumps(step.to_dict()), encoding="utf-8")
            store = InvestigationCheckpointStore(run_dir)
            store.write(
                InvestigationCheckpoint(
                    run_id="run",
                    sequence=1,
                    hypothesis_states={hypothesis.hypothesis_id or "": "investigating"},
                    hypothesis_refs=[str(hypothesis_ref)],
                    completed_action_keys=[action_key],
                    step_refs=[str(step_ref)],
                    evidence_gate_refs=[],
                    verification_plan_refs=[],
                    remaining_budget={"requests": 39},
                )
            )
            checkpoint, hypotheses, steps, errors = store.restore("run")
            self.assertIsNotNone(checkpoint)
            self.assertEqual(len(hypotheses), 1)
            self.assertFalse(errors)
            registry = InvestigationActionRegistry(metadata, run_dir=run_dir)
            registry.restore_completed_actions(steps)
            (target / "app.py").unlink()
            output = registry.dispatch("search", arguments)
            self.assertTrue(output["cached"])
            self.assertTrue(output["restored"])


class ScriptedInvestigationClient:
    def __init__(self):
        self.analysis_calls = 0
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        if request.role == "analysis":
            self.analysis_calls += 1
            if self.analysis_calls == 1:
                payload = {
                    "hypotheses": [
                        {
                            "vulnerability_class": "hardcoded-secret",
                            "claim": "A credential literal is consumed by the authentication path.",
                            "target_paths": ["settings.py"],
                            "confidence": 0.88,
                            "rationale": "Credential-named literal and cross-file consumer deserve investigation.",
                            "signal_refs": [],
                        }
                    ],
                    "updates": [],
                    "rationale": "Start with a scanner-independent hypothesis.",
                }
            else:
                hypothesis_id = _first_between(request.prompt, '"hypothesis_id": "', '"')
                if self.analysis_calls == 2:
                    action = {"action": "source_context", "arguments": {"path": "settings.py", "start_line": 1}}
                    assessment = "investigating"
                elif self.analysis_calls == 3:
                    action = {"action": "callers", "arguments": {"symbol": "use"}}
                    assessment = "investigating"
                else:
                    action = {"action": "submit_gate", "arguments": {}}
                    assessment = "supported"
                payload = {
                    "hypotheses": [],
                    "updates": [
                        {
                            "hypothesis_id": hypothesis_id,
                            "assessment": assessment,
                            "next_action": action,
                            "evidence_refs": [],
                        }
                    ],
                    "rationale": "Gather exact source and independent use-path evidence, then gate.",
                }
        else:
            evidence_refs = sorted(set(re.findall(r'"evidence_id":\s*"([^"]+)"', request.prompt)))
            payload = {
                "confidence": 0.9,
                "rationale": "Use the registered static-semantic secret primitive.",
                "primitives": [
                    {
                        "primitive_id": "secret.static-semantic",
                        "parameters": {"path": "settings.py", "line": 1, "minimum_length": 8, "minimum_entropy": 2.5},
                        "expected_observations": ["literal and configuration predicates"],
                        "evidence_refs": evidence_refs,
                    }
                ],
            }
        text = json.dumps(payload)
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=text,
            parsed_json=payload,
            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20, "cost_usd": 0.01},
            finish_reason="stop",
        )


class RepairableInitialClient(ScriptedInvestigationClient):
    def complete(self, request):
        if request.role != "analysis":
            return super().complete(request)
        self.requests.append(request)
        self.analysis_calls += 1
        if self.analysis_calls == 1:
            payload = {"hypotheses": [], "updates": []}
        elif self.analysis_calls == 2:
            payload = {
                "hypotheses": [
                    {
                        "vulnerability_class": "hardcoded-secret",
                        "claim": "A credential literal is consumed by the authentication path.",
                        "target_paths": ["settings.py"],
                        "confidence": 0.88,
                        "rationale": "Credential-named literal deserves bounded investigation.",
                        "signal_refs": [],
                    }
                ],
                "updates": [],
                "rationale": "Repair the missing required rationale without widening authority.",
            }
        else:
            hypothesis_id = _first_between(request.prompt, '"hypothesis_id": "', '"')
            if self.analysis_calls == 3:
                action = {"action": "source_context", "arguments": {"path": "settings.py", "start_line": 1}}
                assessment = "investigating"
            elif self.analysis_calls == 4:
                action = {"action": "callers", "arguments": {"symbol": "use"}}
                assessment = "investigating"
            else:
                action = {"action": "submit_gate", "arguments": {}}
                assessment = "supported"
            payload = {
                "hypotheses": [],
                "updates": [
                    {
                        "hypothesis_id": hypothesis_id,
                        "assessment": assessment,
                        "next_action": action,
                        "evidence_refs": [],
                    }
                ],
                "rationale": "Continue the repaired bounded investigation.",
            }
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=json.dumps(payload),
            parsed_json=payload,
            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
            finish_reason="stop",
        )


class FailingVerificationClient(ScriptedInvestigationClient):
    def complete(self, request):
        if request.role == "verification":
            raise RuntimeError("synthetic verification provider failure")
        return super().complete(request)


class FailingInitialClient:
    def complete(self, request):
        raise RuntimeError("synthetic initial provider failure")


class BootstrapActionClient(ScriptedInvestigationClient):
    def __init__(self):
        super().__init__()
        self.bootstrap_source_seen = False

    def complete(self, request):
        if request.role != "analysis":
            return super().complete(request)
        self.requests.append(request)
        self.analysis_calls += 1
        if self.analysis_calls == 1:
            self.bootstrap_source_seen = "CREDENTIAL" in request.prompt and "settings.py" in request.prompt
            payload = {
                "hypotheses": [
                    {
                        "vulnerability_class": "hardcoded-secret",
                        "claim": "A credential literal may be consumed by authentication.",
                        "target_paths": ["settings.py"],
                        "confidence": 0.82,
                        "rationale": "The bounded source preview exposes a credential-named literal.",
                        "signal_refs": [],
                        "next_action": {
                            "action": "source_context",
                            "arguments": {"path": "settings.py", "start_line": 1},
                        },
                    }
                ],
                "rationale": "Create and inspect a scanner-independent hypothesis in one response.",
            }
        else:
            hypothesis_id = _first_between(request.prompt, '"hypothesis_id": "', '"')
            if self.analysis_calls == 2:
                next_action = {"action": "callers", "arguments": {"symbol": "use"}}
                assessment = "investigating"
            else:
                next_action = {"action": "submit_gate", "arguments": {}}
                assessment = "supported"
            payload = {
                "hypotheses": [],
                "updates": [
                    {
                        "hypothesis_id": hypothesis_id,
                        "assessment": assessment,
                        "next_action": next_action,
                        "evidence_refs": [],
                    }
                ],
                "rationale": "Continue the registered investigation.",
            }
        text = json.dumps(payload)
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=text,
            parsed_json=payload,
            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
            finish_reason="stop",
        )


class ResumeContinuationClient(ScriptedInvestigationClient):
    """Continue after source_context without replaying completed model/tool work."""

    def complete(self, request):
        if request.role != "analysis":
            return super().complete(request)
        self.requests.append(request)
        self.analysis_calls += 1
        hypothesis_id = _first_between(request.prompt, '"hypothesis_id": "', '"')
        if self.analysis_calls == 1:
            action = {"action": "callers", "arguments": {"symbol": "use"}}
            assessment = "investigating"
        else:
            action = {"action": "submit_gate", "arguments": {}}
            assessment = "supported"
        payload = {
            "hypotheses": [],
            "updates": [
                {
                    "hypothesis_id": hypothesis_id,
                    "assessment": assessment,
                    "next_action": action,
                    "evidence_refs": [],
                }
            ],
            "rationale": "Continue from the committed checkpoint without replay.",
        }
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=json.dumps(payload),
            parsed_json=payload,
            usage={"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
            finish_reason="stop",
        )


class SchemaInvalidInitialClient:
    def complete(self, request):
        payload = {"hypotheses": "not-an-array", "rationale": "invalid contract"}
        return LLMResponse(
            request_id=request.id or "",
            provider="mock",
            model=request.model,
            text=json.dumps(payload),
            parsed_json=payload,
            usage={"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
            finish_reason="stop",
        )


class BlockingCancellationClient:
    def __init__(self):
        self.token = None
        self.started = threading.Event()

    def set_cancellation_token(self, token):
        self.token = token

    def complete(self, request):
        self.started.set()
        self.token.wait(10)
        raise LLMCancelled("cancelled blocking test client")


def _first_between(value: str, prefix: str, suffix: str) -> str:
    start = value.index(prefix) + len(prefix)
    end = value.index(suffix, start)
    return value[start:end]


class AgentLedEndToEndTests(unittest.TestCase):
    def test_active_model_call_is_cancelled_and_accounted_without_waiting_for_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            token = CancellationToken()
            client = BlockingCancellationClient()
            result = {}

            def worker():
                result["summary"] = run_audit(
                    str(root), config, Path(tmp) / "runs", cancellation_token=token
                )

            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(client.started.wait(5))
                token.cancel()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            summary = result["summary"]
            self.assertEqual(summary["status"], "cancelled")
            lifecycle = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (Path(summary["run_dir"]) / "llm_attempts").glob("*/*.json")
            ]
            terminals = [item for item in lifecycle if item.get("kind") == "request-terminal"]
            self.assertEqual(terminals[-1]["terminal_status"], "cancelled")
    def test_public_resume_entry_reuses_completed_run_without_model_or_tool_redispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            client = ScriptedInvestigationClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                first = run_audit(str(root), config, output)
            run_dir = Path(first["run_dir"])
            lifecycle_before = sorted((run_dir / "llm" / "lifecycle").glob("*.json"))
            pattern_before = sorted((run_dir / "tool_outputs").glob("pattern-signals*.json"))
            with patch(
                "audit_agent.runtime.build_llm_client",
                side_effect=AssertionError("completed resume must not dispatch the model"),
            ):
                resumed = run_audit(
                    str(root),
                    config,
                    output,
                    resume_run_id=run_dir.name,
                )
            self.assertEqual(resumed["run_dir"], first["run_dir"])
            self.assertEqual(sorted((run_dir / "llm" / "lifecycle").glob("*.json")), lifecycle_before)
            self.assertEqual(sorted((run_dir / "tool_outputs").glob("pattern-signals*.json")), pattern_before)

    def test_interrupted_run_resumes_from_checkpoint_without_repeating_model_or_tool_calls(self):
        class SimulatedProcessInterruption(BaseException):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            output = Path(tmp) / "runs"
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            config.cve_mcp.enabled = False
            first_client = ScriptedInvestigationClient()
            original_terminalize = AgentLedInvestigationCoordinator._terminalize_response
            interrupted = {"raised": False}

            def interrupt_after_committed_source(self, response, accepted, refs, reason=""):
                original_terminalize(self, response, accepted, refs, reason)
                if (
                    accepted
                    and not interrupted["raised"]
                    and any(step.action == "source_context" for step in self.steps)
                ):
                    interrupted["raised"] = True
                    raise SimulatedProcessInterruption("synthetic process exit after checkpoint")

            with patch("audit_agent.runtime.build_llm_client", return_value=first_client), patch.object(
                AgentLedInvestigationCoordinator,
                "_terminalize_response",
                new=interrupt_after_committed_source,
            ):
                with self.assertRaises(SimulatedProcessInterruption):
                    run_audit(str(root), config, output)

            run_dirs = [item for item in output.iterdir() if item.is_dir()]
            self.assertEqual(len(run_dirs), 1)
            run_dir = run_dirs[0]
            state_paths = list((run_dir / "runtime_state").glob("state*.json"))
            self.assertTrue(state_paths, "checkpoint must persist resumable runtime state")
            interrupted_state = json.loads(
                max(state_paths, key=lambda item: item.stat().st_mtime_ns).read_text(encoding="utf-8")
            )
            self.assertEqual(interrupted_state["status"], "running")
            self.assertEqual(interrupted_state["llm_accounting"]["requests_used"], 2)
            pattern_before = sorted((run_dir / "tool_outputs").glob("pattern-signals*.json"))
            source_before = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (run_dir / "investigations" / "steps").glob("*.json")
                if json.loads(path.read_text(encoding="utf-8"))["action"] == "source_context"
            ]
            self.assertEqual(len(source_before), 1)

            resume_client = ResumeContinuationClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=resume_client):
                resumed = run_audit(
                    str(root),
                    config,
                    output,
                    resume_run_id=run_dir.name,
                )

            self.assertEqual(resumed["run_dir"], str(run_dir))
            self.assertEqual(resumed["status"], "succeeded", resumed)
            self.assertEqual(resumed["confirmed_count"], 1)
            self.assertEqual(resume_client.analysis_calls, 2)
            self.assertIn('"action": "source_context"', resume_client.requests[0].prompt)
            source_after = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (run_dir / "investigations" / "steps").glob("*.json")
                if json.loads(path.read_text(encoding="utf-8"))["action"] == "source_context"
            ]
            self.assertEqual(len(source_after), 1, "completed source tool action must not replay")
            self.assertEqual(resumed["investigation_budget"]["used"]["tool_calls"], 2)
            self.assertEqual(resumed["investigation_budget"]["used"]["requests"], 5)
            self.assertEqual(
                sorted((run_dir / "tool_outputs").glob("pattern-signals*.json")),
                pattern_before,
            )
            resource = json.loads(Path(resumed["resource_summary_ref"]).read_text(encoding="utf-8"))
            self.assertEqual(resource["llm_reconciliation_status"], "complete", resource.get("llm_gap_ids"))

    def test_initial_hypothesis_can_dispatch_first_source_action_without_existing_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            client = BootstrapActionClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["effective_mode"], "agent-led", summary)
            self.assertEqual(summary["status"], "succeeded", summary)
            self.assertTrue(client.bootstrap_source_seen)
            steps = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (Path(summary["run_dir"]) / "investigations" / "steps").glob("*.json")
            ]
            bootstrap_steps = [item for item in steps if item["action"] == "source_context"]
            self.assertEqual(len(bootstrap_steps), 1)
            self.assertNotEqual(bootstrap_steps[0]["hypothesis_id"], "")

    def test_schema_invalid_initial_response_is_repaired_in_a_separate_audited_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            config.cve_mcp.enabled = False
            client = RepairableInitialClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "succeeded", summary)
            self.assertEqual(summary["confirmed_count"], 1)
            self.assertEqual(client.requests[0].metadata["schema_repair_attempt"], 0)
            self.assertEqual(client.requests[1].metadata["schema_repair_attempt"], 1)
            self.assertIn("Missing required field: rationale", client.requests[1].prompt)
            self.assertIn("Original trusted request context", client.requests[1].prompt)
            self.assertIn("settings.py", client.requests[1].prompt)
            self.assertIn("remove that hypothesis", client.requests[1].prompt)
            lifecycle = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (Path(summary["run_dir"]) / "llm_attempts").glob("*/*.json")
            ]
            terminals = [item["terminal_status"] for item in lifecycle if item["kind"] == "request-terminal"]
            self.assertIn("fallback", terminals)
            self.assertIn("accepted", terminals)
            resource = json.loads(Path(summary["resource_summary_ref"]).read_text(encoding="utf-8"))
            self.assertEqual(resource["llm_reconciliation_status"], "complete", resource.get("llm_gap_ids"))

    def test_schema_invalid_initial_response_has_terminal_accounting_and_fallback_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            with patch("audit_agent.runtime.build_llm_client", return_value=SchemaInvalidInitialClient()):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            resource = json.loads(Path(summary["resource_summary_ref"]).read_text(encoding="utf-8"))
            self.assertEqual(resource["llm_reconciliation_status"], "complete", resource.get("llm_gap_ids"))
            self.assertFalse(
                any("missing-terminal" in item for item in resource.get("llm_gap_ids", [])),
                resource.get("llm_gap_ids"),
            )
            state = json.loads(Path(summary["runtime_state_ref"]).read_text(encoding="utf-8"))
            analysis_tasks = [
                item for item in state["tasks"] if item["kind"] == "agent-led-investigation"
            ]
            self.assertEqual(analysis_tasks[0]["status"], "fallback")
            self.assertEqual(analysis_tasks[0]["fallback_reason"], "schema-invalid")

    def test_scanner_independent_hypothesis_promotes_plans_and_confirms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            config.cve_mcp.enabled = False
            output = Path(tmp) / "runs"
            client = ScriptedInvestigationClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                summary = run_audit(str(root), config, output)
            self.assertEqual(summary["status"], "succeeded", summary)
            self.assertEqual(summary["effective_mode"], "agent-led")
            self.assertEqual(summary["confirmed_count"], 1)
            self.assertEqual(summary["evidence_gate_counts"].get("promoted"), 1)
            self.assertEqual(len(summary["verification_plan_refs"]), 1)
            self.assertTrue(client.requests)
            self.assertTrue(
                all(request.response_format == "auto" for request in client.requests),
                [request.response_format for request in client.requests],
            )
            run_dir = Path(summary["run_dir"])
            signals = list((run_dir / "signals").glob("*.json"))
            self.assertEqual(signals, [], "fixture must be a Pattern scanner blind spot")
            state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["requested_mode"], "agent-led")
            self.assertGreaterEqual(state["checkpoint_summary"]["count"], 4)
            report = json.loads((run_dir / "reports" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["runtime"]["investigation"]["effective_mode"], "agent-led")

    def test_midrun_provider_failure_preserves_committed_evidence_and_trusted_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from settings import CREDENTIAL\ndef auth():\n    return use(CREDENTIAL)\n",
                encoding="utf-8",
            )
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            with patch("audit_agent.runtime.build_llm_client", return_value=FailingVerificationClient()):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "degraded")
            self.assertEqual(summary["effective_mode"], "agent-led")
            self.assertEqual(summary["confirmed_count"], 1)
            self.assertTrue(any("verification-plan-fallback" in item for item in summary["degraded_reasons"]))

    def test_initial_provider_failure_runs_full_deterministic_fallback_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            with patch("audit_agent.runtime.build_llm_client", return_value=FailingInitialClient()):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "degraded")
            self.assertEqual(summary["effective_mode"], "deterministic-graph")
            self.assertIn("analysis-initial-failure", summary["fallback_reason"])

    def test_request_budget_denial_converges_without_extra_provider_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "settings.py").write_text("CREDENTIAL = 'Aa9$supersecret'\n", encoding="utf-8")
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.investigation.request_budget = 1
            config.llm.request_budget = 1
            config.dependency_intelligence.enabled = False
            client = ScriptedInvestigationClient()
            with patch("audit_agent.runtime.build_llm_client", return_value=client):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "degraded")
            self.assertEqual(client.analysis_calls, 1)
            self.assertEqual(summary["investigation_budget"]["used"]["requests"], 1)
            self.assertLessEqual(
                summary["investigation_budget"]["used"]["requests"],
                summary["investigation_budget"]["limits"]["request_budget"],
            )

    def test_default_mock_uses_explicit_degraded_deterministic_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.dependency_intelligence.enabled = False
            config.cve_mcp.enabled = False
            summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "degraded")
            self.assertEqual(summary["requested_mode"], "agent-led")
            self.assertEqual(summary["effective_mode"], "deterministic-graph")

    def test_real_provider_without_credential_degrades_without_attempting_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            config = AuditConfig.default()
            config.runtime_enabled = True
            config.llm.provider = "openai-compatible"
            config.llm.model = "course-model"
            config.llm.api_key_env = "AGENT_LED_MISSING_TEST_KEY"
            config.dependency_intelligence.enabled = False
            with patch.dict("os.environ", {}, clear=True), patch(
                "audit_agent.runtime.build_llm_client",
                side_effect=AssertionError("missing credential must not dispatch a model"),
            ):
                summary = run_audit(str(root), config, Path(tmp) / "runs")
            self.assertEqual(summary["status"], "degraded")
            self.assertEqual(summary["effective_mode"], "deterministic-graph")
            self.assertEqual(config.graph.mode, "agent-led")
            self.assertTrue(config.runtime_enabled)

    def test_pre_cancelled_agent_led_run_writes_terminal_cancelled_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
            token = CancellationToken()
            token.cancel()
            config = AuditConfig.default()
            config.investigation.allow_mock_provider = True
            config.dependency_intelligence.enabled = False
            with patch("audit_agent.runtime.build_llm_client", return_value=MockLLMClient()):
                summary = run_audit(str(root), config, Path(tmp) / "runs", cancellation_token=token)
            self.assertEqual(summary["status"], "cancelled")
            state = json.loads(Path(summary["runtime_state_ref"]).read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
