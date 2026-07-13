from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .benchmark import (
    BenchmarkConfig,
    BenchmarkRunner,
    build_engine_identity,
    compare_files,
    default_corpus_path,
    lock_manifest,
    readiness_for_profile,
    run_benchmark,
)
from .benchmark_evaluation import aggregate_repetitions, promotion_readiness
from .benchmark_runtime import AtomicJsonStore, run_child_scan
from .config import AuditConfig
from .integration import load_integration_environment, run_integration_preflight, run_integration_smoke
from .message_bus import replay_summary
from .pipeline import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-agent",
        description="CLI-first agentic security audit and validation pipeline.",
    )
    parser.add_argument("--config", help="Path to JSON configuration file.")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Audit one local directory or repository URL.")
    scan.add_argument("--target", required=True, help="Local path, GitHub URL, or GitLab URL.")
    scan.add_argument("--output", default="runs", help="Run output directory.")
    scan.add_argument(
        "--graph-mode",
        choices=["legacy", "deterministic-graph", "adaptive-graph"],
        default=None,
        help="Execution mode. deterministic-graph is the default; legacy remains available for rollback.",
    )
    scan.add_argument(
        "--validation-level",
        choices=["static-only", "poc-generate", "sandbox", "manual"],
        default=None,
        help="Validation level for accepted findings.",
    )
    scan.add_argument(
        "--sandbox",
        action="store_true",
        help="Enable sandbox execution for PoC-backed validation. Required for sandbox validation execution.",
    )
    scan.add_argument(
        "--sandbox-runner",
        choices=["local", "docker"],
        default=None,
        help="Sandbox runner to use for PoC execution.",
    )
    scan.add_argument(
        "--sandbox-docker-image",
        default=None,
        help="Docker image for Docker sandbox execution, such as python:3.12-slim.",
    )
    scan.add_argument(
        "--sandbox-docker-context",
        default=None,
        help="Docker CLI context for Docker sandbox execution, such as desktop-linux.",
    )
    scan.add_argument(
        "--sandbox-docker-host",
        default=None,
        help="Docker host endpoint for Docker sandbox execution, such as npipe:////./pipe/dockerDesktopLinuxEngine.",
    )
    scan.add_argument(
        "--llm-poc-repair",
        action="store_true",
        help="Explicitly enable constrained LLM PoC repair. Requires sandbox validation with the Docker runner.",
    )
    scan.add_argument(
        "--max-repair-attempts",
        type=int,
        default=None,
        help="Maximum LLM repair executions in 0..2, in addition to the deterministic initial execution.",
    )
    scan.add_argument("--runtime", action="store_true", help="Enable LLM runtime, prompt, memory, MCP, and message logs.")
    scan.add_argument("--llm-provider", default=None, help="LLM provider, such as mock or openai-compatible.")
    scan.add_argument("--model", default=None, help="LLM model name.")
    scan.add_argument("--prompt-version", default=None, help="Prompt template version.")
    scan.add_argument(
        "--llm-decisions",
        action="store_true",
        help="Allow schema-valid LLM proposals to participate in guarded agent decisions.",
    )
    scan.add_argument(
        "--llm-decision-roles",
        default=None,
        help="Comma-separated roles enabled for LLM decisions, such as analysis,verification.",
    )
    scan.add_argument(
        "--memory-mode",
        choices=["lexical", "embedding", "off"],
        default=None,
        help="Memory retrieval mode.",
    )
    scan.add_argument(
        "--mcp-mode",
        choices=["on", "off", "degraded"],
        default=None,
        help="MCP mode. degraded keeps audit running when server is unavailable.",
    )
    scan.add_argument(
        "--include",
        action="append",
        default=[],
        help="Repository-relative include glob. Repeat to set multiple include patterns.",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Repository-relative exclude glob. Repeat to add exclusion patterns.",
    )

    benchmark = subparsers.add_parser("benchmark", help="Run a configured benchmark corpus.")
    benchmark.add_argument("--benchmark-config", default=None, help="Benchmark JSON file.")
    benchmark.add_argument("--output", default="runs", help="Run output directory.")
    benchmark.add_argument("--profile", default="fixture", help="Corpus profile ID.")
    benchmark.add_argument("--case", action="append", default=[], help="Select a case ID; repeatable.")
    benchmark.add_argument("--cache-root", default=".benchmark-cache", help="Verified mirror/export cache root.")
    network = benchmark.add_mutually_exclusive_group()
    network.add_argument("--offline", action="store_true", default=True, help="Use local fixtures/cache only (default).")
    network.add_argument("--allow-network", action="store_true", help="Explicitly allow policy-approved fixed-argv Git acquisition.")
    benchmark.add_argument("--timeout", type=int, default=None, help="Upper bound for each selected case in seconds.")
    benchmark.add_argument("--provider", default=None, help="Explicit benchmark LLM provider identity.")
    benchmark.add_argument("--model", default=None, help="Explicit benchmark model identity.")
    benchmark.add_argument("--allow-docker", action="store_true", help="Allow case-declared Docker use and exact-label cleanup.")
    benchmark.add_argument("--resume", default=None, help="Resume a benchmark run ID.")
    benchmark.add_argument("--allow-partial", action="store_true", help="Emit partial results without a failure exit code.")
    benchmark.add_argument("--repetition", default=None, help="Real-model repetition ID retained as a comparison dimension.")
    benchmark.add_argument("--truth", default=None, help="Ground-truth manifest path.")
    benchmark.add_argument("--adjudications", default=None, help="Adjudication manifest path.")
    benchmark.add_argument("--comparison-dimension", action="append", default=[], help="Declared comparison dimension.")
    benchmark.add_argument("--compare", nargs=2, metavar=("BASELINE", "CANDIDATE"), help="Compare two benchmark JSON files.")
    benchmark.add_argument("--comparison-output", default=None, help="Comparison JSON output path.")
    benchmark.add_argument("--aggregate-repetitions", nargs="+", default=None, help="Compatible repetition benchmark JSON files.")
    benchmark.add_argument("--promote", default=None, help="Validate and promote a benchmark JSON path.")
    benchmark.add_argument("--baseline-output", default=None, help="Destination for an eligible promoted baseline.")
    benchmark.add_argument("--readiness", action="store_true", help="Validate selected profile readiness only.")
    benchmark.add_argument("--lock", action="store_true", help="Resolve a reviewed lock using --lock-resolutions.")
    benchmark.add_argument("--lock-resolutions", default=None, help="JSON with resolver, resolutions, and review_refs.")
    benchmark.add_argument("--lock-output", default=None, help="Resolved corpus lock output path.")

    child = subparsers.add_parser("benchmark-child", help=argparse.SUPPRESS)
    child.add_argument("--case-config", required=True, help=argparse.SUPPRESS)

    subparsers.add_parser("show-config", help="Print default or supplied configuration.")
    replay = subparsers.add_parser("replay", help="Replay or summarize a run message log.")
    replay.add_argument("--messages", required=True, help="Path to messages.jsonl.")

    integration = subparsers.add_parser("integration", help="Run live integration preflight or smoke checks.")
    integration_subparsers = integration.add_subparsers(dest="integration_command")
    preflight = integration_subparsers.add_parser("preflight", help="Check real LLM and MCP configuration.")
    _add_integration_flags(preflight)
    smoke = integration_subparsers.add_parser("smoke", help="Run a controlled live integration smoke audit.")
    _add_integration_flags(smoke)
    smoke.add_argument("--target", default=None, help="Small local target for the smoke audit.")

    graph_smoke = subparsers.add_parser(
        "graph-decision-smoke",
        help="Run an opt-in bounded real-model adaptive graph decision smoke on a local fixture.",
    )
    graph_smoke.add_argument("--target", default="fixtures/integration_smoke")
    graph_smoke.add_argument("--output", default="runs/graph-decision-smoke")
    graph_smoke.add_argument("--provider", default=None)
    graph_smoke.add_argument("--model", default=None)
    graph_smoke.add_argument("--live", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = AuditConfig.from_json(args.config) if args.config else AuditConfig.default()
    if getattr(args, "validation_level", None):
        config.default_validation_level = args.validation_level
    _apply_runtime_args(config, args)

    if args.command == "scan":
        try:
            config.validate_poc_repair_prerequisites()
        except ValueError as exc:
            parser.error(str(exc))
        result = run_audit(args.target, config, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "graph-decision-smoke":
        return _run_graph_decision_smoke(config, args)
    if args.command == "benchmark":
        corpus_path = Path(args.benchmark_config) if args.benchmark_config else default_corpus_path()
        dimensions = args.comparison_dimension or ["engine"]
        if args.compare:
            comparison = compare_files(args.compare[0], args.compare[1], dimensions)
            if args.comparison_output:
                AtomicJsonStore.write(args.comparison_output, comparison)
            print(json.dumps(comparison, ensure_ascii=False, indent=2))
            return 0
        if args.aggregate_repetitions:
            reports = [json.loads(Path(path).read_text(encoding="utf-8")) for path in args.aggregate_repetitions]
            aggregate = aggregate_repetitions(reports)
            if args.comparison_output:
                AtomicJsonStore.write(args.comparison_output, aggregate)
            print(json.dumps(aggregate, ensure_ascii=False, indent=2))
            return 0
        if args.readiness:
            readiness = readiness_for_profile(corpus_path, args.profile)
            print(json.dumps(readiness, ensure_ascii=False, indent=2))
            return 0 if readiness["ready"] else 2
        if args.lock:
            if not args.lock_resolutions or not args.lock_output:
                parser.error("--lock requires --lock-resolutions and --lock-output")
            lock_input = json.loads(Path(args.lock_resolutions).read_text(encoding="utf-8"))
            locked = lock_manifest(
                corpus_path,
                args.lock_output,
                resolver=str(lock_input.get("resolver") or ""),
                resolutions=dict(lock_input.get("resolutions") or {}),
                review_refs=dict(lock_input.get("review_refs") or {}),
            )
            print(json.dumps(locked, ensure_ascii=False, indent=2))
            return 0
        if args.promote:
            report = json.loads(Path(args.promote).read_text(encoding="utf-8"))
            readiness = promotion_readiness(report, profile_kind=args.profile)
            if readiness["ready"] and args.baseline_output:
                AtomicJsonStore.write(args.baseline_output, report)
            print(json.dumps(readiness, ensure_ascii=False, indent=2))
            return 0 if readiness["ready"] else 2
        if corpus_path.name != "projects.json":
            load_integration_environment(config, cwd=Path.cwd(), env=dict(os.environ))
            identity = build_engine_identity(
                prompt_version=config.prompts.default_version,
                template_dir=config.prompts.template_dir,
                provider=args.provider or config.llm.provider,
                model=args.model or config.llm.model,
                repetition=args.repetition,
            )
            report, exit_code = run_benchmark(
                corpus_path=corpus_path,
                profile_id=args.profile,
                output_root=args.output,
                cache_root=args.cache_root,
                truth_path=args.truth or corpus_path.parent / "truth.v1.json",
                adjudication_path=args.adjudications or corpus_path.parent / "adjudications.v1.json",
                case_ids=args.case or None,
                allow_network=bool(args.allow_network),
                allow_docker=bool(args.allow_docker),
                allow_partial=args.allow_partial,
                resume_run_id=args.resume,
                comparison_dimensions=dimensions,
                engine_identity=identity,
                timeout_seconds=args.timeout,
            )
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return exit_code
        benchmark_config = (
            BenchmarkConfig.load(args.benchmark_config) if args.benchmark_config else BenchmarkConfig.load_default()
        )
        runner = BenchmarkRunner(benchmark_config.targets)

        def audit_target(target):
            if target.source.startswith("http"):
                return {
                    "candidate_count": 0,
                    "rejected_count": 0,
                    "validated_count": 0,
                    "setup_status": "remote-download-skipped",
                }
            return run_audit(target.source, config, args.output)

        summary = runner.run(audit_target)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        return 0 if summary.failed_projects == 0 else 2
    if args.command == "benchmark-child":
        return run_child_scan(args.case_config)
    if args.command == "replay":
        print(json.dumps(replay_summary(args.messages), ensure_ascii=False, indent=2))
        return 0
    if args.command == "integration":
        include_llm = args.llm or not args.mcp
        include_mcp = args.mcp or not args.llm
        if args.integration_command == "preflight":
            report = run_integration_preflight(
                config,
                output_dir=args.output,
                include_llm=include_llm,
                include_mcp=include_mcp,
                execute_live=args.live,
                command="integration preflight",
            )
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
            return 0
        if args.integration_command == "smoke":
            report = run_integration_smoke(
                config,
                target=args.target,
                output_dir=args.output,
                execute_live=args.live,
                include_llm=include_llm,
                include_mcp=include_mcp,
            )
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
            return 0
        parser.error("integration requires a subcommand: preflight or smoke")
    if args.command == "show-config":
        print(json.dumps(config.to_dict(), ensure_ascii=False, indent=2))
        return 0
    parser.print_help()
    return 0

def _apply_runtime_args(config: AuditConfig, args) -> None:
    if getattr(args, "graph_mode", None):
        config.graph.mode = args.graph_mode
    if getattr(args, "validation_level", None):
        config.default_validation_level = args.validation_level
    if getattr(args, "llm_decisions", False):
        config.runtime_enabled = True
        config.llm_decisions.enabled = True
    if getattr(args, "llm_decision_roles", None):
        config.llm_decisions.roles = [
            item.strip() for item in args.llm_decision_roles.split(",") if item.strip()
        ]
    if not hasattr(args, "runtime"):
        return
    if args.runtime:
        config.runtime_enabled = True
    if args.llm_provider:
        config.llm.provider = args.llm_provider
    if args.model:
        config.llm.model = args.model
    if args.prompt_version:
        config.prompts.default_version = args.prompt_version
    if args.memory_mode:
        config.memory.enabled = args.memory_mode != "off"
        config.memory.mode = "lexical" if args.memory_mode == "off" else args.memory_mode
    if args.mcp_mode:
        config.mcp.enabled = args.mcp_mode != "off"
        config.mcp.degraded_mode = args.mcp_mode in {"degraded", "on"}
    if getattr(args, "include", None):
        config.audit_scope.include_patterns.extend(args.include)
    if getattr(args, "exclude", None):
        config.audit_scope.exclude_patterns.extend(args.exclude)
    if getattr(args, "sandbox", False):
        config.sandbox.enabled = True
    if getattr(args, "sandbox_runner", None):
        config.sandbox.runner = args.sandbox_runner
    if getattr(args, "sandbox_docker_image", None):
        config.sandbox.docker_image = args.sandbox_docker_image
    if getattr(args, "sandbox_docker_context", None):
        config.sandbox.docker_context = args.sandbox_docker_context
    if getattr(args, "sandbox_docker_host", None):
        config.sandbox.docker_host = args.sandbox_docker_host
    if getattr(args, "llm_poc_repair", False):
        config.poc_repair.enabled = True
        config.poc_repair.effective_source = "explicit"
        config.runtime_enabled = True
    if getattr(args, "max_repair_attempts", None) is not None:
        config.poc_repair.max_repair_attempts = args.max_repair_attempts
        config.poc_repair.effective_source = "explicit"


def _run_graph_decision_smoke(config: AuditConfig, args) -> int:
    load_integration_environment(config, cwd=Path.cwd(), env=os.environ)
    if args.provider:
        config.llm.provider = args.provider
    if args.model:
        config.llm.model = args.model
    prerequisites = {
        "live_flag": bool(args.live),
        "policy_opt_in": os.environ.get("AUDIT_AGENT_RUN_GRAPH_SMOKE") == "1",
        "real_provider": config.llm.provider not in {"", "mock", "disabled"},
        "model_configured": config.llm.model not in {"", "mock", "disabled"},
        "api_key_configured": bool(os.environ.get(config.llm.api_key_env)),
    }
    if not all(prerequisites.values()):
        print(json.dumps({"status": "skipped", "prerequisites": prerequisites}, indent=2))
        return 0
    target = Path(args.target).resolve()
    fixture_root = (Path.cwd() / "fixtures").resolve()
    if not target.is_relative_to(fixture_root) or not target.is_dir():
        print(json.dumps({"status": "skipped", "reason": "target-must-be-local-fixture"}, indent=2))
        return 0
    config.runtime_enabled = True
    config.graph.mode = "adaptive-graph"
    config.graph.max_nodes = min(config.graph.max_nodes, 20)
    config.graph.max_scheduler_iterations = min(config.graph.max_scheduler_iterations, 64)
    config.graph.max_replans = min(config.graph.max_replans, 2)
    config.graph.max_checkpoints = min(config.graph.max_checkpoints, 2)
    config.llm_decisions.enabled = True
    config.llm_decisions.roles = ["orchestrator"]
    config.llm.request_budget = min(config.llm.request_budget or 2, 2)
    config.llm.token_budget = min(config.llm.token_budget, 20_000)
    config.memory.enabled = False
    config.mcp.enabled = False
    config.cve_mcp.enabled = False
    config.sandbox.enabled = False
    summary = run_audit(str(target), config, args.output)
    run_dir = Path(summary["run_dir"])
    state = json.loads((run_dir / "runtime_state" / "state.json").read_text(encoding="utf-8"))
    decision_artifacts = sorted(str(path) for path in (run_dir / "prompts").glob("*graph-decision*"))
    status = "passed" if state.get("status") == "succeeded" and decision_artifacts else "failed"
    print(
        json.dumps(
            {
                "status": status,
                "graph_mode": state.get("graph_mode"),
                "checkpoint_counts": state.get("checkpoint_counts", {}),
                "graph_fallback_reason": state.get("graph_fallback_reason", ""),
                "decision_artifact_count": len(decision_artifacts),
                "run_dir": str(run_dir),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if status == "passed" else 2


def _add_integration_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--llm", action="store_true", help="Include LLM provider preflight.")
    parser.add_argument("--mcp", action="store_true", help="Include CVE MCP preflight.")
    parser.add_argument("--live", action="store_true", help="Perform live calls instead of config-only checks.")
    parser.add_argument("--llm-decisions", action="store_true", help="Enable guarded LLM decision participation during smoke.")
    parser.add_argument("--llm-decision-roles", default=None, help="Comma-separated roles enabled for LLM decisions.")
    parser.add_argument("--output", default="runs", help="Run output directory.")


if __name__ == "__main__":
    raise SystemExit(main())
